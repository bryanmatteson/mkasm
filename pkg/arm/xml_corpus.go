package arm

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	maxTarXMLFileSize       = 64 << 20
	maxTarXMLTotal          = 512 << 20
	defaultTarInflightBytes = 32 << 20
)

var ErrCorpusEntryUnavailable = errors.New("corpus entry unavailable")

// XMLCorpus provides the logical XML documents used by the ARM pipeline.
// Directory corpora expose every document. Streaming tar corpora retain only
// encodingindex.xml and serve IForms from their prepared compact models.
type XMLCorpus interface {
	OpenXML(name string) (io.ReadCloser, error)
	Description() string
}

type DirectoryXMLCorpus struct {
	root string
}

func NewDirectoryXMLCorpus(root string) *DirectoryXMLCorpus {
	return &DirectoryXMLCorpus{root: root}
}

func (c *DirectoryXMLCorpus) OpenXML(name string) (io.ReadCloser, error) {
	name, err := cleanCorpusName(name)
	if err != nil {
		return nil, err
	}
	filename := filepath.Join(c.root, filepath.FromSlash(name))
	if isUnavailableCloudFile(filename) {
		return nil, fmt.Errorf("%w: %s", ErrCorpusEntryUnavailable, name)
	}
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("open corpus entry %q: %w", name, err)
	}
	return f, nil
}

func (c *DirectoryXMLCorpus) Description() string { return c.root }

// TarXMLCorpusOptions bounds the concurrent preparation stage. One member
// larger than MaxInflightBytes is admitted alone, so the actual hard bound is
// max(MaxInflightBytes, the largest allowed XML member).
type TarXMLCorpusOptions struct {
	Workers          int
	MaxInflightBytes int64
}

func (o TarXMLCorpusOptions) normalized() TarXMLCorpusOptions {
	if o.Workers <= 0 {
		o.Workers = runtime.GOMAXPROCS(0)
	}
	if o.Workers > 32 {
		o.Workers = 32
	}
	if o.MaxInflightBytes <= 0 {
		o.MaxInflightBytes = defaultTarInflightBytes
	}
	return o
}

type TarXMLCorpusStats struct {
	XMLMembers          int
	IFormPages          int
	PreparedIForms      int
	PreparedAliases     int
	ExpandedXMLBytes    int64
	PeakInflightBytes   int64
	RetainedRawXMLBytes int64
}

// TarXMLCorpus is a prepared, immutable view of a tar stream. The loader
// consumes gzip/tar sequentially and retains compact ParsedIForm models rather
// than the expanded XML members. Only encodingindex.xml remains as raw XML for
// Pass 1; it is released immediately after that pass.
type TarXMLCorpus struct {
	mu      sync.RWMutex
	source  string
	files   map[string][]byte
	forms   map[string]map[string]*ParsedIForm
	aliases []AliasEncoding
	stats   TarXMLCorpusStats
}

func LoadTarXMLCorpus(r io.Reader, source string) (*TarXMLCorpus, error) {
	return LoadTarXMLCorpusWithOptions(r, source, TarXMLCorpusOptions{})
}

func LoadTarXMLCorpusWithOptions(r io.Reader, source string, options TarXMLCorpusOptions) (*TarXMLCorpus, error) {
	options = options.normalized()

	br := bufio.NewReader(r)
	payload := io.Reader(br)
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return nil, fmt.Errorf("open gzip corpus: %w", err)
		}
		defer gz.Close()
		payload = gz
	}

	type memberJob struct {
		name   string
		data   []byte
		charge int64
	}

	tr := tar.NewReader(payload)
	jobs := make(chan memberJob, options.Workers)
	budget := newInflightBudget(options.MaxInflightBytes)
	arena := newMemberBufferArena()
	builder := newPreparedCorpusBuilder()
	rootHint := datedArchiveRootHint(source)

	var (
		workers  sync.WaitGroup
		errOnce  sync.Once
		firstErr error
	)
	recordError := func(err error) {
		errOnce.Do(func() {
			firstErr = err
			budget.cancel()
		})
	}

	for range options.Workers {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for job := range jobs {
				if !budget.canceled() {
					if err := prepareXMLMember(builder, job.name, job.data); err != nil {
						recordError(fmt.Errorf("prepare tar member %q: %w", job.name, err))
					}
				}
				arena.put(job.data)
				budget.release(job.charge)
			}
		}()
	}

	roots := make(map[string]struct{})
	seen := make(map[string]struct{}, 4096)
	sawFeaturesJSON := false
	sawInstructionsJSON := false
	var total int64
readLoop:
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			recordError(fmt.Errorf("read tar corpus: %w", err))
			break
		}
		if !h.FileInfo().Mode().IsRegular() {
			continue
		}
		name, err := cleanCorpusName(h.Name)
		if err != nil {
			recordError(fmt.Errorf("tar member %q: %w", h.Name, err))
			break
		}
		switch strings.ToLower(path.Base(name)) {
		case "features.json":
			sawFeaturesJSON = true
		case "instructions.json":
			sawInstructionsJSON = true
		}
		if !strings.EqualFold(path.Ext(name), ".xml") {
			continue
		}
		if h.Size < 0 || h.Size > maxTarXMLFileSize {
			recordError(fmt.Errorf("tar member %q has invalid XML size %d", name, h.Size))
			break
		}
		total += h.Size
		if total > maxTarXMLTotal {
			recordError(fmt.Errorf("tar XML payload exceeds %d bytes", maxTarXMLTotal))
			break
		}
		if _, duplicate := seen[name]; duplicate {
			recordError(fmt.Errorf("duplicate tar XML member %q", name))
			break
		}
		seen[name] = struct{}{}
		if path.Base(name) == "encodingindex.xml" {
			roots[path.Dir(name)] = struct{}{}
		}
		if rootHint != "" && !strings.HasPrefix(name, rootHint+"/") {
			continue
		}

		size := int(h.Size)
		charge := int64(memberBufferClass(size))
		if !budget.acquire(charge) {
			break readLoop
		}
		data := arena.get(size)
		if _, err := io.ReadFull(tr, data); err != nil {
			arena.put(data)
			budget.release(charge)
			recordError(fmt.Errorf("read tar member %q: %w", name, err))
			break
		}
		jobs <- memberJob{name: name, data: data, charge: charge}
	}

	close(jobs)
	workers.Wait()
	arena.reset()
	if firstErr != nil {
		return nil, firstErr
	}
	if len(roots) == 0 {
		switch {
		case sawInstructionsJSON:
			return nil, fmt.Errorf("tar corpus contains AARCHMRS Instructions.json, but this generator requires the A64 ISA XML archive containing encodingindex.xml")
		case sawFeaturesJSON:
			return nil, fmt.Errorf("tar corpus contains AARCHMRS Features.json only; assembler generation requires the A64 ISA XML archive containing encodingindex.xml")
		}
		return nil, fmt.Errorf("tar corpus has no encodingindex.xml")
	}
	root, err := selectCorpusRoot(roots, rootHint)
	if err != nil {
		return nil, err
	}

	corpus, err := builder.finish(source, root)
	if err != nil {
		return nil, err
	}
	corpus.stats.XMLMembers = len(seen)
	corpus.stats.ExpandedXMLBytes = total
	corpus.stats.PeakInflightBytes = budget.peakBytes()
	return corpus, nil
}

// datedArchiveRootHint returns the corpus root named by an official release
// archive. For example, ISA_A64_xml_A_profile-2026-06.tar.gz names the
// ISA_A64_xml_A_profile-2026-06 root. Restricting this optimization to dated
// release names keeps renamed and generic archives on the fully general path.
func datedArchiveRootHint(source string) string {
	source = strings.TrimRight(source, "/")
	if cut := strings.IndexAny(source, "?#"); cut >= 0 {
		source = source[:cut]
	}
	name := path.Base(source)
	for _, suffix := range []string{".tar.gz", ".tgz", ".tar"} {
		if len(name) >= len(suffix) && strings.EqualFold(name[len(name)-len(suffix):], suffix) {
			name = name[:len(name)-len(suffix)]
			break
		}
	}
	if _, _, ok := splitDatedCorpusRoot(name); !ok {
		return ""
	}
	return name
}

func selectCorpusRoot(roots map[string]struct{}, hint string) (string, error) {
	if hint != "" {
		if _, ok := roots[hint]; ok {
			return hint, nil
		}
		return "", fmt.Errorf(
			"tar archive name selects corpus root %q, but available roots are %s",
			hint, formatCorpusRoots(roots),
		)
	}
	if len(roots) == 1 {
		for root := range roots {
			return root, nil
		}
	}

	var (
		series   string
		selected string
		latest   int
	)
	for root := range roots {
		rootSeries, release, ok := splitDatedCorpusRoot(root)
		if !ok || series != "" && rootSeries != series {
			return "", fmt.Errorf(
				"tar corpus has %d unrelated encodingindex.xml roots: %s",
				len(roots), formatCorpusRoots(roots),
			)
		}
		series = rootSeries
		if selected == "" || release > latest {
			selected, latest = root, release
		}
	}
	if selected == "" {
		return "", fmt.Errorf("tar corpus has no encodingindex.xml")
	}
	return selected, nil
}

// splitDatedCorpusRoot recognizes a trailing YYYY-MM release without regex.
// The returned series includes the parent path so unrelated nested corpora
// cannot be silently combined.
func splitDatedCorpusRoot(root string) (series string, release int, ok bool) {
	base := path.Base(root)
	const suffixLen = len("-2000-01")
	if len(base) <= suffixLen ||
		base[len(base)-suffixLen] != '-' ||
		base[len(base)-3] != '-' {
		return "", 0, false
	}
	year, ok := decimalDigits(base[len(base)-7 : len(base)-3])
	if !ok {
		return "", 0, false
	}
	month, ok := decimalDigits(base[len(base)-2:])
	if !ok || month < 1 || month > 12 {
		return "", 0, false
	}
	series = path.Join(path.Dir(root), base[:len(base)-suffixLen])
	return series, year*12 + month, true
}

func decimalDigits(s string) (int, bool) {
	value := 0
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		value = value*10 + int(s[i]-'0')
	}
	return value, true
}

func formatCorpusRoots(roots map[string]struct{}) string {
	names := make([]string, 0, len(roots))
	for root := range roots {
		names = append(names, root)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

func OpenTarXMLCorpus(ctx context.Context, location string) (*TarXMLCorpus, error) {
	return OpenTarXMLCorpusWithOptions(ctx, location, TarXMLCorpusOptions{})
}

func OpenTarXMLCorpusWithOptions(ctx context.Context, location string, options TarXMLCorpusOptions) (*TarXMLCorpus, error) {
	if location == "" {
		return nil, fmt.Errorf("empty corpus location")
	}
	if location == "-" {
		return LoadTarXMLCorpusWithOptions(os.Stdin, "stdin", options)
	}
	if strings.HasPrefix(location, "https://") || strings.HasPrefix(location, "http://") {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
		if err != nil {
			return nil, fmt.Errorf("create corpus request: %w", err)
		}
		client := &http.Client{Timeout: 5 * time.Minute}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("download corpus: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			_, _ = io.CopyN(io.Discard, resp.Body, 4096)
			return nil, fmt.Errorf("download corpus: HTTP %s", resp.Status)
		}
		return LoadTarXMLCorpusWithOptions(resp.Body, location, options)
	}

	f, err := os.Open(location)
	if err != nil {
		return nil, fmt.Errorf("open tar corpus %q: %w", location, err)
	}
	defer f.Close()
	return LoadTarXMLCorpusWithOptions(f, location, options)
}

func (c *TarXMLCorpus) OpenXML(name string) (io.ReadCloser, error) {
	name, err := cleanCorpusName(name)
	if err != nil {
		return nil, err
	}
	c.mu.RLock()
	data, ok := c.files[name]
	c.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("corpus entry %q: %w", name, os.ErrNotExist)
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (c *TarXMLCorpus) Description() string { return c.source }
func (c *TarXMLCorpus) Stats() TarXMLCorpusStats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.stats
}

func (c *TarXMLCorpus) preparedIForm(name, encodingID string) (*ParsedIForm, bool) {
	name, err := cleanCorpusName(name)
	if err != nil {
		return nil, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	byEncoding := c.forms[name]
	form, ok := byEncoding[encodingID]
	return form, ok
}

func (c *TarXMLCorpus) preparedAliases() []AliasEncoding {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]AliasEncoding(nil), c.aliases...)
}

func (c *TarXMLCorpus) releaseXML(name string) {
	name, err := cleanCorpusName(name)
	if err != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if data, ok := c.files[name]; ok {
		c.stats.RetainedRawXMLBytes -= int64(len(data))
		delete(c.files, name)
	}
}

func (c *TarXMLCorpus) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.files)
	clear(c.forms)
	c.aliases = nil
	c.stats.RetainedRawXMLBytes = 0
	return nil
}

type preparedCorpusBuilder struct {
	mu      sync.Mutex
	files   map[string][]byte
	forms   map[string]map[string]*ParsedIForm
	aliases []AliasEncoding
}

func newPreparedCorpusBuilder() *preparedCorpusBuilder {
	return &preparedCorpusBuilder{
		files: make(map[string][]byte),
		forms: make(map[string]map[string]*ParsedIForm),
	}
}

func prepareXMLMember(builder *preparedCorpusBuilder, name string, data []byte) error {
	if path.Base(name) == "encodingindex.xml" {
		builder.mu.Lock()
		builder.files[name] = bytes.Clone(data)
		builder.mu.Unlock()
		return nil
	}

	ids, aliases, isIForm, err := inspectIFormMemberBytes(data, name)
	if err != nil || !isIForm {
		return err
	}

	forms := make(map[string]*ParsedIForm, len(ids))
	var explanations []AsmExplanation
	for i, id := range ids {
		if _, duplicate := forms[id]; duplicate {
			return fmt.Errorf("duplicate encoding %q", id)
		}
		var shared *[]AsmExplanation
		if i > 0 {
			shared = &explanations
		}
		form, err := parseIFormShared(bytes.NewReader(data), id, shared)
		if err != nil {
			return fmt.Errorf("parse encoding %q: %w", id, err)
		}
		if i == 0 {
			explanations = form.Explanations
		}
		forms[id] = form
	}

	builder.mu.Lock()
	builder.forms[name] = forms
	builder.aliases = append(builder.aliases, aliases...)
	builder.mu.Unlock()
	return nil
}

func (b *preparedCorpusBuilder) finish(source, root string) (*TarXMLCorpus, error) {
	prefix := ""
	if root != "." {
		prefix = root + "/"
	}
	relative := func(name string) (string, bool) {
		if !strings.HasPrefix(name, prefix) {
			return "", false
		}
		name = strings.TrimPrefix(name, prefix)
		return name, name != ""
	}

	files := make(map[string][]byte, 1)
	var retained int64
	for name, data := range b.files {
		if rel, ok := relative(name); ok {
			files[rel] = data
			retained += int64(len(data))
		}
	}
	if _, ok := files["encodingindex.xml"]; !ok {
		return nil, fmt.Errorf("tar corpus root %q has no encodingindex.xml", root)
	}

	forms := make(map[string]map[string]*ParsedIForm, len(b.forms))
	pageCount, formCount := 0, 0
	for name, byEncoding := range b.forms {
		rel, ok := relative(name)
		if !ok {
			continue
		}
		forms[rel] = byEncoding
		pageCount++
		formCount += len(byEncoding)
	}

	aliases := make([]AliasEncoding, 0, len(b.aliases))
	for _, alias := range b.aliases {
		rel, ok := relative(alias.IFormFile)
		if !ok {
			continue
		}
		alias.IFormFile = rel
		aliases = append(aliases, alias)
	}

	return &TarXMLCorpus{
		source:  source,
		files:   files,
		forms:   forms,
		aliases: aliases,
		stats: TarXMLCorpusStats{
			IFormPages:          pageCount,
			PreparedIForms:      formCount,
			PreparedAliases:     len(aliases),
			RetainedRawXMLBytes: retained,
		},
	}, nil
}

// memberBufferArena is a safe, resettable region for transient tar members.
// Buffers are grouped by power-of-two capacity and reused only during one load.
type memberBufferArena struct {
	mu   sync.Mutex
	free map[int][][]byte
}

func newMemberBufferArena() *memberBufferArena {
	return &memberBufferArena{free: make(map[int][][]byte)}
}

func memberBufferClass(size int) int {
	if size <= 4096 {
		return 4096
	}
	return 1 << bits.Len(uint(size-1))
}

func (a *memberBufferArena) get(size int) []byte {
	class := memberBufferClass(size)
	a.mu.Lock()
	list := a.free[class]
	if len(list) != 0 {
		buffer := list[len(list)-1]
		a.free[class] = list[:len(list)-1]
		a.mu.Unlock()
		return buffer[:size]
	}
	a.mu.Unlock()
	return make([]byte, size, class)
}

func (a *memberBufferArena) put(buffer []byte) {
	class := cap(buffer)
	a.mu.Lock()
	a.free[class] = append(a.free[class], buffer[:class])
	a.mu.Unlock()
}

func (a *memberBufferArena) reset() {
	a.mu.Lock()
	clear(a.free)
	a.mu.Unlock()
}

type inflightBudget struct {
	mu       sync.Mutex
	cond     *sync.Cond
	limit    int64
	used     int64
	peak     int64
	stopping bool
}

func newInflightBudget(limit int64) *inflightBudget {
	b := &inflightBudget{limit: limit}
	b.cond = sync.NewCond(&b.mu)
	return b
}

func (b *inflightBudget) acquire(size int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for !b.stopping && b.used != 0 && b.used+size > b.limit {
		b.cond.Wait()
	}
	if b.stopping {
		return false
	}
	b.used += size
	if b.used > b.peak {
		b.peak = b.used
	}
	return true
}

func (b *inflightBudget) release(size int64) {
	b.mu.Lock()
	b.used -= size
	b.cond.Broadcast()
	b.mu.Unlock()
}

func (b *inflightBudget) cancel() {
	b.mu.Lock()
	b.stopping = true
	b.cond.Broadcast()
	b.mu.Unlock()
}

func (b *inflightBudget) canceled() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.stopping
}

func (b *inflightBudget) peakBytes() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.peak
}

func cleanCorpusName(name string) (string, error) {
	name = strings.ReplaceAll(name, "\\", "/")
	name = strings.TrimPrefix(name, "./")
	clean := path.Clean(name)
	if clean == "." || clean == "" || path.IsAbs(clean) || clean == ".." ||
		strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("invalid corpus entry name %q", name)
	}
	return clean, nil
}
