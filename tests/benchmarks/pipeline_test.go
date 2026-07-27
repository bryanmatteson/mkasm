package benchmarks_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bryanmatteson/mkasm/pkg/arm"
)

const corpusEnv = "MKASM_BENCH_CORPUS"

var benchmarkInput struct {
	once   sync.Once
	source string
	data   []byte
	err    error
}

func compressedCorpus(b *testing.B) (string, []byte) {
	b.Helper()
	benchmarkInput.once.Do(func() {
		benchmarkInput.source = os.Getenv(corpusEnv)
		if benchmarkInput.source == "" {
			benchmarkInput.err = fmt.Errorf("%s is required", corpusEnv)
			return
		}
		if benchmarkInput.source == "-" {
			benchmarkInput.err = fmt.Errorf("%s=- is not repeatable; use a URL or filepath", corpusEnv)
			return
		}
		benchmarkInput.data, benchmarkInput.err = readBenchmarkInput(benchmarkInput.source)
	})
	if benchmarkInput.err != nil {
		b.Fatal(benchmarkInput.err)
	}
	return benchmarkInput.source, benchmarkInput.data
}

func readBenchmarkInput(location string) ([]byte, error) {
	if !strings.HasPrefix(location, "http://") && !strings.HasPrefix(location, "https://") {
		data, err := os.ReadFile(location)
		if err != nil {
			return nil, fmt.Errorf("read corpus %q: %w", location, err)
		}
		return data, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		return nil, fmt.Errorf("create corpus request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download corpus: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("download corpus: HTTP %s", resp.Status)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("download corpus body: %w", err)
	}
	return data, nil
}

// BenchmarkCompressedCorpusLoad measures the streaming gzip/tar loader,
// hand-written IForm scan, compact model construction, and release selection.
func BenchmarkCompressedCorpusLoad(b *testing.B) {
	source, data := compressedCorpus(b)
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()

	var stats arm.TarXMLCorpusStats
	for range b.N {
		corpus, err := arm.LoadTarXMLCorpus(bytes.NewReader(data), source)
		if err != nil {
			b.Fatal(err)
		}
		stats = corpus.Stats()
		if err := corpus.Close(); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(stats.PreparedIForms), "iforms")
	b.ReportMetric(float64(stats.PeakInflightBytes)/(1<<20), "peak-inflight-MiB")
}

// BenchmarkParsePipeline measures corpus loading plus Pass 1 and Pass 2.
func BenchmarkParsePipeline(b *testing.B) {
	benchmarkPipeline(b, "")
}

// BenchmarkRustCodegenPipeline measures corpus loading and all three passes,
// including writing the generated Rust project. It does not compile the crate.
func BenchmarkRustCodegenPipeline(b *testing.B) {
	benchmarkPipeline(b, arm.LangRust)
}

func benchmarkPipeline(b *testing.B, language arm.CodegenLang) {
	source, data := compressedCorpus(b)
	output := filepath.Join(b.TempDir(), "aarch64")
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()

	resolved := 0
	for range b.N {
		corpus, err := arm.LoadTarXMLCorpus(bytes.NewReader(data), source)
		if err != nil {
			b.Fatal(err)
		}
		config := arm.ARMParserConfig{
			Corpus:            corpus,
			EncodingIndexPath: arm.ArchAArch64.SpecIndexFile(),
			OutputDirectory:   output,
			SkipCodegen:       language == "",
			IFormWorkers:      8,
			Arch:              arm.ArchAArch64,
		}
		if language != "" {
			config.Languages = []arm.CodegenLang{language}
		}
		parser := arm.NewARMParser(config)
		if err := parser.Parse(context.Background()); err != nil {
			b.Fatal(err)
		}
		resolved = len(parser.ResolvedInstructions())
		if err := parser.Close(2 * time.Second); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(resolved), "instructions")
}
