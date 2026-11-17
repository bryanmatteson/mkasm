package ptx

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

type Profile struct {
	MaxVersion  string `json:"max_version,omitempty"`
	Target      string `json:"target,omitempty"`
	AddressSize int    `json:"address_size,omitempty"`
}
type Issue struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Message  string `json:"message"`
	Offset   int    `json:"offset"`
	Document string `json:"document,omitempty"`
}
type Validation struct {
	Issues           []Issue `json:"issues"`
	SemanticComplete bool    `json:"semantic_complete"`
}

func (v Validation) Error() error {
	for _, i := range v.Issues {
		if i.Severity == "error" {
			return fmt.Errorf("PTX %s at %d: %s", i.Code, i.Offset, i.Message)
		}
	}
	return nil
}
func version(s string) int {
	p := strings.Split(s, ".")
	if len(p) != 2 {
		return 0
	}
	a, e := strconv.Atoi(p[0])
	if e != nil {
		return 0
	}
	b, e := strconv.Atoi(p[1])
	if e != nil || a < 1 || a > 100000 || b < 0 || b > 9 {
		return 0
	}
	return a*10 + b
}

var targetRE = regexp.MustCompile(`^sm_([0-9]+)([af]?)$`)

func target(s string) (int, string) {
	m := targetRE.FindStringSubmatch(s)
	if m == nil {
		return 0, ""
	}
	n, _ := strconv.Atoi(m[1])
	return n, m[2]
}
func family(n int) int {
	if n == 101 {
		return 11
	}
	return n / 10
}
func (c *Catalog) Check(m *Module, p Profile) Validation {
	v := Validation{}
	add := func(code, msg string, off int) {
		v.Issues = append(v.Issues, Issue{Severity: "error", Code: code, Message: msg, Offset: off})
	}
	ver := version(m.Version)
	if ver == 0 {
		add("version", "missing/invalid .version", 0)
	} else if ver > version(c.ISAVersion) {
		add("version", "module exceeds pinned PTX ISA "+c.ISAVersion, 0)
	}
	if p.MaxVersion != "" && (version(p.MaxVersion) == 0 || ver > version(p.MaxVersion)) {
		add("profile-version", "module exceeds requested maximum PTX version", 0)
	}
	if m.AddressSize != 32 && m.AddressSize != 64 {
		add("address-size", ".address_size must be 32 or 64", 0)
	}
	if p.AddressSize != 0 && p.AddressSize != m.AddressSize {
		add("profile-address-size", "module does not match profile address size", 0)
	}
	known := map[string]bool{}
	for _, d := range c.Documents {
		for _, s := range d.Syntax {
			for _, a := range regexp.MustCompile(`sm_[0-9]+[af]?`).FindAllString(s, -1) {
				known[a] = true
			}
		}
	}
	arch := ""
	for _, t := range m.Targets {
		if strings.HasPrefix(t, "sm_") {
			if arch != "" {
				add("target", "multiple SM targets", 0)
			}
			arch = t
			if !known[t] {
				add("target", "unknown target in pinned source: "+t, 0)
			}
		} else if t != "texmode_unified" && t != "texmode_independent" && t != "debug" && t != "map_f64_to_f32" {
			add("target-option", "unknown target option "+t, 0)
		}
	}
	sm, suffix := target(arch)
	if min := c.TargetVersions[arch]; min > ver {
		add("target-version", "SM target requires newer PTX version", 0)
	}
	if sm == 0 {
		add("target", "missing SM target", 0)
	}
	if p.Target != "" {
		device, _ := target(p.Target)
		if device == 0 || !known[p.Target] {
			add("profile-target", "invalid profile target", 0)
		} else if sm > device || suffix == "a" && sm != device || suffix == "f" && family(sm) != family(device) {
			add("profile-target", "module target is incompatible with requested device", 0)
		}
	}
	for _, in := range m.Instructions {
		docs := c.Lookup(in.Opcode)
		if len(docs) == 0 {
			add("unknown-opcode", "opcode is absent from pinned NVIDIA registry: "+in.Opcode, in.Start)
			continue
		}
		validVersion, validTarget := false, false
		for _, d := range docs {
			if d.MinVersion == 0 || ver >= d.MinVersion {
				validVersion = true
			}
			if d.MinTarget == 0 || sm >= d.MinTarget {
				validTarget = true
			}
		}
		if !validVersion {
			add("instruction-version", in.Opcode+" predates its instruction family", in.Start)
		}
		if !validTarget {
			add("instruction-target", in.Opcode+" requires a newer target", in.Start)
		}
	}
	return v
}

// ValidateWith executes an explicitly supplied primary validator. Source is sent
// on stdin; arguments must arrange stdin input (e.g. ptxas - -o /dev/null).
// The report is semantically complete only after that validator succeeds.
func (c *Catalog) ValidateWith(ctx context.Context, m *Module, p Profile, command string, args ...string) (Validation, error) {
	v := c.Check(m, p)
	if e := v.Error(); e != nil {
		return v, e
	}
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Stdin = strings.NewReader(m.Source)
	var log bytes.Buffer
	cmd.Stdout = &log
	cmd.Stderr = &log
	if e := cmd.Run(); e != nil {
		return v, fmt.Errorf("PTX validator: %w: %s", e, log.String())
	}
	v.SemanticComplete = true
	return v, nil
}
