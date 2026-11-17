package tricore

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Ghidra's packaged tc172x/tc176x/tc29x language IDs all use its V2 SLA.
// Compile the actual pinned source with each revision's independent SLEIGH
// compiler predicates, then load this artifact-only language definition file.
func prepareOracleLanguages(t *testing.T, artifact string) string {
	t.Helper()
	home := os.Getenv("MKASM_GHIDRA_HOME")
	if home == "" {
		user, err := os.UserHomeDir()
		if err != nil {
			t.Fatal(err)
		}
		home = filepath.Join(user, "Ghidra")
	}
	directory := filepath.Join(artifact, "languages")
	if err := os.MkdirAll(directory, 0755); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{"tricore.sinc": Source, "tricore.pcp.sinc": PCPSource, "UPSTREAM-LICENSE": upstreamNotice + "\n" + upstreamLicense} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"tricore.pspec", "tricore.cspec"} {
		data, err := os.ReadFile(filepath.Join(home, "Ghidra", "Processors", "tricore", "data", "languages", name))
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(directory, name), data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	compiler := filepath.Join(home, "support", "sleigh")
	platform := map[string]string{"darwin/arm64": "mac_arm_64", "darwin/amd64": "mac_x86_64", "linux/amd64": "linux_x86_64"}[runtime.GOOS+"/"+runtime.GOARCH]
	if platform != "" {
		native := filepath.Join(home, "Ghidra", "Features", "Decompiler", "os", platform, "sleigh")
		if _, err := os.Stat(native); err == nil {
			compiler = native
		}
	}
	var definitions strings.Builder
	definitions.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<language_definitions>\n")
	for _, profile := range []string{"v2", "rider-d", "rider-b"} {
		source := fmt.Sprintf("@define Tricore \"\"\n@define TRICORE_GENERIC \"\"\n@define TRICORE_%s \"\"\ndefine endian=little;\n@include \"tricore.sinc\"\n", strings.ToUpper(strings.ReplaceAll(profile, "-", "_")))
		spec := filepath.Join(directory, profile+".slaspec")
		if err := os.WriteFile(spec, []byte(source), 0644); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(compiler, spec, filepath.Join(directory, profile+".sla"))
		var log bytes.Buffer
		cmd.Stdout = &log
		cmd.Stderr = &log
		err := cmd.Run()
		os.WriteFile(filepath.Join(directory, profile+".compile.log"), log.Bytes(), 0644)
		if err != nil {
			t.Fatalf("independent SLEIGH compile %s: %v\n%s", profile, err, log.Bytes())
		}
		fmt.Fprintf(&definitions, "<language processor=\"tricore\" endian=\"little\" size=\"32\" variant=\"mkasm-%s\" version=\"1.0\" slafile=\"%s.sla\" processorspec=\"tricore.pspec\" id=\"tricore:LE:32:mkasm-%s\"><description>Pinned TriCore %s oracle</description><compiler name=\"default\" spec=\"tricore.cspec\" id=\"default\"/></language>\n", profile, profile, profile, profile)
	}
	definitions.WriteString("</language_definitions>\n")
	path, err := filepath.Abs(filepath.Join(directory, "tricore-oracle.ldefs"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte(definitions.String()), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}
