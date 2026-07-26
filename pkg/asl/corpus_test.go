package asl_test

import (
	"fmt"
	"os"
	"sort"
	"testing"

	"mkasm/pkg/asl"
)

// aslPathEnv names the arm_instrs.asl file to parse. The ASL lives outside this
// repository — it is generated from ARM's XML by mra_tools — so the corpus test
// is skipped unless a path is given.
const aslPathEnv = "MKASM_ASL_INSTRS"

func instrsPath(t *testing.T) string {
	t.Helper()
	p := os.Getenv(aslPathEnv)
	if p == "" {
		t.Skipf("set %s to an arm_instrs.asl to run this", aslPathEnv)
	}
	if _, err := os.Stat(p); err != nil {
		t.Skipf("%s=%s: %v", aslPathEnv, p, err)
	}
	return p
}

// TestParseWholeCorpus parses every instruction in the ASL specification. A
// hand-written parser is only worth trusting if it accepts the whole input, so
// this fails on the first construct it cannot read rather than skipping it.
func TestParseWholeCorpus(t *testing.T) {
	path := instrsPath(t)
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	instrs, err := asl.ParseInstructions(string(src))
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	bySet := map[string]int{}
	encodings, withDecode, fields, unpredictable := 0, 0, 0, 0
	for _, in := range instrs {
		for _, e := range in.Encodings {
			encodings++
			bySet[e.Set]++
			fields += len(e.Fields)
			unpredictable += len(e.Unpredictable)
			if len(e.Decode) > 0 {
				withDecode++
			}
			if len(e.Opcode) != 32 && e.Set == "A64" {
				t.Errorf("%s: opcode has %d bits, want 32", e.Name, len(e.Opcode))
			}
		}
	}
	fmt.Printf("\ninstructions %d | encodings %d | with decode %d | fields %d | unpredictable_unless %d\n",
		len(instrs), encodings, withDecode, fields, unpredictable)
	sets := make([]string, 0, len(bySet))
	for s := range bySet {
		sets = append(sets, s)
	}
	sort.Strings(sets)
	for _, s := range sets {
		fmt.Printf("   %-4s %d\n", s, bySet[s])
	}
	if encodings == 0 {
		t.Fatal("parsed no encodings")
	}
}

// TestDecodeStatementCoverage reports which statement forms appear in A64
// decode bodies, so an unhandled construct shows up as a number rather than as
// a silently dropped statement.
func TestDecodeStatementCoverage(t *testing.T) {
	path := instrsPath(t)
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	instrs, err := asl.ParseInstructions(string(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	kinds := map[string]int{}
	var count func([]asl.Stmt)
	count = func(ss []asl.Stmt) {
		for _, s := range ss {
			kinds[fmt.Sprintf("%T", s)]++
			switch v := s.(type) {
			case *asl.Case:
				for _, a := range v.Alts {
					count(a.Body)
				}
			case *asl.If:
				count(v.Then)
				for _, e := range v.Elsifs {
					count(e.Then)
				}
				count(v.Else)
			}
		}
	}
	for _, in := range instrs {
		for _, e := range in.Encodings {
			if e.Set == "A64" {
				count(e.Decode)
			}
		}
	}
	keys := make([]string, 0, len(kinds))
	for k := range kinds {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return kinds[keys[i]] > kinds[keys[j]] })
	fmt.Println("\nA64 decode statements by form:")
	for _, k := range keys {
		fmt.Printf("   %6d  %s\n", kinds[k], k)
	}
}
