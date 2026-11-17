package amdgpu

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

var sourceOnce sync.Once
var sourceValue *codec.Catalog
var sourceError error

func sourceCatalog(t *testing.T) *codec.Catalog {
	t.Helper()
	sourceOnce.Do(func() {
		f, err := os.Open("testdata/llvm22.json.gz")
		if err != nil {
			sourceError = err
			return
		}
		defer f.Close()
		z, err := gzip.NewReader(f)
		if err != nil {
			sourceError = err
			return
		}
		defer z.Close()
		sourceValue, sourceError = Parse(z, "amdgcn")
	})
	if sourceError != nil {
		t.Fatal(sourceError)
	}
	return sourceValue
}

func llvmInstruction(t *testing.T, cpu, text string) []byte {
	t.Helper()
	llvm := "/opt/homebrew/opt/llvm/bin/llvm-mc"
	if _, err := os.Stat(llvm); err != nil {
		t.Skip(err)
	}
	command := exec.Command(llvm, "-triple=amdgcn", "-mcpu="+cpu, "-show-encoding")
	command.Stdin = strings.NewReader(text + "\n")
	out, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("LLVM %s %s: %v\n%s", cpu, text, err, out)
	}
	m := regexp.MustCompile(`encoding: \[([^]]+)\]`).FindSubmatch(out)
	if m == nil {
		t.Fatalf("missing LLVM bytes: %s", out)
	}
	var b []byte
	for _, s := range strings.Split(string(m[1]), ",") {
		v, err := strconv.ParseUint(strings.TrimSpace(s), 0, 8)
		if err != nil {
			t.Fatal(err)
		}
		b = append(b, byte(v))
	}
	return b
}

func TestLLVMShaderWorkflows(t *testing.T) {
	c := sourceCatalog(t)
	cases := []struct{ cpu, text string }{
		{"gfx900", "s_mov_b32 s0, 0x12345678"},
		{"gfx1250", "s_mov_b64 s[0:1], 0x123456789abcdef0"},
		{"gfx1100", "v_add_f64 v[0:1], lit(0x12345678), v[2:3]"},
		{"gfx1100", "v_ldexp_f64 v[0:1], lit(0x12345678), lit(0x12345678)"},
		{"gfx1200", "v_fmaak_f32 v0, 0x12345678, v2, 0x12345678"},
		{"gfx1200", "global_load_b32 v0, v[0:1], off th:TH_LOAD_NT scope:SCOPE_DEV"},
		{"gfx900", "v_add_f32_sdwa v0, v1, v2 dst_sel:DWORD dst_unused:UNUSED_PAD src0_sel:DWORD src1_sel:DWORD"},
		{"gfx1100", "v_add_f32_e32 v0, v1, v2"},
		{"gfx1100", "v_mul_f32_e64 v3, -v1, |v2| clamp"},
		{"gfx1100", "v_add_f16_e64 v0.l, v1.h, v2.l op_sel:[1,0,0]"},
		{"gfx1100", "v_add_f16_e64 v0.h, v1.l, v2.h op_sel:[0,1,1]"},
		{"gfx1100", "v_add_f16_e32 v0.h, v1.l, v2.h"},
		{"gfx1100", "v_cmp_class_f16_e64 s0, v0.h, v1.l op_sel:[1,0]"},
		{"gfx1100", "v_add_f32_dpp v0, v1, v2 quad_perm:[3,2,1,0] row_mask:15 bank_mask:15"},
		{"gfx1100", "v_add_f32_dpp v0, v1, v2 dpp8:[7,6,5,4,3,2,1,0]"},
		{"gfx1100", "buffer_load_b32 v0, off, s[0:3], s0 offset:16"},
		{"gfx1100", "image_load v0, [v0,v1,v2], s[0:7] dmask:1 dim:SQ_RSRC_IMG_2D_ARRAY"},
		{"gfx1010", "image_gather4_b_cl_o v[0:1], v[0:2], s[0:7], s[0:3] dmask:1 dim:SQ_RSRC_IMG_1D a16 d16"},
		{"gfx900", "image_load v0, v0, s[0:7] dmask:1 a16"},
		{"gfx1010", "image_sample_c_d_o_g16 v0, [v0,v0,v0,v0,v0,v0,v0,v0,v0], s[0:7], s[0:3] dmask:1 dim:SQ_RSRC_IMG_3D"},
		{"gfx1100", "image_sample_c_d_g16 v0, [v0,v0,v0,v0,v[0:1]], s[0:7], s[0:3] dmask:1 dim:SQ_RSRC_IMG_2D_ARRAY"},
		{"gfx1250", "v_dual_add_f32 v0, v0, v2 :: v_dual_add_f32 v2, v1, v3"},
	}
	for _, tt := range cases {
		t.Run(tt.cpu+"/"+tt.text, func(t *testing.T) {
			want := llvmInstruction(t, tt.cpu, tt.text)
			assembled, err := c.AssembleWithFeatures(tt.text, 0x1000, c.FeatureSets[tt.cpu])
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, b := range assembled {
				if bytes.Equal(b, want) {
					found = true
				}
			}
			if !found {
				t.Fatalf("LLVM %x absent from %x", want, assembled)
			}
			decoded, err := c.DecodeWithFeatures(want, c.FeatureSets[tt.cpu])
			if err != nil {
				t.Fatal(err)
			}
			if decoded.Length != len(want) {
				t.Fatalf("decoded %d bytes, expected %d", decoded.Length, len(want))
			}
			back, err := c.Encode(decoded.Encoding.ID, decoded.Values)
			if err != nil || !bytes.Equal(back, want) {
				t.Fatalf("structured roundtrip %x: %v", back, err)
			}
			text := decoded.Format(0x1000)
			again, err := c.AssembleWithFeatures(text, 0x1000, c.FeatureSets[tt.cpu])
			if err != nil {
				t.Fatal(err)
			}
			found = false
			for _, b := range again {
				if bytes.Equal(b, want) {
					found = true
				}
			}
			if !found {
				t.Fatalf("formatted %q lost %s", text, hex.EncodeToString(want))
			}
		})
	}
}

func TestLLVMKernelStream(t *testing.T) {
	c := sourceCatalog(t)
	cpu := "gfx1100"
	instructions := []string{
		"s_mov_b32 s0, 0x12345678",
		"v_mov_b32_e32 v0, 0",
		"v_mov_b32_e32 v1, 0",
		"global_load_b32 v2, v[0:1], off",
		"s_waitcnt 0",
		"v_add_f32_e32 v2, 1.0, v2",
		"global_store_b32 v[0:1], v2, off",
		"s_endpgm",
	}
	var stream []byte
	var lengths []int
	for _, text := range instructions {
		b := llvmInstruction(t, cpu, text)
		stream = append(stream, b...)
		lengths = append(lengths, len(b))
	}
	offset := 0
	for i, length := range lengths {
		d, err := c.DecodeWithFeatures(stream[offset:], c.FeatureSets[cpu])
		if err != nil {
			t.Fatalf("instruction %d at byte %d: %v", i, offset, err)
		}
		if d.Length != length {
			t.Fatalf("instruction %d consumed %d, LLVM emitted %d", i, d.Length, length)
		}
		text := d.Format(uint64(0x1000 + offset))
		assembled, err := c.AssembleWithFeatures(text, uint64(0x1000+offset), c.FeatureSets[cpu])
		if err != nil {
			t.Fatal(text, err)
		}
		found := false
		for _, b := range assembled {
			if bytes.Equal(b, stream[offset:offset+length]) {
				found = true
			}
		}
		if !found {
			t.Fatalf("instruction %d formatted %q lost bytes %x", i, text, stream[offset:offset+length])
		}
		offset += length
	}
	if offset != len(stream) {
		t.Fatalf("stream left %d bytes", len(stream)-offset)
	}
}

func TestLLVMOperandDomains(t *testing.T) {
	c := sourceCatalog(t)
	invalid := []struct{ cpu, text string }{
		{"gfx1100", "image_load v[0:4], v[0:1], s[0:7] dmask:1 dim:SQ_RSRC_IMG_2D"},
		{"gfx1100", "v_dual_add_f32 v0, v0, v2 :: v_dual_add_f32 v1, v4, v3"},
		{"gfx950", "v_add_f64_e64 v[1:2], v[2:3], v[4:5]"},
	}
	for _, tt := range invalid {
		t.Run(tt.cpu+"/"+tt.text, func(t *testing.T) {
			llvm := "/opt/homebrew/opt/llvm/bin/llvm-mc"
			if _, err := os.Stat(llvm); err != nil {
				t.Skip(err)
			}
			cmd := exec.Command(llvm, "-triple=amdgcn", "-mcpu="+tt.cpu, "-show-encoding")
			cmd.Stdin = strings.NewReader(tt.text + "\n")
			if out, err := cmd.CombinedOutput(); err == nil {
				t.Fatalf("LLVM unexpectedly accepted invalid domain: %s", out)
			}
			assembled, err := c.AssembleWithFeatures(tt.text, 0x1000, c.FeatureSets[tt.cpu])
			if err == nil || len(assembled) > 0 {
				t.Fatalf("invalid operand domain accepted: %x, %v", assembled, err)
			}
		})
	}
	want := llvmInstruction(t, "gfx1100", "s_branch 3")
	forms, err := c.AssembleWithFeatures("s_branch 0x1010", 0x1000, c.FeatureSets["gfx1100"])
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, b := range forms {
		found = found || bytes.Equal(b, want)
	}
	if !found {
		t.Fatalf("relative branch differs: %x vs LLVM %x", forms, want)
	}
	d, err := c.DecodeWithFeatures(want, c.FeatureSets["gfx1100"])
	if err != nil {
		t.Fatal(err)
	}
	target, ok := d.BranchTarget(0x1000)
	if !ok || target != 0x1010 {
		t.Fatalf("branch target %#x, %v", target, ok)
	}
}

func TestLLVMSourceCoverage(t *testing.T) {
	c := sourceCatalog(t)
	f, err := os.Open("testdata/llvm22.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	var source struct {
		Instances map[string][]string `json:"!instanceof"`
	}
	if err := json.NewDecoder(z).Decode(&source); err != nil {
		t.Fatal(err)
	}
	supported := map[string]bool{}
	for _, e := range c.Encodings {
		supported[strings.Split(e.ID, "/")[0]] = true
	}
	unsupported := map[string]bool{}
	for _, u := range c.Unsupported {
		if u.Reason == "" {
			t.Fatalf("unsupported %s has no reason", u.ID)
		}
		unsupported[u.ID] = true
	}
	if len(source.Instances["Instruction"]) != 36223 {
		t.Fatalf("unexpected LLVM22 source size: %d", len(source.Instances["Instruction"]))
	}
	for _, id := range source.Instances["Instruction"] {
		if supported[id] == unsupported[id] {
			t.Fatalf("source %s must be supported or explicitly unsupported exactly once", id)
		}
	}
	t.Logf("%d concrete LLVM records: %d supported, %d explicitly unsupported; %d expanded encoding and syntax forms", len(source.Instances["Instruction"]), len(supported), len(unsupported), len(c.Encodings))
}
