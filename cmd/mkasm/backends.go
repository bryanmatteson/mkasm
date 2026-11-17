package main

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/arc"
	"github.com/bryanmatteson/mkasm/pkg/avr"
	"github.com/bryanmatteson/mkasm/pkg/codec"
	"github.com/bryanmatteson/mkasm/pkg/dex"
	"github.com/bryanmatteson/mkasm/pkg/ebpf"
	"github.com/bryanmatteson/mkasm/pkg/hexagon"
	"github.com/bryanmatteson/mkasm/pkg/jvm"
	"github.com/bryanmatteson/mkasm/pkg/loongarch"
	"github.com/bryanmatteson/mkasm/pkg/m68k"
	"github.com/bryanmatteson/mkasm/pkg/mcs51"
	"github.com/bryanmatteson/mkasm/pkg/mips"
	"github.com/bryanmatteson/mkasm/pkg/mos6502"
	"github.com/bryanmatteson/mkasm/pkg/msp430"
	"github.com/bryanmatteson/mkasm/pkg/pic"
	"github.com/bryanmatteson/mkasm/pkg/powerpc"
	"github.com/bryanmatteson/mkasm/pkg/ptx"
	"github.com/bryanmatteson/mkasm/pkg/riscv"
	"github.com/bryanmatteson/mkasm/pkg/sparc"
	"github.com/bryanmatteson/mkasm/pkg/spirv"
	"github.com/bryanmatteson/mkasm/pkg/systemz"
	"github.com/bryanmatteson/mkasm/pkg/tricore"
	"github.com/bryanmatteson/mkasm/pkg/v850"
	"github.com/bryanmatteson/mkasm/pkg/w65c816"
	"github.com/bryanmatteson/mkasm/pkg/wasm"
	"github.com/bryanmatteson/mkasm/pkg/xtensa"
	"github.com/bryanmatteson/mkasm/pkg/z80"
)

type backendLoader func(io.Reader, string) (codec.Backend, error)

func loadBackend[T codec.Backend](parse func(io.Reader, string) (T, error)) backendLoader {
	return func(r io.Reader, a string) (codec.Backend, error) { return parse(r, a) }
}

var backendLoaders = map[string]backendLoader{
	"amdgpu": loadBackend(parseAMDGPU),
	"cil":    loadBackend(parseManagedCIL),
	"arc32":  loadBackend(arc.Parse), "arc32be": loadBackend(arc.Parse),
	"arcem": loadBackend(arc.Parse), "arcembe": loadBackend(arc.Parse),
	"arc600": loadBackend(arc.Parse), "arc600be": loadBackend(arc.Parse),
	"arc700": loadBackend(arc.Parse), "arc700be": loadBackend(arc.Parse),
	"arc64": loadBackend(arc.Parse), "arc64be": loadBackend(arc.Parse),
	"arcv3-32": loadBackend(arc.Parse), "arcv3-32be": loadBackend(arc.Parse),
	"arcnps400": loadBackend(arc.Parse), "arcnps400be": loadBackend(arc.Parse),
	"hexagon": loadBackend(hexagon.Parse),
	"jvm":     loadBackend(jvm.Parse),
	"dex":     loadBackend(dex.Parse),
	"avr":     loadBackend(avr.Parse),
	"bpfel":   loadBackend(ebpf.Parse), "bpfeb": loadBackend(ebpf.Parse),
	"loongarch32": loadBackend(loongarch.Parse), "loongarch64": loadBackend(loongarch.Parse),
	"m68k": loadBackend(m68k.Parse), "coldfire": loadBackend(m68k.Parse),
	"mcs51": loadBackend(mcs51.Parse), "mcs80390": loadBackend(mcs51.Parse),
	"mips32": loadBackend(mips.Parse), "mips64": loadBackend(mips.Parse), "mips32el": loadBackend(mips.Parse), "mips64el": loadBackend(mips.Parse),
	"micromips32": loadBackend(mips.Parse), "micromips32el": loadBackend(mips.Parse), "micromips64": loadBackend(mips.Parse), "micromips64el": loadBackend(mips.Parse),
	"mips16": loadBackend(mips.Parse), "mips16el": loadBackend(mips.Parse),
	"mips16-64": loadBackend(mips.Parse), "mips16-64el": loadBackend(mips.Parse),
	"mos6502": loadBackend(mos6502.Parse),
	"w65c816": loadBackend(w65c816.Parse),
	"msp430":  loadBackend(msp430.Parse), "msp430x": loadBackend(msp430.Parse),
	"powerpc32": loadBackend(powerpc.Parse), "powerpc64": loadBackend(powerpc.Parse), "powerpc32le": loadBackend(powerpc.Parse), "powerpc64le": loadBackend(powerpc.Parse),
	"ptx":   loadBackend(ptx.Parse),
	"pic12": loadBackend(pic.Parse), "pic16c5x": loadBackend(pic.Parse),
	"pic14": loadBackend(pic.Parse), "pic14-enhanced": loadBackend(pic.Parse),
	"pic16": loadBackend(pic.Parse), "pic17": loadBackend(pic.Parse), "pic18": loadBackend(pic.Parse),
	"pic24": loadBackend(pic.Parse), "pic24e": loadBackend(pic.Parse), "pic24f": loadBackend(pic.Parse), "pic24h": loadBackend(pic.Parse),
	"dspic": loadBackend(pic.Parse), "dspic30f": loadBackend(pic.Parse), "dspic33f": loadBackend(pic.Parse), "dspic33e": loadBackend(pic.Parse), "dspic33c": loadBackend(pic.Parse),
	"riscv32": loadBackend(riscv.Parse), "riscv64": loadBackend(riscv.Parse),
	"sparc32": loadBackend(sparc.Parse), "sparc64": loadBackend(sparc.Parse), "sparc32le": loadBackend(sparc.Parse),
	"spirv":   loadBackend(spirv.Parse),
	"systemz": loadBackend(systemz.Parse),
	"tricore": loadBackend(tricore.Parse), "tricore-pcp": loadBackend(tricore.Parse),
	"v850":   loadBackend(v850.Parse),
	"wasm32": loadBackend(wasm.Parse), "wasm64": loadBackend(wasm.Parse),
	"xtensa": loadBackend(xtensa.Parse), "xtensaeb": loadBackend(xtensa.Parse),
	"z80": loadBackend(z80.Parse), "z180": loadBackend(z80.Parse),
	"ez80": loadBackend(z80.ParseVariant), "ez80-adl": loadBackend(z80.ParseVariant),
	"z80n": loadBackend(z80.ParseVariant), "r800": loadBackend(z80.ParseVariant), "gbz80": loadBackend(z80.ParseVariant),
}

func architectureNames() []string {
	names := []string{"aarch64", "arm32", "x86_32", "x86_64"}
	for k := range backendLoaders {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

func canonicalArchitecture(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	switch name {
	case "arm64", "arm64e":
		return "aarch64"
	case "amd64", "x86-64", "x64":
		return "x86_64"
	case "x86", "i386", "i686", "x86-32":
		return "x86_32"
	case "arm", "aarch32", "a32", "thumb", "thumb2", "t32":
		return "arm32"
	case "arc", "arcv2", "archs":
		return "arc32"
	case "arceb", "archsbe":
		return "arc32be"
	case "ebpf", "bpf":
		return "bpfel"
	case "amdgcn", "gcn", "rdna":
		return "amdgpu"
	case "nvptx", "nvptx32", "nvptx64", "nvidia-ptx":
		return "ptx"
	case "rv32", "riscv-32":
		return "riscv32"
	case "rv64", "riscv-64":
		return "riscv64"
	case "mips":
		return "mips32"
	case "mipsel":
		return "mips32el"
	case "micromips":
		return "micromips32"
	case "micromipsel":
		return "micromips32el"
	case "6502", "6502x", "65sc02", "65c02", "w65c02":
		return "mos6502"
	case "65816", "65c816", "w65816":
		return "w65c816"
	case "8051", "mcs-51":
		return "mcs51"
	case "80390", "ds390":
		return "mcs80390"
	case "ppc", "ppc32":
		return "powerpc32"
	case "ppc64":
		return "powerpc64"
	case "ppc64le":
		return "powerpc64le"
	case "la32":
		return "loongarch32"
	case "la64", "loongarch":
		return "loongarch64"
	case "java", "java-bytecode":
		return "jvm"
	case "dalvik", "android", "android-dex", "android_dex":
		return "dex"
	case "dotnet", ".net", "net", "msil", "dotnet-cil", "cli":
		return "cil"
	case "tricore32", "tricore-32":
		return "tricore"
	case "tricore_pcp", "pcp":
		return "tricore-pcp"
	case "wasm", "webassembly", "webassembly32":
		return "wasm32"
	case "webassembly64":
		return "wasm64"
	case "spir-v", "spirv32", "spirv64":
		return "spirv"
	case "sparc", "sparcv8":
		return "sparc32"
	case "sparcv9", "sparc-v9":
		return "sparc64"
	case "s390x", "s390", "zarchitecture", "zarch":
		return "systemz"
	case "68000", "mc68000", "m68000", "68k", "motorola68k":
		return "m68k"
	case "mcf", "mcfv4":
		return "coldfire"
	case "v850e", "v850e1", "v850e2", "v850e2v3", "v850e3v5":
		return "v850"
	case "ez80adl":
		return "ez80-adl"
	case "lr35902", "sm83", "gameboy":
		return "gbz80"
	case "xtensael", "xtensa32":
		return "xtensa"
	case "xtensabe":
		return "xtensaeb"
	}
	return name
}

func runBackend(ctx context.Context, architecture, input string, stdin io.Reader, stdout, stderr io.Writer, output string, jsonIR bool, cpu string, strict bool) error {
	var backend codec.Backend
	var err error
	if info, statErr := os.Stat(input); statErr == nil && info.IsDir() && (architecture == "riscv32" || architecture == "riscv64") {
		backend, err = riscv.ParseDirectory(input, architecture)
	} else {
		r, closeInput, openErr := openSpecification(ctx, input, stdin)
		if openErr != nil {
			return openErr
		}
		defer closeInput()
		backend, err = backendLoaders[architecture](r, architecture)
	}
	if err != nil {
		return fmt.Errorf("parse %s specification: %w", architecture, err)
	}
	if c, ok := backend.(*m68k.Catalog); ok && cpu != "" {
		backend, err = c.WithCPU(cpu)
		if err != nil {
			return err
		}
		cpu = ""
	}
	if c, ok := backend.(*hexagon.Catalog); ok {
		if strict && len(c.Unsupported) > 0 {
			return fmt.Errorf("hexagon: %d unsupported source records (first: %s: %s)", len(c.Unsupported), c.Unsupported[0].ID, c.Unsupported[0].Reason)
		}
		if cpu != "" {
			backend, err = c.WithCPU(cpu)
			if err != nil {
				return err
			}
			cpu = ""
		}
	}
	if c, ok := backend.(*xtensa.Catalog); ok && cpu != "" {
		backend, err = c.WithCPU(cpu)
		if err != nil {
			return err
		}
		cpu = ""
	}
	if fixed, ok := backend.(interface{ InstructionCatalog() *codec.Catalog }); ok {
		c := fixed.InstructionCatalog()
		if strict && len(c.Unsupported) > 0 {
			return fmt.Errorf("%s: %d unsupported source records (first: %s: %s)", architecture, len(c.Unsupported), c.Unsupported[0].ID, c.Unsupported[0].Reason)
		}
		if cpu != "" {
			features, exists := c.FeatureSets[cpu]
			if !exists {
				return fmt.Errorf("%s: unknown CPU profile %q", architecture, cpu)
			}
			var selected []codec.Encoding
			for _, e := range c.Encodings {
				match := true
				for _, required := range e.Features {
					found := false
					for _, f := range features {
						if f == required {
							found = true
							break
						}
					}
					if !found {
						match = false
						break
					}
				}
				if match {
					selected = append(selected, e)
				}
			}
			c.Encodings = selected
			if err := c.Validate(); err != nil {
				return fmt.Errorf("CPU %s: %w", cpu, err)
			}
		}
		fmt.Fprintf(stderr, "Architecture: %s\nEncodings: %d\nUnsupported source records: %d\n", architecture, len(c.Encodings), len(c.Unsupported))
	} else if cpu != "" {
		return fmt.Errorf("%s does not expose CPU profiles", architecture)
	}
	if jsonIR {
		return backend.WriteJSON(stdout)
	}
	if err := backend.GenerateRust(output); err != nil {
		return fmt.Errorf("generate %s Rust: %w", architecture, err)
	}
	fmt.Fprintln(stderr, "Generated: rust")
	return nil
}

func openSpecification(ctx context.Context, input string, stdin io.Reader) (io.Reader, func(), error) {
	var r io.Reader
	closeFn := func() {}
	if input == "-" {
		r = stdin
	} else if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, input, nil)
		if err != nil {
			return nil, closeFn, err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, closeFn, err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, closeFn, fmt.Errorf("download specification: HTTP %s", resp.Status)
		}
		r = resp.Body
		closeFn = func() { resp.Body.Close() }
	} else {
		f, err := os.Open(input)
		if err != nil {
			return nil, closeFn, err
		}
		r = f
		closeFn = func() { f.Close() }
	}
	// The architecture parser handles tar.gz streams; JSON corpora can also be
	// compressed without changing their schema or requiring an external command.
	if strings.HasSuffix(strings.Split(input, "?")[0], ".json.gz") {
		z, err := gzip.NewReader(r)
		if err != nil {
			closeFn()
			return nil, func() {}, err
		}
		parent := closeFn
		closeFn = func() { z.Close(); parent() }
		r = z
	}
	return io.LimitReader(r, 512<<20), closeFn, nil
}
