package arm

import (
	"bytes"
	"testing"
)

// These implementation microbenchmarks stay in package arm because they
// intentionally measure private hot paths. Corpus-scale, public-API benchmarks
// live in the top-level benchmarks package.

func BenchmarkParseIForm(b *testing.B) {
	data := []byte(benchmarkIFormXML)
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for range b.N {
		if _, err := parseIForm(bytes.NewReader(data), "CLREX_BN_barriers"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseAsmTemplate(b *testing.B) {
	const input = "ADD <Xd:foo,bar>, <Xn>, #<imm>{, <shift>}"
	b.ReportAllocs()
	for range b.N {
		_ = parseAsmTemplate(input)
	}
}

func BenchmarkPseudocodeParser(b *testing.B) {
	lines := []string{
		`result = X[n] + AddWithCarry(x, y, carry_in)`,
		`if result == 0 then`,
		`for i = 0 to 63 step 8`,
		`while IsZero(value) do`,
		`return SignExtend(result, 64)`,
		`Mem[address, 8] = data`,
		`BranchTo(target, BranchType_DIR)`,
		`// architectural operation`,
	}
	p := NewPseudocodeParser()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = p.ParseLines(lines)
	}
}

func BenchmarkTarCorpusPreparedIFormLookup(b *testing.B) {
	data := []byte(benchmarkIFormXML)
	archive := tarCorpusFixture(b, true, map[string][]byte{
		"ISA/encodingindex.xml": []byte(`<encodingindex/>`),
		"ISA/clrex.xml":         data,
	})
	corpus, err := LoadTarXMLCorpus(bytes.NewReader(archive), "fixture.tar.gz")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, ok := corpus.preparedIForm("clrex.xml", "CLREX_BN_barriers"); !ok {
			b.Fatal("CLREX was not prepared")
		}
	}
}

const benchmarkIFormXML = `<instructionsection id="CLREX" type="instruction">
  <docvars>
    <docvar key="instr-class" value="system"/>
    <docvar key="isa" value="A64"/>
    <docvar key="mnemonic" value="CLREX"/>
  </docvars>
  <classes>
    <iclass name="System" isa="A64">
      <regdiagram form="32" psname="A64.control.barriers.CLREX_BN_barriers">
        <box hibit="31" width="3"><c>1</c><c>1</c><c>0</c></box>
        <box hibit="28" width="3"><c>1</c><c>0</c><c>1</c></box>
        <box hibit="25" width="14">
          <c>0</c><c>1</c><c>0</c><c>0</c><c>0</c><c>0</c><c>0</c>
          <c>0</c><c>1</c><c>1</c><c>0</c><c>0</c><c>1</c><c>1</c>
        </box>
        <box hibit="11" width="4" name="CRm"><c colspan="4"/></box>
        <box hibit="7" width="3" name="op2"><c>0</c><c>1</c><c>0</c></box>
        <box hibit="4" width="5" name="Rt"><c>1</c><c>1</c><c>1</c><c>1</c><c>1</c></box>
      </regdiagram>
      <encoding name="CLREX_BN_barriers">
        <docvars>
          <docvar key="mnemonic" value="CLREX"/>
          <docvar key="instr-class" value="system"/>
        </docvars>
        <asmtemplate><text>CLREX {#</text><a hover="Optional 4-bit immediate encoded in the CRm field.">&lt;imm&gt;</a><text>}</text></asmtemplate>
      </encoding>
      <ps_section><ps name="A64.control.barriers.CLREX_BN_barriers">
        <pstext section="Decode">// CRm field is ignored</pstext>
      </ps></ps_section>
    </iclass>
  </classes>
  <explanations scope="all">
    <explanation enclist="CLREX_BN_barriers">
      <symbol>&lt;imm&gt;</symbol>
      <account encodedin="CRm"><intro><para>Optional immediate encoded in the "CRm" field.</para></intro></account>
    </explanation>
  </explanations>
  <ps_section><ps name="A64.control.barriers.CLREX_BN_barriers">
    <pstext section="Execute">ClearExclusiveLocal(ProcessorID());</pstext>
  </ps></ps_section>
</instructionsection>`
