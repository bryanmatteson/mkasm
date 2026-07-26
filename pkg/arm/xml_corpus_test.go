package arm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestTarXMLCorpusMatchesDirectoryParse(t *testing.T) {
	data, err := os.ReadFile(clrexFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	archive := tarCorpusFixture(t, false, map[string][]byte{
		"release/ISA/encodingindex.xml": []byte(`<encodingindex/>`),
		"release/ISA/clrex.xml":         data,
		"release/README.txt":            []byte("ignored"),
	})
	corpus, err := LoadTarXMLCorpus(bytes.NewReader(archive), "fixture.tar")
	if err != nil {
		t.Fatal(err)
	}

	got, ok := corpus.preparedIForm("clrex.xml", "CLREX_BN_barriers")
	if !ok {
		t.Fatal("CLREX was not prepared")
	}
	want, err := parseIForm(bytes.NewReader(data), "CLREX_BN_barriers")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("tar corpus parse differs from directory parse")
	}
}

func TestOpenTarXMLCorpusDownloadsGzipWithoutExtraction(t *testing.T) {
	archive := tarCorpusFixture(t, true, map[string][]byte{
		"bundle/ISA/encodingindex.xml": []byte(`<encodingindex/>`),
		"bundle/ISA/example.xml": []byte(
			`<instructionsection><classes><iclass><encoding name="EXAMPLE"/></iclass></classes></instructionsection>`),
	})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(archive)
	}))
	defer server.Close()

	corpus, err := OpenTarXMLCorpus(context.Background(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := corpus.preparedIForm("example.xml", "EXAMPLE"); !ok {
		t.Fatal("downloaded IForm was not prepared")
	}
}

func TestTarXMLCorpusRejectsTraversal(t *testing.T) {
	archive := tarCorpusFixture(t, false, map[string][]byte{
		"../encodingindex.xml": []byte(`<encodingindex/>`),
	})
	if _, err := LoadTarXMLCorpus(bytes.NewReader(archive), "unsafe.tar"); err == nil {
		t.Fatal("expected traversal error")
	}
}

func TestTarXMLCorpusRejectsAmbiguousRoots(t *testing.T) {
	archive := tarCorpusFixture(t, false, map[string][]byte{
		"a/encodingindex.xml": []byte(`<encodingindex/>`),
		"b/encodingindex.xml": []byte(`<encodingindex/>`),
	})
	_, err := LoadTarXMLCorpus(bytes.NewReader(archive), "ambiguous.tar")
	if err == nil || !strings.Contains(err.Error(), "a, b") {
		t.Fatalf("error = %v", err)
	}
}

func TestTarXMLCorpusSelectsReleaseNamedByArchive(t *testing.T) {
	archive := releaseBundleFixture(t, []string{"2026-03", "2026-06"})
	corpus, err := LoadTarXMLCorpus(
		bytes.NewReader(archive),
		"ISA_A64_xml_A_profile-2026-06.tar.gz",
	)
	if err != nil {
		t.Fatal(err)
	}
	assertSelectedRelease(t, corpus, "ENC_2026_06")
}

func TestTarXMLCorpusSelectsNewestReleaseFromStdin(t *testing.T) {
	for _, releases := range [][]string{
		{"2026-03", "2026-06"},
		{"2026-06", "2026-03"},
	} {
		archive := releaseBundleFixture(t, releases)
		corpus, err := LoadTarXMLCorpus(bytes.NewReader(archive), "stdin")
		if err != nil {
			t.Fatal(err)
		}
		assertSelectedRelease(t, corpus, "ENC_2026_06")
	}
}

func TestTarXMLCorpusRejectsMismatchedReleaseArchiveName(t *testing.T) {
	archive := tarCorpusFixture(t, false, map[string][]byte{
		"ISA_A64_xml_A_profile-2026-03/encodingindex.xml": []byte(`<encodingindex/>`),
	})
	_, err := LoadTarXMLCorpus(
		bytes.NewReader(archive),
		"ISA_A64_xml_A_profile-2026-06.tar.gz",
	)
	if err == nil || !strings.Contains(err.Error(), `selects corpus root "ISA_A64_xml_A_profile-2026-06"`) {
		t.Fatalf("error = %v", err)
	}
}

func TestTarXMLCorpusRejectsDatedRootsFromDifferentSeries(t *testing.T) {
	archive := tarCorpusFixture(t, false, map[string][]byte{
		"ISA_A64_xml_A_profile-2026-06/encodingindex.xml": []byte(`<encodingindex/>`),
		"SysReg_xml_A_profile-2026-07/encodingindex.xml":  []byte(`<encodingindex/>`),
	})
	_, err := LoadTarXMLCorpus(bytes.NewReader(archive), "stdin")
	if err == nil || !strings.Contains(err.Error(), "unrelated") {
		t.Fatalf("error = %v", err)
	}
}

func TestTarXMLCorpusMissingEntry(t *testing.T) {
	archive := tarCorpusFixture(t, false, map[string][]byte{
		"ISA/encodingindex.xml": []byte(`<encodingindex/>`),
	})
	corpus, err := LoadTarXMLCorpus(bytes.NewReader(archive), "fixture.tar")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := corpus.OpenXML("missing.xml"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing entry error = %v", err)
	}
}

func releaseBundleFixture(t testing.TB, releases []string) []byte {
	t.Helper()
	members := make([]tarFixtureMember, 0, len(releases)*2)
	for _, release := range releases {
		root := "ISA_A64_xml_A_profile-" + release
		encodingID := "ENC_" + strings.ReplaceAll(release, "-", "_")
		members = append(members,
			tarFixtureMember{
				name: root + "/encodingindex.xml",
				data: []byte(`<encodingindex/>`),
			},
			tarFixtureMember{
				name: root + "/example.xml",
				data: []byte(`<instructionsection><classes><iclass><encoding name="` + encodingID + `"/></iclass></classes></instructionsection>`),
			},
		)
	}
	return tarCorpusFixtureOrdered(t, true, members)
}

func assertSelectedRelease(t testing.TB, corpus *TarXMLCorpus, encodingID string) {
	t.Helper()
	if _, ok := corpus.preparedIForm("example.xml", encodingID); !ok {
		t.Fatalf("selected corpus does not contain %s", encodingID)
	}
	for _, other := range []string{"ENC_2026_03", "ENC_2026_06"} {
		if other == encodingID {
			continue
		}
		if _, ok := corpus.preparedIForm("example.xml", other); ok {
			t.Fatalf("selected corpus unexpectedly contains %s", other)
		}
	}
}

func TestTarXMLCorpusExplainsFeaturesOnlyPackage(t *testing.T) {
	archive := tarCorpusFixture(t, true, map[string][]byte{
		"Features.json": []byte(`{"parameters":[]}`),
	})
	_, err := LoadTarXMLCorpus(bytes.NewReader(archive), "features.tar.gz")
	if err == nil || !strings.Contains(err.Error(), "Features.json only") {
		t.Fatalf("error = %v", err)
	}
}

func TestTarXMLCorpusBoundsInflightMemory(t *testing.T) {
	data, err := os.ReadFile(clrexFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	archive := tarCorpusFixture(t, true, map[string][]byte{
		"ISA/encodingindex.xml": []byte(`<encodingindex/>`),
		"ISA/a.xml":             data,
		"ISA/b.xml":             data,
		"ISA/c.xml":             data,
	})
	const limit = 1 << 20
	corpus, err := LoadTarXMLCorpusWithOptions(bytes.NewReader(archive), "fixture.tar.gz", TarXMLCorpusOptions{
		Workers:          4,
		MaxInflightBytes: limit,
	})
	if err != nil {
		t.Fatal(err)
	}
	stats := corpus.Stats()
	if stats.PeakInflightBytes > limit {
		t.Fatalf("peak in-flight bytes = %d, limit = %d", stats.PeakInflightBytes, limit)
	}
	if stats.RetainedRawXMLBytes != int64(len(`<encodingindex/>`)) {
		t.Fatalf("retained raw XML = %d", stats.RetainedRawXMLBytes)
	}
}

func TestTarXMLCorpusHandlesIndexAfterInstructionPages(t *testing.T) {
	archive := tarCorpusFixtureOrdered(t, false, []tarFixtureMember{
		{
			name: "release/ISA/example.xml",
			data: []byte(`<instructionsection><classes><iclass><encoding name="EXAMPLE"/></iclass></classes></instructionsection>`),
		},
		{name: "release/ISA/encodingindex.xml", data: []byte(`<encodingindex/>`)},
	})
	corpus, err := LoadTarXMLCorpus(bytes.NewReader(archive), "fixture.tar")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := corpus.preparedIForm("example.xml", "EXAMPLE"); !ok {
		t.Fatal("instruction page preceding encodingindex.xml was not prepared")
	}
}

func TestTarXMLCorpusReleasesRetainedIndexAndProtectsAliases(t *testing.T) {
	const index = `<encodingindex/>`
	archive := tarCorpusFixture(t, false, map[string][]byte{
		"ISA/encodingindex.xml": []byte(index),
		"ISA/alias.xml": []byte(`<instructionsection type="alias">
			<aliasto refiform="canonical.xml"/>
			<docvars><docvar key="alias_mnemonic" value="FOO"/><docvar key="mnemonic" value="BAR"/></docvars>
			<classes><iclass><encoding name="FOO_BAR_alias"/></iclass></classes>
		</instructionsection>`),
	})
	corpus, err := LoadTarXMLCorpus(bytes.NewReader(archive), "fixture.tar")
	if err != nil {
		t.Fatal(err)
	}
	aliases := corpus.preparedAliases()
	if len(aliases) != 1 || aliases[0].EncodingID != "FOO_BAR_alias" {
		t.Fatalf("prepared aliases = %#v", aliases)
	}
	aliases[0].EncodingID = "MUTATED"
	if got := corpus.preparedAliases()[0].EncodingID; got != "FOO_BAR_alias" {
		t.Fatalf("caller mutated corpus alias: %q", got)
	}

	corpus.releaseXML("encodingindex.xml")
	if got := corpus.Stats().RetainedRawXMLBytes; got != 0 {
		t.Fatalf("retained raw XML after release = %d", got)
	}
	if _, err := corpus.OpenXML("encodingindex.xml"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("released index error = %v", err)
	}
}

func tarCorpusFixture(t testing.TB, compressed bool, files map[string][]byte) []byte {
	t.Helper()
	members := make([]tarFixtureMember, 0, len(files))
	for name, data := range files {
		members = append(members, tarFixtureMember{name: name, data: data})
	}
	return tarCorpusFixtureOrdered(t, compressed, members)
}

type tarFixtureMember struct {
	name string
	data []byte
}

func tarCorpusFixtureOrdered(t testing.TB, compressed bool, members []tarFixtureMember) []byte {
	t.Helper()
	var out bytes.Buffer
	var dst io.Writer = &out
	var gz *gzip.Writer
	if compressed {
		gz = gzip.NewWriter(&out)
		dst = gz
	}
	tw := tar.NewWriter(dst)
	for _, member := range members {
		if err := tw.WriteHeader(&tar.Header{
			Name: member.name,
			Mode: 0o644,
			Size: int64(len(member.data)),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(member.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if gz != nil {
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return out.Bytes()
}
