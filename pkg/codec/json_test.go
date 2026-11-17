package codec

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"testing"
)

func TestStreamingCatalogJSON(t *testing.T) {
	c := exampleCatalog(t)
	c.SourceLicense = "Source notice with \"encodings\":null and <special> characters"
	c.SourceLicenseID = "MIT"
	c.Unsupported = []Unsupported{{ID: "source-only", Reason: "no physical instruction"}}
	c.FeatureSets = map[string][]string{"base": {"feature"}}
	var output bytes.Buffer
	if err := c.WriteJSON(&output); err != nil {
		t.Fatal(err)
	}
	want, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var gotValue, wantValue any
	if err = json.Unmarshal(output.Bytes(), &gotValue); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(want, &wantValue); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Fatal("streamed catalog changed JSON fields or values")
	}
	if err := c.WriteJSON(errorWriter{}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("lost writer failure: %v", err)
	}
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
