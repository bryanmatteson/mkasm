package codec

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// WriteJSON streams the corpus one encoding at a time. Register tables can be
// large and shared among tens of thousands of forms; serializing the complete
// catalog into an intermediate buffer would multiply that storage unnecessarily.
func (c *Catalog) WriteJSON(output io.Writer) error {
	header := *c
	header.Encodings = nil
	metadata, err := json.Marshal(header)
	if err != nil {
		return err
	}
	const marker = `"encodings":null`
	position := bytes.Index(metadata, []byte(marker))
	if position < 0 {
		return errors.New("codec JSON is missing its encoding field")
	}
	w := bufio.NewWriter(output)
	if _, err = w.Write(metadata[:position]); err != nil {
		return err
	}
	if _, err = w.WriteString(`"encodings":[`); err != nil {
		return err
	}
	encoder := json.NewEncoder(w)
	for i := range c.Encodings {
		if i != 0 {
			if err = w.WriteByte(','); err != nil {
				return err
			}
		}
		if err = encoder.Encode(&c.Encodings[i]); err != nil {
			return err
		}
	}
	if err = w.WriteByte(']'); err != nil {
		return err
	}
	if _, err = w.Write(metadata[position+len(marker):]); err != nil {
		return err
	}
	if err = w.WriteByte('\n'); err != nil {
		return err
	}
	return w.Flush()
}
