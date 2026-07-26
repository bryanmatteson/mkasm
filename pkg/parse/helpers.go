package parse

import (
	"encoding/xml"
)

func GetAttr(elem xml.StartElement, name string) string {
	for _, attr := range elem.Attr {
		if attr.Name.Local == name {
			return attr.Value
		}
	}
	return ""
}
