package arm

import (
	"fmt"
	"sort"
	"strings"
)

// The analysis surface reuses the formatter's operand definitions and scalar
// transforms. This table only supplies identity; no instruction bits or operand
// placement are duplicated here.
func buildRustAnalysisData(catalog *Catalog, surfaces ...*DisasmSurface) struct {
	Identities, Buckets string
	Capacity            int
} {
	entries := make(map[string]CatalogEntry, len(catalog.Entries))
	for _, e := range catalog.Entries {
		entries[e.EncodingID] = e
	}
	ids := make([]string, 0, len(entries))
	for id := range entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var b strings.Builder
	for _, id := range ids {
		e := entries[id]
		canonical := e
		seen := map[string]bool{id: true}
		for canonical.AliasOf != "" && !seen[canonical.AliasOf] {
			next, ok := entries[canonical.AliasOf]
			if !ok {
				canonical.EncodingID = canonical.AliasOf
				canonical.AsmMnemonic = ""
				canonical.AliasOf = ""
				break
			}
			seen[next.EncodingID] = true
			canonical = next
		}
		if canonical.AliasOf != "" {
			canonical.EncodingID = ""
			canonical.AsmMnemonic = ""
		}
		fmt.Fprintf(&b, "    (%s, %s, %s, %s),\n", rustStringLiteral(id), rustStringLiteral(canonical.EncodingID), rustStringLiteral(canonical.AsmMnemonic), rustStringLiteral(e.AsmMnemonic))
	}
	capacity := 1
	var buckets strings.Builder
	if len(surfaces) > 0 && surfaces[0] != nil {
		forms := append([]DisasmForm(nil), surfaces[0].Forms...)
		sort.Slice(forms, func(i, j int) bool { return forms[i].EncodingID < forms[j].EncodingID })
		for _, form := range forms {
			count := 0
			for _, part := range form.Parts {
				if part.Op != nil {
					count++
				}
			}
			if count > capacity {
				capacity = count
			}
		}
		// Sort once by the exact display preference. The first matching
		// candidate is then the preferred spelling; no per-call ranking.
		order := make([]int, len(forms))
		for i := range forms {
			order[i] = i
		}
		sort.Slice(order, func(i, j int) bool {
			a, b := order[i], order[j]
			return betterRustDisasmForm(&forms[a], entries[forms[a].EncodingID], &forms[b], entries[forms[b].EncodingID])
		})
		var candidates strings.Builder
		buckets.WriteString("static BUCKETS: &[u32] = &[\n")
		offset := 0
		for high := 0; high < 4096; high++ {
			fmt.Fprintf(&buckets, "%d,", offset)
			for _, i := range order {
				form := forms[i]
				e := entries[form.EncodingID]
				mask, value := e.Mask|form.ConstraintMask, e.Value|form.ConstraintValue
				if e.Mask != 0 && uint32(high)&(mask>>20) == value>>20 {
					fmt.Fprintf(&candidates, "%d,", i)
					offset++
				}
			}
			if high%32 == 31 {
				buckets.WriteByte('\n')
			}
		}
		fmt.Fprintf(&buckets, "%d,];\nstatic BUCKET_FORMS: &[u16] = &[%s];\n", offset, candidates.String())
	}
	if buckets.Len() == 0 {
		buckets.WriteString("static BUCKETS: &[u32] = &[0;4097];\nstatic BUCKET_FORMS: &[u16] = &[];\n")
	}
	return struct {
		Identities, Buckets string
		Capacity            int
	}{b.String(), buckets.String(), capacity}
}
