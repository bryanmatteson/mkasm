package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/bryanmatteson/mkasm/pkg/dotnet"
)

type managedMetadataReference struct {
	path     string
	metadata *dotnet.Metadata
}

// References are explicit local paths/globs; this does not perform implicit
// runtime probing or download dependencies. Metadata owns borrowed input bytes.
func loadManagedReferences(patterns []string, local *dotnet.Metadata) ([]managedMetadataReference, error) {
	out := []managedMetadataReference{}
	seen := map[string]bool{}
	for _, pattern := range patterns {
		paths, e := filepath.Glob(pattern)
		if e != nil {
			return nil, e
		}
		if len(paths) == 0 {
			return nil, fmt.Errorf("reference pattern %q matched no files", pattern)
		}
		for _, path := range paths {
			absolute, e := filepath.Abs(path)
			if e != nil {
				return nil, e
			}
			if seen[absolute] {
				continue
			}
			seen[absolute] = true
			b, e := os.ReadFile(path)
			if e != nil {
				return nil, e
			}
			image, e := dotnet.Open(b)
			if e != nil {
				return nil, fmt.Errorf("reference %s: %w", path, e)
			}
			if !image.HasMetadata {
				return nil, fmt.Errorf("reference %s has no metadata", path)
			}
			metadata := image.Metadata
			if bytes.Equal(metadata.Data, local.Data) {
				metadata = local
			} else {
				for _, reference := range out {
					if bytes.Equal(metadata.Data, reference.metadata.Data) {
						metadata = reference.metadata
						break
					}
				}
			}
			out = append(out, managedMetadataReference{absolute, metadata})
		}
	}
	return out, nil
}

// Adjacent explicitly supplied paths retain manifest File identity when several
// assemblies contain same-named netmodules. This never probes for additional
// files or selects a different manifest's module merely by its basename.
func managedReferenceSet(patterns []string, local *dotnet.Metadata, input string) (*dotnet.ReferenceSet, error) {
	references, err := loadManagedReferences(patterns, local)
	if err != nil {
		return nil, err
	}
	metadata := make([]*dotnet.Metadata, 0, len(references))
	for _, reference := range references {
		metadata = append(metadata, reference.metadata)
	}
	set, err := dotnet.NewReferenceSet(local, metadata...)
	if err != nil {
		return nil, err
	}
	if info, err := os.Stat(input); err == nil && info.Mode().IsRegular() {
		absolute, err := filepath.Abs(input)
		if err != nil {
			return nil, err
		}
		references = append(references, managedMetadataReference{absolute, local})
	}
	for _, manifest := range references {
		if manifest.metadata.Tables[32].Count != 1 {
			continue
		}
		for rid := uint32(1); rid <= manifest.metadata.Tables[38].Count; rid++ {
			row, err := manifest.metadata.Row(38, rid)
			if err != nil {
				return nil, err
			}
			if row[0] != 0 {
				continue // File contains no metadata, or unsupported flags.
			}
			name, err := manifest.metadata.String(row[1])
			if err != nil {
				return nil, err
			}
			candidates := map[*dotnet.Metadata]bool{}
			for _, reference := range references {
				if reference.metadata.Tables[32].Count == 0 && filepath.Base(reference.path) == name && filepath.Dir(reference.path) == filepath.Dir(manifest.path) {
					candidates[reference.metadata] = true
				}
			}
			if len(candidates) > 1 {
				return nil, fmt.Errorf("ambiguous explicitly supplied module file %q for %s", name, manifest.path)
			}
			for module := range candidates {
				if err := set.BindModule(manifest.metadata, dotnet.Token(38<<24|rid), module); err != nil {
					return nil, fmt.Errorf("module file %q: %w", name, err)
				}
			}
		}
	}
	return set, nil
}
