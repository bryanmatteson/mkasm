package templates

import "embed"

// FS holds language-specific codegen templates.
//
//	go/*.tmpl   — Go module emission
//	rust/*.tmpl — Rust crate emission
//
// Authoritative Pass 3 surface: every template here is executed by a live
// codegen path, so a template that no longer matches the data model fails the
// build rather than sitting unreachable.
//
//go:embed go/*.tmpl rust/*.tmpl x86_rust/*.tmpl
var FS embed.FS
