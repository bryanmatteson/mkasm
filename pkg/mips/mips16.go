package mips

import _ "embed"

//go:embed testdata/mips16-opc.c
var gnuMips16 string

//go:embed testdata/COPYING3
var gnuMips16License string
