//go:build darwin

package arm_test

import (
	"path/filepath"
	"syscall"
	"testing"
)

func TestDatalessDetectionMatchesFindFlags(t *testing.T) {
	const sfDataless = 0x40000000
	root := filepath.Join("..", "..", "spec", "ISA")

	var st syscall.Stat_t
	// clrex is known dataless in this workspace's iCloud checkout
	path := filepath.Join(root, "clrex.xml")
	if err := syscall.Stat(path, &st); err != nil {
		t.Skipf("stat %s: %v", path, err)
	}
	if st.Flags&sfDataless == 0 {
		t.Skipf("%s is hydrated (flags=%#x); skip", path, st.Flags)
	}

	// adc.xml is typically local
	adc := filepath.Join(root, "adc.xml")
	if err := syscall.Stat(adc, &st); err != nil {
		t.Fatalf("stat adc: %v", err)
	}
	if st.Flags&sfDataless != 0 {
		t.Fatalf("adc.xml unexpectedly dataless flags=%#x", st.Flags)
	}
}
