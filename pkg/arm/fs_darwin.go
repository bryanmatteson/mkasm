//go:build darwin

package arm

import "syscall"

// SF_DATALESS marks iCloud placeholder files that have not been hydrated.
// Opening them can block while the system fetches content.
// See sys/stat.h: SF_DATALESS = 0x40000000
const sfDataless = 0x40000000

func isUnavailableCloudFile(path string) bool {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return false
	}
	return st.Flags&sfDataless != 0
}
