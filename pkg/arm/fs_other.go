//go:build !darwin

package arm

func isUnavailableCloudFile(path string) bool {
	return false
}
