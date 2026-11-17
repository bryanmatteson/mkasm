package managed

import (
	"context"
	"fmt"
	"os/exec"
)

// TypeVerification retains the external verifier's diagnostics verbatim.
// ILVerify requires the complete reference set; no assemblies are downloaded or
// implicitly selected by this API. Unsafe CIL can be valid yet unverifiable.
type TypeVerification struct {
	Verified    bool   `json:"verified"`
	Diagnostics string `json:"diagnostics"`
}

func VerifyTypes(ctx context.Context, verifier, image string, references []string) (TypeVerification, error) {
	return VerifyTypesWith(ctx, verifier, image, references, "System.Private.CoreLib")
}

// VerifyTypesWith also supports framework and custom core libraries by name.
func VerifyTypesWith(ctx context.Context, verifier, image string, references []string, systemModule string) (TypeVerification, error) {
	var result TypeVerification
	if verifier == "" || image == "" {
		return result, fmt.Errorf("managed: explicit verifier and image paths required")
	}
	args := []string{image}
	for _, reference := range references {
		args = append(args, "-r", reference)
	}
	if systemModule != "" {
		args = append(args, "-s", systemModule)
	}
	out, e := exec.CommandContext(ctx, verifier, args...).CombinedOutput()
	result.Diagnostics = string(out)
	result.Verified = e == nil
	if e != nil {
		return result, fmt.Errorf("managed: type verification failed: %w\n%s", e, out)
	}
	return result, nil
}
