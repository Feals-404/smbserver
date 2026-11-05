package utils

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/TheManticoreProject/Manticore/crypto/spnego/ntlm/version"
)

// ParseChallenge decodes a fixed 8-byte NTLM server challenge from its hex form
// (16 hex digits, optionally 0x-prefixed). A fixed challenge is what makes a
// captured NetNTLM response crackable against a precomputed table.
func ParseChallenge(value string) (*[8]byte, error) {
	trimmed := strings.TrimPrefix(strings.TrimSpace(value), "0x")
	decoded, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("invalid challenge %q: %v", value, err)
	}
	if len(decoded) != 8 {
		return nil, fmt.Errorf("challenge must be 8 bytes (16 hex digits), got %d", len(decoded))
	}
	var challenge [8]byte
	copy(challenge[:], decoded)
	return &challenge, nil
}

// ParseOSVersion builds an advertised NTLM version from a "major.minor.build"
// string (e.g. "10.0.19041"). Advertising a version is OPSEC: a real Windows
// host always sends one, so omitting it is a tell.
func ParseOSVersion(value string) (*version.Version, error) {
	parts := strings.Split(strings.TrimSpace(value), ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("version must be major.minor.build (e.g. 10.0.19041), got %q", value)
	}
	nums := make([]int, 3)
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid version component %q", part)
		}
		nums[i] = n
	}
	if nums[0] > 255 || nums[1] > 255 || nums[2] > 65535 {
		return nil, fmt.Errorf("version component out of range in %q", value)
	}
	v := version.NewVersion(byte(nums[0]), byte(nums[1]), uint16(nums[2]), version.NTLMSSP_REVISION_W2K3)
	return &v, nil
}
