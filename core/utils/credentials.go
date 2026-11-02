package utils

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/TheManticoreProject/Manticore/crypto/nt"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

// SplitDomainUsername splits a domain-qualified username of the form
// DOMAIN\user or DOMAIN/user into its domain and user parts. The embedded
// domain takes precedence over the one given separately (e.g. with -d). When
// the username carries no domain, or either side of the separator is empty, the
// inputs are returned unchanged.
func SplitDomainUsername(domain, username string) (string, string) {
	for _, sep := range []string{"\\", "/"} {
		if userDomain, userName, found := strings.Cut(username, sep); found && userDomain != "" && userName != "" {
			return userDomain, userName
		}
	}
	return domain, username
}

// AccountHash returns the NT hash of an account, from its [LMhash:]NThash when
// one is given and from its password otherwise.
func AccountHash(password, hashes string) ([16]byte, error) {
	var ntHash [16]byte
	if hashes == "" {
		return nt.NTHash(password), nil
	}
	_, ntHex, err := credentials.ParseLMNTHashes(hashes)
	if err != nil {
		return ntHash, err
	}
	decoded, err := hex.DecodeString(ntHex)
	if err != nil || len(decoded) != len(ntHash) {
		return ntHash, fmt.Errorf("invalid NT hash %q", ntHex)
	}
	copy(ntHash[:], decoded)
	return ntHash, nil
}
