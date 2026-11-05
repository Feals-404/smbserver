package server

import (
	"testing"

	"github.com/TheManticoreProject/Manticore/crypto/spnego/ntlm/message/challenge"
	"github.com/TheManticoreProject/Manticore/crypto/spnego/ntlm/message/negotiate"
	"github.com/TheManticoreProject/Manticore/crypto/spnego/ntlm/message/negotiate/flags"
)

// TestDowngradeChallenge checks that the provided CHALLENGE round-trips through
// Manticore's own parser (the 56-vs-60-byte trap), carries the fixed challenge,
// and has extended session security and target info stripped — the three things
// that make a captured NTLMv1 response crackable on crack.sh.
func TestDowngradeChallenge(t *testing.T) {
	// A client NEGOTIATE that offers ESS, so stripping it is actually exercised.
	neg, err := negotiate.CreateNegotiateMessage("", "",
		flags.NTLMSSP_NEGOTIATE_UNICODE|flags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY, nil)
	if err != nil {
		t.Fatalf("CreateNegotiateMessage: %v", err)
	}
	negBytes, err := neg.Marshal()
	if err != nil {
		t.Fatalf("Marshal negotiate: %v", err)
	}

	fixed := [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	provided, err := downgradeChallenge(negBytes, "LAB", &fixed, nil)
	if err != nil {
		t.Fatalf("downgradeChallenge: %v", err)
	}

	parsed := &challenge.ChallengeMessage{}
	if _, err := parsed.Unmarshal(provided); err != nil {
		t.Fatalf("provided CHALLENGE does not round-trip: %v (len %d)", err, len(provided))
	}
	if parsed.ServerChallenge != fixed {
		t.Errorf("ServerChallenge = %x, want %x", parsed.ServerChallenge, fixed)
	}
	if parsed.NegotiateFlags&flags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY != 0 {
		t.Error("extended session security was not stripped")
	}
	if parsed.NegotiateFlags&flags.NTLMSSP_NEGOTIATE_TARGET_INFO != 0 {
		t.Error("target info was not stripped")
	}
}
