package server

import (
	"bytes"

	"github.com/TheManticoreProject/Manticore/network/smb/common/transport"
)

// Protocol is the SMB family a connection is served with.
type Protocol int

const (
	SMB1 Protocol = iota
	SMB2
)

func (p Protocol) String() string {
	if p == SMB1 {
		return "SMB1"
	}
	return "SMB2"
}

var (
	smb1ProtocolID = []byte{0xFF, 'S', 'M', 'B'}
	// smb2DialectString prefixes every SMB2 dialect string ("SMB 2.002",
	// "SMB 2.???") of an SMB1 NEGOTIATE, behind its 0x02 buffer format byte.
	smb2DialectString = []byte("\x02SMB 2.")
)

// route picks the protocol for a connection from its first frame. An SMB1
// NEGOTIATE offering no SMB2 dialect goes to the SMB1 server. Anything else, an
// SMB2 NEGOTIATE or a multi-protocol SMB1 NEGOTIATE, goes to the SMB2 server,
// which performs the SMB1 to SMB2 upgrade itself.
func route(first []byte) Protocol {
	if bytes.HasPrefix(first, smb1ProtocolID) && !bytes.Contains(first, smb2DialectString) {
		return SMB1
	}
	return SMB2
}

// replayTransport hands back a frame already read off the transport before
// reading further, so the server that is chosen sees the connection from its
// first frame.
type replayTransport struct {
	transport.Transport
	first []byte
}

func (t *replayTransport) Receive() ([]byte, error) {
	if first := t.first; first != nil {
		t.first = nil
		return first, nil
	}
	return t.Transport.Receive()
}
