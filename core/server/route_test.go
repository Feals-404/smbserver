package server

import "testing"

// smb1Negotiate builds an SMB1 NEGOTIATE frame offering dialects.
func smb1Negotiate(dialects ...string) []byte {
	frame := append([]byte{0xFF, 'S', 'M', 'B', 0x72}, make([]byte, 27)...)
	var body []byte
	for _, d := range dialects {
		body = append(append(append(body, 0x02), d...), 0)
	}
	frame = append(frame, 0, byte(len(body)), byte(len(body)>>8))
	return append(frame, body...)
}

func TestRoute(t *testing.T) {
	cases := []struct {
		name  string
		frame []byte
		want  Protocol
	}{
		{"SMB1 only", smb1Negotiate("PC NETWORK PROGRAM 1.0", "LANMAN1.0", "NT LM 0.12"), SMB1},
		{"multi-protocol wildcard", smb1Negotiate("NT LM 0.12", "SMB 2.002", "SMB 2.???"), SMB2},
		{"multi-protocol 2.002", smb1Negotiate("NT LM 0.12", "SMB 2.002"), SMB2},
		{"SMB2 NEGOTIATE", append([]byte{0xFE, 'S', 'M', 'B'}, make([]byte, 60)...), SMB2},
	}
	for _, c := range cases {
		if got := route(c.frame); got != c.want {
			t.Errorf("%s: route() = %s, want %s", c.name, got, c.want)
		}
	}
}

func TestReplayTransport(t *testing.T) {
	replay := &replayTransport{first: []byte("first")}
	got, err := replay.Receive()
	if err != nil || string(got) != "first" {
		t.Fatalf("Receive() = %q, %v, want \"first\"", got, err)
	}
	if replay.first != nil {
		t.Fatal("the first frame was not consumed")
	}
}
