package server

import "testing"

func TestNewServerShares(t *testing.T) {
	srv, err := NewServer(Options{
		Shares:     []ShareSpec{{Name: "FILES", Path: t.TempDir()}, {Name: "DATA", Path: t.TempDir()}},
		TCPPort:    445,
		ServerName: "FILESRV",
		Domain:     "WORKGROUP",
		EnableSMB1: true,
		EnableSMB2: true,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	for _, name := range []string{"FILES", "DATA"} {
		if srv.smb1.Share(name) == nil {
			t.Errorf("share %q was not registered on the SMB1 server", name)
		}
	}
}

func TestNewServerRejectsNoShares(t *testing.T) {
	if _, err := NewServer(Options{TCPPort: 445, EnableSMB2: true}); err == nil {
		t.Error("NewServer with no shares should error")
	}
}
