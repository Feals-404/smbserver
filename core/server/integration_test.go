package server

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/TheManticoreProject/Manticore/network/smb"
	smbclient "github.com/TheManticoreProject/Manticore/network/smb/client"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

// serveTestServer starts a guest capture server on a free loopback port and
// returns the port and the capture file. The server runs until the test process
// exits, which is enough for a test.
func serveTestServer(t *testing.T) (int, string) {
	t.Helper()

	probe := t.TempDir()
	if err := os.WriteFile(filepath.Join(probe, "probe.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	hashes := filepath.Join(t.TempDir(), "hashes.txt")

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	srv, err := NewServer(Options{
		Shares:        []ShareSpec{{Name: "FILES", Path: probe}},
		ListenAddress: "127.0.0.1",
		TCPPort:       port,
		ServerName:    "FILESRV",
		Domain:        "WORKGROUP",
		EnableSMB1:    true,
		EnableSMB2:    true,
		OutputFile:    hashes,
	})
	if err != nil {
		t.Fatal(err)
	}
	go srv.ListenAndServe()

	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	for i := 0; i < 100; i++ {
		if c, err := net.DialTimeout("tcp", addr, 50*time.Millisecond); err == nil {
			c.Close()
			return port, hashes
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("server did not come up")
	return 0, ""
}

// waitCaptured polls the capture file for a user, since the write races the
// client's Login returning.
func waitCaptured(t *testing.T, path, user string) bool {
	t.Helper()
	for i := 0; i < 100; i++ {
		if data, _ := os.ReadFile(path); strings.Contains(string(data), user) {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// TestServeAndCapture drives the server with the Manticore client over both
// protocols: each connection must be routed to the matching sub-server (so the
// negotiated dialect is the one asked for) and its logon captured.
func TestServeAndCapture(t *testing.T) {
	port, hashes := serveTestServer(t)

	cases := []struct {
		name    string
		version smb.SMBProtocolVersion
		user    string
	}{
		{"SMB1", smb.SMB_VERSION_1_0, "alice"},
		{"SMB2", smb.SMB_VERSION_2_1, "bob"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client, err := smbclient.Dial("127.0.0.1", port, smbclient.Options{
				Preferred: []smb.SMBProtocolVersion{c.version},
			})
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			defer client.Disconnect()

			if got := client.Dialect(); got != c.version {
				t.Errorf("routed to dialect %v, want %v", got, c.version)
			}

			creds, err := credentials.NewCredentials("", c.user, "s3cret", "")
			if err != nil {
				t.Fatal(err)
			}
			if err := client.Login(creds); err != nil {
				t.Fatalf("Login: %v", err)
			}
			if !waitCaptured(t, hashes, c.user) {
				t.Errorf("%s logon was not captured to the output file", c.user)
			}
		})
	}
}
