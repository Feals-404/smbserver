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

func TestNewServerOPSECNames(t *testing.T) {
	base := Options{
		Shares:     []ShareSpec{{Name: "FILES", Path: t.TempDir()}},
		TCPPort:    445,
		ServerName: "FILESRV",
		Domain:     "WORKGROUP",
		EnableSMB1: true,
	}

	// Explicit names reach the SMB1 config.
	opts := base
	opts.DNSComputerName, opts.DNSDomainName, opts.NativeOS = "fs.corp.local", "corp.local", "Windows 10 Pro"
	srv, err := NewServer(opts)
	if err != nil {
		t.Fatal(err)
	}
	cfg := srv.smb1.Config()
	if cfg.DNSComputerName != "fs.corp.local" || cfg.DNSDomainName != "corp.local" || cfg.NativeOS != "Windows 10 Pro" {
		t.Errorf("explicit names not applied: %q %q %q", cfg.DNSComputerName, cfg.DNSDomainName, cfg.NativeOS)
	}

	// Empty DNS names fall back to the NetBIOS name and domain.
	srv2, err := NewServer(base)
	if err != nil {
		t.Fatal(err)
	}
	cfg2 := srv2.smb1.Config()
	if cfg2.DNSComputerName != "FILESRV" || cfg2.DNSDomainName != "WORKGROUP" {
		t.Errorf("DNS fallback wrong: %q %q", cfg2.DNSComputerName, cfg2.DNSDomainName)
	}
}
