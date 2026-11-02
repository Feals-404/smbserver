// Command smbserver serves a local directory over SMB 2/3, in the spirit of
// impacket's smbserver.py, and prints the NetNTLM response of every logon in
// hashcat form.
//
// Usage:
//
//	manticore-smbserver SHARE /path/to/dir [options]
//
// Without -u every logon is admitted as a guest, which is what a capture wants.
package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/TheManticoreProject/Manticore/crypto/nt"
	"github.com/TheManticoreProject/Manticore/logger"
	smb1 "github.com/TheManticoreProject/Manticore/network/smb/smb_v10/server"
	"github.com/TheManticoreProject/Manticore/network/smb/smb_v20/server"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"github.com/TheManticoreProject/goopts/parser"
)

var (
	shareName string
	sharePath string

	listenAddress string
	listenPort    int
	serverName    string

	domain   string
	username string
	password string
	hashes   string

	readOnly          bool
	requireSigning    bool
	requireEncryption bool
	outputFile        string
	debug             bool
)

func parseArgs() {
	ap := parser.ArgumentsParser{Banner: "smbserver - SMB 2/3 server - TheManticoreProject"}
	ap.NewStringPositionalArgument(&shareName, "shareName", "Name of the share.")
	ap.NewStringPositionalArgument(&sharePath, "sharePath", "Local directory to serve.")
	ap.NewBoolArgument(&debug, "", "--debug", false, "Enable debug logging.")

	if group, err := ap.NewArgumentGroup("Network"); err == nil {
		group.NewStringArgument(&listenAddress, "-ip", "--interface-address", "0.0.0.0", false, "Address to listen on.")
		group.NewTcpPortArgument(&listenPort, "", "--port", 445, false, "TCP port to listen on.")
		group.NewStringArgument(&serverName, "", "--server-name", "FILESRV", false, "NetBIOS name advertised to clients.")
	}
	if group, err := ap.NewArgumentGroup("Authentication"); err == nil {
		group.NewStringArgument(&domain, "-d", "--domain", "WORKGROUP", false, "Domain of the accepted account.")
		group.NewStringArgument(&username, "-u", "--username", "", false, "Accepted account. Without it every logon is a guest.")
		group.NewStringArgument(&password, "-p", "--password", "", false, "Password of the accepted account.")
		group.NewStringArgument(&hashes, "-H", "--hashes", "", false, "NT hash of the accepted account, as LMhash:NThash or NThash.")
	}
	if group, err := ap.NewArgumentGroup("Security"); err == nil {
		group.NewBoolArgument(&readOnly, "", "--read-only", false, "Refuse every modification.")
		group.NewBoolArgument(&requireSigning, "", "--require-signing", false, "Refuse unsigned sessions.")
		group.NewBoolArgument(&requireEncryption, "", "--require-encryption", false, "Encrypt every session (SMB 3.x clients only).")
		group.NewStringArgument(&outputFile, "-o", "--output-file", "", false, "Append captured hashes to this file.")
	}
	ap.Parse()
}

func main() {
	parseArgs()
	logger.SetLevel(logger.LevelInfo)
	if debug {
		logger.SetLevel(logger.LevelDebug)
	}
	if err := run(); err != nil {
		logger.Errorf("%v", err)
		os.Exit(1)
	}
}

func run() error {
	config := server.Config{
		ServerName:        serverName,
		DomainName:        domain,
		DNSComputerName:   serverName,
		DNSDomainName:     domain,
		AllowGuest:        username == "",
		AllowAnonymous:    username == "",
		RequireSigning:    requireSigning,
		RequireEncryption: requireEncryption,
	}
	if username != "" {
		ntHash, err := accountHash()
		if err != nil {
			return err
		}
		config.Authenticator = smb1.StaticAccounts(smb1.Account{Domain: domain, Username: username, NTHash: ntHash})
	}

	srv, err := server.NewServer(config)
	if err != nil {
		return err
	}

	// Harvest every NTLM response and append it to the output file. Known
	// accounts are still served (pass-through); the rest fall to the guest or
	// logon-failure policy above.
	capture, err := server.NewCaptureHandler(server.CaptureConfig{
		CaptureConfig: smb1.CaptureConfig{OutputFile: outputFile, UniquePerUser: true},
		PassThrough:   true,
	})
	if err != nil {
		return err
	}
	srv.RegisterHandler(capture)
	fs, err := smb1.NewLocalFileSystem(sharePath, shareName)
	if err != nil {
		return err
	}
	fs.SetReadOnly(readOnly)
	if err := srv.AddShare(&server.Share{Name: shareName, FS: fs, ReadOnly: readOnly}); err != nil {
		return err
	}

	logger.Infof("Serving %s as \\\\%s\\%s", sharePath, serverName, shareName)
	return srv.ListenAndServe(fmt.Sprintf("%s:%d", listenAddress, listenPort))
}

// accountHash returns the NT hash of the accepted account.
func accountHash() ([16]byte, error) {
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
