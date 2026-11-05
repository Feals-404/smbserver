package main

import (
	"fmt"
	"os"

	"github.com/TheManticoreProject/smbserver/core/server"
	"github.com/TheManticoreProject/smbserver/core/utils"

	"github.com/TheManticoreProject/Manticore/logger"
	smb1 "github.com/TheManticoreProject/Manticore/network/smb/smb_v10/server"
	"github.com/TheManticoreProject/goopts/parser"
)

// version is the release shown in the banner. It is overridden at build time
// with -ldflags "-X main.version=<tag>" (see .github/workflows/release.yaml).
var version = "dev"

// banner returns the smbserver ASCII art banner, with the version
// right-justified in a 10-character field. The backticks of the art cannot
// appear inside a raw string, so they are injected explicitly.
func banner() string {
	art := `               _
 ___ _ __ ___ | |__  ___  ___ _ ____   _____ _ __
/ __| '_ ` + "`" + ` _ \| '_ \/ __|/ _ \ '__\ \ / / _ \ '__|
\__ \ | | | | | |_) \__ \  __/ |   \ V /  __/ |
|___/_| |_| |_|_.__/|___/\___|_|    \_/ \___|_|
                                      %10s`
	return fmt.Sprintf(art, "v"+version)
}

var (
	// Configuration
	debug bool

	// Share
	shareName string
	sharePath string
	readOnly  bool

	// Network
	listenAddress string
	port          int
	useNBT        bool
	serverName    string

	// Authentication
	authDomain   string
	authUsername string
	authPassword string
	authHashes   string

	// Protocols
	noSMB1 bool
	noSMB2 bool
	browse bool

	// Security
	requireSigning    bool
	requireEncryption bool

	// Capture
	challenge  string
	osVersion  string
	disableESS bool

	// Output
	outputFile string
	logAccess  bool
)

func parseArgs() {
	ap := parser.ArgumentsParser{
		Banner: banner(),
	}
	ap.SetOptShowBannerOnHelp(true)
	ap.SetOptShowBannerOnRun(true)

	// Configuration flags
	ap.NewBoolArgument(&debug, "", "--debug", false, "Debug mode.")

	// Share positionals
	ap.NewStringPositionalArgument(&shareName, "shareName", "Name of the share.")
	ap.NewStringPositionalArgument(&sharePath, "sharePath", "Local directory to serve.")

	// Network flags
	group_network, err := ap.NewArgumentGroup("Network")
	if err != nil {
		logger.Warnf("Error creating ArgumentGroup: %s", err)
	} else {
		group_network.NewStringArgument(&listenAddress, "-ip", "--interface-address", "0.0.0.0", false, "Address to listen on.")
		group_network.NewTcpPortArgument(&port, "-P", "--port", 0, false, "TCP port to listen on (default 445, or 139 with --nbt).")
		group_network.NewBoolArgument(&useNBT, "", "--nbt", false, "Use NetBIOS (NBT) transport instead of direct TCP.")
		group_network.NewStringArgument(&serverName, "", "--server-name", "FILESRV", false, "NetBIOS name advertised to clients.")
	}

	// Authentication flags
	group_auth, err := ap.NewArgumentGroup("Authentication")
	if err != nil {
		logger.Warnf("Error creating ArgumentGroup: %s", err)
	} else {
		group_auth.NewStringArgument(&authDomain, "-d", "--domain", "WORKGROUP", false, "Domain of the served account.")
		group_auth.NewStringArgument(&authUsername, "-u", "--user", "", false, "Served account. Supports DOMAIN\\user. Without it every logon is a guest.")
		group_auth.NewStringArgument(&authPassword, "-p", "--password", "", false, "Password of the served account.")
		group_auth.NewStringArgument(&authHashes, "", "--hashes", "", false, "NT/LM hashes of the served account, format is [LMhash:]NThash.")
	}

	// Protocol flags
	group_protocols, err := ap.NewArgumentGroup("Protocols")
	if err != nil {
		logger.Warnf("Error creating ArgumentGroup: %s", err)
	} else {
		group_protocols.NewBoolArgument(&noSMB1, "", "--no-smb1", false, "Do not serve SMB1 clients.")
		group_protocols.NewBoolArgument(&noSMB2, "", "--no-smb2", false, "Do not serve SMB 2/3 clients.")
		group_protocols.NewBoolArgument(&browse, "", "--browse", false, "Serve IPC$ so clients can list the share (net view, smbclient -L; SMB1 only).")
	}

	// Security flags
	group_security, err := ap.NewArgumentGroup("Security")
	if err != nil {
		logger.Warnf("Error creating ArgumentGroup: %s", err)
	} else {
		group_security.NewBoolArgument(&readOnly, "", "--read-only", false, "Refuse every modification.")
		group_security.NewBoolArgument(&requireSigning, "", "--require-signing", false, "Refuse unsigned sessions.")
		group_security.NewBoolArgument(&requireEncryption, "", "--require-encryption", false, "Encrypt every session (SMB 3.x only, implies --no-smb1).")
	}

	// Capture flags
	group_capture, err := ap.NewArgumentGroup("Capture")
	if err != nil {
		logger.Warnf("Error creating ArgumentGroup: %s", err)
	} else {
		group_capture.NewStringArgument(&challenge, "", "--challenge", "", false, "Fix the 8-byte NTLM server challenge (16 hex), to crack responses against a precomputed table.")
		group_capture.NewStringArgument(&osVersion, "", "--os-version", "", false, "Advertise this Windows version (major.minor.build) in the NTLM challenge, to look like a real host.")
		group_capture.NewBoolArgument(&disableESS, "", "--disable-ess", false, "Strip extended session security, so an NTLMv1 client yields a crack.sh-crackable response (use with --challenge).")
	}

	// Output flags
	group_output, err := ap.NewArgumentGroup("Output")
	if err != nil {
		logger.Warnf("Error creating ArgumentGroup: %s", err)
	} else {
		group_output.NewStringArgument(&outputFile, "-o", "--output-file", "", false, "Append captured hashes to this file, in hashcat format.")
		group_output.NewBoolArgument(&logAccess, "", "--log-access", false, "Log every file a client opens (who, path, read or write).")
	}

	ap.Parse()
}

func main() {
	parseArgs()

	logger.SetLevel(logger.LevelInfo)
	if debug {
		logger.SetLevel(logger.LevelDebug)
	}

	// NetBIOS is served on 139 and direct TCP on 445, unless a port was given.
	if port == 0 {
		port = 445
		if useNBT {
			port = 139
		}
	}

	options := server.Options{
		ShareName:         shareName,
		SharePath:         sharePath,
		ReadOnly:          readOnly,
		ListenAddress:     listenAddress,
		Port:              port,
		UseNBT:            useNBT,
		ServerName:        serverName,
		Domain:            authDomain,
		RequireSigning:    requireSigning,
		RequireEncryption: requireEncryption,
		EnableSMB1:        !noSMB1 && !requireEncryption,
		EnableSMB2:        !noSMB2,
		OutputFile:        outputFile,
		Browsable:         browse,
		LogFileAccess:     logAccess,
		DisableESS:        disableESS,
	}

	if challenge != "" {
		parsed, err := utils.ParseChallenge(challenge)
		if err != nil {
			logger.Error(err.Error())
			os.Exit(1)
		}
		options.Challenge = parsed
	}
	if osVersion != "" {
		parsed, err := utils.ParseOSVersion(osVersion)
		if err != nil {
			logger.Error(err.Error())
			os.Exit(1)
		}
		options.AdvertiseVersion = parsed
	}

	// Accept DOMAIN\user and DOMAIN/user; the embedded domain overrides -d.
	if authUsername != "" {
		domain, username := utils.SplitDomainUsername(authDomain, authUsername)
		ntHash, err := utils.AccountHash(authPassword, authHashes)
		if err != nil {
			logger.Errorf("Invalid credentials: %s", err)
			os.Exit(1)
		}
		options.Account = &smb1.Account{Domain: domain, Username: username, NTHash: ntHash}
	}

	srv, err := server.NewServer(options)
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
	if err := srv.ListenAndServe(); err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
}
