package server

import (
	"github.com/TheManticoreProject/Manticore/logger"
	smb1message "github.com/TheManticoreProject/Manticore/network/smb/smb_v10/message"
	smb1commands "github.com/TheManticoreProject/Manticore/network/smb/smb_v10/message/commands"
	smb1codes "github.com/TheManticoreProject/Manticore/network/smb/smb_v10/message/commands/codes"
	smb1 "github.com/TheManticoreProject/Manticore/network/smb/smb_v10/server"
	smb2message "github.com/TheManticoreProject/Manticore/network/smb/smb_v20/message"
	smb2commands "github.com/TheManticoreProject/Manticore/network/smb/smb_v20/message/commands"
	smb2codes "github.com/TheManticoreProject/Manticore/network/smb/smb_v20/message/commands/codes"
	smb2 "github.com/TheManticoreProject/Manticore/network/smb/smb_v20/server"
	"github.com/TheManticoreProject/Manticore/windows/fileflags"
)

// writeBits are the desired-access rights that let a handle change the file, so
// an open requesting any of them is logged as a write.
const writeBits = fileflags.FILE_WRITE_DATA | fileflags.FILE_APPEND_DATA |
	fileflags.GENERIC_WRITE | fileflags.GENERIC_ALL | fileflags.DELETE

func mode(desiredAccess uint32) string {
	if desiredAccess&writeBits != 0 {
		return "write"
	}
	return "read"
}

// logSMB2FileAccess logs each file a client opens over SMB 2/3 — the path and
// whether it is opened for writing — identified by the client's address, which
// the capture line already ties to a user. Directory and root opens are
// skipped, as those are browsing rather than file access.
func logSMB2FileAccess() smb2.Handler {
	return smb2.HandlerFunc(func(_ *smb2.Server, _ *smb2.Connection, w smb2.ResponseWriter, req *smb2message.Message) bool {
		if req.Header.Command == smb2codes.SMB2_CREATE {
			if create, ok := req.Command.(*smb2commands.CreateRequest); ok && create.Name != "" {
				logger.Infof("Access: %s opened %q for %s", w.RemoteAddr(), create.Name, mode(uint32(create.DesiredAccess)))
			}
		}
		return false
	})
}

// logSMB1FileAccess logs each file a client opens over SMB1. The session's user
// is known here (unlike SMB2), so it is named when present.
func logSMB1FileAccess() smb1.Handler {
	return smb1.HandlerFunc(func(_ *smb1.Server, conn *smb1.Connection, _ smb1.ResponseWriter, req *smb1message.Message) bool {
		// Opens on IPC$ are pipe binds (srvsvc/wkssvc for browsing), not file
		// access, so they are left out of the file log.
		if tree := conn.Tree(uint16(req.Header.TID)); tree != nil && tree.Share != nil && tree.Share.Type == smb1.ShareTypeNamedPipe {
			return false
		}
		unicode := req.Header.Flags2.IsUnicode()
		who := conn.Remote.String()
		if session := conn.Session(uint16(req.Header.UID)); session != nil && session.Username != "" {
			who = session.Username + "@" + who
		}
		switch req.Header.Command {
		case smb1codes.SMB_COM_NT_CREATE_ANDX:
			if create, ok := req.Command.(*smb1commands.NtCreateAndxRequest); ok {
				if name := create.FileName.StringWithEncoding(unicode); name != "" {
					logger.Infof("Access: %s opened %q for %s", who, name, mode(uint32(create.DesiredAccess)))
				}
			}
		case smb1codes.SMB_COM_OPEN_ANDX:
			if open, ok := req.Command.(*smb1commands.OpenAndxRequest); ok {
				if name := open.FileName.StringWithEncoding(unicode); name != "" {
					logger.Infof("Access: %s opened %q for %s", who, name, openAndxMode(uint16(open.AccessMode)))
				}
			}
		}
		return false
	})
}

// openAndxMode reads the access mode of a legacy OPEN_ANDX, whose low three bits
// are 0 read, 1 write, 2 read-write ([MS-CIFS] 2.2.4.41.1).
func openAndxMode(accessMode uint16) string {
	switch accessMode & 0x7 {
	case 1, 2:
		return "write"
	default:
		return "read"
	}
}
