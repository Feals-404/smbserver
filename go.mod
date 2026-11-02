module github.com/TheManticoreProject/manticore-smbserver

go 1.24.0

require (
	github.com/TheManticoreProject/Manticore v1.1.7
	github.com/TheManticoreProject/goopts v1.2.4
)

require (
	github.com/TheManticoreProject/winacl v1.3.1 // indirect
	golang.org/x/sys v0.37.0 // indirect
	golang.org/x/term v0.36.0 // indirect
)

// Until the SMB 2/3 server lands in a tagged Manticore release, build against a
// local checkout. Drop this and pin a published version once it is merged.
replace github.com/TheManticoreProject/Manticore => ../Manticore
