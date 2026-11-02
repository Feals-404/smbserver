# manticore-smbserver

A standalone SMB 2/3 server, in the spirit of impacket's `smbserver.py`, built on
the [Manticore](https://github.com/TheManticoreProject/Manticore) SMB 2/3 server
library (`network/smb/smb_v20/server`). It serves a local directory over SMB 2.0.2
to 3.1.1 and harvests the NetNTLM response of every logon in hashcat form.

## Install

```bash
go install github.com/TheManticoreProject/manticore-smbserver@latest
```

## Usage

```bash
# Capture mode: without -u every logon is admitted as a guest and its hash is
# recorded. Port 445 needs root (or setcap cap_net_bind_service=+ep).
sudo manticore-smbserver FILES /srv/share -o hashes.txt

# Serve a real account, by password or NT hash, on a non-privileged port
manticore-smbserver FILES /srv/share --port 4455 -d LAB -u alice -p 'Passw0rd!'
manticore-smbserver FILES /srv/share --port 4455 -d LAB -u alice -H <NThash>

# Require signing or encryption
manticore-smbserver FILES /srv/share --require-signing
manticore-smbserver FILES /srv/share --require-encryption
```

| Group | Options |
| --- | --- |
| Positional | `shareName`, `sharePath` |
| Network | `-ip/--interface-address`, `--port` (445), `--server-name` |
| Authentication | `-d/--domain`, `-u/--username`, `-p/--password`, `-H/--hashes` |
| Security | `--read-only`, `--require-signing`, `--require-encryption` |
| Output | `-o/--output-file`, `--debug` |

Captured responses are written to `--output-file` in hashcat form, ready for
`hashcat -m 5600` (NetNTLMv2) or `-m 5500` (NetNTLMv1). A known account (`-u`) is
still served while every other logon is captured and refused.

## Building against a local Manticore checkout

Until the SMB 2/3 server lands in a tagged Manticore release, `go.mod` carries a
`replace` directive pointing at a sibling `../Manticore` checkout. Drop it and pin
a published version once the server is merged.
