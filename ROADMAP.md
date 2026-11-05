# Roadmap

Planned work for smbserver, and the capabilities that depend on changes in the
upstream [Manticore](https://github.com/TheManticoreProject/Manticore) library.

## Planned (in this repo)

- [ ] **JSON capture output** — a structured capture log (user, domain, workstation, source address, timestamp, hashcat line, NetNTLM version) alongside the hashcat file, including the victim OS version read from the NTLM AUTHENTICATE `Version` field.
- [ ] **Kerberos serving** — accept Kerberos logons with a keytab or AES key (`smb2.Config.Kerberos`); SMB 2/3 only.

## Depends on Manticore

These need the library to expose or change something. They are tracked here so
the server side is ready when the upstream support lands.

- [ ] **Capture a delegated TGT** — with unconstrained delegation and coercion, recover the forwarded TGT (à la krbrelayx). Needs the Kerberos `SecContext` (and its `Authenticator`, for `gssapi.ExtractDelegatedCred`) exposed to a server handler.
- [ ] **Browse shares over SMB2/3** — `smbclient -L`, `net view` and Explorer list nothing over SMB2, as the SMB2 server has no named-pipe (srvsvc/wkssvc) stack. Browsing is SMB1-only today.
- [ ] **SMB2 byte-range locks and security descriptors** — currently answered `STATUS_NOT_SUPPORTED`; Office and the Explorer Security tab need them.
- [ ] **Serve an unauthenticated client as a full (non-guest) session** — Windows 10 1709+ refuses guest SMB sessions, so without `-u` a modern client is captured but cannot read files. The guest flag is set inside Manticore's session establishment.
- [ ] **Drop the local SMB1 capture pass-through** — `passThroughCapture` duplicates what the SMB2 capture handler does; a `PassThrough` option on `smb1.CaptureConfig` would remove it.
- [ ] **Hand SMB1-only clients from the SMB2 server to an `smb1.Server`** — it already upgrades an SMB1 NEGOTIATE; a handoff would remove this repo's `route.go`, `replayTransport` and accept loop.
- [ ] **Validate signing/encryption in `smb2.NewServer`** — refuse required signing or encryption with no account, as the SMB1 server already does (smbserver guards this itself for now).
- [ ] **First-class ESS-less challenge** — `--disable-ess` strips extended session security by post-processing a Manticore-built CHALLENGE through the `ChallengeProvider` seam; an option on the acceptor would be cleaner.
- [ ] **Fix `ChallengeMessage` round-trip** — `Marshal` emits a 56-byte message (no target name or info) that `Unmarshal` rejects as `< 60`; `downgrade.go` pads around it.

## Known limitations

- **Guest on modern Windows** — Windows 10 1709+ refuses guest sessions and Windows 11 24H2 requires signing by default. Serve a real account with `-u` for a modern client to mount a share.
- **Cross-protocol open state** — file contents are consistent across SMB1 and SMB 2/3 (one backend per share), but share modes and oplocks are tracked per protocol, so an exclusive open over one does not block the other.
