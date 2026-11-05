# smbserver

A standalone SMB server for offensive work, built on the
[Manticore](https://github.com/TheManticoreProject/Manticore) protocol library.
It serves one local directory over SMB1 and SMB 2.0.2–3.1.1 **on the same port**,
routing each connection on its first NEGOTIATE, and harvests the NetNTLM
response of every logon on both protocols.

## Features

- [x] SMB1 (`NT LM 0.12`) and SMB 2.0.2 to 3.1.1 on the same port, routed on the client's first NEGOTIATE.
- [x] Direct TCP (445) or NetBIOS over TCP (139) transport; over NetBIOS it answers to any CALLED name, so a coerced `\\anything\share` still lands.
- [x] NetNTLMv1 and NetNTLMv2 capture in hashcat format (`-m 5500` / `-m 5600`), deduplicated per user.
- [x] Guest mode (every logon admitted and captured) or a real account, by password or NT hash.
- [x] `--challenge` to fix the server challenge (precomputed cracking), `--disable-ess` to force plain NetNTLMv1 for crack.sh.
- [x] `--browse` to serve IPC$ so a client can list the share (`net view`, `smbclient -L`, Explorer).
- [x] `--log-access` to record every file a client opens (who, path, read or write).
- [x] `--os-version` to advertise a Windows version in the challenge, to look like a real host.
- [x] Read-only shares, required signing, required encryption (SMB 3.x).
- [x] `--no-smb1` / `--no-smb2` to restrict the protocols served.

## Install

```
go install github.com/TheManticoreProject/smbserver@latest
```

Or grab a prebuilt binary from the [releases](https://github.com/TheManticoreProject/smbserver/releases).

## Usage

```
$ smbserver -h
Usage: smbserver <shareName> <sharePath> [--debug] [--domain <string>] [--user <string>] [--password <string>] [--hashes <string>] [--challenge <string>] [--os-version <string>] [--disable-ess] [--interface-address <string>] [--port <tcp port>] [--nbt] [--server-name <string>] [--output-file <string>] [--log-access] [--no-smb1] [--no-smb2] [--browse] [--read-only] [--require-signing] [--require-encryption]

  --debug         Debug mode. (default: false)

  Authentication:
    -d, --domain <string>   Domain of the served account. (default: "WORKGROUP")
    -u, --user <string>     Served account. Supports DOMAIN\user. Without it every logon is a guest. (default: "")
    -p, --password <string> Password of the served account. (default: "")
    --hashes <string>       NT/LM hashes of the served account, format is [LMhash:]NThash. (default: "")

  Capture:
    --challenge <string>  Fix the 8-byte NTLM server challenge (16 hex), to crack responses against a precomputed table. (default: "")
    --os-version <string> Advertise this Windows version (major.minor.build) in the NTLM challenge, to look like a real host. (default: "")
    --disable-ess         Strip extended session security, so an NTLMv1 client yields a crack.sh-crackable response (use with --challenge). (default: false)

  Network:
    -ip, --interface-address <string> Address to listen on. (default: "0.0.0.0")
    -P, --port <tcp port>             TCP port to listen on (default 445, or 139 with --nbt).
    --nbt                             Use NetBIOS (NBT) transport instead of direct TCP. (default: false)
    --server-name <string>            NetBIOS name advertised to clients. (default: "FILESRV")

  Output:
    -o, --output-file <string> Append captured hashes to this file, in hashcat format. (default: "")
    --log-access               Log every file a client opens (who, path, read or write). (default: false)

  Protocols:
    --no-smb1       Do not serve SMB1 clients. (default: false)
    --no-smb2       Do not serve SMB 2/3 clients. (default: false)
    --browse        Serve IPC$ so clients can list the share (net view, smbclient -L; SMB1 only). (default: false)

  Security:
    --read-only          Refuse every modification. (default: false)
    --require-signing    Refuse unsigned sessions. (default: false)
    --require-encryption Encrypt every session (SMB 3.x only, implies --no-smb1). (default: false)
```

## Quick start commands

 + Capture every logon as a guest (port 445 needs root, or `setcap cap_net_bind_service=+ep`):
    ```
    sudo smbserver FILES /srv/share -o hashes.txt
    ```

 + Serve a real account on a non-privileged port:
    ```
    smbserver FILES /srv/share -P 4455 -d LAB -u alice -p 'Passw0rd!'
    smbserver FILES /srv/share -P 4455 -u 'LAB\alice' --hashes <NThash>
    ```

 + Browsable share, logging each file opened, looking like a Windows 10 host:
    ```
    sudo smbserver FILES /srv/share -o hashes.txt --browse --log-access --os-version 10.0.19041
    ```

 + Fixed challenge, forcing plain NetNTLMv1 for crack.sh (legacy / appliance clients only):
    ```
    sudo smbserver FILES /srv/share -o hashes.txt --challenge 1122334455667788 --disable-ess
    ```

A known account (`-u`) is still served while every other logon is captured and refused.

## Notes

- **Guest sessions.** Windows 10 1709 and later refuse guest SMB sessions, and Windows 11 24H2 requires signing by default. In guest mode the logon is still captured, but such a client cannot then read files; serve a real account with `-u` if a client must actually mount the share.
- **Cracking without `--challenge`.** The random per-logon challenge is embedded in the captured hashcat line, so every capture is crackable by dictionary or brute force as is. `--challenge` only enables *precomputed* attacks — chiefly crack.sh for NetNTLMv1, which recovers the NT hash directly.
- **`--disable-ess` is situational.** Whether a client sends NTLMv1 is decided by its `LmCompatibilityLevel`. A modern client (level 3, NTLMv2-only) ignores the stripped ESS and still answers NTLMv2; the downgrade only yields a crack.sh-crackable response from a client that still speaks NTLMv1 (legacy Windows, appliances, embedded SMB stacks).
- **Browsing is SMB1-only**, since the SMB2 server has no named-pipe stack to answer srvsvc/wkssvc over IPC$.

## Roadmap

Planned features and the capabilities that depend on upstream Manticore changes
are tracked in [ROADMAP.md](ROADMAP.md).

## Contributing

Pull requests are welcome. Feel free to open an issue if you want to add other features.
