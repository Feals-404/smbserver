## Features

- [x] SMB1 (`NT LM 0.12`) and SMB 2.0.2 to 3.1.1 on the same port, routed on the client's first NEGOTIATE.
- [x] Direct TCP (445) or NetBIOS over TCP (139) transport.
- [x] NetNTLMv1 and NetNTLMv2 capture in hashcat format (`-m 5500` / `-m 5600`), deduplicated per user.
- [x] Guest mode (every logon admitted and captured) or a real account, by password or NT hash.
- [x] Read-only shares, required signing, required encryption (SMB 3.x).
- [x] `--no-smb1` / `--no-smb2` to restrict the protocols served.

## Usage

```
$ ./smbserver -h
Usage: smbserver <shareName> <sharePath> [--debug] [--domain <string>] [--user <string>] [--password <string>] [--hashes <string>] [--interface-address <string>] [--port <tcp port>] [--nbt] [--server-name <string>] [--output-file <string>] [--no-smb1] [--no-smb2] [--read-only] [--require-signing] [--require-encryption]

  --debug         Debug mode. (default: false)

  Authentication:
    -d, --domain <string>   Domain of the served account. (default: "WORKGROUP")
    -u, --user <string>     Served account. Supports DOMAIN\user. Without it every logon is a guest. (default: "")
    -p, --password <string> Password of the served account. (default: "")
    --hashes <string>       NT/LM hashes of the served account, format is [LMhash:]NThash. (default: "")

  Network:
    -ip, --interface-address <string> Address to listen on. (default: "0.0.0.0")
    -P, --port <tcp port>             TCP port to listen on. (default: 445)
    --nbt                             Use NetBIOS (NBT) transport instead of direct TCP. (default: false)
    --server-name <string>            NetBIOS name advertised to clients. (default: "FILESRV")

  Output:
    -o, --output-file <string> Append captured hashes to this file, in hashcat format. (default: "")

  Protocols:
    --no-smb1       Do not serve SMB1 clients. (default: false)
    --no-smb2       Do not serve SMB 2/3 clients. (default: false)

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

 + SMB 3.x only, encrypted:
    ```
    smbserver FILES /srv/share --require-encryption
    ```

A known account (`-u`) is still served while every other logon is captured and refused.

## Contributing

Pull requests are welcome. Feel free to open an issue if you want to add other features.
