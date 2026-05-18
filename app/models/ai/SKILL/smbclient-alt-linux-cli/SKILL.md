---
name: smbclient-alt-linux-cli
description: Token-optimized reference for smbclient (Samba 4.21) Linux CLI — all connection options, interactive commands, tar operations, authentication methods, NetBIOS/name resolution, and computername/netbiosname settings. Use this skill whenever the user needs to construct, debug, or automate smbclient commands, browse SMB shares, transfer files via SMB/CIFS, perform tar backups/restores over SMB, or asks about smbclient syntax, options, or usage — even if they don't explicitly mention "smbclient" but describe SMB/CIFS file access, Windows share mounting, or Samba client operations on Linux.
---

# smbclient — Linux CLI Reference (Samba 4.21.9-alt1)

## Quick Start

```bash
# List shares on a host
smbclient -L //SERVER -U user%pass

# Connect to a share interactively
smbclient //SERVER/share -U user%pass

# One-shot command
smbclient //SERVER/share -U user%pass -c "ls; get file.txt"

# Download file non-interactive
smbclient //SERVER/share -U user%pass -c "get remotefile localfile"
```

## SYNOPSIS

```
smbclient [OPTIONS] servicename [password]
```

`servicename` = `//server/service` (server = NetBIOS name, NOT necessarily DNS hostname)

For detailed option descriptions and interactive commands, read `references/smbclient.md`.
