---
name: rpcclient-alt-linux-cli
description: Token-optimized reference for rpcclient (Samba 4.21) Linux CLI — all connection options, binding strings, interactive commands across 15+ RPC interfaces (LSARPC, SAMR, SRVSVC, SPOOLSS, NETLOGON, DFS, FSRVP, CLUSAPI, DRSUAPI, EVENTLOG, WINREG, WITNESS, WKSSVC, NTSVCS, MDSSVC, ECHO, EPMAPPER), authentication methods (anonymous, NTLM, NT hash, Kerberos, schannel), and computername enumeration via wkssvc_enumeratecomputernames with all info levels and name types. Use this skill whenever the user needs to construct, debug, or automate rpcclient commands, enumerate Windows domain users/groups/shares/ privileges/trusts/computernames via MS-RPC, perform SMB-based Active Directory reconnaissance, query LSA/SAM policies, manage printers remotely, or asks about rpcclient syntax, options, or usage — even if they don't explicitly mention "rpcclient" but describe MS-RPC enumeration, Windows remote management, Samba RPC client operations, domain user/group enumeration, or AD recon on Linux.
---

# rpcclient — Linux CLI Reference (Samba 4.21.9-alt1)

## Quick Start

```bash
# Anonymous enumeration
rpcclient -U "" -N <IP>

# Connect with credentials
rpcclient -U "DOMAIN/user%pass" <IP>

# One-shot batch commands
rpcclient -U "user%pass" -c "enumdomusers;enumdomgroups;lsaquery" <IP>

# Enumerate all computer names
rpcclient -U "" -N -c "wkssvc_enumeratecomputernames 1" <IP>
```

## SYNOPSIS

```
rpcclient [OPTIONS] {BINDING-STRING|HOST}
```

`BINDING-STRING` = `TRANSPORT:host[options]` (ncacn_np, ncacn_ip_tcp, ncalrpc)
`HOST` = IP, hostname, or NetBIOS name

For detailed option descriptions, all RPC commands, binding string reference,
and computername deep reference, read `references/rpcclient.md`.
