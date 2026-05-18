# AI Skill: rpcclient-alt-linux-cli

> **ID**: `rpcclient-alt-linux-cli`
> **Version**: 4.21.9-alt1
> **Platform**: Linux (ALT/Samba)
> **Type**: CLI enumeration / MS-RPC client
> **Token-optimized**: yes (compact notation, no prose)

---

## Purpose

Execute client-side MS-RPC functions against Windows/Samba hosts for enumeration, querying, and management of users, groups, shares, registry, printers, trusts, and more.

---

## Quick Connect Patterns

```bash
# Anonymous
rpcclient -U "" -N <IP>

# User+pass
rpcclient -U "DOMAIN/user%pass" <IP>

# NT hash auth
rpcclient -U "user" --pw-nt-hash -N <IP>   # pass=NTLMhash

# Auth file
rpcclient -A auth.txt <IP>

# Kerberos
rpcclient --use-kerberos=required <FQDN>

# Machine account
rpcclient -P <IP>

# Binding string
rpcclient "ncacn_np:HOST[samr,sign]"
rpcclient "ncacn_ip_tcp:HOST[1024,seal,krb5]"
rpcclient "ncalrpc:/path/to/socket"

# One-liner (batch commands)
rpcclient -U "user%pass" -c "enumdomusers;enumdomgroups" <IP>

# Specific port
rpcclient -p 139 -U "user%pass" <IP>

# Target IP override
rpcclient -I 10.0.0.1 -U "user%pass" HOSTNAME
```

---

## CLI Options (Full Reference)

| Opt | Long | Arg | Desc |
|-----|------|-----|------|
| `-c` | `--command` | CMDS | Semicolon-separated commands to execute |
| `-I` | `--dest-ip` | IP | Force server IP (skip NetBIOS resolution) |
| `-p` | `--port` | PORT | TCP port (default 139) |
| `-d` | `--debuglevel` | 0-10 | Log verbosity (default 1) |
| | `--debug-stdout` | | Redirect debug to STDOUT |
| | `--configfile` | FILE | smb.conf path |
| | `--option` | name=value | Override smb.conf option |
| `-l` | `--log-basename` | DIR | Log file base directory |
| | `--leak-report` | | Talloc leak report on exit |
| | `--leak-report-full` | | Full talloc leak report |
| `-R` | `--name-resolve` | ORDER | Name resolution order: lmhosts,host,wins,bcast |
| `-O` | `--socket-options` | OPTS | TCP socket options |
| `-m` | `--max-protocol` | PROTO | Highest SMB protocol level |
| `-n` | `--netbiosname` | NAME | Override local NetBIOS name |
| | `--netbios-scope` | SCOPE | NetBIOS scope (RFC1001/1002) |
| `-W` | `--workgroup` | WG | SMB domain/workgroup |
| `-r` | `--realm` | REALM | Kerberos realm |
| `-U` | `--user` | [DOM\]USER[%PASS] | SMB credentials |
| `-N` | `--no-pass` | | Suppress password prompt |
| | `--password` | STRING | Password on CLI |
| | `--pw-nt-hash` | | Treat password as NT hash |
| `-A` | `--authentication-file` | FILE | Auth file (username/password/domain) |
| `-P` | `--machine-pass` | | Use stored machine account password |
| | `--simple-bind-dn` | DN | DN for simple LDAP bind |
| | `--use-kerberos` | desired/required/off | Kerberos auth mode |
| | `--use-krb5-ccache` | CCACHE | Kerberos credential cache path (implies --use-kerberos=required) |
| | `--use-winbind-ccache` | | Use winbind credential cache |
| | `--client-protection` | sign/encrypt/off | Connection protection level |
| `-V` | `--version` | | Print version |
| `-?` | `--help` | | Help summary |
| | `--usage` | | Brief usage |

---

## Binding String Format

```
TRANSPORT:host[options]
```

### Transports
| Transport | Desc |
|-----------|------|
| `ncacn_np` | Named pipes (SMB) |
| `ncacn_ip_tcp` | DCERPC over TCP/IP |
| `ncalrpc` | Local RPC (unix socket) |

### Binding Options
| Option | Desc |
|--------|------|
| `sign` | RPC integrity auth |
| `seal` | RPC privacy (encryption) |
| `connect` | RPC connect-level auth (no sign/seal) |
| `packet` | RPC packet auth level |
| `spnego` | Use SPNEGO (vs NTLMSSP) |
| `ntlm` | Use plain NTLM |
| `krb5` | Use Kerberos |
| `schannel` | Schannel sealed connection |
| `smb1` | Force SMB1 for named pipes |
| `smb2` | Force SMB2/3 for named pipes |
| `validate` | Enable NDR validator |
| `print` | Debug packet output |
| `padcheck` | Check non-zero pad bytes |
| `bigendian` | Big-endian RPC |
| `ndr64` | NDR64 transfer syntax |

### Binding Examples
```
ncacn_ip_tcp:samba.example.com[1024]
ncacn_ip_tcp:samba.example.com[sign,seal,krb5]
ncacn_ip_tcp:samba.example.com[sign,spnego]
ncacn_np:samba.example.com
ncacn_np:samba.example.com[samr]
ncacn_np:samba.example.com[samr,sign,print]
ncalrpc:/path/to/unix/socket
//SAMBA
```

---

## Interactively Available Commands (In-Session)

### GENERAL

| Cmd | Desc |
|-----|------|
| `help` | List commands / help on command |
| `?` | Alias for help |
| `debuglevel` | Set/get debug level |
| `debug` | Alias for debuglevel |
| `list` | List available commands on pipe |
| `exit` | Exit program |
| `quit` | Alias for exit |
| `sign` | Force RPC pipe signing |
| `seal` | Force RPC pipe sealing (encryption) |
| `packet` | Force RPC pipe packet auth level |
| `schannel` | Force RPC pipe sealing via schannel (requires valid machine account) |
| `schannelsign` | Force RPC pipe signing via schannel (not sealed) |
| `timeout` | Set timeout (ms) for RPC operations |
| `transport` | Choose ncacn transport |
| `none` | Remove special pipe properties |

---

## Command Reference by RPC Interface

### LSARPC (Local Security Authority)

| Cmd | Syntax | Desc |
|-----|--------|------|
| `lsaquery` | | Query info policy (domain SID, name) |
| `lookupsids` | `lookupsids <SID1> [SID2]...` | SIDs to names |
| `lookupsids3` | `lookupsids3 <SID>...` | SIDs to names (level 3) |
| `lookupsids_level` | `lookupsids_level <level> <SID>...` | SIDs to names (custom level) |
| `lookupnames` | `lookupnames <NAME>...` | Names to SIDs |
| `lookupnames4` | `lookupnames4 <NAME>...` | Names to SIDs (level 4) |
| `lookupnames_level` | `lookupnames_level <level> <NAME>...` | Names to SIDs (custom level) |
| `enumtrust` | | Enumerate trusted domains |
| `enumprivs` | | Enumerate all privileges |
| `getdispname` | `getdispname <privname>` | Get privilege display name |
| `lsaenumsid` | | Enumerate LSA SIDs |
| `lsacreateaccount` | `lsacreateaccount <SID>` | Create LSA account |
| `lsaenumprivsaccount` | `lsaenumprivsaccount <SID>` | Enumerate privileges of SID |
| `lsaenumacctrights` | `lsaenumacctrights <SID>` | Enumerate rights of SID |
| `lsaaddpriv` | `lsaaddpriv <SID> <privname>` | Assign privilege to SID |
| `lsadelpriv` | `lsadelpriv <SID> <privname>` | Revoke privilege from SID |
| `lsaaddacctrights` | `lsaaddacctrights <SID> <right>` | Add rights to account |
| `lsaremoveacctrights` | `lsaremoveacctrights <SID> <right>` | Remove rights from account |
| `lsalookupprivvalue` | `lsalookupprivvalue <name>` | Get privilege value by name |
| `lsaquerysecobj` | | Query LSA security object |
| `lsaquerytrustdominfo` | `lsaquerytrustdominfo <SID>` | Query trusted domain info by SID |
| `lsaquerytrustdominfobyname` | `lsaquerytrustdominfobyname <name>` | Query trusted domain info by name (Win2k+) |
| `lsaquerytrustdominfobysid` | `lsaquerytrustdominfobysid <SID>` | Query trusted domain info by SID |
| `lsasettrustdominfo` | | Set trusted domain info |
| `getusername` | | Get current username |
| `createsecret` | `createsecret <name>` | Create LSA secret |
| `deletesecret` | `deletesecret <name>` | Delete LSA secret |
| `querysecret` | `querysecret <name>` | Query LSA secret |
| `setsecret` | `setsecret <name> <val>` | Set LSA secret value |
| `retrieveprivatedata` | `retrieveprivatedata <key>` | Retrieve private data |
| `storeprivatedata` | `storeprivatedata <key> <val>` | Store private data |
| `createtrustdom` | `createtrustdom <sid> <name>` | Create trusted domain |
| `deletetrustdom` | `deletetrustdom <sid>` | Delete trusted domain |

### LSARPC-DS

| Cmd | Syntax | Desc |
|-----|--------|------|
| `dsroledominfo` | | Get primary domain information (role, forest, domain GUIDs) |

### DFS (Distributed File System)

| Cmd | Syntax | Desc |
|-----|--------|------|
| `dfsversion` | | Query DFS support version |
| `dfsadd` | `dfsadd <path> <server> <share> <comment>` | Add DFS share |
| `dfsremove` | `dfsremove <path> <server> <share>` | Remove DFS share |
| `dfsgetinfo` | `dfsgetinfo <path>` | Query DFS share info |
| `dfsenum` | | Enumerate DFS shares |
| `dfsenumex` | | Enumerate DFS shares (extended) |

### SHUTDOWN

| Cmd | Syntax | Desc |
|-----|--------|------|
| `shutdowninit` | `shutdowninit [-m message]` | Initiate remote shutdown |
| `shutdownabort` | | Abort remote shutdown |

### SRVSVC (Server Service)

| Cmd | Syntax | Desc |
|-----|--------|------|
| `srvinfo` | | Server query info (OS, version, server type) |
| `netshareenum` | | Enumerate shares |
| `netshareenumall` | | Enumerate all shares (including hidden) |
| `netsharegetinfo` | `netsharegetinfo <share> [level]` | Get share info |
| `netsharesetinfo` | `netsharesetinfo <share>` | Set share info |
| `netsharesetdfsflags` | | Set DFS flags |
| `netfileenum` | | Enumerate open files |
| `netremotetod` | | Fetch remote time of day |
| `netnamevalidate` | `netnamevalidate <name>` | Validate share name |
| `netfilegetsec` | | Get file security |
| `netsessdel` | `netsessdel <client>` | Delete session |
| `netsessenum` | | Enumerate sessions |
| `netdiskenum` | | Enumerate disks |
| `netconnenum` | | Enumerate connections |
| `netshareadd` | `netshareadd <share>` | Add share |
| `netsharedel` | `netsharedel <share>` | Delete share |

### SAMR (Security Account Manager)

| Cmd | Syntax | Desc |
|-----|--------|------|
| `queryuser` | `queryuser <RID>` | Query user info by RID |
| `querygroup` | `querygroup <RID>` | Query group info by RID |
| `queryusergroups` | `queryusergroups <RID>` | Query user's groups |
| `queryuseraliases` | `queryuseraliases <SID> <RID>` | Query user's aliases |
| `querygroupmem` | `querygroupmem <RID>` | Query group membership |
| `queryaliasmem` | `queryaliasmem <RID>` | Query alias membership |
| `queryaliasinfo` | `queryaliasinfo <RID>` | Query alias info |
| `deletealias` | `deletealias <RID>` | Delete alias |
| `querydispinfo` | `querydispinfo [level] [start] [size]` | Query display info (level 1-4) |
| `querydispinfo2` | `querydispinfo2 [level] [start] [size]` | Query display info v2 |
| `querydispinfo3` | `querydispinfo3 [level] [start] [size]` | Query display info v3 |
| `querydominfo` | `querydominfo [level]` | Query domain info |
| `enumdomusers` | `enumdomusers [start] [size] [acct_flags]` | Enumerate domain users |
| `enumdomgroups` | `enumdomgroups [start] [size]` | Enumerate domain groups |
| `enumalsgroups` | `enumalsgroups <SID> [start] [size]` | Enumerate alias groups in domain |
| `enumdomains` | | Enumerate domains |
| `createdomuser` | `createdomuser <name>` | Create domain user |
| `createdomgroup` | `createdomgroup <name>` | Create domain group |
| `createdomalias` | `createdomalias <name>` | Create domain alias |
| `samlookupnames` | `samlookupnames <domain> <name>...` | Look up names (to RIDs) |
| `samlookuprids` | `samlookuprids <domain> <RID>...` | Look up RIDs (to names) |
| `deletedomgroup` | `deletedomgroup <RID>` | Delete domain group |
| `deletedomuser` | `deletedomuser <RID>` | Delete domain user |
| `samquerysecobj` | | Query SAMR security object |
| `getdompwinfo` | | Retrieve domain password policy |
| `getusrdompwinfo` | `getusrdompwinfo <RID>` | Retrieve user domain password info |
| `lookupdomain` | `lookupdomain <name>` | Lookup domain name (get SID) |
| `chgpasswd` | `chgpasswd <user> <oldpass> <newpass>` | Change user password |
| `chgpasswd2` | `chgpasswd2 <user> <oldpass> <newpass>` | Change user password v2 |
| `chgpasswd3` | `chgpasswd3 <user> <oldpass> <newpass>` | Change password (RC4 encrypted) |
| `chgpasswd4` | `chgpasswd4 <user> <oldpass> <newpass>` | Change password (AES encrypted) |
| `getdispinfoidx` | `getdispinfoidx <level>` | Get display information index |
| `setuserinfo` | `setuserinfo <RID> <level> <data>` | Set user info |
| `setuserinfo2` | `setuserinfo2 <RID> <level> <data>` | Set user info v2 |

### SPOOLSS (Print Spooler)

| Cmd | Syntax | Desc |
|-----|--------|------|
| `adddriver` | `adddriver <arch> <config> [<ver>]` | Install printer driver |
| `addprinter` | `addprinter <printer> <share> <driver> <port>` | Add printer |
| `deldriver` | `deldriver <driver>` | Delete printer driver (all arch) |
| `deldriverex` | `deldriverex <driver> [arch] [ver] [flags]` | Delete driver + optionally files |
| `enumdata` | | Enumerate printer setting data |
| `enumdataex` | `enumdataex <key>` | Enumerate printer data for key |
| `enumkey` | `enumkey <key>` | Enumerate printer keys |
| `enumjobs` | `enumjobs <printer>` | List jobs and status |
| `getjob` | `getjob <printer> <job>` | Get print job |
| `setjob` | `setjob <printer> <job>` | Set print job |
| `enumports` | `enumports [level]` | Enumerate ports (level 1,2) |
| `enumdrivers` | `enumdrivers [level]` | Enumerate printer drivers (level 1,2,3) |
| `enumprinters` | `enumprinters [level]` | Enumerate printers (level 1,2,5) |
| `getdata` | `getdata <printer> <value>` | Get printer setting data |
| `getdataex` | `getdataex <key>` | Get printer driver data with key |
| `getdriver` | `getdriver <printer>` | Get printer driver info |
| `getdriverdir` | `getdriverdir <arch>` | Get driver directory for arch |
| `getdriverpackagepath` | | Get print driver package path |
| `getprinter` | `getprinter <printer>` | Get printer info |
| `openprinter` | `openprinter <printer>` | Open/close printer handle test |
| `openprinter_ex` | `openprinter_ex <printer>` | Open printer handle |
| `setdriver` | `setdriver <printer> <driver>` | Set printer driver |
| `getprintprocdir` | | Get print processor directory |
| `addform` | `addform <printer>` | Add form |
| `setform` | `setform <printer>` | Set form |
| `getform` | `getform <printer> <form>` | Get form |
| `deleteform` | `deleteform <printer> <form>` | Delete form |
| `enumforms` | `enumforms <printer>` | Enumerate forms |
| `setprinter` | `setprinter <printer>` | Set printer comment |
| `setprinterdata` | `setprinterdata <printer> <val>` | Set REG_SZ printer data |
| `setprintername` | `setprintername <old> <new>` | Rename printer |
| `rffpcnex` | | Rffpcnex test |
| `printercmp` | | Printer comparison test |
| `enumprocs` | | Enumerate print processors |
| `enumprocdatatypes` | | Enumerate print processor data types |
| `enummonitors` | | Enumerate print monitors |
| `createprinteric` | | Create printer IC |
| `playgdiscriptonprinteric` | | Play GDI script on printer IC |
| `getcoreprinterdrivers` | | Get CorePrinterDriver |
| `enumpermachineconnections` | | Enumerate per-machine connections |
| `addpermachineconnection` | | Add per-machine connection |
| `delpermachineconnection` | | Delete per-machine connection |

#### adddriver arch values
`Windows 4.0` | `Windows NT x86` | `Windows NT PowerPC` | `Windows NT Alpha_AXP` | `Windows NT R4000`

#### adddriver config format
```
Long Driver Name:\
Driver File Name:\
Data File Name:\
Config File Name:\
Help File Name:\
Language Monitor Name:\
Default Data Type:\
Comma Separated list of Files
```
(Use `"NULL"` for empty fields)

#### deldriverex flags
| Value | Meaning |
|-------|---------|
| 1 | DPD_DELETE_UNUSED_FILES |
| 2 | DPD_DELETE_SPECIFIC_VERSION |
| 3 | DPD_DELETE_UNUSED_FILES \| DPD_DELETE_SPECIFIC_VERSION |

### NETLOGON

| Cmd | Syntax | Desc |
|-----|--------|------|
| `logonctrl2` | | Logon Control 2 |
| `getanydcname` | | Get trusted DC name |
| `getdcname` | | Get trusted PDC name |
| `dsr_getdcname` | `dsr_getdcname <domain> <flags>` | Get DC name (DSR) |
| `dsr_getdcnameex` | | Get DC name extended |
| `dsr_getdcnameex2` | | Get DC name extended v2 |
| `dsr_getsitename` | `dsr_getsitename <computer>` | Get AD site name |
| `dsr_getforesttrustinfo` | | Get forest trust info |
| `logonctrl` | | Logon Control |
| `samlogon` | `samlogon <user> <pass> <domain> <workstation>` | SAM Logon test |
| `change_trust_pw` | | Change trust account password |
| `gettrustrid` | | Get trust RID |
| `dsr_enumtrustdom` | | Enumerate trusted domains (DSR) |
| `dsenumdomtrusts` | | Enumerate all trusted domains in AD forest |
| `deregisterdnsrecords` | | Deregister DNS records |
| `netrenumtrusteddomains` | | Enumerate trusted domains (NETR) |
| `netrenumtrusteddomainsex` | | Enumerate trusted domains extended |
| `getdcsitecoverage` | | Get site-coverage from DC |
| `capabilities` | | Return netlogon capabilities |
| `logongetdomaininfo` | | Return LogonGetDomainInfo |

### FSRVP (File Server Remote VSS)

| Cmd | Syntax | Desc |
|-----|--------|------|
| `fss_is_path_sup` | `fss_is_path_sup <share>` | Check shadow-copy support |
| `fss_get_sup_version` | | Get supported FSRVP version |
| `fss_create_expose` | `fss_create_expose <share> <snap>` | Create and expose shadow-copy |
| `fss_delete` | `fss_delete <snap>` | Delete shadow-copy share |
| `fss_has_shadow_copy` | `fss_has_shadow_copy <share>` | Check for shadow-copy |
| `fss_get_mapping` | `fss_get_mapping <snap>` | Get shadow-copy mapping info |
| `fss_recovery_complete` | `fss_recovery_complete <snap>` | Flag read-write snapshot recovery complete |

### CLUSAPI (Cluster API)

| Cmd | Syntax | Desc |
|-----|--------|------|
| `clusapi_open_cluster` | | Open cluster |
| `clusapi_get_cluster_name` | | Get cluster name |
| `clusapi_get_cluster_version` | | Get cluster version |
| `clusapi_get_quorum_resource` | | Get quorum resource |
| `clusapi_create_enum` | | Create enum query |
| `clusapi_create_enumex` | | Create enumex query |
| `clusapi_open_resource` | `clusapi_open_resource <name>` | Open cluster resource |
| `clusapi_online_resource` | `clusapi_online_resource <res>` | Set resource online |
| `clusapi_offline_resource` | `clusapi_offline_resource <res>` | Set resource offline |
| `clusapi_get_resource_state` | `clusapi_get_resource_state <res>` | Get resource state |
| `clusapi_get_cluster_version2` | | Get cluster version v2 |
| `clusapi_pause_node` | `clusapi_pause_node <node>` | Pause cluster node |
| `clusapi_resume_node` | `clusapi_resume_node <node>` | Resume cluster node |

### DRSUAPI (Directory Replication Service)

| Cmd | Syntax | Desc |
|-----|--------|------|
| `dscracknames` | `dscracknames <format> <name>...` | Crack name (format conversion) |
| `dsgetdcinfo` | | Get Domain Controller Info |
| `dsgetncchanges` | | Get NC Changes (replication) |
| `dswriteaccountspn` | | Write Account SPN |

### ECHO (RPC Echo Test)

| Cmd | Syntax | Desc |
|-----|--------|------|
| `echoaddone` | `echoaddone <num>` | Add one to number |
| `echodata` | `echodata <data>` | Echo data back |
| `sinkdata` | | Sink (receive) data |
| `sourcedata` | | Source (send) data |

### EPMAPPER (Endpoint Mapper)

| Cmd | Syntax | Desc |
|-----|--------|------|
| `epmmap` | | Map a binding |
| `epmlookup` | | Lookup bindings |

### EVENTLOG

| Cmd | Syntax | Desc |
|-----|--------|------|
| `eventlog_readlog` | | Read eventlog |
| `eventlog_numrecord` | | Get number of records |
| `eventlog_oldestrecord` | | Get oldest record |
| `eventlog_reportevent` | | Report event |
| `eventlog_reporteventsource` | | Report event and source |
| `eventlog_registerevsource` | | Register event source |
| `eventlog_backuplog` | | Backup eventlog file |
| `eventlog_loginfo` | | Get eventlog information |

### IRemoteWinspool

| Cmd | Syntax | Desc |
|-----|--------|------|
| `winspool_AsyncOpenPrinter` | | Open printer handle (async) |
| `winspool_AsyncCorePrinterDriverInstalled` | | Query core printer driver installed |

### NTSVCS (NT Service Control)

| Cmd | Syntax | Desc |
|-----|--------|------|
| `ntsvcs_getversion` | | Query NTSVCS version |
| `ntsvcs_validatedevinst` | | Query device instance |
| `ntsvcs_hwprofflags` | | Query HW profile flags |
| `ntsvcs_hwprofinfo` | | Query HW profile info |
| `ntsvcs_getdevregprop` | | Query device registry property |
| `ntsvcs_getdevlistsize` | | Query device list size |
| `ntsvcs_getdevlist` | | Query device list |

### MDSSVC (Metadata Service)

| Cmd | Syntax | Desc |
|-----|--------|------|
| `fetch_properties` | | Fetch connection properties |
| `fetch_attributes` | `fetch_attributes <CNID>` | Fetch attributes for CNID |

### WINREG (Windows Registry)

| Cmd | Syntax | Desc |
|-----|--------|------|
| `winreg_enumkey` | `winreg_enumkey <key> <idx>` | Enumerate registry keys |
| `querymultiplevalues` | | Query multiple values |
| `querymultiplevalues2` | | Query multiple values v2 |

### WITNESS

| Cmd | Syntax | Desc |
|-----|--------|------|
| `GetInterfaceList` | | List witness interfaces |
| `Register` | `Register <netname> <ip>` | Register for state change notifications |
| `UnRegister` | | Unregister notifications |
| `AsyncNotify` | | Request async notification |
| `RegisterEx` | `RegisterEx <netname> <share> <ip>...` | Extended registration with share + multiple IPs |

### WKSSVC (Workstation Service) — COMPUTERNAME

| Cmd | Syntax | Desc |
|-----|--------|------|
| `wkssvc_wkstagetinfo` | `wkssvc_wkstagetinfo [level]` | Query workstation information |
| `wkssvc_getjoininformation` | | Query domain join information (joined domain/workgroup) |
| `wkssvc_messagebuffersend` | `wkssvc_messagebuffersend <to> <msg>` | Send workstation message |
| **`wkssvc_enumeratecomputernames`** | **`wkssvc_enumeratecomputernames [level]`** | **Enumerate all computer names for the target host** |
| `wkssvc_enumerateusers` | | Enumerate logged-on users |

---

## COMPUTERNAME — Deep Reference

### `wkssvc_enumeratecomputernames [level]`

Enumerates all registered computer names for the target workstation/server. This is the **primary command** for retrieving all NetBIOS and DNS computer names associated with a Windows host via MS-RPC.

#### Info Levels

| Level | Returns |
|-------|---------|
| `0` | Name list only (NetBIOS primary + aliases) |
| `1` | Name list + name source/type (most detailed) |

#### Name Types Returned (Level 1)

| Type | Meaning |
|------|---------|
| `NetPrimaryComputerName` | Primary NetBIOS name of the computer |
| `NetAlternateComputerName` | Alternate/alias NetBIOS name |
| `NetDnsComputerName` | Full DNS hostname (e.g. `server01.domain.local`) |
| `NetDnsHostName` | DNS host label (e.g. `server01`) |
| `NetDnsDomainName` | DNS domain name (e.g. `domain.local`) |

#### Usage Examples

```bash
# Anonymous — list all computer names (level 1 = most info)
rpcclient -U "" -N -c "wkssvc_enumeratecomputernames 1" <IP>

# Authenticated — full detail
rpcclient -U "admin%pass" -c "wkssvc_enumeratecomputernames 1" <IP>

# Level 0 — name list only
rpcclient -U "" -N -c "wkssvc_enumeratecomputernames 0" <IP>

# Interactive session
rpcclient -U "" -N <IP>
rpcclient $> wkssvc_enumeratecomputernames 1
```

#### Typical Output
```
result: WERR_OK
count: 5
name[0]: COMPUTER01 (NetPrimaryComputerName)
name[1]: COMPUTER01$ (NetAlternateComputerName)
name[2]: computer01.domain.local (NetDnsComputerName)
name[3]: computer01 (NetDnsHostName)
name[4]: domain.local (NetDnsDomainName)
```

### Related Computername Commands

| Cmd | Interface | Desc |
|-----|-----------|------|
| `wkssvc_enumeratecomputernames` | WKSSVC | All computer names (primary + alternate + DNS) |
| `wkssvc_wkstagetinfo` | WKSSVC | Workstation info (includes computername at certain levels) |
| `wkssvc_getjoininformation` | WKSSVC | Domain join info (workgroup/domain + computer role) |
| `srvinfo` | SRVSVC | Server info (includes server/computer name) |
| `lsaquery` | LSARPC | Domain SID + domain name (related to computer identity) |
| `netshareenum` | SRVSVC | Share list (may reveal computer name in UNC paths) |
| `dsroledominfo` | LSARPC-DS | Primary domain info (computer role context) |

### wkssvc_wkstagetinfo Levels

| Level | Field Set |
|-------|-----------|
| `100` | Platform ID, Computer name, Lan group, Ver major/minor, Logged-on users |
| `101` | All of 100 + Lan root |
| `102` | All of 101 + logged-on users list, connection count, share count, open files |
| `502` | All of 102 + workstation flags, DNS computer name, DNS domain name, DNS forest name |

---

## Penetration Testing Cheat Sheet

### Recon (Anonymous / Low-priv)

```bash
# Connect anonymous
rpcclient -U "" -N <IP>

# Inside session:
srvinfo                          # OS version, server name
enumdomusers                     # Domain users list
enumdomgroups                    # Domain groups list
querydominfo                     # Domain info (users, groups count)
lsaquery                         # Domain SID, name
wkssvc_enumeratecomputernames 1  # All computer names
wkssvc_getjoininformation        # Domain/workgroup join info
wkssvc_wkstagetinfo 102          # Workstation details + DNS names
lookupdomain BUILTIN             # Domain SID
lookupdomain <DOMAIN>            # Domain SID
netshareenumall                  # All shares incl hidden
netsharegetinfo <share> 2        # Share details (level 2)
netdiskenum                      # Disk info
netsessenum                      # Active sessions
netfileenum                      # Open files
netconnenum                      # Connections
enumprivs                        # All available privileges
getdompwinfo                     # Password policy
enumtrust                        # Trusted domains
```

### User Enumeration Deep

```bash
# List all users
enumdomusers

# Query specific user (need RID from enumdomusers)
queryuser <RID>                  # Full user info
queryusergroups <RID>            # User's groups
queryuseraliases <SID> <RID>     # User's aliases

# Display info bulk (more structured)
querydispinfo 3                  # Users with details (level 3)
querydispinfo 4                  # Users with details (level 4)

# Name <-> RID
samlookupnames <domain> <user>   # Name to RID
samlookuprids <domain> <RID>     # RID to name

# SID lookup
lookupsids <SID>                 # SID to name
lookupnames <name>               # Name to SID
```

### Group Enumeration Deep

```bash
enumdomgroups                    # All groups
querygroup <RID>                 # Group info
querygroupmem <RID>              # Group members (RID list)
enumalsgroups <SID>              # Alias groups
queryaliasinfo <RID>             # Alias info
queryaliasmem <RID>              # Alias members
```

### LSA Privilege Escalation Check

```bash
enumprivs                        # List all privileges
lsaenumsid                       # Enumerate SIDs
lsaenumprivsaccount <SID>        # Check SID's privileges
lsaenumacctrights <SID>          # Check SID's rights
```

### Trust & Domain Info

```bash
enumtrust                        # Trusted domains
lsaquerytrustdominfo <SID>       # Trust info by SID
lsaquerytrustdominfobyname <DOM> # Trust info by name (Win2k+)
dsroledominfo                    # Primary domain role
dsenumdomtrusts                  # All forest trusts
dsr_enumtrustdom                 # Trusted domains (DSR)
dsr_getsitename <computer>       # AD site name
getdcsitecoverage                # DC site coverage
```

### Registry (WINREG)

```bash
winreg_enumkey <key> <idx>       # Enumerate registry subkeys
querymultiplevalues              # Query multiple values
```

### Print Spooler Recon

```bash
enumprinters 1                   # Installed printers
enumdrivers 3                    # Printer drivers
enumports 2                      # Ports
enumforms <printer>              # Forms
enummonitors                     # Print monitors
```

### Change Password

```bash
chgpasswd <user> <old> <new>     # Change password
chgpasswd3 <user> <old> <new>    # Change password (RC4)
chgpasswd4 <user> <old> <new>    # Change password (AES)
```

### Session Control

```bash
sign                             # Force signing
seal                             # Force encryption
schannel                         # Schannel sealed
schannelsign                     # Schannel signed only
timeout <ms>                     # Set timeout
transport ncacn_ip_tcp           # Switch transport
none                             # Reset pipe properties
```

---

## Auth File Format (-A)

```
username = admin
password = P@ssw0rd
domain   = CORP
```

---

## Common SID Patterns

| SID | Meaning |
|-----|---------|
| `S-1-5-32-544` | BUILTIN\Administrators |
| `S-1-5-32-545` | BUILTIN\Users |
| `S-1-5-32-550` | BUILTIN\Print Operators |
| `S-1-5-32-551` | BUILTIN\Backup Operators |
| `S-1-5-32-552` | BUILTIN\Replicator |
| `S-1-5-32-555` | BUILTIN\Remote Desktop Users |
| `S-1-5-32-558` | BUILTIN\Machine Operators |
| `S-1-5-32-559` | BUILTIN\Account Operators |
| `S-1-5-21-...-500` | Domain Administrator |
| `S-1-5-21-...-501` | Guest |
| `S-1-5-21-...-502` | KRBTGT |
| `S-1-5-21-...-512` | Domain Admins |
| `S-1-5-21-...-513` | Domain Users |
| `S-1-5-21-...-514` | Domain Guests |
| `S-1-5-21-...-515` | Domain Computers |
| `S-1-5-21-...-516` | Domain Controllers |
| `S-1-5-21-...-519` | Enterprise Admins |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Generic failure / connection error |
| 2 | Command syntax error |

---

## Token-Optimized AI Usage Hints

- Use `-c "cmd1;cmd2"` for batch to avoid multi-turn
- Always specify info level for richer output (e.g., `wkssvc_enumeratecomputernames 1`)
- Use `querydispinfo 3` over `enumdomusers` + `queryuser` loop (fewer round trips)
- Anonymous bind (`-U "" -N`) works on many default Windows configs
- Pipe output: `rpcclient -c "enumdomusers" <IP> | grep -i admin`
- RID 500 = built-in admin; RID 1000+ = typically first custom user
- `netshareenumall` reveals hidden shares (C$, ADMIN$, IPC$)
