# samba-tool time — Retrieve the Time on a Server

Retrieve the current time from a Samba/Active Directory server.

## Synopsis

```bash
samba-tool time <server> [options]
```

## Parameters

| Parameter | Description |
|-----------|-------------|
| `server` | Hostname or IP address of the server |

## Options

| Option | Description |
|--------|-------------|
| `-U, --user=USER` | Username for authentication |
| `--password=PASSWORD` | Password for authentication |

## Examples

### Get time from a domain controller
```bash
samba-tool time dc1.example.com
```

### Get time from a server using authentication
```bash
samba-tool time 192.168.1.1 -U Administrator
```

## Notes

- Time synchronization is critical in Active Directory environments
- Kerberos authentication requires that the time difference between client and server is less than 5 minutes (by default)
- Use this command to verify time synchronization between DCs and clients
- For production time synchronization, use `chrony` or `ntpd` to sync all machines to a reliable time source
- The PDC Emulator FSMO role holder is typically the authoritative time source in the domain

## Typical Workflows

### Check time sync across DCs
```bash
# Check time on all DCs
samba-tool time dc1.example.com
samba-tool time dc2.example.com
samba-tool time dc3.example.com
```

### Verify PDC Emulator time
```bash
# 1. Identify the PDC Emulator
samba-tool fsmo show | grep PdcEmulation

# 2. Check its time
samba-tool time dc1.example.com
```
