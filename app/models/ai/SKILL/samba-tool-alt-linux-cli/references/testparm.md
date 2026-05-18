# samba-tool testparm — Syntax Check Configuration File

Check the syntax of the Samba configuration file (`smb.conf`).

## Synopsis

```bash
samba-tool testparm [options]
```

## Description

The `testparm` command checks the syntax of the Samba configuration file (`/etc/samba/smb.conf` by default). It validates the configuration and reports any syntax errors or unrecognized parameters.

## Options

| Option | Description |
|--------|-------------|
| `-s, --suppress-prompt` | Suppress the prompt to press Enter |
| `-v, --verbose` | Show all options including defaults |
| `--parameter-name=PARAM` | Show the value of a specific parameter |
| `--section-name=SECTION` | Show the definition of a specific section |
| `-f, --show-all-params` | Show all parameters |
| `--configfile=FILE` | Specify alternative config file |

## Examples

### Basic syntax check
```bash
samba-tool testparm
```

### Show all parameters including defaults
```bash
samba-tool testparm --verbose
```

### Check specific parameter value
```bash
samba-tool testparm --parameter-name="workgroup"
samba-tool testparm --parameter-name="realm"
samba-tool testparm --parameter-name="server role"
```

### Check specific section
```bash
samba-tool testparm --section-name="global"
samba-tool testparm --section-name="share1"
```

### Check alternative config file
```bash
samba-tool testparm --configfile=/etc/samba/smb.conf.new
```

### Non-interactive (scripted) check
```bash
samba-tool testparm -s
```

## Notes

- This is a separate command from the standalone `testparm` utility
- Always run `testparm` after modifying `smb.conf` before restarting Samba services
- Syntax errors can prevent Samba from starting
- The `--verbose` option is useful for seeing the effective configuration including all default values
