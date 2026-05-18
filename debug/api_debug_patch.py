#!/usr/bin/env python3
"""
Patch for api_debug.py — add Shell endpoints (v1.4.3).

Apply these changes to the existing api_debug.py:

1. Add shell endpoint definitions to the ENDPOINTS list (after Misc section).
2. Add "shell" group to ENDPOINT_GROUPS.
3. Add shell timeout overrides to ENDPOINT_TIMEOUTS.

See the specific changes below.
"""

# ──────────────────────────────────────────────────────────────────────
# 1. Add to ENDPOINTS list (after the Misc section, before the closing ])
#
#    Insert these lines AFTER the last misc endpoint
#    ("DELETE", "/api/v1/misc/spn/delete", ...) and BEFORE the closing ]:
# ──────────────────────────────────────────────────────────────────────

SHELL_ENDPOINTS_ADDITION = '''
    # ── Shell (v1.4.3) ───────────────────────────────────────────────
    # Shell endpoints: execute bash/python3 commands on the server.
    ("GET", "/api/v1/shell/", {}, None, "List available shells", None),
    # Bash command without sudo (safe read-only)
    ("POST", "/api/v1/shell/exec", {}, {"shell": "bash", "sudo": False, "cmd": "uname -a", "timeout": 10}, "Shell exec: bash uname", None),
    # Bash command with sudo (requires NOPASSWD or SAMBA_SUDO_PASSWORD)
    ("POST", "/api/v1/shell/exec", {}, {"shell": "bash", "sudo": True, "cmd": "whoami", "timeout": 10}, "Shell exec: bash sudo whoami", "needs_sudo"),
    # Python3 command without sudo
    ("POST", "/api/v1/shell/exec", {}, {"shell": "python3", "sudo": False, "cmd": "import platform; print(platform.node())", "timeout": 10}, "Shell exec: python3 hostname", None),
    # Multi-line bash script
    ("POST", "/api/v1/shell/script", {}, {"shell": "bash", "sudo": False, "lines": ["echo 'Hello from shell API'", "uname -r", "uptime"], "timeout": 15}, "Shell script: bash multi-line", None),
'''

# ──────────────────────────────────────────────────────────────────────
# 2. Add to ENDPOINT_GROUPS dict:
# ──────────────────────────────────────────────────────────────────────

ENDPOINT_GROUPS_ADDITION = '''
    "shell":    ["/api/v1/shell/"],
'''

# ──────────────────────────────────────────────────────────────────────
# 3. Add to ENDPOINT_TIMEOUTS dict:
# ──────────────────────────────────────────────────────────────────────

ENDPOINT_TIMEOUTS_ADDITION = '''
    "/api/v1/shell/": 30,      # Shell commands have their own timeout
'''
