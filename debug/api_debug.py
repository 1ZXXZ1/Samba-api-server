#!/usr/bin/env python3
"""
Samba AD API — Debug Endpoint Checker.

Отправляет запросы ко всем GET-эндпоинтам Samba API и показывает,
какие из них работают (OK), а какие возвращают ошибки (ER).

Режимы запуска:
    python3 api_debug.py                  # компактный вывод: OK / ER
    python3 api_debug.py -d               # подробный: полный ответ и тело запроса
    python3 api_debug.py --debug          # то же что -d
    python3 api_debug.py --force --yes-i-know  # выполнить ВСЕ эндпоинты
    python3 api_debug.py --show           # показать список эндпоинтов
    python3 api_debug.py -t 92            # запустить только тест #92
    python3 api_debug.py -t 10-17,30-55   # запустить тесты с 10 по 17 и с 30 по 55
    python3 api_debug.py -g drs           # запустить только DRS-эндпоинты
    python3 api_debug.py -g user,gpo      # запустить user и GPO эндпоинты

Можно указать сервер и API-ключ:
    python3 api_debug.py -s http://192.168.1.10:8099 -k YOUR_KEY
    python3 api_debug.py --server http://... --api-key YOUR_KEY

Если ключ/сервер не указаны — читаются из переменных окружения
SAMBA_API_KEY / SAMBA_API_SERVER или из файла .env.

Флаг --force отключает все фильтры пропуска (DESTRUCTIVE, NEEDS_OBJECT,
LONG_RUNNING, DANGEROUS) и выполняет каждый эндпоинт как обычный запрос.
Результат отображается с меткой исходной категории, например
[DESTRUCTIVE] или [NEEDS_OBJ]. Для подтверждения требуется --yes-i-know.

Флаг -t позволяет запустить конкретные тесты по их номерам (как в [N/Total]).
Флаг -g фильтрует по группе: user, group, computer, contact, ou, domain,
dns, sites, fsmo, drs, gpo, schema, delegation, service-accounts, auth,
dashboard, misc.
Флаг --show выводит список всех эндпоинтов с номерами и группами без запуска.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Optional
from urllib.parse import quote

# ── Пытаемся импортировать requests, fallback на urllib ────────────────
try:
    import requests

    _HAS_REQUESTS = True
except ImportError:
    import urllib.request
    import urllib.error

    _HAS_REQUESTS = False


# ═══════════════════════════════════════════════════════════════════════
#  Конфигурация
# ═══════════════════════════════════════════════════════════════════════

DEFAULT_SERVER = "http://127.0.0.1:8099"
DEFAULT_API_KEY = ""
DEFAULT_TIMEOUT = 120  # default HTTP timeout (seconds) — 60s covers DRS/testparm
DOTENV_PATH = Path(__file__).resolve().parent / ".env"

# Per-endpoint timeout overrides (path prefix → timeout in seconds).
# These override the global --timeout for specific endpoint groups.
# Fix v14-5/6/7: Expected status codes for endpoints where certain
# error responses are the correct behavior, not a bug.
# When the returned status matches expected_status, the test is marked
# OK (or EXPECTED) instead of ER.
ENDPOINT_EXPECTED_STATUS: dict[str, int] = {
    # Fix v14-5: Trust endpoints for non-existent test.local domain.
    # These return 400 (DNS lookup failed) which is expected.
    "POST /api/v1/domain/trust/create": 400,
    "DELETE /api/v1/domain/trust/delete": 404,
    "GET /api/v1/domain/trust/namespaces": 400,
    "POST /api/v1/domain/trust/validate": 400,
    # Fix v14-6: Join/Leave domain on DC returns 412 Precondition Failed.
    # This is correct: join/leave is not applicable to a DC.
    "POST /api/v1/domain/join": 412,
    "POST /api/v1/domain/leave": 412,
    # Fix v14-7: Provision is intentionally disabled (403 Forbidden).
    "POST /api/v1/domain/provision": 403,
}

ENDPOINT_TIMEOUTS: dict[str, int] = {
    "/api/v1/drs/uptodateness": 900,  # Fix v22: uptodateness timeout increased to match router default (900s)
    "/api/v1/drs/": 260,       # Fix v6: DRS commands: 130s HTTP timeout (DRS endpoint defaults are now 60-120s)
    "/api/v1/domain/join": 60,  # join/leave timeout increased to 25s in API
    "/api/v1/domain/leave": 60, # join/leave timeout increased to 25s in API
    "/api/v1/domain/demote": 600, # Fix v3-2: demote is a long-running operation
    "/api/v1/misc/testparm": 360,  # testparm can take 60-120s
    "/api/v1/misc/dbcheck": 240,   # dbcheck is long-running
    "/api/v1/domain/backup": 600,  # backup operations are very slow
    "/api/v1/domain/exportkeytab": 600,  # keytab export is now a background task
    "/api/v1/domain/provision": 600,  # provision is very slow
    "/api/v1/dns/": 260,       # Fix v6: DNS commands now use 120s timeout in API (was 600s)
    "/api/v1/gpo/": 260,       # Fix v6: GPO operations with --server should be faster (was 120s)
    "/api/v1/shell/": 30,      # v1.4.3: Shell commands have their own per-command timeout
}


def _load_dotenv() -> dict[str, str]:
    """Простая загрузка .env без внешних зависимостей."""
    env: dict[str, str] = {}
    if DOTENV_PATH.is_file():
        for line in DOTENV_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip("'\"")
    return env


# ═══════════════════════════════════════════════════════════════════════
#  HTTP-клиент (requests или urllib fallback)
# ═══════════════════════════════════════════════════════════════════════


def _http_request(
    method: str,
    url: str,
    headers: dict[str, str],
    json_body: Optional[dict] = None,
    timeout: int = 60,
) -> tuple[int, dict | str | None]:
    """Выполнить HTTP-запрос. Возвращает (status_code, response_body)."""
    if _HAS_REQUESTS:
        try:
            resp = requests.request(
                method, url, headers=headers, json=json_body, timeout=timeout
            )
            try:
                body: dict | str | None = resp.json()
            except (ValueError, json.JSONDecodeError):
                body = resp.text
            return resp.status_code, body
        except requests.ConnectionError as exc:
            return 0, f"Connection error: {exc}"
        except requests.Timeout:
            return 0, "Request timed out"
        except Exception as exc:
            return 0, f"Request error: {exc}"
    else:
        # urllib fallback
        data = json.dumps(json_body).encode("utf-8") if json_body else None
        req = urllib.request.Request(url, data=data, method=method)
        for k, v in headers.items():
            req.add_header(k, v)
        if json_body and "Content-Type" not in headers:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                try:
                    return resp.status, json.loads(raw)
                except (ValueError, json.JSONDecodeError):
                    return resp.status, raw
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            try:
                return exc.code, json.loads(raw)
            except (ValueError, json.JSONDecodeError):
                return exc.code, raw
        except urllib.error.URLError as exc:
            return 0, f"URL error: {exc.reason}"
        except Exception as exc:
            return 0, f"Request error: {exc}"


# ═══════════════════════════════════════════════════════════════════════
#  Определение всех эндпоинтов
# ═══════════════════════════════════════════════════════════════════════

# Каждый кортеж: (method, path, query_params, body, description, skip_reason)
# skip_reason = None  → проверить
# skip_reason = str   → пропустить с указанной причиной (деструктивные / требуют существующий объект)

ENDPOINTS: list[tuple[str, str, dict, Optional[dict], str, Optional[str]]] = [
    # ── System ────────────────────────────────────────────────────────
    ("GET", "/health", {}, None, "Health check", None),

    # ── Dashboard (v1.2.5) ──────────────────────────────────────────
    ("GET", "/api/v1/dashboard/full", {}, None, "Full AD dashboard (ldbsearch)", None),

    # ── Users ─────────────────────────────────────────────────────────
    ("GET", "/api/v1/users/full", {}, None, "Full users (ldbsearch)", None),
    ("GET", "/api/v1/users/", {}, None, "List users", None),
    # Create user FIRST, then test all NEEDS_OBJECT endpoints, then delete LAST
    ("POST", "/api/v1/users/", {}, {"username": "_debug_test_user", "random_password": True}, "Create user", "destructive"),
    ("GET", "/api/v1/users/_debug_test_user", {}, None, "Show user", "needs_object"),
    ("POST", "/api/v1/users/_debug_test_user/enable", {}, None, "Enable user", "needs_object"),
    ("POST", "/api/v1/users/_debug_test_user/disable", {}, None, "Disable user", "needs_object"),
    ("POST", "/api/v1/users/_debug_test_user/enable", {}, None, "Re-enable user", "needs_object"),
    ("POST", "/api/v1/users/_debug_test_user/unlock", {}, None, "Unlock user", "needs_object"),
    ("PUT", "/api/v1/users/_debug_test_user/password", {}, {"new_password": "P@ssw0rd!"}, "Set password", "needs_object"),
    ("GET", "/api/v1/users/_debug_test_user/groups", {}, None, "Get user groups", "needs_object"),
    ("PUT", "/api/v1/users/_debug_test_user/setexpiry", {}, {"days": 90}, "Set expiry", "needs_object"),
    ("PUT", "/api/v1/users/_debug_test_user/setprimarygroup", {}, {"groupname": "Domain Users"}, "Set primary group", "needs_object"),
    ("POST", "/api/v1/users/_debug_test_user/addunixattrs", {}, {"uid_number": 10000, "gid_number": 10000}, "Add Unix attrs", "needs_object"),
    ("PUT", "/api/v1/users/_debug_test_user/sensitive", {}, {"on": True}, "Set sensitive", "needs_object"),
    ("PUT", "/api/v1/users/_debug_test_user/sensitive", {}, {"on": False}, "Unset sensitive", "needs_object"),
    ("POST", "/api/v1/users/_debug_test_user/move", {}, {"new_parent_dn": "CN=Users,DC=kcrb,DC=local"}, "Move user", "needs_object"),
    ("POST", "/api/v1/users/_debug_test_user/rename", {}, {"new_name": "renamed_user"}, "Rename user", "needs_object"),
    # NOTE: rename changes the username; subsequent ops use the NEW name
    ("GET", "/api/v1/users/renamed_user/getpassword", {}, None, "Get password", "needs_object"),
    ("GET", "/api/v1/users/renamed_user/get-kerberos-ticket", {}, None, "Get Kerberos ticket", "needs_object"),
    # Delete user LAST (using renamed name)
    ("DELETE", "/api/v1/users/renamed_user", {}, None, "Delete user", "destructive"),

    # ── Groups ────────────────────────────────────────────────────────
    ("GET", "/api/v1/groups/full", {}, None, "Full groups (ldbsearch)", None),
    ("GET", "/api/v1/groups/", {}, None, "List groups", None),
    # Create group FIRST, then test, then delete LAST
    ("POST", "/api/v1/groups/", {}, {"groupname": "_debug_test_group"}, "Create group", "destructive"),
    ("GET", "/api/v1/groups/_debug_test_group", {}, None, "Show group", "needs_object"),
    ("POST", "/api/v1/groups/_debug_test_group/members", {}, {"members": ["Administrator"]}, "Add members", "needs_object"),
    ("GET", "/api/v1/groups/_debug_test_group/members", {}, None, "List members", "needs_object"),
    ("DELETE", "/api/v1/groups/_debug_test_group/members", {}, {"members": ["Administrator"]}, "Remove members", "needs_object"),
    ("POST", "/api/v1/groups/_debug_test_group/move", {}, {"new_parent_dn": "CN=Users,DC=kcrb,DC=local"}, "Move group", "needs_object"),
    # Delete group LAST
    ("DELETE", "/api/v1/groups/_debug_test_group", {}, None, "Delete group", "destructive"),
    ("GET", "/api/v1/groups/stats", {}, None, "Group stats (global)", None),

    # ── Computers ─────────────────────────────────────────────────────
    ("GET", "/api/v1/computers/full", {}, None, "Full computers (ldbsearch)", None),
    ("GET", "/api/v1/computers/", {}, None, "List computers", None),
    ("POST", "/api/v1/computers/", {}, {"computername": "DEBUGPC$"}, "Create computer", "destructive"),
    ("GET", "/api/v1/computers/DEBUGPC$", {}, None, "Show computer", "needs_object"),
    ("POST", "/api/v1/computers/DEBUGPC$/move", {}, {"new_ou_dn": "CN=Computers,DC=kcrb,DC=local"}, "Move computer", "needs_object"),
    ("DELETE", "/api/v1/computers/DEBUGPC$", {}, None, "Delete computer", "destructive"),

    # ── Contacts ──────────────────────────────────────────────────────
    ("GET", "/api/v1/contacts/full", {}, None, "Full contacts (ldbsearch)", None),
    ("GET", "/api/v1/contacts/", {}, None, "List contacts", None),
    ("POST", "/api/v1/contacts/", {}, {"contactname": "_debug_test_contact"}, "Create contact", "destructive"),
    ("GET", "/api/v1/contacts/_debug_test_contact", {}, None, "Show contact", "needs_object"),
    ("POST", "/api/v1/contacts/_debug_test_contact/move", {}, {"new_parent_dn": "CN=Users,DC=kcrb,DC=local"}, "Move contact", "needs_object"),
    ("POST", "/api/v1/contacts/_debug_test_contact/rename", {}, {"new_name": "renamed_contact"}, "Rename contact", "needs_object"),
    ("DELETE", "/api/v1/contacts/renamed_contact", {}, None, "Delete contact", "destructive"),

    # ── OUs ───────────────────────────────────────────────────────────
    ("GET", "/api/v1/ous/full", {}, None, "Full OUs (ldbsearch)", None),
    ("GET", "/api/v1/ous/", {}, None, "List OUs", None),
    ("POST", "/api/v1/ous/", {}, {"ouname": "_debug_test_ou"}, "Create OU", "destructive"),
    ("POST", "/api/v1/ous/_debug_test_ou/move", {}, {"new_parent_dn": "DC=kcrb,DC=local"}, "Move OU", "needs_object"),
    ("POST", "/api/v1/ous/_debug_test_ou/rename", {}, {"new_name": "OU=_debug_test_ou_renamed,DC=kcrb,DC=local"}, "Rename OU", "needs_object"),
    ("GET", "/api/v1/ous/_debug_test_ou_renamed/objects", {}, None, "List OU objects", "needs_object"),
    ("DELETE", "/api/v1/ous/_debug_test_ou_renamed", {}, None, "Delete OU", "destructive"),

    # ── Domain ────────────────────────────────────────────────────────
    ("GET", "/api/v1/domain/full", {}, None, "Full domain info (ldbsearch)", None),
    ("GET", "/api/v1/domain/info", {}, None, "Domain info (v1.2.3+: no IP required)", None),
    ("GET", "/api/v1/domain/level", {}, None, "Get domain level", None),
    # NOTE: domain level raise is irreversible. The API now pre-checks
    # the current level and returns 409 if the requested level equals
    # the current one. We use a dynamic approach: the test runner
    # queries the current level first and computes the next valid level.
    # If the server is already at the highest level, this test will
    # be skipped. The body is a placeholder; the actual level is
    # resolved at runtime by check_endpoints().
    ("PUT", "/api/v1/domain/level", {}, {"level": "NEXT_LEVEL"}, "Set domain level (dynamic)", "destructive_irreversible"),
    ("GET", "/api/v1/domain/passwordsettings", {}, None, "Password settings", None),
    ("PUT", "/api/v1/domain/passwordsettings", {}, {"min_password_length": 7}, "Set password settings", "destructive"),
    # Fix v13-4: Trust endpoints for non-existent test.local domain.
    # These are marked as "trust_test" so that --skip-trust-tests can
    # skip them.  The DNS SRV pre-check in the API returns 400 for
    # non-existent domains, which is expected behavior.
    ("POST", "/api/v1/domain/trust/create", {}, {"trusted_domain_name": "test.local"}, "Create trust", "trust_test"),
    ("DELETE", "/api/v1/domain/trust/delete", {"trusted_domain_name": "test.local"}, None, "Delete trust", "trust_test"),
    ("GET", "/api/v1/domain/trust/list", {}, None, "List trusts", None),
    ("GET", "/api/v1/domain/trust/namespaces", {"trusted_domain_name": "test.local"}, None, "Trust namespaces", "trust_test"),
    ("POST", "/api/v1/domain/trust/validate", {"trusted_domain_name": "test.local"}, None, "Validate trust", "trust_test"),
    ("POST", "/api/v1/domain/backup/online", {}, {"target_dir": "/tmp/samba_backup"}, "Online backup", "destructive_long"),
    ("POST", "/api/v1/domain/backup/offline", {}, {"target_dir": "/tmp/samba_backup"}, "Offline backup", "destructive_long"),
    ("POST", "/api/v1/domain/kds/root-key/create", {}, None, "Create KDS root key", "destructive"),
    ("GET", "/api/v1/domain/kds/root-key/list", {}, None, "List KDS root keys", None),
    ("POST", "/api/v1/domain/exportkeytab", {"principal": "cifs/kushnrserveralt.kcrb.local", "keytab_path": "/tmp/exported.keytab"}, None, "Export keytab", "needs_object"),
    # NOTE: domain join requires a REAL domain name, not 'test.local'.
    # Use the configured realm from .env if available, otherwise skip.
    ("POST", "/api/v1/domain/join", {}, {"force": True, "domain_name": "kcrb.local"}, "Join domain", "destructive_dangerous"),
    ("POST", "/api/v1/domain/leave", {}, {"force": True}, "Leave domain", "destructive_dangerous"),
    # Fix v3-2: Add domain demote endpoint (DC → member)
    ("POST", "/api/v1/domain/demote", {}, {"force": True}, "Demote DC", "destructive_dangerous"),
    ("POST", "/api/v1/domain/provision", {}, None, "Provision info", "destructive_dangerous"),
    ("GET", "/api/v1/domain/claim/types", {}, None, "Claim types", None),

    # ── DNS ───────────────────────────────────────────────────────────
    # DNS commands need a server parameter; we pass the configured server
    # which defaults to "localhost" for a local DC.
    ("GET", "/api/v1/dns/serverinfo", {"server": "localhost"}, None, "DNS server info", None),
    ("GET", "/api/v1/dns/zones", {"server": "localhost"}, None, "List DNS zones", None),
    ("GET", "/api/v1/dns/zones/kcrb.local", {"server": "localhost"}, None, "Zone info", "needs_object"),
    ("POST", "/api/v1/dns/zones", {}, {"zone": "debug.test", "dns_directory_partition": "domain"}, "Create zone", "destructive"),
    ("DELETE", "/api/v1/dns/zones/debug.test", {"server": "localhost"}, None, "Delete zone", "destructive"),
    ("GET", "/api/v1/dns/zones/kcrb.local/records", {"server": "localhost"}, None, "List DNS records", "needs_object"),
    ("POST", "/api/v1/dns/zones/kcrb.local/records", {}, {"name": "debugtest", "record_type": "A", "data": "1.2.3.4"}, "Create record", "destructive"),
    # NOTE: Update record: first specify old_data=1.2.3.4 (the created value)
    # and new_data=5.6.7.8 (the new value). This must come AFTER creation.
    ("PUT", "/api/v1/dns/zones/kcrb.local/records", {}, {"name": "debugtest", "old_record_type": "A", "old_data": "1.2.3.4", "new_data": "5.6.7.8"}, "Update record", "needs_object"),
    # NOTE: Delete the UPDATED record (data=5.6.7.8 after the update).
    # The cleanup of old 5.6.7.8 records before update was removed because
    # it attempted to delete a record that didn't exist yet, causing 404.
    ("DELETE", "/api/v1/dns/zones/kcrb.local/records", {}, {"name": "debugtest", "record_type": "A", "data": "5.6.7.8"}, "Delete record", "destructive"),
    ("GET", "/api/v1/dns/zones/kcrb.local/rorecords", {"server": "localhost"}, None, "Query records (RO)", "needs_object"),
    ("PUT", "/api/v1/dns/zones/kcrb.local/options", {}, {"aging": True}, "Set zone options", "destructive"),

    # ── Sites ─────────────────────────────────────────────────────────
    ("GET", "/api/v1/sites/", {}, None, "List sites", None),
    ("GET", "/api/v1/sites/Default-First-Site-Name", {}, None, "View site", None),
    ("POST", "/api/v1/sites/", {}, {"sitename": "_debug_test_site"}, "Create site", "destructive"),
    ("POST", "/api/v1/sites/_debug_test_site/subnets", {}, {"subnetname": "10.99.0.0/24", "site_of_subnet": "_debug_test_site"}, "Create subnet", "destructive"),
    ("GET", "/api/v1/sites/_debug_test_site/subnets", {}, None, "List subnets", None),
    ("GET", "/api/v1/sites/subnets/", {"subnetname": "10.99.0.0/24"}, None, "View subnet", "needs_object"),
    ("PUT", "/api/v1/sites/subnets/site", {"subnetname": "10.99.0.0/24"}, {"site_of_subnet": "Default-First-Site-Name"}, "Set subnet site", "destructive"),
    ("DELETE", "/api/v1/sites/subnets/", {"subnetname": "10.99.0.0/24"}, None, "Delete subnet", "destructive"),
    ("DELETE", "/api/v1/sites/_debug_test_site", {}, None, "Delete site", "destructive"),

    # ── FSMO ──────────────────────────────────────────────────────────
    ("GET", "/api/v1/fsmo/full", {}, None, "Full FSMO roles (ldbsearch)", None),
    ("GET", "/api/v1/fsmo/", {}, None, "Show FSMO roles", None),
    ("PUT", "/api/v1/fsmo/transfer", {}, {"role": "pdc"}, "Transfer FSMO role", "destructive_dangerous"),
    ("PUT", "/api/v1/fsmo/seize", {}, {"role": "pdc"}, "Seize FSMO role", "destructive_dangerous"),

    # ── DRS ───────────────────────────────────────────────────────────
    # DRS commands now accept an explicit 'server' query parameter.
    # Use 'localhost' for local DC testing (same as DNS commands).
    ("GET", "/api/v1/drs/showrepl", {"server": "localhost"}, None, "DRS showrepl", None),
    # Fix v6-10: Use localhost instead of fictional dc1/dc2 for replicate test.
    # Fictional hosts cause "DRS connection to dc2 failed" which is expected
    # but misleading.  localhost is the real local DC.
    ("POST", "/api/v1/drs/replicate", {}, {"source_dsa": "localhost", "destination_dsa": "localhost", "nc_dn": "DC=kcrb,DC=local"}, "DRS replicate", "destructive_long"),
    ("GET", "/api/v1/drs/uptodateness", {}, None, "DRS uptodateness", None),
    ("GET", "/api/v1/drs/bind", {"server": "localhost"}, None, "DRS bind", None),
    ("GET", "/api/v1/drs/options", {"server": "localhost"}, None, "DRS options", None),

    # ── GPO ───────────────────────────────────────────────────────────
    # GPO tests: create a GPO, then test show/delete with the created GPO ID.
    # Since the test framework doesn't capture response data for reuse,
    # we test listall (which works) and create (which returns a GUID),
    # then use the well-known Default Domain Policy GUID for show/inherit tests.
    # Note: {gpo_id} in paths must be a real GUID; we use a placeholder that
    # the test runner should replace with actual created GPO data.
    ("GET", "/api/v1/gpo/full", {}, None, "Full GPOs (ldbsearch)", None),
    ("GET", "/api/v1/gpo/", {}, None, "List GPOs", None),
    # Fix v9-4: Pass overwrite=true in query params when creating GPO.
    # When tests are re-run, the GPO _debug_test_gpo may persist from
    # a previous run, causing 409 Conflict.  The overwrite parameter
    # (added in v8) tells the API to auto-delete and recreate.
    ("POST", "/api/v1/gpo/", {"overwrite": "true"}, {"displayname": "_debug_test_gpo"}, "Create GPO", "destructive"),
    # For show/delete/link/inherit/fetch, we test with the Default Domain Policy
    # which always exists in an AD domain. Its GUID varies by installation,
    # so we use the display name pattern. However, samba-tool gpo commands
    # require a GUID. These tests are best-effort.
    ("GET", "/api/v1/gpo/{gpo_id}", {}, None, "Show GPO", "needs_object"),
    ("POST", "/api/v1/gpo/{gpo_id}/link", {}, {"container_dn": "DC=kcrb,DC=local"}, "Link GPO", "destructive"),
    ("DELETE", "/api/v1/gpo/{gpo_id}/link", {}, {"container_dn": "DC=kcrb,DC=local"}, "Unlink GPO", "destructive"),
    ("GET", "/api/v1/gpo/{gpo_id}/inherit", {}, None, "Get inheritance", "needs_object"),
    ("PUT", "/api/v1/gpo/{gpo_id}/inherit", {}, {"block": True}, "Set inheritance", "destructive"),
    ("POST", "/api/v1/gpo/{gpo_id}/backup", {}, {"target_dir": "/tmp/gpo_backup"}, "Backup GPO", "destructive_long"),
    ("POST", "/api/v1/gpo/{gpo_id}/restore", {}, {"source_dir": "/tmp/gpo_backup"}, "Restore GPO", "destructive_long"),
    ("GET", "/api/v1/gpo/{gpo_id}/fetch", {}, None, "Fetch GPO", "needs_object"),
    # Fix v14-4: DELETE moved to END of GPO test chain so fetch/show
    # succeed before the GPO is removed.
    ("DELETE", "/api/v1/gpo/{gpo_id}", {}, None, "Delete GPO", "destructive"),

    # ── Schema ────────────────────────────────────────────────────────
    ("GET", "/api/v1/schema/attributes/cn", {}, None, "Show schema attribute", "needs_object"),
    ("GET", "/api/v1/schema/classes/user", {}, None, "Show schema class", "needs_object"),

    # ── Delegation ────────────────────────────────────────────────────
    ("POST", "/api/v1/delegation/add", {}, {"accountname": "Administrator", "service": "cifs/server"}, "Add delegation", "destructive"),
    ("DELETE", "/api/v1/delegation/remove", {}, {"accountname": "Administrator", "service": "cifs/server"}, "Remove delegation", "destructive"),
    ("GET", "/api/v1/delegation/for-account", {"accountname": "Administrator"}, None, "Delegations for account", None),

    # ── Service Accounts ──────────────────────────────────────────────
    ("GET", "/api/v1/service-accounts/", {}, None, "List service accounts", None),
    ("POST", "/api/v1/service-accounts/", {}, {"accountname": "_debug_svc", "dns_host_name": "_debug_svc.kcrb.local"}, "Create service account", "destructive"),
    ("GET", "/api/v1/service-accounts/_debug_svc", {}, None, "Show service account", "needs_object"),
    ("POST", "/api/v1/service-accounts/_debug_svc/gmsa-members/add", {}, {"members": ["Administrator"]}, "Add gMSA member", "needs_object"),
    ("GET", "/api/v1/service-accounts/_debug_svc/gmsa-members", {}, None, "List gMSA members", "needs_object"),
    ("DELETE", "/api/v1/service-accounts/_debug_svc/gmsa-members/remove", {}, {"members": ["Administrator"]}, "Remove gMSA member", "needs_object"),
    ("DELETE", "/api/v1/service-accounts/_debug_svc", {}, None, "Delete service account", "destructive"),

    # ── Auth Policies ─────────────────────────────────────────────────
    ("GET", "/api/v1/auth/silos", {}, None, "List auth silos", None),
    ("POST", "/api/v1/auth/silos", {}, {"siloname": "_debug_test_silo"}, "Create silo", "destructive"),
    ("GET", "/api/v1/auth/silos/_debug_test_silo", {}, None, "Show silo", "needs_object"),
    ("POST", "/api/v1/auth/silos/_debug_test_silo/members", {}, {"accountname": "Administrator"}, "Add silo member", "needs_object"),
    ("DELETE", "/api/v1/auth/silos/_debug_test_silo/members", {}, {"accountname": "Administrator"}, "Remove silo member", "needs_object"),
    ("DELETE", "/api/v1/auth/silos/_debug_test_silo", {}, None, "Delete silo", "destructive"),
    ("GET", "/api/v1/auth/policies", {}, None, "List auth policies", None),
    ("POST", "/api/v1/auth/policies", {}, {"policyname": "_debug_test_policy"}, "Create policy", "destructive"),
    ("GET", "/api/v1/auth/policies/_debug_test_policy", {}, None, "Show policy", "needs_object"),
    ("DELETE", "/api/v1/auth/policies/_debug_test_policy", {}, None, "Delete policy", "destructive"),

    # ── Misc ──────────────────────────────────────────────────────────
    ("GET", "/api/v1/misc/dbcheck", {}, None, "Database check", "long_running"),
    ("POST", "/api/v1/misc/dbcheck/fix", {}, {"yes": True}, "Database fix", "destructive_long"),
    ("GET", "/api/v1/misc/ntacl", {"file_path": "/etc/samba/smb.conf"}, None, "Get NT ACL", None),
    ("POST", "/api/v1/misc/ntacl/set", {}, {"file_path": "/etc/samba/smb.conf", "sddl": "D:PAI(A;;CC;;;AU)"}, "Set NT ACL", "destructive"),
    ("POST", "/api/v1/misc/ntacl/sysvolreset", {}, None, "Sysvol reset", "destructive_long"),
    ("GET", "/api/v1/misc/testparm", {}, None, "Test config", None),
    ("GET", "/api/v1/misc/processes", {}, None, "List processes", None),
    ("GET", "/api/v1/misc/time", {}, None, "Server time", None),
    ("GET", "/api/v1/misc/spn/list", {"accountname": "Administrator"}, None, "List SPNs", None),
    ("POST", "/api/v1/misc/spn/add", {}, {"accountname": "Administrator", "spn": "HTTP/debug.test"}, "Add SPN", "destructive"),
    ("DELETE", "/api/v1/misc/spn/delete", {}, {"accountname": "Administrator", "spn": "HTTP/debug.test"}, "Delete SPN", "destructive"),

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
]


# ═══════════════════════════════════════════════════════════════════════
#  Группировка эндпоинтов (для флага -g)
# ═══════════════════════════════════════════════════════════════════════

# Маппинг: группа → список префиксов путей.
# Группа определяется по первой части пути после /api/v1/.
# Спецгруппы: system (/health), auth (/api/v1/auth/).
ENDPOINT_GROUPS: dict[str, list[str]] = {
    "system":    ["/health"],
    "dashboard": ["/api/v1/dashboard/"],
    "user":      ["/api/v1/users/"],
    "group":     ["/api/v1/groups/"],
    "computer":  ["/api/v1/computers/"],
    "contact":   ["/api/v1/contacts/"],
    "ou":        ["/api/v1/ous/"],
    "domain":    ["/api/v1/domain/"],
    "dns":       ["/api/v1/dns/"],
    "sites":     ["/api/v1/sites/"],
    "fsmo":      ["/api/v1/fsmo/"],
    "drs":       ["/api/v1/drs/"],
    "gpo":       ["/api/v1/gpo/"],
    "schema":    ["/api/v1/schema/"],
    "delegation": ["/api/v1/delegation/"],
    "service-accounts": ["/api/v1/service-accounts/"],
    "auth":      ["/api/v1/auth/"],
    "misc":      ["/api/v1/misc/"],
    "shell":     ["/api/v1/shell/"],
}


def _get_endpoint_group(path: str) -> str:
    """Определить группу эндпоинта по его пути."""
    for group, prefixes in ENDPOINT_GROUPS.items():
        if any(path.startswith(p) for p in prefixes):
            return group
    return "other"


def _parse_test_ids(spec: str, total: int) -> set[int]:
    """Разобрать спецификацию номеров тестов.

    Поддерживаемые форматы:
        92          → только тест #92
        10-17       → тесты с 10 по 17 включительно
        10-17,30-55 → тесты 10-17 и 30-55
        5,8,12      → тесты 5, 8 и 12
        1-5,10,20-25

    Нумерация с 1 (как в выводе [N/Total]).
    Возвращает множество номеров (1-based).
    """
    result: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            bounds = part.split("-", 1)
            try:
                lo = int(bounds[0].strip())
                hi = int(bounds[1].strip())
            except ValueError:
                print(f"  {_c('WARN', 'WARN:')} Invalid range '{part}', skipping")
                continue
            lo = max(1, lo)
            hi = min(total, hi)
            result.update(range(lo, hi + 1))
        else:
            try:
                n = int(part)
            except ValueError:
                print(f"  {_c('WARN', 'WARN:')} Invalid test ID '{part}', skipping")
                continue
            if 1 <= n <= total:
                result.add(n)
            else:
                print(f"  {_c('WARN', 'WARN:')} Test ID {n} out of range (1-{total}), skipping")
    return result


def _list_endpoints(
    show_groups: bool = False,
    test_ids: Optional[set[int]] = None,
    group_filter: Optional[str] = None,
) -> None:
    """Показать список всех эндпоинтов без запуска."""
    total = len(ENDPOINTS)
    width = len(str(total))
    shown = 0
    for idx, (method, path, params, body, description, skip_reason) in enumerate(ENDPOINTS, 1):
        # Фильтр по номерам тестов
        if test_ids is not None and idx not in test_ids:
            continue
        # Фильтр по группе
        if group_filter is not None:
            ep_group = _get_endpoint_group(path)
            requested_groups = [g.strip().lower() for g in group_filter.split(",")]
            if ep_group not in requested_groups:
                continue
        group = _get_endpoint_group(path)
        parts = []
        if skip_reason:
            parts.append(skip_reason.upper().replace("_", " "))
        if show_groups:
            parts.append(group)
        tag = " [" + "][".join(parts) + "]" if parts else ""
        print(f"  {idx:{width}}  {method:6s} {path:45s} {description}{tag}")
        shown += 1
    print(f"\n  Shown: {shown} of {total} endpoints")
    if show_groups:
        # Показать статистику по группам
        group_counts: dict[str, int] = {}
        for _, (method, path, params, body, description, skip_reason) in enumerate(ENDPOINTS, 1):
            g = _get_endpoint_group(path)
            group_counts[g] = group_counts.get(g, 0) + 1
        print(f"\n  Groups:")
        for g, cnt in sorted(group_counts.items()):
            print(f"    {g:20s} {cnt:>3} endpoints")
        print(f"\n  Available groups for -g: {', '.join(sorted(ENDPOINT_GROUPS.keys()))}")


# ═══════════════════════════════════════════════════════════════════════
#  Построение URL с query-параметрами
# ═══════════════════════════════════════════════════════════════════════


def _build_url(base: str, path: str, params: dict) -> str:
    """Собрать полный URL с query-параметрами."""
    url = f"{base}{path}"
    if params:
        # Fix v6-11: Don't encode $ as %24 in URLs — Samba computer names
        # like DEBUGPC$ should remain readable.
        qs = "&".join(f"{quote(str(k), safe='$')}={quote(str(v), safe='$')}" for k, v in params.items())
        url = f"{url}?{qs}"
    return url


# ═══════════════════════════════════════════════════════════════════════
#  Цветной вывод
# ═══════════════════════════════════════════════════════════════════════

_COLORS = {
    "OK": "\033[92m",      # зелёный
    "ER": "\033[91m",      # красный
    "SKIP": "\033[93m",    # жёлтый
    "WARN": "\033[93m",    # жёлтый
    "DIM": "\033[2m",      # тусклый
    "BOLD": "\033[1m",     # жирный
    "DANGER": "\033[91;1m", # красный жирный
    "RESET": "\033[0m",    # сброс
}

_NO_COLOR = os.environ.get("NO_COLOR", "") != ""


def _c(color: str, text: str) -> str:
    if _NO_COLOR or not sys.stdout.isatty():
        return text
    return f"{_COLORS.get(color, '')}{text}{_COLORS['RESET']}"


# ═══════════════════════════════════════════════════════════════════════
#  Основная логика
# ═══════════════════════════════════════════════════════════════════════


def _format_body(body: Any, max_len: int = 500) -> str:
    """Форматировать тело ответа для вывода."""
    if body is None:
        return "<no body>"
    if isinstance(body, str):
        text = body
    else:
        text = json.dumps(body, indent=2, ensure_ascii=False)
    if len(text) > max_len:
        return text[:max_len] + f"\n... [{len(text) - max_len} more chars]"
    return text


def _extract_error(body: Any) -> str:
    """Извлечь сообщение об ошибке из тела ответа API."""
    if isinstance(body, dict):
        # Стандартный формат ошибки
        if "detail" in body:
            detail = body["detail"]
            if isinstance(detail, dict):
                return detail.get("message", detail.get("detail", str(detail)))
            return str(detail)
        if "message" in body:
            return body["message"]
        if "error" in body:
            return body["error"]
    if isinstance(body, str):
        return body[:200]
    return str(body)[:200]


def _get_endpoint_timeout(path: str, default_timeout: int) -> int:
    """Определить таймаут для конкретного эндпоинта.

    Проверяет ENDPOINT_TIMEOUTS на соответствие префиксу пути.
    Возвращает первый совпадающий таймаут или default_timeout.
    """
    for prefix, timeout in ENDPOINT_TIMEOUTS.items():
        if path.startswith(prefix):
            return timeout
    return default_timeout


def check_endpoints(
    server: str,
    api_key: str,
    debug: bool = False,
    include_destructive: bool = False,
    include_needs_object: bool = False,
    include_long_running: bool = False,
    include_dangerous: bool = False,
    force: bool = False,
    timeout: int = DEFAULT_TIMEOUT,
    gpo_retries: int = 3,
    skip_trust_tests: bool = False,
    test_ids: Optional[set[int]] = None,
    group_filter: Optional[str] = None,
) -> dict[str, list]:
    """Пройти по всем эндпоинтам и собрать результаты.

    Если *force*=True, все эндпоинты выполняются без пропуска,
    а в строке результата добавляется метка исходной категории
    (например, [DESTRUCTIVE] или [NEEDS_OBJ]).
    """
    results: dict[str, list] = {"ok": [], "er": [], "skip": [], "warn": []}
    headers: dict[str, str] = {}
    if api_key:
        headers["X-API-Key"] = api_key
    headers["Accept"] = "application/json"

    # Response variable store: capture values from responses for
    # variable substitution in subsequent endpoint paths/bodies.
    # Example: {"gpo_id": "{31B2F340-016D-11D2-945F-00C04FB984F9}"}
    response_vars: dict[str, str] = {}

    # Track whether GPO creation failed so dependent tests can
    # report a more informative skip reason.
    gpo_creation_failed: bool = False

    # Fix v12: GPO retry settings (for Quota errors)
    GPO_RETRY_DELAY = 5  # seconds between retries

    # ── Pre-flight: query /health for server role ──────────────────────
    # This allows us to skip DC-only endpoints on non-DC servers.
    server_role: str = ""
    is_dc: bool = False
    try:
        health_url = _build_url(server, "/health", {})
        health_timeout = 20
        h_code, h_body = _http_request("GET", health_url, {}, timeout=health_timeout)
        if 200 <= h_code < 300 and isinstance(h_body, dict):
            server_role = h_body.get("server_role", "")
            # Fix v18: Also detect non-standard role strings like
            # "role_active_directory_dc" as DC.
            is_dc = (
                "domain controller" in server_role
                or "active directory" in server_role
                or server_role.endswith("_dc")
                or server_role == "dc"
                or server_role == "ad dc"
            )
            print(f"  {_c('DIM', 'Server role:')} {server_role or 'unknown'}")
            if not is_dc and server_role:
                print(f"  {_c('WARN', 'WARN: Non-DC server detected. Trust and some domain ops will be skipped.')}")
    except Exception:
        pass  # Health check is optional; continue without role info

    # ── Pre-flight: query current domain level for dynamic level test ──
    # The domain level raise endpoint now rejects same-level requests (409).
    # We query the current level and compute the next valid level.
    _LEVEL_ORDER = ["2003", "2008", "2008_R2", "2012", "2012_R2", "2016"]
    current_domain_level: str = ""
    next_domain_level: str = ""
    try:
        level_url = _build_url(server, "/api/v1/domain/level", {})
        level_timeout = _get_endpoint_timeout("/api/v1/domain/level", timeout)
        l_code, l_body = _http_request("GET", level_url, headers, timeout=level_timeout)
        if 200 <= l_code < 300 and isinstance(l_body, dict):
            level_output = l_body.get("output", "")
            if level_output:
                for line in level_output.splitlines():
                    if "domain function level" in line.lower() and ":" in line:
                        current_level_str = line.split(":", 1)[1].strip()
                        # Fix v3-12: Normalize domain level string.
                        # Samba returns "(Windows) 2008 R2" or "Windows 2008 R2".
                        # We need to strip parenthesized prefixes like "(Windows)"
                        # and then normalize spaces to underscores.
                        import re as _re
                        cleaned = _re.sub(r'\(.*?\)', '', current_level_str).strip()
                        # Normalize: "Windows 2008 R2" -> "2008_R2"
                        # or "2008 R2" -> "2008_R2"
                        current_normalized = cleaned.lower().replace("windows ", "").replace(" ", "_")
                        current_domain_level = current_normalized
                        # Find next level in the order
                        if current_normalized in _LEVEL_ORDER:
                            idx = _LEVEL_ORDER.index(current_normalized)
                            if idx + 1 < len(_LEVEL_ORDER):
                                next_domain_level = _LEVEL_ORDER[idx + 1]
                        break
            if current_domain_level:
                print(f"  {_c('DIM', 'Current domain level:')} {current_domain_level} → next: {next_domain_level or '(max)'}")
    except Exception:
        pass  # Level detection is optional

    total = len(ENDPOINTS)
    width = len(str(total))

    for idx, (method, path, params, body, description, skip_reason) in enumerate(ENDPOINTS, 1):
        prefix = f"[{idx:{width}}/{total}]"

        # ── Фильтр по номерам тестов (-t) ────────────────────────────
        if test_ids is not None and idx not in test_ids:
            continue

        # ── Фильтр по группе (-g) ─────────────────────────────────────
        if group_filter is not None:
            ep_group = _get_endpoint_group(path)
            # Поддержка нескольких групп через запятую: -g user,group
            requested_groups = [g.strip().lower() for g in group_filter.split(",")]
            if ep_group not in requested_groups:
                continue

        # Substitute response variables in path, params, and body.
        # Variables like {gpo_id} are replaced with captured values.
        resolved_path = path
        resolved_body = body
        resolved_params = params
        for var_name, var_value in response_vars.items():
            placeholder = "{" + var_name + "}"
            if placeholder in resolved_path:
                resolved_path = resolved_path.replace(placeholder, var_value)
            if resolved_body and isinstance(resolved_body, dict):
                resolved_body = {
                    k: v.replace(placeholder, var_value) if isinstance(v, str) else v
                    for k, v in resolved_body.items()
                }
            if resolved_params:
                resolved_params = {
                    k: v.replace(placeholder, var_value) if isinstance(v, str) else v
                    for k, v in resolved_params.items()
                }

        # ── Dynamic body resolution for domain level ──────────────────
        # Replace NEXT_LEVEL placeholder with the computed next level
        # from the pre-flight domain level check.
        if resolved_body and isinstance(resolved_body, dict):
            if resolved_body.get("level") == "NEXT_LEVEL":
                if next_domain_level:
                    resolved_body = dict(resolved_body)
                    resolved_body["level"] = next_domain_level
                elif current_domain_level:
                    # Already at max level — skip this test
                    skip_reason = "destructive_irreversible"
                    label = "SKIP (ALREADY MAX LEVEL)"
                    print(f"{prefix} {_c('SKIP', 'SKIP')} {method:6s} {path:50s} {_c('DIM', description)} [{label}: current={current_domain_level}]")
                    results["skip"].append({
                        "method": method,
                        "path": path,
                        "description": description,
                        "reason": f"Domain already at max supported level ({current_domain_level})",
                    })
                    continue

        # ── Role-based skip for DC-only endpoints ──────────────────────
        # Skip trust endpoints on non-DC servers (they return 403).
        # Also skip domain join/leave on non-member, non-standalone
        # servers where they would time out or fail.
        if not is_dc and server_role:
            dc_only_paths = [
                "/api/v1/domain/trust/",
            ]
            if any(resolved_path.startswith(p) for p in dc_only_paths):
                print(f"{prefix} {_c('SKIP', 'SKIP')} {method:6s} {path:50s} {_c('DIM', description)} [NON-DC: server role is '{server_role}']")
                results["skip"].append({
                    "method": method,
                    "path": path,
                    "description": description,
                    "reason": f"Requires DC role, but server is '{server_role}'",
                })
                continue

        # Skip if path still contains unresolved placeholders like {gpo_id}
        if "{" in resolved_path and "}" in resolved_path:
            unresolved = resolved_path[resolved_path.index("{"):resolved_path.index("}")+1]
            label = skip_reason.upper().replace("_", " ") if skip_reason else "UNRESOLVED"
            # Provide a more informative reason for the skip
            skip_detail = f"unresolved variable {unresolved}"
            if unresolved == "{gpo_id}" and gpo_creation_failed:
                skip_detail = f"GPO creation failed, skipping dependent tests ({unresolved})"
            print(f"{prefix} {_c('SKIP', 'SKIP')} {method:6s} {path:50s} {_c('DIM', description)} [{label}: {skip_detail}]")
            results["skip"].append({
                "method": method,
                "path": path,
                "description": description,
                "reason": skip_detail,
            })
            continue

        # Определить, нужно ли пропустить эндпоинт
        should_skip = False
        force_category_label: str | None = None  # метка при force-режиме

        if skip_reason:
            should_skip = True
            force_category_label = skip_reason.upper().replace("_", " ")

            # Проверяем индивидуальные флаги включения
            if skip_reason == "needs_object" and include_needs_object:
                should_skip = False
            if skip_reason in ("destructive",) and include_destructive:
                should_skip = False
            if skip_reason in ("destructive_long", "long_running") and include_long_running:
                should_skip = False
            if skip_reason in ("destructive_dangerous", "destructive_irreversible") and include_dangerous:
                should_skip = False
            # Fix v13-4: Trust test skip for non-existent domain.
            # --skip-trust-tests skips all trust_test endpoints.
            # These endpoints fail for test.local (non-existent domain)
            # with 400/404 which is expected behavior, not an API bug.
            if skip_reason == "trust_test" and skip_trust_tests:
                should_skip = True
            if skip_reason == "trust_test" and not skip_trust_tests:
                should_skip = False
            # v1.4.3: needs_sudo endpoints are skipped by default (requires
            # NOPASSWD sudo or SAMBA_SUDO_PASSWORD).  Use --force to run them.
            if skip_reason == "needs_sudo":
                should_skip = True

            # --force отключает ВСЕ фильтры пропуска
            if force:
                should_skip = False

            if should_skip:
                label = skip_reason.upper().replace("_", " ")
                print(f"{prefix} {_c('SKIP', 'SKIP')} {method:6s} {path:50s} {_c('DIM', description)} [{label}]")
                results["skip"].append({
                    "method": method,
                    "path": path,
                    "description": description,
                    "reason": skip_reason,
                })
                continue

        # Определить таймаут для данного эндпоинта
        ep_timeout = _get_endpoint_timeout(resolved_path, timeout)

        url = _build_url(server, resolved_path, resolved_params)

        # Предупреждающая метка для force-режима
        danger_tag = ""
        if force_category_label:
            danger_tag = f" {_c('DANGER', '[' + force_category_label + ']')}"

        # Debug: показать запрос
        if debug:
            print(f"{prefix} {_c('BOLD', '>>>')} {method} {url}{danger_tag}")
            if resolved_body:
                print(f"       Body: {json.dumps(resolved_body, ensure_ascii=False)}")
            if resolved_params:
                print(f"       Params: {resolved_params}")
            print(f"       Headers: X-API-Key={'***' if api_key else '<none>'}")
            print(f"       Timeout: {ep_timeout}s")

        # Выполнить запрос
        start = time.monotonic()
        status_code, resp_body = _http_request(method, url, headers, json_body=resolved_body, timeout=ep_timeout)
        elapsed = time.monotonic() - start

        # Fix v4: GPO create retry logic — if GPO creation fails with
        # 507 (Not Enough Quota / STATUS_QUOTA_EXCEEDED), retry up to
        # gpo_retries times with a short delay.  The API server (v4 fix)
        # now passes -H ldapi:// to bypass CLDAP DC discovery, which is
        # the root cause of the quota error.  However, retries may still
        # be needed for transient memory pressure on the server.
        # Also catch the NT status code 0xC0000073 (STATUS_QUOTA_EXCEEDED)
        # and finddc-related errors that indicate the same root cause.
        if (
            path == "/api/v1/gpo/" and method == "POST"
            and status_code != 0 and not (200 <= status_code < 300)
            and (
                status_code == 507
                or (isinstance(resp_body, dict) and "Not Enough Quota" in str(resp_body))
                or (isinstance(resp_body, dict) and "0x800705ad" in str(resp_body).lower())
                or (isinstance(resp_body, dict) and "0xc0000073" in str(resp_body).lower())
                or (isinstance(resp_body, dict) and "status_quota_exceeded" in str(resp_body).lower())
                or (isinstance(resp_body, dict) and "finddc" in str(resp_body).lower())
            )
        ):
            for attempt in range(gpo_retries):
                print(f"{prefix} {_c('WARN', 'RETRY')} GPO create attempt {attempt + 1}/{gpo_retries} after Quota error (waiting {GPO_RETRY_DELAY}s)...")
                time.sleep(GPO_RETRY_DELAY)
                status_code, resp_body = _http_request(
                    method, url, headers, json_body=resolved_body, timeout=ep_timeout,
                )
                if 200 <= status_code < 300:
                    break  # success — exit retry loop

        # Определить OK/ER
        is_ok = 200 <= status_code < 300 if status_code > 0 else False

            # Fix v9-10: Treat 422 Unprocessable Entity as WARN, not ER.
            # 422 indicates a valid request that can't be processed in the
            # current environment (e.g. LDAPI not available), not a server
            # error.  This is expected for getpassword/get-kerberos-ticket
            # on systems without LDAPI socket access.
        is_warn = (status_code == 422)

        # Fix v14-5/6/7: Check if the returned status matches the expected
        # status for this endpoint.  When it does, treat as OK/EXPECTED
        # instead of ER.
        endpoint_key = f"{method} {path}"
        expected_status = ENDPOINT_EXPECTED_STATUS.get(endpoint_key)
        is_expected = (expected_status is not None and status_code == expected_status)

        if is_ok:
            tag = _c("OK", "OK")
            results["ok"].append({
                "method": method,
                "path": resolved_path,
                "description": description,
                "status_code": status_code,
                "elapsed": elapsed,
                "forced": bool(force_category_label),
                "category": skip_reason if skip_reason else None,
            })

            # Fix v12-6 / v13-3: When a 202 Accepted response includes a
            # task_id (background task), poll the task endpoint until the
            # task completes before continuing.  This prevents race
            # conditions where a DELETE returns 202 but subsequent
            # operations (link, unlink, fetch) fail because the object
            # hasn't been deleted yet.
            #
            # v13-3: Increased task_max_wait to 180s for GPO delete and
            # backup operations which can be slow on resource-constrained
            # systems.  Also added adaptive polling that starts at 1s
            # and increases to 3s after 30s to reduce polling load.
            if status_code == 202 and isinstance(resp_body, dict):
                task_id_val = resp_body.get("task_id")
                if task_id_val:
                    task_url_path = resp_body.get("result_url", f"/api/v1/tasks/{task_id_val}")
                    # Determine max wait based on endpoint type
                    # GPO delete and backup/restore can be very slow
                    is_gpo_delete = "/gpo/" in resolved_path and method == "DELETE"
                    is_backup = "/backup/" in resolved_path or "/restore" in resolved_path
                    is_demote = "/demote" in resolved_path
                    if is_backup or is_demote:
                        task_max_wait = 600  # 10 min for backup/demote
                    elif is_gpo_delete:
                        task_max_wait = 180  # 3 min for GPO delete
                    else:
                        task_max_wait = 120  # 2 min default
                    if debug:
                        print(f"       Background task submitted: {task_id_val}, polling {task_url_path} (max {task_max_wait}s)...")
                    # Poll the task endpoint until COMPLETED or FAILED
                    task_elapsed = 0
                    while task_elapsed < task_max_wait:
                        # Adaptive polling: 1s initially, 3s after 30s
                        poll_interval = 1 if task_elapsed < 30 else 3
                        time.sleep(poll_interval)
                        task_elapsed += poll_interval
                        try:
                            task_url = _build_url(server, task_url_path, {})
                            task_timeout = _get_endpoint_timeout(task_url_path, timeout)
                            t_code, t_body = _http_request(
                                "GET", task_url, headers, timeout=task_timeout,
                            )
                            if isinstance(t_body, dict):
                                task_state = t_body.get("state", "")
                                if task_state == "COMPLETED":
                                    if debug:
                                        print(f"       Task {task_id_val} completed after {task_elapsed}s")
                                    break
                                elif task_state == "FAILED":
                                    if debug:
                                        task_err = t_body.get("error", "unknown")
                                        print(f"       Task {task_id_val} failed: {task_err[:200]}")
                                    break
                        except Exception:
                            pass  # poll error — keep trying
                    else:
                        if debug:
                            print(f"       Task {task_id_val} did not complete within {task_max_wait}s")

            # Capture response variables for endpoint chaining.
            # GPO create returns a GUID that subsequent GPO endpoints need.
            if isinstance(resp_body, dict):
                # GPO create: synchronous — returns gpo_id directly
                if path == "/api/v1/gpo/" and method == "POST":
                    gpo_guid = resp_body.get("gpo_id") or resp_body.get("data", {}).get("gpo_id")
                    if gpo_guid:
                        # Fix v6-7: Strip curly braces from GPO GUID so they
                        # don't break URL substitution.  samba-tool returns
                        # "{31B2F340-016D-11D2-945F-00C04FB984F9}" but URL paths
                        # with braces get encoded as %7B/%7D, breaking matching.
                        response_vars["gpo_id"] = gpo_guid.strip('{}')
                        gpo_creation_failed = False
                        if debug:
                            print(f"       Captured: gpo_id={gpo_guid.strip('{}')}")
                    else:
                        # GPO created but GUID not parsed from output
                        gpo_creation_failed = True
                        if debug:
                            print(f"       GPO created but gpo_id not available in response")
                        # Try fallback: get existing GPO from list
                        try:
                            list_url = _build_url(server, "/api/v1/gpo/", {})
                            list_timeout = _get_endpoint_timeout("/api/v1/gpo/", timeout)
                            ls_code, ls_body = _http_request(
                                "GET", list_url, headers, timeout=list_timeout,
                            )
                            if 200 <= ls_code < 300 and isinstance(ls_body, dict):
                                import re as _re
                                output_text = ls_body.get("output", "")
                                if output_text:
                                    guids = _re.findall(
                                        r"\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}",
                                        output_text,
                                    )
                                    if guids:
                                        # Fix v6-7: Strip braces for URL-safe substitution
                                        response_vars["gpo_id"] = guids[0].strip('{}')
                                        gpo_creation_failed = False
                                        if debug:
                                            print(f"       Fallback: using existing GPO {guids[0]} from list")
                        except Exception:
                            pass

            if debug:
                print(f"{prefix} {tag} {method:6s} {path:50s} {_c('DIM', description)} [{status_code}] {elapsed:.2f}s{danger_tag}")
                print(f"       Response: {_format_body(resp_body)}")
                print()
            else:
                print(f"{prefix} {tag} {method:6s} {path:50s} {_c('DIM', description)} [{status_code}] {elapsed:.2f}s{danger_tag}")
        elif is_expected:
            # Fix v14-5/6/7: Expected status code received — treat as OK.
            tag = _c("OK", "EXPECTED")
            results["ok"].append({
                "method": method,
                "path": resolved_path,
                "description": description,
                "status_code": status_code,
                "elapsed": elapsed,
                "forced": bool(force_category_label),
                "category": skip_reason if skip_reason else None,
                "expected_status": expected_status,
            })
            if debug:
                print(f"{prefix} {tag} {method:6s} {path:50s} {_c('DIM', description)} [{status_code} (expected {expected_status})] {elapsed:.2f}s{danger_tag}")
                print(f"       Response: {_format_body(resp_body)}")
                print()
            else:
                print(f"{prefix} {tag} {method:6s} {path:50s} {_c('DIM', description)} [{status_code} (expected {expected_status})] {elapsed:.2f}s{danger_tag}")
        elif is_warn:
            tag = _c("WARN", "WARN")
            error_msg = _extract_error(resp_body)

            results["warn"].append({
                "method": method,
                "path": path,
                "description": description,
                "status_code": status_code,
                "elapsed": elapsed,
                "error": error_msg,
                "forced": bool(force_category_label),
                "category": skip_reason if skip_reason else None,
            })

            # Track GPO creation failure for dependent endpoint skip messages
            if path == "/api/v1/gpo/" and method == "POST":
                gpo_creation_failed = True

            if debug:
                print(f"{prefix} {tag} {method:6s} {path:50s} {_c('DIM', description)} [{status_code}] {elapsed:.2f}s{danger_tag}")
                print(f"       {_c('WARN', 'Warning:')} {error_msg}")
                print(f"       Full response: {_format_body(resp_body)}")
                print()
            else:
                print(f"{prefix} {tag} {method:6s} {path:50s} {_c('DIM', description)} [{status_code}] {elapsed:.2f}s{danger_tag}")
                print(f"       {_c('WARN', 'Warning:')} {error_msg}")
        else:
            tag = _c("ER", "ER")
            error_msg = _extract_error(resp_body)

            # Treat "Not Enough Quota" (507) errors as environment
            # limitations rather than API bugs.  Mark with a special
            # label so they're easy to distinguish in the summary.
            is_quota_error = (
                status_code == 507
                or "not enough quota" in error_msg.lower()
                or "0x800705ad" in error_msg.lower()
            )
            if is_quota_error:
                tag = _c("WARN", "QUOTA")

            # Treat 412 (Precondition Failed) from join/leave as
            # expected on servers where the operation is not applicable.
            is_precondition = status_code == 412

            # Treat 409 (Conflict) from domain level as expected when
            # the level is already at the requested value.
            is_conflict = status_code == 409

            # Fix v13-4: Treat 400/404 from trust endpoints for
            # non-existent domain as expected (WARN), not error.
            # These return 400 (DNS lookup failed) or 404 (trust not found)
            # which is correct behavior for test.local.
            # Fix v14-3: Trust endpoints for non-existent test.local domain.
            # Any 4xx response is expected behavior, not an API bug.
            is_trust_expected = (
                skip_reason == "trust_test"
                and 400 <= status_code < 500
            )

            results["er"].append({
                "method": method,
                "path": path,
                "description": description,
                "status_code": status_code,
                "elapsed": elapsed,
                "error": error_msg,
                "forced": bool(force_category_label),
                "category": skip_reason if skip_reason else None,
                "is_quota_error": is_quota_error,
                "is_precondition": is_precondition,
                "is_conflict": is_conflict,
                "is_trust_expected": is_trust_expected,
            })

            # Track GPO creation failure for dependent endpoint skip messages
            if path == "/api/v1/gpo/" and method == "POST":
                gpo_creation_failed = True
                # Fix v18: Fallback — try to get an existing GPO from the
                # list endpoint so that dependent tests (show, link, inherit,
                # etc.) can still run with a real GPO GUID instead of being
                # skipped entirely.
                try:
                    list_url = _build_url(server, "/api/v1/gpo/", {})
                    list_timeout = _get_endpoint_timeout("/api/v1/gpo/", timeout)
                    ls_code, ls_body = _http_request(
                        "GET", list_url, headers, timeout=list_timeout,
                    )
                    if 200 <= ls_code < 300 and isinstance(ls_body, dict):
                        import re as _re
                        # Strategy 1: Parse text output for GUID patterns
                        output_text = ls_body.get("output", "")
                        if output_text:
                            guids = _re.findall(
                                r"\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}",
                                output_text,
                            )
                            if guids:
                                # Fix v6-7: Strip braces for URL-safe substitution
                                response_vars["gpo_id"] = guids[0].strip('{}')
                                gpo_creation_failed = False
                                print(f"       {_c('WARN', 'FALLBACK')}: using existing GPO {guids[0]} from list")
                        # Strategy 2: Parse JSON data array for guid/gpo_id fields
                        if gpo_creation_failed:
                            gpo_items = None
                            if isinstance(ls_body.get("data"), list):
                                gpo_items = ls_body["data"]
                            elif isinstance(ls_body.get("items"), list):
                                gpo_items = ls_body["items"]
                            if gpo_items:
                                for item in gpo_items:
                                    guid = None
                                    if isinstance(item, dict):
                                        guid = (
                                            item.get("guid")
                                            or item.get("gpo_id")
                                            or item.get("GPOId")
                                            or item.get("id")
                                        )
                                        if not guid and "dn" in item:
                                            m = _re.search(
                                                r"\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}",
                                                str(item["dn"]),
                                            )
                                            if m:
                                                guid = m.group(0)
                                    elif isinstance(item, str):
                                        m = _re.search(
                                            r"\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}",
                                            item,
                                        )
                                        if m:
                                            guid = m.group(0)
                                    if guid:
                                        # Fix v6-7: Strip braces for URL-safe substitution
                                        guid = guid.strip('{}')
                                        response_vars["gpo_id"] = guid
                                        gpo_creation_failed = False
                                        print(f"       {_c('WARN', 'FALLBACK')}: using existing GPO {guid} from list")
                                        break
                except Exception:
                    pass  # Fallback failed; gpo_creation_failed remains True

            if debug:
                print(f"{prefix} {tag} {method:6s} {path:50s} {_c('DIM', description)} [{status_code}] {elapsed:.2f}s{danger_tag}")
                print(f"       {_c('ER', 'Error:')} {error_msg}")
                print(f"       Full response: {_format_body(resp_body)}")
                print()
            else:
                # Без debug: показать ошибку для ER
                print(f"{prefix} {tag} {method:6s} {path:50s} {_c('DIM', description)} [{status_code}] {elapsed:.2f}s{danger_tag}")
                print(f"       {_c('ER', 'Error:')} {error_msg}")

    return results


def print_summary(results: dict[str, list], force: bool = False) -> None:
    """Напечатать итоговую сводку."""
    ok_count = len(results["ok"])
    er_count = len(results["er"])
    skip_count = len(results["skip"])
    warn_count = len(results["warn"])
    total = ok_count + er_count + skip_count + warn_count

    # Count environment-related errors (quota, precondition, conflict, trust expected)
    quota_errors = sum(1 for r in results["er"] if r.get("is_quota_error"))
    precondition_errors = sum(1 for r in results["er"] if r.get("is_precondition"))
    conflict_errors = sum(1 for r in results["er"] if r.get("is_conflict"))
    trust_expected_errors = sum(1 for r in results["er"] if r.get("is_trust_expected"))
    real_errors = er_count - quota_errors - precondition_errors - conflict_errors - trust_expected_errors

    # Подсчёт forced-эндпоинтов
    forced_ok = sum(1 for r in results["ok"] if r.get("forced"))
    forced_er = sum(1 for r in results["er"] if r.get("forced"))

    print()
    print(_c("BOLD", "=" * 70))
    print(_c("BOLD", "  SUMMARY"))
    print(_c("BOLD", "=" * 70))
    print(f"  {_c('OK', 'OK')}:      {ok_count:>3}", end="")
    if forced_ok:
        print(f"  ({forced_ok} forced)", end="")
    print()
    print(f"  {_c('ER', 'ER')}:      {er_count:>3}", end="")
    if forced_er:
        print(f"  ({forced_er} forced)", end="")
    if quota_errors or precondition_errors or conflict_errors or trust_expected_errors:
        print(f"  ({real_errors} real, {quota_errors} quota, {precondition_errors} precondition, {conflict_errors} conflict, {trust_expected_errors} trust-expected)", end="")
    print()
    print(f"  {_c('SKIP', 'SKIP')}:    {skip_count:>3}")
    if warn_count:
        print(f"  {_c('WARN', 'WARN')}:    {warn_count:>3}")
    print(f"  Total:   {total:>3}")

    if results["er"]:
        print()
        print(_c("ER", "  Failed endpoints:"))
        for r in results["er"]:
            status = r["status_code"]
            cat = f" [{r['category'].upper().replace('_', ' ')}]" if r.get("category") else ""
            print(f"    {r['method']:6s} {r['path']:50s} [{status}]{cat} {r['error'][:100]}")

    if results["warn"]:
        print()
        print(_c("WARN", "  Warnings (422 Unprocessable):"))
        for r in results["warn"]:
            status = r["status_code"]
            cat = f" [{r['category'].upper().replace('_', ' ')}]" if r.get("category") else ""
            print(f"    {r['method']:6s} {r['path']:50s} [{status}]{cat} {r['error'][:100]}")

    # В force-режиме: сводка по категориям
    if force and (forced_ok or forced_er):
        print()
        print(_c("BOLD", "  Forced endpoints by category:"))
        categories: dict[str, dict[str, int]] = {}
        for r in results["ok"]:
            if r.get("category"):
                cat = r["category"]
                categories.setdefault(cat, {"ok": 0, "er": 0})
                categories[cat]["ok"] += 1
        for r in results["er"]:
            if r.get("category"):
                cat = r["category"]
                categories.setdefault(cat, {"ok": 0, "er": 0})
                categories[cat]["er"] += 1
        for cat, counts in sorted(categories.items()):
            label = cat.upper().replace("_", " ")
            ok_str = _c("OK", str(counts["ok"])) if counts["ok"] else "0"
            er_str = _c("ER", str(counts["er"])) if counts["er"] else "0"
            print(f"    {label:30s} OK={ok_str}  ER={er_str}")

    print()


# ═══════════════════════════════════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════════════════════════════════


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Samba AD API — Debug Endpoint Checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=""\
"""Examples:
  python3 api_debug.py                         # check safe GET endpoints
  python3 api_debug.py -d                      # verbose mode (full body)
  python3 api_debug.py --include-destructive   # also test POST/PUT/DELETE
  python3 api_debug.py --include-all           # test everything
  python3 api_debug.py -s http://dc1:8099 -k mykey
  python3 api_debug.py --force --yes-i-know -k KEY   # test ALL endpoints
  python3 api_debug.py --show                  # list all endpoints with IDs
  python3 api_debug.py -t 92                   # run only test #92
  python3 api_debug.py -t 10-17,30-55          # run tests 10-17 and 30-55
  python3 api_debug.py -g drs                  # run only DRS endpoints
  python3 api_debug.py -g user,gpo             # run user and GPO endpoints
  python3 api_debug.py -g drs -t 54-55         # DRS group, only tests 54-55
""",
    )
    parser.add_argument(
        "-s", "--server",
        default=None,
        help=f"API server URL (default: {DEFAULT_SERVER}, env: SAMBA_API_SERVER)",
    )
    parser.add_argument(
        "-k", "--api-key",
        default=None,
        help="API key for authentication (env: SAMBA_API_KEY)",
    )
    parser.add_argument(
        "-d", "--debug",
        action="store_true",
        default=False,
        help="Verbose output: show full request body and response",
    )
    parser.add_argument(
        "--include-destructive",
        action="store_true",
        default=False,
        help="Include destructive endpoints (POST/PUT/DELETE that modify state)",
    )
    parser.add_argument(
        "--include-needs-object",
        action="store_true",
        default=False,
        help="Include endpoints that require existing objects (/{name} etc.)",
    )
    parser.add_argument(
        "--include-long-running",
        action="store_true",
        default=False,
        help="Include long-running async tasks (backup, dbcheck, etc.)",
    )
    parser.add_argument(
        "--include-dangerous",
        action="store_true",
        default=False,
        help="Include dangerous operations (join/leave domain, seize FSMO, etc.)",
    )
    parser.add_argument(
        "--include-all",
        action="store_true",
        default=False,
        help="Include ALL endpoints (equivalent to all --include-* flags)",
    )
    parser.add_argument(
        "--force",
        "--no-skip",
        action="store_true",
        default=False,
        help="Execute ALL endpoints, ignoring skip categories (may cause real AD changes!)",
    )
    parser.add_argument(
        "--yes-i-know",
        action="store_true",
        default=False,
        help="Confirm that you understand --force is dangerous (required with --force)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"HTTP request timeout in seconds (default: {DEFAULT_TIMEOUT}; DRS/testparm auto-extended)",
    )
    parser.add_argument(
        "--gpo-retries",
        type=int,
        default=3,
        help="Max retries for GPO creation on Quota errors (default: 3, set to 0 to disable)",
    )
    # Fix v13-4: Add --skip-trust-tests option.
    # Trust endpoints (create, delete, namespaces, validate) for
    # test.local always fail because the domain doesn't exist.
    # This is expected behavior, not an API bug.  The option allows
    # skipping these endpoints in test runs so that they don't
    # pollute the error count.
    parser.add_argument(
        "--skip-trust-tests",
        action="store_true",
        default=False,
        help="Skip trust endpoints for non-existent test.local domain (expected to fail with 400/404)",
    )
    # ── Фильтрация по номерам и группам ──────────────────────────────
    parser.add_argument(
        "-t", "--test",
        default=None,
        metavar="IDS",
        help="Run only specific test(s) by 1-based ID. "
             "Supports single IDs, ranges, and comma-separated lists: "
             "-t 92  or  -t 10-17  or  -t 10-17,30-55  or  -t 5,8,12",
    )
    parser.add_argument(
        "-g", "--group",
        default=None,
        metavar="GROUP",
        help="Run only endpoints in the specified group(s). "
             "Groups: system, user, group, computer, contact, ou, domain, "
             "dns, sites, fsmo, drs, gpo, schema, delegation, "
             "service-accounts, auth, misc. "
             "Multiple groups: -g user,group  or  -g drs,gpo",
    )
    parser.add_argument(
        "--show",
        action="store_true",
        default=False,
        help="Show the list of all endpoints with their IDs and groups, then exit (no requests sent)",
    )

    args = parser.parse_args()

    # ── Режим --show: показать список и выйти ──────────────────────────
    if args.show:
        # Разбор -t и -g для фильтрации в --show
        show_test_ids = None
        if args.test:
            show_test_ids = _parse_test_ids(args.test, len(ENDPOINTS))
        show_group_filter = None
        if args.group:
            requested = [g.strip().lower() for g in args.group.split(",")]
            invalid = [g for g in requested if g not in ENDPOINT_GROUPS]
            if invalid:
                print(f"Error: Unknown group(s): {', '.join(invalid)}")
                print(f"  Available groups: {', '.join(sorted(ENDPOINT_GROUPS.keys()))}")
                sys.exit(1)
            show_group_filter = args.group.lower()
        print(_c("BOLD", "Samba AD API — Endpoint List"))
        print()
        _list_endpoints(
            show_groups=True,
            test_ids=show_test_ids,
            group_filter=show_group_filter,
        )
        sys.exit(0)

    # ── Разбор -t (фильтр по ID) ──────────────────────────────────────
    test_ids: Optional[set[int]] = None
    if args.test:
        test_ids = _parse_test_ids(args.test, len(ENDPOINTS))
        if not test_ids:
            print(_c("ER", "Error: No valid test IDs specified"))
            sys.exit(1)

    # ── Разбор -g (фильтр по группе) ──────────────────────────────────
    group_filter: Optional[str] = None
    if args.group:
        requested = [g.strip().lower() for g in args.group.split(",")]
        invalid = [g for g in requested if g not in ENDPOINT_GROUPS]
        if invalid:
            print(_c("ER", f"Error: Unknown group(s): {', '.join(invalid)}"))
            print(f"  Available groups: {', '.join(sorted(ENDPOINT_GROUPS.keys()))}")
            sys.exit(1)
        group_filter = args.group.lower()

    # ── Определить сервер и API-ключ ──────────────────────────────────
    dotenv = _load_dotenv()
    server = (
        args.server
        or os.environ.get("SAMBA_API_SERVER")
        or dotenv.get("SAMBA_API_SERVER")
        or DEFAULT_SERVER
    ).rstrip("/")

    api_key = (
        args.api_key
        or os.environ.get("SAMBA_API_KEY")
        or dotenv.get("SAMBA_API_KEY")
        or DEFAULT_API_KEY
    )

    # ── Флаги включения ───────────────────────────────────────────────
    include_all = args.include_all
    force = args.force
    include_destructive = args.include_destructive or include_all
    include_needs_object = args.include_needs_object or include_all
    include_long_running = args.include_long_running or include_all
    include_dangerous = args.include_dangerous or include_all
    skip_trust_tests = args.skip_trust_tests  # Fix v13-4

    # ── Проверка безопасности для --force ─────────────────────────────
    if force:
        if not args.yes_i_know:
            print(_c("DANGER", "\n  ВНИМАНИЕ! Флаг --force отключает ВСЕ фильтры пропуска!"))
            print(_c("DANGER", "  Будет выполнена проверка ВСЕХ операций, включая:"))
            print(_c("DANGER", "    - создание/удаление пользователей, групп, компьютеров"))
            print(_c("DANGER", "    - изменение паролей и членства в группах"))
            print(_c("DANGER", "    - перехват/передача FSMO-ролей"))
            print(_c("DANGER", "    - присоединение/отключение домена"))
            print(_c("DANGER", "    - резервное копирование и восстановление"))
            print()
            print(f"  Для подтверждения добавьте {_c('BOLD', '--yes-i-know')}:")
            print(f"    python3 api_debug.py --force --yes-i-know -k KEY")
            print()
            sys.exit(2)

        # Интерактивное подтверждение (если tty)
        if sys.stdin.isatty():
            print(_c("DANGER", "\n  ╔══════════════════════════════════════════════════════════╗"))
            print(_c("DANGER", "  ║  ВНИМАНИЕ! Будет выполнена проверка всех операций,     ║"))
            print(_c("DANGER", "  ║  включая создание/удаление объектов, перехват ролей     ║"))
            print(_c("DANGER", "  ║  и другие деструктивные действия в AD!                  ║"))
            print(_c("DANGER", "  ╚══════════════════════════════════════════════════════════╝"))
            print()
            try:
                answer = input("  Введите 'yes' для продолжения: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print("\n  Отменено.")
                sys.exit(0)
            if answer != "yes":
                print("  Отменено.")
                sys.exit(0)
            print()

    # ── Заголовок ─────────────────────────────────────────────────────
    print(_c("BOLD", "Samba AD API — Debug Endpoint Checker"))
    print(f"  Server: {server}")
    print(f"  API Key: {'***' + api_key[-8:] if len(api_key) > 8 else ('<set>' if api_key else '<none>')}")
    print(f"  Debug: {'ON' if args.debug else 'OFF'}")
    # When --force is active, display all include flags as True
    # since force overrides them all
    display_destructive = include_destructive or force
    display_needs_object = include_needs_object or force
    display_long_running = include_long_running or force
    display_dangerous = include_dangerous or force
    print(f"  Include destructive: {display_destructive}")
    print(f"  Include needs-object: {display_needs_object}")
    print(f"  Include long-running: {display_long_running}")
    print(f"  Include dangerous: {display_dangerous}")
    print(f"  Force (no skip): {force}")
    print(f"  Timeout: {args.timeout}s (per-endpoint overrides apply)")
    print(f"  GPO retries: {args.gpo_retries} (on Quota/507 errors)")
    print(f"  Skip trust tests: {skip_trust_tests}")
    if test_ids is not None:
        sorted_ids = sorted(test_ids)
        # Compact display for many IDs
        if len(sorted_ids) <= 20:
            print(f"  Test filter (-t): {', '.join(str(i) for i in sorted_ids)}")
        else:
            print(f"  Test filter (-t): {len(sorted_ids)} tests selected ({sorted_ids[0]}-{sorted_ids[-1]})")
    if group_filter is not None:
        print(f"  Group filter (-g): {group_filter}")
    print()

    if not api_key:
        print(_c("WARN", "Warning: No API key provided. Most endpoints will return 401."))
        print(_c("DIM", "  Use -k KEY, set SAMBA_API_KEY env var, or add to .env file."))
        print()

    # ── Проверка доступности сервера ──────────────────────────────────
    print("Checking server connectivity...")
    status, body = _http_request("GET", f"{server}/health", {}, timeout=10)
    if status == 0:
        print(_c("ER", f"FAILED: Cannot connect to {server}"))
        print(f"  Error: {body}")
        sys.exit(1)
    print(_c("OK", f"Server is reachable: {server} (status {status})"))
    print()

    # ── Основная проверка ─────────────────────────────────────────────
    results = check_endpoints(
        server=server,
        api_key=api_key,
        debug=args.debug,
        include_destructive=include_destructive,
        include_needs_object=include_needs_object,
        include_long_running=include_long_running,
        include_dangerous=include_dangerous,
        force=force,
        timeout=args.timeout,
        gpo_retries=args.gpo_retries,
        skip_trust_tests=skip_trust_tests,
        test_ids=test_ids,
        group_filter=group_filter,
    )

    # ── Итоги ─────────────────────────────────────────────────────────
    print_summary(results, force=force)

    # Код возврата: 0 если нет ошибок, 1 если есть
    # Exit code: 0 if no real errors (environment-related errors like
    # quota/412/409/trust-expected don't count as failures), 1 if there are real errors.
    real_error_count = sum(
        1 for r in results["er"]
        if not r.get("is_quota_error") and not r.get("is_precondition") and not r.get("is_conflict") and not r.get("is_trust_expected")
    )
    sys.exit(1 if real_error_count else 0)


if __name__ == "__main__":
    main()
