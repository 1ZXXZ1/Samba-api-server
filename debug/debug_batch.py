#!/usr/bin/env python3
"""
Samba AD API — Batch Endpoint Debug Script.

Tests the POST /api/v1/batch endpoint with various scenarios:
  1. Simple sequential operations (create user + group, add member, shell verify)
  2. Template substitution ({{ step_id.field }}, {{ batch_id }})
  3. Rollback on failure
  4. stop_on_failure=False (continue on error)
  5. Edge cases (empty batch, unknown method, etc.)

Usage:
    python3 debug_batch.py                          # run all tests
    python3 debug_batch.py -s http://localhost:8099  # custom server
    python3 debug_batch.py -k YOUR_API_KEY          # custom API key
    python3 debug_batch.py -t 1-3                   # run only tests 1-3
    python3 debug_batch.py -d                       # debug output (verbose)
    python3 debug_batch.py --cleanup                # cleanup created objects after test

Environment variables:
    SAMBA_API_SERVER  — default http://127.0.0.1:8099
    SAMBA_API_KEY     — API key for authentication
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Optional

# ── HTTP client ───────────────────────────────────────────────────────

try:
    import requests
    _HAS_REQUESTS = True
except ImportError:
    import urllib.request
    import urllib.error
    _HAS_REQUESTS = False

DOTENV_PATH = Path(__file__).resolve().parent.parent / ".env"


def _load_dotenv() -> dict[str, str]:
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


def _http_request(
    method: str,
    url: str,
    headers: dict[str, str],
    json_body: Optional[dict] = None,
    timeout: int = 120,
) -> tuple[int, Any]:
    if _HAS_REQUESTS:
        try:
            resp = requests.request(method, url, headers=headers, json=json_body, timeout=timeout)
            try:
                body = resp.json()
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
        except Exception as exc:
            return 0, f"Request error: {exc}"


# ── Colors ────────────────────────────────────────────────────────────

_COLORS = {
    "OK": "\033[92m",
    "ER": "\033[91m",
    "SKIP": "\033[93m",
    "DIM": "\033[2m",
    "BOLD": "\033[1m",
    "RESET": "\033[0m",
}
_NO_COLOR = os.environ.get("NO_COLOR", "") != ""


def _c(color: str, text: str) -> str:
    if _NO_COLOR or not sys.stdout.isatty():
        return text
    return f"{_COLORS.get(color, '')}{text}{_COLORS['RESET']}"


# ═══════════════════════════════════════════════════════════════════════
#  Test definitions
# ═══════════════════════════════════════════════════════════════════════

BATCH_TESTS: list[dict[str, Any]] = [
    # ── Test 1: Simple create user + shell verify ────────────────────
    {
        "name": "Create user + shell verify (basic sequential)",
        "description": "Create a user with random_password, then verify with shell exec",
        "batch": {
            "actions": [
                {
                    "id": "step1",
                    "method": "user.create",
                    "params": {
                        "username": "batch_test_{{ batch_id }}",
                        "random_password": True,
                    },
                },
                {
                    "id": "step2",
                    "method": "shell.exec",
                    "params": {
                        "shell": "bash",
                        "cmd": "id batch_test_{{ batch_id }}",
                        "timeout": 10,
                    },
                },
            ],
            "stop_on_failure": True,
        },
        "cleanup": {
            "method": "user.delete",
            "params_key": "step1",
            "param_name": "username",
        },
    },

    # ── Test 2: Create user + group + add member ─────────────────────
    {
        "name": "Create user + group + add member",
        "description": "Create a user, create a group, add user to group, list members",
        "batch": {
            "actions": [
                {
                    "id": "step1",
                    "method": "user.create",
                    "params": {
                        "username": "batch_user_{{ batch_id }}",
                        "random_password": True,
                    },
                },
                {
                    "id": "step2",
                    "method": "group.create",
                    "params": {
                        "groupname": "batch_group_{{ batch_id }}",
                    },
                },
                {
                    "id": "step3",
                    "method": "group.addmembers",
                    "params": {
                        "groupname": "batch_group_{{ batch_id }}",
                        "members": ["batch_user_{{ batch_id }}"],
                    },
                },
                {
                    "id": "step4",
                    "method": "group.listmembers",
                    "params": {
                        "groupname": "batch_group_{{ batch_id }}",
                    },
                },
            ],
            "stop_on_failure": True,
        },
        "cleanup": [
            {"method": "group.delete", "params_from": {"groupname": "batch_group_{{ batch_id }}"}},
            {"method": "user.delete", "params_from": {"username": "batch_user_{{ batch_id }}"}},
        ],
    },

    # ── Test 3: Template substitution with step reference ─────────────
    {
        "name": "Template {{ step1.created_user }} substitution",
        "description": "Create user, then use created_user context to add to group",
        "batch": {
            "actions": [
                {
                    "id": "step1",
                    "method": "user.create",
                    "params": {
                        "username": "tmpl_test_{{ batch_id }}",
                        "random_password": True,
                    },
                },
                {
                    "method": "user.enable",
                    "params": {
                        "username": "{{ step1.created_user }}",
                    },
                },
            ],
            "stop_on_failure": True,
        },
        "cleanup": {
            "method": "user.delete",
            "params_from_template": {"username": "tmpl_test_{{ batch_id }}"},
        },
    },

    # ── Test 4: Rollback on failure ──────────────────────────────────
    {
        "name": "Rollback on failure (create user + fail + auto-delete)",
        "description": "Create a user, then trigger a deliberate error. "
                       "With rollback_on_failure=True, the user should be auto-deleted.",
        "batch": {
            "actions": [
                {
                    "id": "step1",
                    "method": "user.create",
                    "params": {
                        "username": "rb_test_{{ batch_id }}",
                        "random_password": True,
                    },
                },
                {
                    "id": "step2",
                    "method": "user.create",
                    "params": {
                        "username": "rb_test_{{ batch_id }}",  # Duplicate — will fail
                        "random_password": True,
                    },
                },
            ],
            "rollback_on_failure": True,
            "stop_on_failure": True,
        },
        "expect_status": "failed",
        "note": "User rb_test_{{ batch_id }} should be auto-deleted by rollback",
    },

    # ── Test 5: stop_on_failure=False (partial_failure) ──────────────
    {
        "name": "stop_on_failure=False (partial failure mode)",
        "description": "Create a user (OK), try unknown method (fail), list users (OK)",
        "batch": {
            "actions": [
                {
                    "id": "step1",
                    "method": "user.create",
                    "params": {
                        "username": "pf_test_{{ batch_id }}",
                        "random_password": True,
                    },
                },
                {
                    "id": "step2",
                    "method": "nonexistent.method",
                    "params": {},
                },
                {
                    "id": "step3",
                    "method": "user.list",
                    "params": {},
                },
            ],
            "stop_on_failure": False,
        },
        "expect_status": "partial_failure",
        "cleanup": {
            "method": "user.delete",
            "params_from_template": {"username": "pf_test_{{ batch_id }}"},
        },
    },

    # ── Test 6: DNS zone + record operations ─────────────────────────
    {
        "name": "DNS zone + record operations",
        "description": "Create DNS zone, add A record, list records, delete record, delete zone",
        "batch": {
            "actions": [
                {
                    "id": "step1",
                    "method": "dns.zone.create",
                    "params": {
                        "zone": "batch-dns-{{ batch_id }}.test",
                        "dns_directory_partition": "domain",
                    },
                },
                {
                    "id": "step2",
                    "method": "dns.record.create",
                    "params": {
                        "zone": "batch-dns-{{ batch_id }}.test",
                        "name": "testrec",
                        "record_type": "A",
                        "data": "10.0.0.1",
                    },
                },
                {
                    "id": "step3",
                    "method": "dns.record.list",
                    "params": {
                        "zone": "batch-dns-{{ batch_id }}.test",
                    },
                },
                {
                    "id": "step4",
                    "method": "dns.record.delete",
                    "params": {
                        "zone": "batch-dns-{{ batch_id }}.test",
                        "name": "testrec",
                        "record_type": "A",
                        "data": "10.0.0.1",
                    },
                },
                {
                    "id": "step5",
                    "method": "dns.zone.delete",
                    "params": {
                        "zone": "batch-dns-{{ batch_id }}.test",
                    },
                },
            ],
            "stop_on_failure": True,
        },
    },

    # ── Test 7: OU create + list + delete ────────────────────────────
    {
        "name": "OU create + list + delete",
        "description": "Create OU, list OUs, delete OU",
        "batch": {
            "actions": [
                {
                    "id": "step1",
                    "method": "ou.create",
                    "params": {
                        "ouname": "OU=batch_ou_{{ batch_id }},DC=kcrb,DC=local",
                    },
                },
                {
                    "id": "step2",
                    "method": "ou.list",
                    "params": {},
                },
                {
                    "id": "step3",
                    "method": "ou.delete",
                    "params": {
                        "ouname": "OU=batch_ou_{{ batch_id }},DC=kcrb,DC=local",
                    },
                },
            ],
            "stop_on_failure": True,
        },
    },

    # ── Test 8: SPN add + list + delete ──────────────────────────────
    {
        "name": "SPN add + list + delete",
        "description": "Add SPN to Administrator, list SPNs, delete SPN",
        "batch": {
            "actions": [
                {
                    "id": "step1",
                    "method": "misc.spn.add",
                    "params": {
                        "accountname": "Administrator",
                        "spn": "HTTP/batch-spn-{{ batch_id }}.test",
                    },
                },
                {
                    "id": "step2",
                    "method": "misc.spn.list",
                    "params": {
                        "accountname": "Administrator",
                    },
                },
                {
                    "id": "step3",
                    "method": "misc.spn.delete",
                    "params": {
                        "accountname": "Administrator",
                        "spn": "HTTP/batch-spn-{{ batch_id }}.test",
                    },
                },
            ],
            "stop_on_failure": True,
        },
    },

    # ── Test 9: Shell script (multi-line) ────────────────────────────
    {
        "name": "Shell script (multi-line)",
        "description": "Execute a multi-line bash script via shell.script",
        "batch": {
            "actions": [
                {
                    "id": "step1",
                    "method": "shell.script",
                    "params": {
                        "shell": "bash",
                        "lines": [
                            "echo 'Batch test: {{ batch_id }}'",
                            "hostname",
                            "date",
                        ],
                        "timeout": 15,
                    },
                },
            ],
        },
    },

    # ── Test 10: Custom batch_id ─────────────────────────────────────
    {
        "name": "Custom batch_id prefix",
        "description": "Use a custom batch_id to name objects",
        "batch": {
            "batch_id": "mytest",
            "actions": [
                {
                    "id": "step1",
                    "method": "user.create",
                    "params": {
                        "username": "custom_mytest",
                        "random_password": True,
                    },
                },
            ],
        },
        "cleanup": {
            "method": "user.delete",
            "params_from_template": {"username": "custom_mytest"},
        },
    },
]


# ═══════════════════════════════════════════════════════════════════════
#  Runner
# ═══════════════════════════════════════════════════════════════════════


def _resolve_template_str(template: str, context: dict[str, str]) -> str:
    """Simple {{ key }} replacement in strings."""
    for key, value in context.items():
        template = template.replace("{{ " + key + " }}", str(value))
        template = template.replace("{{" + key + "}}", str(value))
    return template


def run_tests(
    server: str,
    api_key: str,
    debug: bool = False,
    test_ids: Optional[set[int]] = None,
    cleanup: bool = True,
) -> None:
    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if api_key:
        headers["X-API-Key"] = api_key

    total = len(BATCH_TESTS)
    ok_count = 0
    er_count = 0
    skip_count = 0

    for idx, test in enumerate(BATCH_TESTS, 1):
        if test_ids is not None and idx not in test_ids:
            continue

        name = test["name"]
        desc = test.get("description", "")
        print(f"\n{_c('BOLD', f'[{idx}/{total}]')} {name}")
        if desc:
            print(f"  {_c('DIM', desc)}")

        batch_body = test["batch"]
        url = f"{server}/api/v1/batch"

        if debug:
            print(f"  {_c('DIM', 'POST ' + url)}")
            print(f"  {_c('DIM', json.dumps(batch_body, indent=2, ensure_ascii=False)[:1000])}")

        t_start = time.monotonic()
        status_code, response = _http_request("POST", url, headers, batch_body, timeout=180)
        elapsed = time.monotonic() - t_start

        # Determine test result
        test_passed = False
        expect_status = test.get("expect_status")

        if status_code == 200 and isinstance(response, dict):
            batch_status = response.get("status", "")
            if expect_status:
                test_passed = batch_status == expect_status
            else:
                test_passed = batch_status in ("completed", "partial_failure")

            # Print step results
            steps = response.get("steps", [])
            for step in steps:
                step_status = step.get("status", "")
                step_method = step.get("method", "")
                step_id = step.get("id", "-")
                if step_status == "success":
                    print(f"    {_c('OK', 'OK')} {step_method} (id={step_id})")
                    if debug and step.get("output"):
                        output_str = json.dumps(step["output"], indent=2, ensure_ascii=False)
                        if len(output_str) > 500:
                            output_str = output_str[:500] + "..."
                        print(f"      {_c('DIM', output_str)}")
                else:
                    error_msg = step.get("error", "unknown error")
                    print(f"    {_c('ER', 'ER')} {step_method} (id={step_id}): {error_msg}")

            if batch_status:
                print(f"  Batch status: {_c('OK' if batch_status == 'completed' else 'ER', batch_status)}")
        else:
            test_passed = False
            print(f"  {_c('ER', f'HTTP {status_code}')}: {str(response)[:300]}")

        # Check for rollback
        if isinstance(response, dict) and response.get("rollback_performed"):
            print(f"  {_c('SKIP', 'Rollback performed')}")

        elapsed_str = f"{elapsed:.1f}s"
        if test_passed:
            print(f"  {_c('OK', 'PASS')} ({elapsed_str})")
            ok_count += 1
        else:
            print(f"  {_c('ER', 'FAIL')} ({elapsed_str})")
            er_count += 1

        # Cleanup
        if cleanup and isinstance(response, dict):
            batch_id = response.get("batch_id", "")
            ctx = {"batch_id": batch_id}

            # Extract step context for cleanup
            steps_data = response.get("steps", [])
            for step in steps_data:
                step_id = step.get("id")
                if step_id and step.get("status") == "success" and step.get("output"):
                    output = step["output"]
                    if isinstance(output, dict):
                        ctx[step_id] = output

            # Perform cleanup
            cleanup_spec = test.get("cleanup")
            if cleanup_spec:
                if isinstance(cleanup_spec, dict):
                    cleanup_list = [cleanup_spec]
                else:
                    cleanup_list = cleanup_spec

                for cleanup_item in cleanup_list:
                    method = cleanup_item.get("method", "")
                    if "params_from" in cleanup_item:
                        params = cleanup_item["params_from"]
                    elif "params_from_template" in cleanup_item:
                        params = _resolve_template_str(
                            json.dumps(cleanup_item["params_from_template"]),
                            ctx,
                        )
                        try:
                            params = json.loads(params)
                        except Exception:
                            continue
                    else:
                        continue

                    # Resolve templates in params
                    params_str = json.dumps(params)
                    params_str = _resolve_template_str(params_str, ctx)
                    try:
                        params = json.loads(params_str)
                    except Exception:
                        continue

                    try:
                        cleanup_url = f"{server}/api/v1/batch"
                        cleanup_body = {
                            "actions": [{"method": method, "params": params}],
                            "stop_on_failure": False,
                        }
                        _http_request("POST", cleanup_url, headers, cleanup_body, timeout=60)
                        print(f"    {_c('DIM', f'Cleanup: {method} OK')}")
                    except Exception as exc:
                        print(f"    {_c('SKIP', f'Cleanup: {method} failed: {exc}')}")

    # Summary
    print(f"\n{'='*60}")
    print(f"  Total: {total}  OK: {_c('OK', str(ok_count))}  "
          f"FAIL: {_c('ER', str(er_count))}  "
          f"SKIP: {_c('SKIP', str(skip_count))}")
    print(f"{'='*60}")


# ═══════════════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════════════


def _parse_test_ids(spec: str, total: int) -> set[int]:
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
                continue
            lo = max(1, lo)
            hi = min(total, hi)
            result.update(range(lo, hi + 1))
        else:
            try:
                n = int(part)
                if 1 <= n <= total:
                    result.add(n)
            except ValueError:
                continue
    return result


def main() -> None:
    dotenv = _load_dotenv()
    default_server = dotenv.get("SAMBA_API_SERVER", "http://127.0.0.1:8099")
    default_key = dotenv.get("SAMBA_API_KEY", "")

    parser = argparse.ArgumentParser(
        description="Samba AD API — Batch Endpoint Debug Script",
    )
    parser.add_argument(
        "-s", "--server", default=default_server,
        help=f"API server URL (default: {default_server})",
    )
    parser.add_argument(
        "-k", "--api-key", default=default_key,
        help="API key for X-API-Key header",
    )
    parser.add_argument(
        "-d", "--debug", action="store_true",
        help="Verbose output (show request/response bodies)",
    )
    parser.add_argument(
        "-t", "--tests", default=None,
        help="Run specific tests by number (e.g. -t 1-3,5)",
    )
    parser.add_argument(
        "--no-cleanup", action="store_true",
        help="Skip cleanup of created objects",
    )
    args = parser.parse_args()

    test_ids = None
    if args.tests:
        test_ids = _parse_test_ids(args.tests, len(BATCH_TESTS))

    print(f"{_c('BOLD', 'Samba AD API — Batch Endpoint Debug')}")
    print(f"  Server: {args.server}")
    print(f"  API Key: {'***' + args.api_key[-4:] if len(args.api_key) > 4 else '(not set)'}")
    print(f"  Tests: {len(BATCH_TESTS)}")
    print()

    # Pre-flight health check
    h_code, h_body = _http_request("GET", f"{args.server}/health", {}, timeout=10)
    if 200 <= h_code < 300:
        if isinstance(h_body, dict):
            role = h_body.get("server_role", "unknown")
            print(f"  {_c('OK', 'Health OK')} — role: {role}")
    else:
        print(f"  {_c('ER', f'Health check failed (HTTP {h_code})')}")

    run_tests(
        server=args.server,
        api_key=args.api_key,
        debug=args.debug,
        test_ids=test_ids,
        cleanup=not args.no_cleanup,
    )


if __name__ == "__main__":
    main()
