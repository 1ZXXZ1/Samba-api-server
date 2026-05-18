#!/usr/bin/env python3
"""
Samba AD DC Management API — CLI Client.

A comprehensive command-line interface for the Samba AD DC Management
REST API server.  Uses *click* for command parsing and *requests* for
HTTP communication.

Usage examples::

    # List all users (--api-key BEFORE the subcommand)
    python cli.py --api-key secret user list

    # Create a user
    python cli.py --api-key secret user create jdoe --password 'P@ssw0rd'

    # Show domain info
    python cli.py --api-key secret domain info

    # RECOMMENDED: Use environment variable for API key
    export SAMBA_API_KEY=secret
    python cli.py user list

    # Alternatively, use a .env file in the current directory:
    # SAMBA_API_KEY=secret
    # SAMBA_API_SERVER=http://127.0.0.1:8099

All output is pretty-printed JSON.  On error, a message is printed to
stderr and the process exits with code 1.

IMPORTANT: The ``--api-key`` option belongs to the root command and
must appear **before** any subcommand::

    # CORRECT:
    python cli.py --api-key KEY user list

    # WRONG (click will not recognise --api-key after the subcommand):
    python cli.py user list --api-key KEY
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import click
import requests


# ═══════════════════════════════════════════════════════════════════════════
# API Client helper
# ═══════════════════════════════════════════════════════════════════════════


class APIClient:
    """Low-level HTTP client for the Samba AD DC Management API.

    Handles authentication headers, request construction, error
    checking and JSON pretty-printing so that individual CLI commands
    stay concise.
    """

    def __init__(self, base_url: str, api_key: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update(
            {
                "X-API-Key": api_key,
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )

    # ── HTTP verbs ─────────────────────────────────────────────────────

    def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        """Send a GET request and return parsed JSON."""
        resp = self.session.get(f"{self.base_url}{path}", params=self._clean(params))
        return self._handle(resp)

    def post(self, path: str, json_body: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None) -> Any:
        """Send a POST request and return parsed JSON."""
        resp = self.session.post(f"{self.base_url}{path}", json=self._clean(json_body), params=self._clean(params))
        return self._handle(resp)

    def put(self, path: str, json_body: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None) -> Any:
        """Send a PUT request and return parsed JSON."""
        resp = self.session.put(f"{self.base_url}{path}", json=self._clean(json_body), params=self._clean(params))
        return self._handle(resp)

    def delete(self, path: str, json_body: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None) -> Any:
        """Send a DELETE request and return parsed JSON."""
        resp = self.session.delete(f"{self.base_url}{path}", json=self._clean(json_body), params=self._clean(params))
        return self._handle(resp)

    # ── Helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _clean(d: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Remove None values from a dict so they aren't sent as query params."""
        if d is None:
            return None
        return {k: v for k, v in d.items() if v is not None}

    @staticmethod
    def _handle(resp: requests.Response) -> Any:
        """Check status code and return parsed JSON, or raise ClickException."""
        try:
            data = resp.json()
        except ValueError:
            data = resp.text

        if not resp.ok:
            # Try to extract a nice error message from the response body.
            if isinstance(data, dict):
                msg = data.get("detail") or data.get("message") or data.get("error") or json.dumps(data)
            else:
                msg = str(data)
            raise click.ClickException(f"API error (HTTP {resp.status_code}): {msg}")

        return data

    @staticmethod
    def pretty(data: Any) -> str:
        """Return pretty-printed JSON string."""
        return json.dumps(data, indent=2, sort_keys=True, default=str)


# ═══════════════════════════════════════════════════════════════════════════
# Helper to obtain the client from click context
# ═══════════════════════════════════════════════════════════════════════════


def _api(ctx: click.Context) -> APIClient:
    """Return the APIClient stored in the root context."""
    return ctx.find_object(APIClient)  # type: ignore[return-value]


def _out(data: Any) -> None:
    """Pretty-print JSON data to stdout."""
    click.echo(APIClient.pretty(data))


# ═══════════════════════════════════════════════════════════════════════════
# Root group
# ═══════════════════════════════════════════════════════════════════════════


def _load_dotenv() -> None:
    """Load key=value pairs from a .env file in the current directory.

    This is a minimal .env loader that does not require the ``python-dotenv``
    package.  It only sets environment variables that are not already defined.
    """
    env_path = Path(".env")
    if not env_path.is_file():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


# Load .env before click processes options.
_load_dotenv()


@click.group()
@click.option(
    "--server",
    default="http://127.0.0.1:8099",
    envvar="SAMBA_API_SERVER",
    show_default=True,
    help="Base URL of the Samba API server.",
)
@click.option(
    "--api-key",
    required=False,
    envvar="SAMBA_API_KEY",
    help=(
        "API key for authentication.  Can also be set via the "
        "SAMBA_API_KEY environment variable or a .env file.  "
        "IMPORTANT: --api-key must appear BEFORE the subcommand."
    ),
)
@click.pass_context
def cli(ctx: click.Context, server: str, api_key: Optional[str]) -> None:
    """Samba AD DC Management CLI client.

    All commands require --api-key (or SAMBA_API_KEY env var / .env file).
    Output is JSON pretty-printed by default.

    \b
    IMPORTANT: --api-key must appear BEFORE the subcommand:
      python cli.py --api-key KEY user list   (correct)
      python cli.py user list --api-key KEY   (WRONG)

    Recommended: use the SAMBA_API_KEY environment variable or a .env
    file so you don't have to pass --api-key on every invocation.
    """
    if api_key is None:
        raise click.ClickException(
            "API key is required.  Pass --api-key BEFORE the subcommand, "
            "set SAMBA_API_KEY env var, or add it to a .env file.\n"
            "\n"
            "  Correct:   python cli.py --api-key KEY user list\n"
            "  Also:      export SAMBA_API_KEY=KEY && python cli.py user list\n"
            "  Wrong:     python cli.py user list --api-key KEY"
        )
    ctx.obj = APIClient(base_url=server, api_key=api_key)


# ═══════════════════════════════════════════════════════════════════════════
# USER commands
# ═══════════════════════════════════════════════════════════════════════════


@cli.group("user", help="Manage user accounts.")
@click.pass_context
def user(ctx: click.Context) -> None:
    """User account management commands."""


@user.command("list", help="List all user accounts.")
@click.option("--verbose", is_flag=True, default=None, help="Verbose output.")
@click.option("--base-dn", default=None, help="Base DN for search.")
@click.option("--full-dn", is_flag=True, default=None, help="Show full DNs.")
@click.pass_context
def user_list(ctx: click.Context, verbose: bool, base_dn: str, full_dn: bool) -> None:
    """List all user accounts in the domain."""
    _out(_api(ctx).get("/api/v1/users/", params={"verbose": verbose, "base_dn": base_dn, "full_dn": full_dn}))


@user.command("create", help="Create a new user account.")
@click.argument("username")
@click.option("--password", default=None, help="Initial password.")
@click.option("--given-name", default=None, help="Given (first) name.")
@click.option("--surname", default=None, help="Surname (last name).")
@click.option("--must-change-at-next-login", is_flag=True, default=None, help="Force password change at next logon.")
@click.option("--random-password", is_flag=True, default=None, help="Generate a random password.")
@click.option("--userou", default=None, help="OU path for the user (e.g. OU=Users).")
@click.option("--initials", default=None, help="Initials.")
@click.option("--profile-path", default=None, help="Profile path.")
@click.option("--script-path", default=None, help="Logon script path.")
@click.option("--home-drive", default=None, help="Home drive letter.")
@click.option("--home-directory", default=None, help="Home directory path.")
@click.option("--job-title", default=None, help="Job title.")
@click.option("--department", default=None, help="Department.")
@click.option("--company", default=None, help="Company.")
@click.option("--description", default=None, help="Description.")
@click.option("--mail-address", default=None, help="Email address.")
@click.option("--telephone-number", default=None, help="Telephone number.")
@click.pass_context
def user_create(ctx: click.Context, username: str, **kwargs: Any) -> None:
    """Create a new user account in the domain."""
    body = {"username": username}
    for k, v in kwargs.items():
        if v is not None:
            body[k] = v
    _out(_api(ctx).post("/api/v1/users/", json_body=body))


@user.command("show", help="Show user account details.")
@click.argument("username")
@click.option("--attributes", default=None, help="Comma-separated list of attributes to show.")
@click.pass_context
def user_show(ctx: click.Context, username: str, attributes: Optional[str]) -> None:
    """Display details for a single user account."""
    _out(_api(ctx).get(f"/api/v1/users/{username}", params={"attributes": attributes}))


@user.command("edit", help="Edit user account attributes.")
@click.argument("username")
@click.option("--surname", default=None, help="Surname.")
@click.option("--given-name", default=None, help="Given name.")
@click.option("--description", default=None, help="Description.")
@click.option("--mail-address", default=None, help="Email address.")
@click.option("--telephone-number", default=None, help="Telephone number.")
@click.option("--department", default=None, help="Department.")
@click.option("--company", default=None, help="Company.")
@click.option("--job-title", default=None, help="Job title.")
@click.pass_context
def user_edit(ctx: click.Context, username: str, **kwargs: Any) -> None:
    """Modify attributes on an existing user account."""
    body = {k: v for k, v in kwargs.items() if v is not None}
    _out(_api(ctx).put(f"/api/v1/users/{username}", json_body=body))


@user.command("delete", help="Delete a user account.")
@click.argument("username")
@click.pass_context
def user_delete(ctx: click.Context, username: str) -> None:
    """Delete a user account from the domain."""
    _out(_api(ctx).delete(f"/api/v1/users/{username}"))


@user.command("enable", help="Enable a disabled user account.")
@click.argument("username")
@click.pass_context
def user_enable(ctx: click.Context, username: str) -> None:
    """Enable a disabled user account."""
    _out(_api(ctx).post(f"/api/v1/users/{username}/enable"))


@user.command("disable", help="Disable a user account.")
@click.argument("username")
@click.pass_context
def user_disable(ctx: click.Context, username: str) -> None:
    """Disable a user account."""
    _out(_api(ctx).post(f"/api/v1/users/{username}/disable"))


@user.command("unlock", help="Unlock a locked user account.")
@click.argument("username")
@click.pass_context
def user_unlock(ctx: click.Context, username: str) -> None:
    """Unlock a locked user account."""
    _out(_api(ctx).post(f"/api/v1/users/{username}/unlock"))


@user.command("setpassword", help="Set a user's password.")
@click.argument("username")
@click.option("--new-password", required=True, help="New password.")
@click.option("--must-change-at-next-login", is_flag=True, default=False, help="Force password change at next logon.")
@click.pass_context
def user_setpassword(ctx: click.Context, username: str, new_password: str, must_change_at_next_login: bool) -> None:
    """Set or reset a user's password."""
    _out(_api(ctx).put(f"/api/v1/users/{username}/password", json_body={"new_password": new_password, "must_change_at_next_login": must_change_at_next_login}))


@user.command("getgroups", help="List groups a user belongs to.")
@click.argument("username")
@click.pass_context
def user_getgroups(ctx: click.Context, username: str) -> None:
    """List groups that the user belongs to."""
    _out(_api(ctx).get(f"/api/v1/users/{username}/groups"))


@user.command("setexpiry", help="Set user account expiry.")
@click.argument("username")
@click.option("--days", required=True, type=int, help="Days until expiry.")
@click.pass_context
def user_setexpiry(ctx: click.Context, username: str, days: int) -> None:
    """Set the number of days until a user account expires."""
    _out(_api(ctx).put(f"/api/v1/users/{username}/setexpiry", json_body={"days": days}))


@user.command("setprimarygroup", help="Set user primary group.")
@click.argument("username")
@click.option("--groupname", required=True, help="Group to set as primary.")
@click.pass_context
def user_setprimarygroup(ctx: click.Context, username: str, groupname: str) -> None:
    """Change the primary group for a user account."""
    _out(_api(ctx).put(f"/api/v1/users/{username}/setprimarygroup", json_body={"groupname": groupname}))


@user.command("move", help="Move user to a new OU.")
@click.argument("username")
@click.option("--new-parent-dn", required=True, help="DN of the destination OU.")
@click.pass_context
def user_move(ctx: click.Context, username: str, new_parent_dn: str) -> None:
    """Move a user account to a different organizational unit."""
    _out(_api(ctx).post(f"/api/v1/users/{username}/move", json_body={"new_parent_dn": new_parent_dn}))


@user.command("rename", help="Rename a user account.")
@click.argument("username")
@click.option("--new-name", required=True, help="New name for the user.")
@click.pass_context
def user_rename(ctx: click.Context, username: str, new_name: str) -> None:
    """Rename a user account."""
    _out(_api(ctx).post(f"/api/v1/users/{username}/rename", json_body={"new_name": new_name}))


# ═══════════════════════════════════════════════════════════════════════════
# GROUP commands
# ═══════════════════════════════════════════════════════════════════════════


@cli.group("group", help="Manage groups.")
@click.pass_context
def group(ctx: click.Context) -> None:
    """Group management commands."""


@group.command("list", help="List all groups.")
@click.option("--verbose", is_flag=True, default=None, help="Verbose output.")
@click.option("--base-dn", default=None, help="Base DN for search.")
@click.option("--full-dn", is_flag=True, default=None, help="Show full DNs.")
@click.pass_context
def group_list(ctx: click.Context, verbose: bool, base_dn: str, full_dn: bool) -> None:
    """List all groups in the domain."""
    _out(_api(ctx).get("/api/v1/groups/", params={"verbose": verbose, "base_dn": base_dn, "full_dn": full_dn}))


@group.command("create", help="Create a new group.")
@click.argument("groupname")
@click.option("--group-scope", default=None, help="Group scope (DomainLocal, Global, Universal).")
@click.option("--group-type", default=None, help="Group type (Security, Distribution).")
@click.option("--description", default=None, help="Group description.")
@click.option("--groupou", default=None, help="OU path for the group.")
@click.option("--mail-address", default=None, help="Email address.")
@click.option("--notes", default=None, help="Notes.")
@click.pass_context
def group_create(ctx: click.Context, groupname: str, **kwargs: Any) -> None:
    """Create a new group in the domain."""
    body: Dict[str, Any] = {"groupname": groupname}
    for k, v in kwargs.items():
        if v is not None:
            body[k] = v
    _out(_api(ctx).post("/api/v1/groups/", json_body=body))


@group.command("show", help="Show group details.")
@click.argument("groupname")
@click.option("--attributes", default=None, help="Comma-separated attributes to show.")
@click.pass_context
def group_show(ctx: click.Context, groupname: str, attributes: Optional[str]) -> None:
    """Display details for a single group."""
    _out(_api(ctx).get(f"/api/v1/groups/{groupname}", params={"attributes": attributes}))


@group.command("delete", help="Delete a group.")
@click.argument("groupname")
@click.pass_context
def group_delete(ctx: click.Context, groupname: str) -> None:
    """Delete a group from the domain."""
    _out(_api(ctx).delete(f"/api/v1/groups/{groupname}"))


@group.command("addmembers", help="Add members to a group.")
@click.argument("groupname")
@click.option("--members", required=True, help="Comma-separated list of member names.")
@click.pass_context
def group_addmembers(ctx: click.Context, groupname: str, members: str) -> None:
    """Add one or more members to a group."""
    member_list = [m.strip() for m in members.split(",")]
    _out(_api(ctx).post(f"/api/v1/groups/{groupname}/members", json_body={"members": member_list}))


@group.command("removemembers", help="Remove members from a group.")
@click.argument("groupname")
@click.option("--members", required=True, help="Comma-separated list of member names.")
@click.pass_context
def group_removemembers(ctx: click.Context, groupname: str, members: str) -> None:
    """Remove one or more members from a group."""
    member_list = [m.strip() for m in members.split(",")]
    _out(_api(ctx).delete(f"/api/v1/groups/{groupname}/members", json_body={"members": member_list}))


@group.command("listmembers", help="List members of a group.")
@click.argument("groupname")
@click.option("--hide-expired", is_flag=True, default=None, help="Hide expired members.")
@click.option("--hide-disabled", is_flag=True, default=None, help="Hide disabled members.")
@click.option("--full-dn", is_flag=True, default=None, help="Show full DNs.")
@click.pass_context
def group_listmembers(ctx: click.Context, groupname: str, hide_expired: bool, hide_disabled: bool, full_dn: bool) -> None:
    """List all members of a group."""
    _out(_api(ctx).get(f"/api/v1/groups/{groupname}/members", params={"hide_expired": hide_expired, "hide_disabled": hide_disabled, "full_dn": full_dn}))


@group.command("move", help="Move a group to a new OU.")
@click.argument("groupname")
@click.option("--new-parent-dn", required=True, help="DN of the destination OU.")
@click.pass_context
def group_move(ctx: click.Context, groupname: str, new_parent_dn: str) -> None:
    """Move a group to a different organizational unit."""
    _out(_api(ctx).post(f"/api/v1/groups/{groupname}/move", json_body={"new_parent_dn": new_parent_dn}))


@group.command("stats", help="Show group statistics.")
@click.argument("groupname")
@click.pass_context
def group_stats(ctx: click.Context, groupname: str) -> None:
    """Display statistics for a group."""
    _out(_api(ctx).get(f"/api/v1/groups/{groupname}/stats"))


# ═══════════════════════════════════════════════════════════════════════════
# COMPUTER commands
# ═══════════════════════════════════════════════════════════════════════════


@cli.group("computer", help="Manage computer accounts.")
@click.pass_context
def computer(ctx: click.Context) -> None:
    """Computer account management commands."""


@computer.command("list", help="List all computer accounts.")
@click.option("--base-dn", default=None, help="Base DN for search.")
@click.option("--full-dn", is_flag=True, default=False, help="Show full DNs.")
@click.pass_context
def computer_list(ctx: click.Context, base_dn: Optional[str], full_dn: bool) -> None:
    """List all computer accounts in the domain."""
    _out(_api(ctx).get("/api/v1/computers/", params={"base_dn": base_dn, "full_dn": full_dn}))


@computer.command("create", help="Create a computer account.")
@click.argument("computername")
@click.option("--description", default=None, help="Computer description.")
@click.option("--computerou", default=None, help="OU path for the computer.")
@click.pass_context
def computer_create(ctx: click.Context, computername: str, description: Optional[str], computerou: Optional[str]) -> None:
    """Create a new computer account in the domain."""
    body: Dict[str, Any] = {"computername": computername}
    if description is not None:
        body["description"] = description
    if computerou is not None:
        body["computerou"] = computerou
    _out(_api(ctx).post("/api/v1/computers/", json_body=body))


@computer.command("show", help="Show computer account details.")
@click.argument("computername")
@click.option("--attributes", default=None, help="Comma-separated attributes to show.")
@click.pass_context
def computer_show(ctx: click.Context, computername: str, attributes: Optional[str]) -> None:
    """Retrieve the attributes of a specific computer account."""
    _out(_api(ctx).get(f"/api/v1/computers/{computername}", params={"attributes": attributes}))


@computer.command("delete", help="Delete a computer account.")
@click.argument("computername")
@click.pass_context
def computer_delete(ctx: click.Context, computername: str) -> None:
    """Delete a computer account from the domain."""
    _out(_api(ctx).delete(f"/api/v1/computers/{computername}"))


@computer.command("move", help="Move a computer to a new OU.")
@click.argument("computername")
@click.option("--new-ou-dn", required=True, help="DN of the destination OU.")
@click.pass_context
def computer_move(ctx: click.Context, computername: str, new_ou_dn: str) -> None:
    """Move a computer account to a different OU."""
    _out(_api(ctx).post(f"/api/v1/computers/{computername}/move", json_body={"new_ou_dn": new_ou_dn}))


# ═══════════════════════════════════════════════════════════════════════════
# CONTACT commands
# ═══════════════════════════════════════════════════════════════════════════


@cli.group("contact", help="Manage contacts.")
@click.pass_context
def contact(ctx: click.Context) -> None:
    """Contact management commands."""


@contact.command("list", help="List all contacts.")
@click.option("--base-dn", default=None, help="Base DN for search.")
@click.option("--full-dn", is_flag=True, default=False, help="Show full DNs.")
@click.pass_context
def contact_list(ctx: click.Context, base_dn: Optional[str], full_dn: bool) -> None:
    """List all contacts in the domain."""
    _out(_api(ctx).get("/api/v1/contacts/", params={"base_dn": base_dn, "full_dn": full_dn}))


@contact.command("create", help="Create a contact.")
@click.argument("contactname")
@click.option("--surname", default=None, help="Surname.")
@click.option("--given-name", default=None, help="Given name.")
@click.option("--display-name", default=None, help="Display name.")
@click.option("--description", default=None, help="Description.")
@click.option("--mail-address", default=None, help="Email address.")
@click.option("--telephone-number", default=None, help="Telephone number.")
@click.option("--contactou", default=None, help="OU path for the contact.")
@click.pass_context
def contact_create(ctx: click.Context, contactname: str, **kwargs: Any) -> None:
    """Create a new contact in the domain."""
    body: Dict[str, Any] = {"contactname": contactname}
    for k, v in kwargs.items():
        if v is not None:
            body[k] = v
    _out(_api(ctx).post("/api/v1/contacts/", json_body=body))


@contact.command("show", help="Show contact details.")
@click.argument("contactname")
@click.option("--attributes", default=None, help="Comma-separated attributes to show.")
@click.pass_context
def contact_show(ctx: click.Context, contactname: str, attributes: Optional[str]) -> None:
    """Retrieve the attributes of a specific contact."""
    _out(_api(ctx).get(f"/api/v1/contacts/{contactname}", params={"attributes": attributes}))


@contact.command("delete", help="Delete a contact.")
@click.argument("contactname")
@click.pass_context
def contact_delete(ctx: click.Context, contactname: str) -> None:
    """Delete a contact from the domain."""
    _out(_api(ctx).delete(f"/api/v1/contacts/{contactname}"))


@contact.command("move", help="Move a contact to a new OU.")
@click.argument("contactname")
@click.option("--new-parent-dn", required=True, help="DN of the destination OU.")
@click.pass_context
def contact_move(ctx: click.Context, contactname: str, new_parent_dn: str) -> None:
    """Move a contact to a different OU."""
    _out(_api(ctx).post(f"/api/v1/contacts/{contactname}/move", json_body={"new_parent_dn": new_parent_dn}))


@contact.command("rename", help="Rename a contact.")
@click.argument("contactname")
@click.option("--new-name", required=True, help="New name for the contact.")
@click.pass_context
def contact_rename(ctx: click.Context, contactname: str, new_name: str) -> None:
    """Rename a contact in the domain."""
    _out(_api(ctx).post(f"/api/v1/contacts/{contactname}/rename", json_body={"new_name": new_name}))


# ═══════════════════════════════════════════════════════════════════════════
# OU commands
# ═══════════════════════════════════════════════════════════════════════════


@cli.group("ou", help="Manage organizational units.")
@click.pass_context
def ou(ctx: click.Context) -> None:
    """Organizational Unit management commands."""


@ou.command("list", help="List all OUs.")
@click.option("--base-dn", default=None, help="Base DN for search.")
@click.option("--full-dn", is_flag=True, default=False, help="Show full DNs.")
@click.pass_context
def ou_list(ctx: click.Context, base_dn: Optional[str], full_dn: bool) -> None:
    """List all Organizational Units in the domain."""
    _out(_api(ctx).get("/api/v1/ous/", params={"base_dn": base_dn, "full_dn": full_dn}))


@ou.command("create", help="Create an OU.")
@click.argument("ouname")
@click.option("--description", default=None, help="OU description.")
@click.pass_context
def ou_create(ctx: click.Context, ouname: str, description: Optional[str]) -> None:
    """Create a new Organizational Unit in the domain."""
    body: Dict[str, Any] = {"ouname": ouname}
    if description is not None:
        body["description"] = description
    _out(_api(ctx).post("/api/v1/ous/", json_body=body))


@ou.command("show", help="Show OU details.")
@click.argument("ouname")
@click.option("--attributes", default=None, help="Comma-separated attributes to show.")
@click.pass_context
def ou_show(ctx: click.Context, ouname: str, attributes: Optional[str]) -> None:
    """Retrieve the attributes of a specific OU."""
    _out(_api(ctx).get(f"/api/v1/ous/{ouname}", params={"attributes": attributes}))


@ou.command("delete", help="Delete an OU.")
@click.argument("ouname")
@click.pass_context
def ou_delete(ctx: click.Context, ouname: str) -> None:
    """Delete an Organizational Unit from the domain."""
    _out(_api(ctx).delete(f"/api/v1/ous/{ouname}"))


@ou.command("move", help="Move an OU to a new parent.")
@click.argument("ouname")
@click.option("--new-parent-dn", required=True, help="DN of the destination parent OU.")
@click.pass_context
def ou_move(ctx: click.Context, ouname: str, new_parent_dn: str) -> None:
    """Move an OU under a new parent OU."""
    _out(_api(ctx).post(f"/api/v1/ous/{ouname}/move", json_body={"new_parent_dn": new_parent_dn}))


@ou.command("rename", help="Rename an OU.")
@click.argument("ouname")
@click.option("--new-name", required=True, help="New name for the OU.")
@click.pass_context
def ou_rename(ctx: click.Context, ouname: str, new_name: str) -> None:
    """Rename an Organizational Unit."""
    _out(_api(ctx).post(f"/api/v1/ous/{ouname}/rename", json_body={"new_name": new_name}))


@ou.command("objects", help="List objects in an OU.")
@click.argument("ouname")
@click.option("--full-dn", is_flag=True, default=False, help="Show full DNs.")
@click.pass_context
def ou_objects(ctx: click.Context, ouname: str, full_dn: bool) -> None:
    """List child objects within a specific OU."""
    _out(_api(ctx).get(f"/api/v1/ous/{ouname}/objects", params={"full_dn": full_dn}))


# ═══════════════════════════════════════════════════════════════════════════
# DOMAIN commands
# ═══════════════════════════════════════════════════════════════════════════


@cli.group("domain", help="Manage domain settings.")
@click.pass_context
def domain(ctx: click.Context) -> None:
    """Domain management commands."""


@domain.command("info", help="Show domain information.")
@click.pass_context
def domain_info(ctx: click.Context) -> None:
    """Return general information about the Samba AD domain."""
    _out(_api(ctx).get("/api/v1/domain/info"))


@domain.command("level", help="Get or set the domain functional level.")
@click.option("--set", "set_level", default=None, type=int, help="Set the functional level to this value.")
@click.pass_context
def domain_level(ctx: click.Context, set_level: Optional[int]) -> None:
    """Get or set the domain functional level.

    Without --set, retrieves the current level.  With --set, raises the
    functional level (irreversible!).
    """
    if set_level is not None:
        _out(_api(ctx).put("/api/v1/domain/level", json_body={"level": set_level}))
    else:
        _out(_api(ctx).get("/api/v1/domain/level"))


@domain.command("passwordsettings", help="Show or set password policy settings.")
@click.option("--min-pwd-length", type=int, default=None, help="Minimum password length.")
@click.option("--history-length", type=int, default=None, help="Password history length.")
@click.option("--min-pwd-age", type=int, default=None, help="Minimum password age (ticks).")
@click.option("--max-pwd-age", type=int, default=None, help="Maximum password age (ticks).")
@click.option("--complexity", type=bool, default=None, help="Require password complexity (on/off).")
@click.option("--store-plaintext", type=bool, default=None, help="Store plaintext passwords (on/off).")
@click.option("--account-lockout-duration", type=int, default=None, help="Account lockout duration (minutes).")
@click.option("--account-lockout-threshold", type=int, default=None, help="Account lockout threshold.")
@click.option("--reset-account-lockout-after", type=int, default=None, help="Reset lockout counter after (minutes).")
@click.pass_context
def domain_passwordsettings(ctx: click.Context, **kwargs: Any) -> None:
    """Retrieve or update password-policy settings.

    Without any options, shows current settings.  Provide one or more
    options to update them.
    """
    body = {k: v for k, v in kwargs.items() if v is not None}
    if body:
        _out(_api(ctx).put("/api/v1/domain/passwordsettings", json_body=body))
    else:
        _out(_api(ctx).get("/api/v1/domain/passwordsettings"))


# ── Domain trust sub-group ─────────────────────────────────────────────


@domain.group("trust", help="Manage domain trusts.")
@click.pass_context
def domain_trust(ctx: click.Context) -> None:
    """Domain trust management commands."""


@domain_trust.command("create", help="Create a trust relationship.")
@click.option("--trusted-domain", required=True, help="FQDN of the trusted domain.")
@click.option("--username", default=None, help="Admin username in the trusted domain.")
@click.option("--password", default=None, help="Admin password in the trusted domain.")
@click.option("--type", "trust_type", default=None, help="Trust type.")
@click.option("--direction", default=None, help="Trust direction.")
@click.pass_context
def trust_create(ctx: click.Context, trusted_domain: str, **kwargs: Any) -> None:
    """Create a trust relationship with another domain."""
    body: Dict[str, Any] = {"trusted_domain_name": trusted_domain}
    mapping = {"username": "trusted_username", "password": "trusted_password", "trust_type": "trust_type", "direction": "trust_direction"}
    for k, v in kwargs.items():
        if v is not None:
            body[mapping.get(k, k)] = v
    _out(_api(ctx).post("/api/v1/domain/trust/create", json_body=body))


@domain_trust.command("delete", help="Delete a trust relationship.")
@click.option("--trusted-domain", required=True, help="FQDN of the trusted domain.")
@click.pass_context
def trust_delete(ctx: click.Context, trusted_domain: str) -> None:
    """Remove a trust relationship."""
    _out(_api(ctx).delete("/api/v1/domain/trust/delete", params={"trusted_domain_name": trusted_domain}))


@domain_trust.command("list", help="List all trusts.")
@click.pass_context
def trust_list(ctx: click.Context) -> None:
    """List all trust relationships."""
    _out(_api(ctx).get("/api/v1/domain/trust/list"))


@domain_trust.command("namespaces", help="Show trust namespaces.")
@click.option("--trusted-domain", required=True, help="FQDN of the trusted domain.")
@click.pass_context
def trust_namespaces(ctx: click.Context, trusted_domain: str) -> None:
    """Show namespace information for a trusted domain."""
    _out(_api(ctx).get("/api/v1/domain/trust/namespaces", params={"trusted_domain_name": trusted_domain}))


@domain_trust.command("validate", help="Validate a trust relationship.")
@click.option("--trusted-domain", required=True, help="FQDN of the trusted domain.")
@click.pass_context
def trust_validate(ctx: click.Context, trusted_domain: str) -> None:
    """Validate an existing trust relationship."""
    _out(_api(ctx).post("/api/v1/domain/trust/validate", params={"trusted_domain_name": trusted_domain}))


# ── Domain backup sub-group ────────────────────────────────────────────


@domain.group("backup", help="Domain backup operations.")
@click.pass_context
def domain_backup(ctx: click.Context) -> None:
    """Domain backup commands."""


@domain_backup.command("online", help="Start an online backup.")
@click.option("--target-dir", default=None, help="Target directory for the backup.")
@click.pass_context
def backup_online(ctx: click.Context, target_dir: Optional[str]) -> None:
    """Start an online backup of the domain controller."""
    body: Dict[str, Any] = {}
    if target_dir is not None:
        body["target_dir"] = target_dir
    _out(_api(ctx).post("/api/v1/domain/backup/online", json_body=body))


@domain_backup.command("offline", help="Start an offline backup.")
@click.option("--target-dir", default=None, help="Target directory for the backup.")
@click.pass_context
def backup_offline(ctx: click.Context, target_dir: Optional[str]) -> None:
    """Start an offline backup of the domain controller."""
    body: Dict[str, Any] = {}
    if target_dir is not None:
        body["target_dir"] = target_dir
    _out(_api(ctx).post("/api/v1/domain/backup/offline", json_body=body))


# ── Other domain commands ─────────────────────────────────────────────


@domain.command("tombstones", help="List tombstone objects.")
@click.pass_context
def domain_tombstones(ctx: click.Context) -> None:
    """List tombstone objects in the domain."""
    _out(_api(ctx).get("/api/v1/domain/tombstones"))


@domain.command("exportkeytab", help="Export a keytab for a service principal.")
@click.option("--principal", required=True, help="Service principal name to export.")
@click.pass_context
def domain_exportkeytab(ctx: click.Context, principal: str) -> None:
    """Export a keytab file for a given service principal."""
    _out(_api(ctx).get("/api/v1/domain/exportkeytab", params={"principal": principal}))


# ═══════════════════════════════════════════════════════════════════════════
# DNS commands
# ═══════════════════════════════════════════════════════════════════════════


@cli.group("dns", help="Manage DNS.")
@click.pass_context
def dns(ctx: click.Context) -> None:
    """DNS management commands."""


@dns.command("serverinfo", help="Get DNS server information.")
@click.option("--server", default=None, help="DNS server hostname.")
@click.option("--client-version", default=None, help="Client version string.")
@click.pass_context
def dns_serverinfo(ctx: click.Context, server: Optional[str], client_version: Optional[str]) -> None:
    """Retrieve DNS server information."""
    _out(_api(ctx).get("/api/v1/dns/serverinfo", params={"server": server, "client_version": client_version}))


# ── DNS zones sub-group ───────────────────────────────────────────────


@dns.group("zones", help="Manage DNS zones.")
@click.pass_context
def dns_zones(ctx: click.Context) -> None:
    """DNS zone management commands."""


@dns_zones.command("list", help="List DNS zones.")
@click.option("--server", default=None, help="DNS server hostname.")
@click.option("--primary", is_flag=True, default=False, help="List primary zones.")
@click.option("--secondary", is_flag=True, default=False, help="List secondary zones.")
@click.option("--cache", is_flag=True, default=False, help="List cache zones.")
@click.option("--auto", is_flag=True, default=False, help="List auto-created zones.")
@click.option("--forward", is_flag=True, default=False, help="List forward zones.")
@click.option("--reverse", is_flag=True, default=False, help="List reverse zones.")
@click.option("--ds", is_flag=True, default=False, help="List AD-integrated zones.")
@click.option("--non-ds", is_flag=True, default=False, help="List non-AD-integrated zones.")
@click.pass_context
def dns_zones_list(ctx: click.Context, server: Optional[str], **kwargs: Any) -> None:
    """List DNS zones, optionally filtered by type."""
    params: Dict[str, Any] = {"server": server}
    params.update(kwargs)
    _out(_api(ctx).get("/api/v1/dns/zones", params=params))


@dns_zones.command("create", help="Create a DNS zone.")
@click.argument("zone")
@click.option("--server", default=None, help="DNS server hostname.")
@click.option("--partition", default="domain", help="DNS directory partition (domain/forest).")
@click.pass_context
def dns_zones_create(ctx: click.Context, zone: str, server: Optional[str], partition: str) -> None:
    """Create a new DNS zone."""
    _out(_api(ctx).post("/api/v1/dns/zones", json_body={"zone": zone, "dns_directory_partition": partition}, params={"server": server}))


@dns_zones.command("delete", help="Delete a DNS zone.")
@click.argument("zone")
@click.option("--server", default=None, help="DNS server hostname.")
@click.pass_context
def dns_zones_delete(ctx: click.Context, zone: str, server: Optional[str]) -> None:
    """Delete an existing DNS zone."""
    _out(_api(ctx).delete(f"/api/v1/dns/zones/{zone}", params={"server": server}))


@dns_zones.command("info", help="Show DNS zone information.")
@click.argument("zone")
@click.option("--server", default=None, help="DNS server hostname.")
@click.pass_context
def dns_zones_info(ctx: click.Context, zone: str, server: Optional[str]) -> None:
    """Retrieve detailed information about a DNS zone."""
    _out(_api(ctx).get(f"/api/v1/dns/zones/{zone}", params={"server": server}))


# ── DNS records sub-group ─────────────────────────────────────────────


@dns.group("records", help="Manage DNS records.")
@click.pass_context
def dns_records(ctx: click.Context) -> None:
    """DNS record management commands."""


@dns_records.command("list", help="List DNS records in a zone.")
@click.argument("zone")
@click.option("--server", default=None, help="DNS server hostname.")
@click.option("--name", default=None, help="Record name to filter by.")
@click.option("--record-type", default=None, help="Record type (A, CNAME, MX, etc.).")
@click.pass_context
def dns_records_list(ctx: click.Context, zone: str, server: Optional[str], name: Optional[str], record_type: Optional[str]) -> None:
    """List DNS records in a zone."""
    _out(_api(ctx).get(f"/api/v1/dns/zones/{zone}/records", params={"server": server, "name": name, "record_type": record_type}))


@dns_records.command("add", help="Add a DNS record.")
@click.argument("zone")
@click.option("--name", required=True, help="Record name.")
@click.option("--record-type", required=True, help="Record type (A, CNAME, etc.).")
@click.option("--data", required=True, help="Record data.")
@click.option("--server", default=None, help="DNS server hostname.")
@click.pass_context
def dns_records_add(ctx: click.Context, zone: str, name: str, record_type: str, data: str, server: Optional[str]) -> None:
    """Add a DNS record to a zone."""
    _out(_api(ctx).post(f"/api/v1/dns/zones/{zone}/records", json_body={"name": name, "record_type": record_type, "data": data}, params={"server": server}))


@dns_records.command("delete", help="Delete a DNS record.")
@click.argument("zone")
@click.option("--name", required=True, help="Record name.")
@click.option("--record-type", required=True, help="Record type.")
@click.option("--data", required=True, help="Record data to delete.")
@click.option("--server", default=None, help="DNS server hostname.")
@click.pass_context
def dns_records_delete(ctx: click.Context, zone: str, name: str, record_type: str, data: str, server: Optional[str]) -> None:
    """Remove a DNS record from a zone."""
    _out(_api(ctx).delete(f"/api/v1/dns/zones/{zone}/records", json_body={"name": name, "record_type": record_type, "data": data}, params={"server": server}))


@dns_records.command("update", help="Update a DNS record.")
@click.argument("zone")
@click.option("--name", required=True, help="Record name.")
@click.option("--old-record-type", required=True, help="Current record type.")
@click.option("--old-data", required=True, help="Current record data.")
@click.option("--new-record-type", required=True, help="New record type.")
@click.option("--new-data", required=True, help="New record data.")
@click.option("--server", default=None, help="DNS server hostname.")
@click.pass_context
def dns_records_update(ctx: click.Context, zone: str, name: str, old_record_type: str, old_data: str, new_record_type: str, new_data: str, server: Optional[str]) -> None:
    """Update (replace) a DNS record in a zone."""
    _out(_api(ctx).put(f"/api/v1/dns/zones/{zone}/records", json_body={"name": name, "old_record_type": old_record_type, "old_data": old_data, "new_record_type": new_record_type, "new_data": new_data}, params={"server": server}))


# ── DNS zone-options ──────────────────────────────────────────────────


@dns.command("zone-options", help="Set DNS zone options.")
@click.argument("zone")
@click.option("--server", default=None, help="DNS server hostname.")
@click.option("--aging", type=bool, default=None, help="Enable aging.")
@click.option("--no-scavenge", type=bool, default=None, help="Disable scavenging.")
@click.pass_context
def dns_zone_options(ctx: click.Context, zone: str, server: Optional[str], aging: Optional[bool], no_scavenge: Optional[bool]) -> None:
    """Set aging/scavenging options for a DNS zone."""
    body: Dict[str, Any] = {}
    if aging is not None:
        body["aging"] = aging
    if no_scavenge is not None:
        body["no_scavenge"] = no_scavenge
    _out(_api(ctx).put(f"/api/v1/dns/zones/{zone}/options", json_body=body, params={"server": server}))


# ═══════════════════════════════════════════════════════════════════════════
# SITES commands
# ═══════════════════════════════════════════════════════════════════════════


@cli.group("sites", help="Manage AD sites and subnets.")
@click.pass_context
def sites(ctx: click.Context) -> None:
    """Sites & Subnets management commands."""


@sites.command("list", help="List all sites.")
@click.pass_context
def sites_list(ctx: click.Context) -> None:
    """List all sites in the Active Directory domain."""
    _out(_api(ctx).get("/api/v1/sites/"))


@sites.command("view", help="View site details.")
@click.argument("sitename")
@click.pass_context
def sites_view(ctx: click.Context, sitename: str) -> None:
    """View details of a specific site."""
    _out(_api(ctx).get(f"/api/v1/sites/{sitename}"))


@sites.command("create", help="Create a site.")
@click.argument("sitename")
@click.pass_context
def sites_create(ctx: click.Context, sitename: str) -> None:
    """Create a new site in the Active Directory domain."""
    _out(_api(ctx).post("/api/v1/sites/", json_body={"sitename": sitename}))


@sites.command("delete", help="Delete a site.")
@click.argument("sitename")
@click.pass_context
def sites_delete(ctx: click.Context, sitename: str) -> None:
    """Delete a site from the Active Directory domain."""
    _out(_api(ctx).delete(f"/api/v1/sites/{sitename}"))


# ── Sites subnet sub-group ────────────────────────────────────────────


@sites.group("subnet", help="Manage subnets.")
@click.pass_context
def sites_subnet(ctx: click.Context) -> None:
    """Subnet management commands."""


@sites_subnet.command("list", help="List subnets in a site.")
@click.argument("sitename")
@click.pass_context
def subnet_list(ctx: click.Context, sitename: str) -> None:
    """List all subnets belonging to a specific site."""
    _out(_api(ctx).get(f"/api/v1/sites/{sitename}/subnets"))


@sites_subnet.command("create", help="Create a subnet.")
@click.argument("sitename")
@click.option("--subnetname", required=True, help="Subnet name (e.g. 10.0.0.0/24).")
@click.option("--site-of-subnet", default=None, help="Site to assign the subnet to (defaults to sitename).")
@click.pass_context
def subnet_create(ctx: click.Context, sitename: str, subnetname: str, site_of_subnet: Optional[str]) -> None:
    """Create a new subnet and assign it to a site."""
    body: Dict[str, Any] = {"subnetname": subnetname, "site_of_subnet": site_of_subnet or sitename}
    _out(_api(ctx).post(f"/api/v1/sites/{sitename}/subnets", json_body=body))


@sites_subnet.command("delete", help="Delete a subnet.")
@click.argument("subnetname")
@click.pass_context
def subnet_delete(ctx: click.Context, subnetname: str) -> None:
    """Delete a subnet from the Active Directory domain."""
    _out(_api(ctx).delete(f"/api/v1/sites/subnets/{subnetname}"))


@sites_subnet.command("view", help="View subnet details.")
@click.argument("subnetname")
@click.pass_context
def subnet_view(ctx: click.Context, subnetname: str) -> None:
    """View details of a specific subnet."""
    _out(_api(ctx).get(f"/api/v1/sites/subnets/{subnetname}"))


@sites_subnet.command("set-site", help="Change the site assignment of a subnet.")
@click.argument("subnetname")
@click.option("--site", required=True, help="Site to assign the subnet to.")
@click.pass_context
def subnet_set_site(ctx: click.Context, subnetname: str, site: str) -> None:
    """Change the site assignment of an existing subnet."""
    _out(_api(ctx).put(f"/api/v1/sites/subnets/{subnetname}/site", json_body={"site_of_subnet": site}))


# ═══════════════════════════════════════════════════════════════════════════
# FSMO commands
# ═══════════════════════════════════════════════════════════════════════════


@cli.group("fsmo", help="Manage FSMO roles.")
@click.pass_context
def fsmo(ctx: click.Context) -> None:
    """FSMO role management commands."""


@fsmo.command("show", help="Show FSMO role holders.")
@click.pass_context
def fsmo_show(ctx: click.Context) -> None:
    """Show the current holders of all FSMO roles."""
    _out(_api(ctx).get("/api/v1/fsmo/"))


@fsmo.command("transfer", help="Transfer a FSMO role.")
@click.option("--role", required=True, help="FSMO role to transfer (pdc, rid, infrastructure, naming, schema).")
@click.pass_context
def fsmo_transfer(ctx: click.Context, role: str) -> None:
    """Transfer a FSMO role to the current server."""
    _out(_api(ctx).put("/api/v1/fsmo/transfer", json_body={"role": role}))


@fsmo.command("seize", help="Seize a FSMO role.")
@click.option("--role", required=True, help="FSMO role to seize (pdc, rid, infrastructure, naming, schema).")
@click.pass_context
def fsmo_seize(ctx: click.Context, role: str) -> None:
    """Seize a FSMO role on the current server.

    WARNING: Seizing should only be done when the current role holder
    is permanently unavailable.
    """
    _out(_api(ctx).put("/api/v1/fsmo/seize", json_body={"role": role}))


# ═══════════════════════════════════════════════════════════════════════════
# DRS commands
# ═══════════════════════════════════════════════════════════════════════════


@cli.group("drs", help="Manage DRS replication.")
@click.pass_context
def drs(ctx: click.Context) -> None:
    """DRS Replication management commands."""


@drs.command("showrepl", help="Show replication status.")
@click.pass_context
def drs_showrepl(ctx: click.Context) -> None:
    """Show the current DRS replication status."""
    _out(_api(ctx).get("/api/v1/drs/showrepl"))


@drs.command("replicate", help="Trigger DRS replication.")
@click.option("--source-dsa", required=True, help="Source DSA server.")
@click.option("--destination-dsa", required=True, help="Destination DSA server.")
@click.option("--nc-dn", required=True, help="Naming context DN to replicate.")
@click.pass_context
def drs_replicate(ctx: click.Context, source_dsa: str, destination_dsa: str, nc_dn: str) -> None:
    """Trigger DRS replication of a naming context.

    This is a background task. The response includes a task_id for polling.
    """
    _out(_api(ctx).post("/api/v1/drs/replicate", json_body={"source_dsa": source_dsa, "destination_dsa": destination_dsa, "nc_dn": nc_dn}))


@drs.command("uptodateness", help="Check uptodateness vector.")
@click.option("--object-dn", default=None, help="DN of the object to check.")
@click.option("--guid", default=None, help="GUID of the DSA to check against.")
@click.pass_context
def drs_uptodateness(ctx: click.Context, object_dn: Optional[str], guid: Optional[str]) -> None:
    """Check the uptodateness vector for a given object."""
    _out(_api(ctx).get("/api/v1/drs/uptodateness", params={"object_dn": object_dn, "guid": guid}))


# ═══════════════════════════════════════════════════════════════════════════
# GPO commands
# ═══════════════════════════════════════════════════════════════════════════


@cli.group("gpo", help="Manage Group Policy Objects.")
@click.pass_context
def gpo(ctx: click.Context) -> None:
    """Group Policy Object management commands."""


@gpo.command("list", help="List all GPOs.")
@click.pass_context
def gpo_list(ctx: click.Context) -> None:
    """List all Group Policy Objects in the domain."""
    _out(_api(ctx).get("/api/v1/gpo/"))


@gpo.command("create", help="Create a GPO.")
@click.option("--displayname", required=True, help="Display name for the new GPO.")
@click.pass_context
def gpo_create(ctx: click.Context, displayname: str) -> None:
    """Create a new Group Policy Object."""
    _out(_api(ctx).post("/api/v1/gpo/", json_body={"displayname": displayname}))


@gpo.command("show", help="Show GPO details.")
@click.argument("gpo_id")
@click.pass_context
def gpo_show(ctx: click.Context, gpo_id: str) -> None:
    """Show details of a specific Group Policy Object."""
    _out(_api(ctx).get(f"/api/v1/gpo/{gpo_id}"))


@gpo.command("delete", help="Delete a GPO.")
@click.argument("gpo_id")
@click.pass_context
def gpo_delete(ctx: click.Context, gpo_id: str) -> None:
    """Delete a Group Policy Object."""
    _out(_api(ctx).delete(f"/api/v1/gpo/{gpo_id}"))


@gpo.command("link", help="Link a GPO to a container.")
@click.argument("gpo_id")
@click.option("--container-dn", required=True, help="DN of the container to link to.")
@click.pass_context
def gpo_link(ctx: click.Context, gpo_id: str, container_dn: str) -> None:
    """Link a Group Policy Object to a container."""
    _out(_api(ctx).post(f"/api/v1/gpo/{gpo_id}/link", json_body={"container_dn": container_dn}))


@gpo.command("unlink", help="Unlink a GPO from a container.")
@click.argument("gpo_id")
@click.option("--container-dn", required=True, help="DN of the container to unlink from.")
@click.pass_context
def gpo_unlink(ctx: click.Context, gpo_id: str, container_dn: str) -> None:
    """Unlink a Group Policy Object from a container."""
    _out(_api(ctx).delete(f"/api/v1/gpo/{gpo_id}/link", json_body={"container_dn": container_dn}))


@gpo.command("backup", help="Backup a GPO.")
@click.argument("gpo_id")
@click.option("--target-dir", default=None, help="Target directory for the backup.")
@click.pass_context
def gpo_backup(ctx: click.Context, gpo_id: str, target_dir: Optional[str]) -> None:
    """Backup a Group Policy Object.

    This is a background task. The response includes a task_id for polling.
    """
    body: Dict[str, Any] = {}
    if target_dir is not None:
        body["target_dir"] = target_dir
    _out(_api(ctx).post(f"/api/v1/gpo/{gpo_id}/backup", json_body=body))


@gpo.command("restore", help="Restore a GPO from backup.")
@click.argument("gpo_id")
@click.option("--source-dir", required=True, help="Source directory for the restore.")
@click.pass_context
def gpo_restore(ctx: click.Context, gpo_id: str, source_dir: str) -> None:
    """Restore a Group Policy Object from a backup directory.

    This is a background task. The response includes a task_id for polling.
    """
    _out(_api(ctx).post(f"/api/v1/gpo/{gpo_id}/restore", json_body={"source_dir": source_dir}))


@gpo.command("getacl", help="Get GPO ACL.")
@click.argument("gpo_id")
@click.pass_context
def gpo_getacl(ctx: click.Context, gpo_id: str) -> None:
    """Retrieve the ACL of a Group Policy Object."""
    _out(_api(ctx).get(f"/api/v1/gpo/{gpo_id}/acl"))


@gpo.command("setacl", help="Set GPO ACL.")
@click.argument("gpo_id")
@click.option("--sddl", required=True, help="SDDL string for the ACL.")
@click.pass_context
def gpo_setacl(ctx: click.Context, gpo_id: str, sddl: str) -> None:
    """Set the ACL of a Group Policy Object using an SDDL string."""
    _out(_api(ctx).put(f"/api/v1/gpo/{gpo_id}/acl", json_body={"sddl": sddl}))


# ═══════════════════════════════════════════════════════════════════════════
# SCHEMA commands
# ═══════════════════════════════════════════════════════════════════════════


@cli.group("schema", help="Manage AD schema.")
@click.pass_context
def schema(ctx: click.Context) -> None:
    """Schema management commands."""


# ── Schema attributes ─────────────────────────────────────────────────


@schema.group("attributes", help="Manage schema attributes.")
@click.pass_context
def schema_attributes(ctx: click.Context) -> None:
    """Schema attribute management commands."""


@schema_attributes.command("list", help="List schema attributes.")
@click.pass_context
def schema_attr_list(ctx: click.Context) -> None:
    """List all attributes defined in the Active Directory schema."""
    _out(_api(ctx).get("/api/v1/schema/attributes"))


@schema_attributes.command("show", help="Show schema attribute details.")
@click.argument("attribute")
@click.pass_context
def schema_attr_show(ctx: click.Context, attribute: str) -> None:
    """Show detailed information about a specific schema attribute."""
    _out(_api(ctx).get(f"/api/v1/schema/attributes/{attribute}"))


@schema_attributes.command("add", help="Add a new schema attribute.")
@click.option("--attribute-name", required=True, help="Name of the attribute.")
@click.option("--syntax", required=True, help="OID of the attribute syntax (e.g. 2.5.5.3).")
@click.option("--description", default=None, help="Human-readable description.")
@click.pass_context
def schema_attr_add(ctx: click.Context, attribute_name: str, syntax: str, description: Optional[str]) -> None:
    """Add a new attribute to the Active Directory schema."""
    body: Dict[str, Any] = {"attribute_name": attribute_name, "syntax": syntax}
    if description is not None:
        body["description"] = description
    _out(_api(ctx).post("/api/v1/schema/attributes", json_body=body))


# ── Schema classes ────────────────────────────────────────────────────


@schema.group("classes", help="Manage schema classes.")
@click.pass_context
def schema_classes(ctx: click.Context) -> None:
    """Schema class management commands."""


@schema_classes.command("list", help="List schema classes.")
@click.pass_context
def schema_class_list(ctx: click.Context) -> None:
    """List all classes defined in the Active Directory schema."""
    _out(_api(ctx).get("/api/v1/schema/classes"))


@schema_classes.command("show", help="Show schema class details.")
@click.argument("classname")
@click.pass_context
def schema_class_show(ctx: click.Context, classname: str) -> None:
    """Show detailed information about a specific schema class."""
    _out(_api(ctx).get(f"/api/v1/schema/classes/{classname}"))


@schema_classes.command("add", help="Add a new schema class.")
@click.option("--classname", required=True, help="Name of the class.")
@click.option("--class-type", required=True, help="Type of class (structural, abstract, auxiliary).")
@click.option("--attributes", default=None, help="Comma-separated list of attribute names.")
@click.pass_context
def schema_class_add(ctx: click.Context, classname: str, class_type: str, attributes: Optional[str]) -> None:
    """Add a new class to the Active Directory schema."""
    body: Dict[str, Any] = {"classname": classname, "class_type": class_type}
    if attributes is not None:
        body["attributes"] = [a.strip() for a in attributes.split(",")]
    _out(_api(ctx).post("/api/v1/schema/classes", json_body=body))


# ═══════════════════════════════════════════════════════════════════════════
# DELEGATION commands
# ═══════════════════════════════════════════════════════════════════════════


@cli.group("delegation", help="Manage delegations.")
@click.pass_context
def delegation(ctx: click.Context) -> None:
    """Delegation management commands."""


@delegation.command("list", help="List all delegations.")
@click.pass_context
def delegation_list(ctx: click.Context) -> None:
    """List all delegation settings in the domain."""
    _out(_api(ctx).get("/api/v1/delegation/"))


@delegation.command("add", help="Add a service delegation.")
@click.option("--accountname", required=True, help="Account name for the delegation.")
@click.option("--service", required=True, help="Service principal for the delegation.")
@click.pass_context
def delegation_add(ctx: click.Context, accountname: str, service: str) -> None:
    """Add a service delegation for an account."""
    _out(_api(ctx).post("/api/v1/delegation/add", json_body={"accountname": accountname, "service": service}))


@delegation.command("remove", help="Remove a service delegation.")
@click.option("--accountname", required=True, help="Account name for the delegation.")
@click.option("--service", required=True, help="Service principal for the delegation.")
@click.pass_context
def delegation_remove(ctx: click.Context, accountname: str, service: str) -> None:
    """Remove a service delegation from an account."""
    _out(_api(ctx).delete("/api/v1/delegation/remove", json_body={"accountname": accountname, "service": service}))


@delegation.command("for-account", help="Show delegations for an account.")
@click.option("--accountname", required=True, help="Account name to query.")
@click.pass_context
def delegation_for_account(ctx: click.Context, accountname: str) -> None:
    """Show all delegations configured for a specific account."""
    _out(_api(ctx).get("/api/v1/delegation/for-account", params={"accountname": accountname}))


# ═══════════════════════════════════════════════════════════════════════════
# SERVICE-ACCOUNT commands
# ═══════════════════════════════════════════════════════════════════════════


@cli.group("service-account", help="Manage service accounts.")
@click.pass_context
def service_account(ctx: click.Context) -> None:
    """Service account management commands."""


@service_account.command("list", help="List all service accounts.")
@click.pass_context
def sa_list(ctx: click.Context) -> None:
    """List all managed service accounts in the domain."""
    _out(_api(ctx).get("/api/v1/service-accounts/"))


@service_account.command("create", help="Create a service account.")
@click.option("--accountname", required=True, help="Name of the service account.")
@click.option("--description", default=None, help="Description for the service account.")
@click.pass_context
def sa_create(ctx: click.Context, accountname: str, description: Optional[str]) -> None:
    """Create a new managed service account."""
    body: Dict[str, Any] = {"accountname": accountname}
    if description is not None:
        body["description"] = description
    _out(_api(ctx).post("/api/v1/service-accounts/", json_body=body))


@service_account.command("show", help="Show service account details.")
@click.argument("accountname")
@click.pass_context
def sa_show(ctx: click.Context, accountname: str) -> None:
    """Show detailed information about a specific service account."""
    _out(_api(ctx).get(f"/api/v1/service-accounts/{accountname}"))


@service_account.command("delete", help="Delete a service account.")
@click.argument("accountname")
@click.pass_context
def sa_delete(ctx: click.Context, accountname: str) -> None:
    """Delete a managed service account."""
    _out(_api(ctx).delete(f"/api/v1/service-accounts/{accountname}"))


# ── gMSA members sub-group ────────────────────────────────────────────


@service_account.group("gmsa-members", help="Manage gMSA members.")
@click.pass_context
def sa_gmsa_members(ctx: click.Context) -> None:
    """Group Managed Service Account membership commands."""


@sa_gmsa_members.command("add", help="Add gMSA members.")
@click.argument("accountname")
@click.option("--members", required=True, help="Comma-separated list of member names.")
@click.pass_context
def gmsa_add(ctx: click.Context, accountname: str, members: str) -> None:
    """Add members to the gMSA membership list."""
    member_list = [m.strip() for m in members.split(",")]
    _out(_api(ctx).post(f"/api/v1/service-accounts/{accountname}/gmsa-members/add", json_body={"members": member_list}))


@sa_gmsa_members.command("remove", help="Remove gMSA members.")
@click.argument("accountname")
@click.option("--members", required=True, help="Comma-separated list of member names.")
@click.pass_context
def gmsa_remove(ctx: click.Context, accountname: str, members: str) -> None:
    """Remove members from the gMSA membership list."""
    member_list = [m.strip() for m in members.split(",")]
    _out(_api(ctx).delete(f"/api/v1/service-accounts/{accountname}/gmsa-members/remove", json_body={"members": member_list}))


@sa_gmsa_members.command("list", help="List gMSA members.")
@click.argument("accountname")
@click.pass_context
def gmsa_list(ctx: click.Context, accountname: str) -> None:
    """List members of the gMSA."""
    _out(_api(ctx).get(f"/api/v1/service-accounts/{accountname}/gmsa-members"))


# ═══════════════════════════════════════════════════════════════════════════
# AUTH commands
# ═══════════════════════════════════════════════════════════════════════════


@cli.group("auth", help="Manage auth policies and silos.")
@click.pass_context
def auth(ctx: click.Context) -> None:
    """Authentication policy and silo management commands."""


# ── Auth silos ────────────────────────────────────────────────────────


@auth.group("silos", help="Manage authentication silos.")
@click.pass_context
def auth_silos(ctx: click.Context) -> None:
    """Authentication silo commands."""


@auth_silos.command("list", help="List authentication silos.")
@click.pass_context
def silos_list(ctx: click.Context) -> None:
    """List all authentication silos in the domain."""
    _out(_api(ctx).get("/api/v1/auth/silos"))


@auth_silos.command("create", help="Create an authentication silo.")
@click.option("--siloname", required=True, help="Name of the silo.")
@click.option("--description", default=None, help="Description for the silo.")
@click.pass_context
def silos_create(ctx: click.Context, siloname: str, description: Optional[str]) -> None:
    """Create a new authentication silo."""
    body: Dict[str, Any] = {"siloname": siloname}
    if description is not None:
        body["description"] = description
    _out(_api(ctx).post("/api/v1/auth/silos", json_body=body))


@auth_silos.command("show", help="Show authentication silo details.")
@click.argument("siloname")
@click.pass_context
def silos_show(ctx: click.Context, siloname: str) -> None:
    """Show detailed information about an authentication silo."""
    _out(_api(ctx).get(f"/api/v1/auth/silos/{siloname}"))


@auth_silos.command("delete", help="Delete an authentication silo.")
@click.argument("siloname")
@click.pass_context
def silos_delete(ctx: click.Context, siloname: str) -> None:
    """Delete an authentication silo."""
    _out(_api(ctx).delete(f"/api/v1/auth/silos/{siloname}"))


# ── Auth silo-members ─────────────────────────────────────────────────


@auth.group("silo-members", help="Manage silo membership.")
@click.pass_context
def auth_silo_members(ctx: click.Context) -> None:
    """Authentication silo member commands."""


@auth_silo_members.command("add", help="Add member to silo.")
@click.argument("siloname")
@click.option("--accountname", required=True, help="Account name to add.")
@click.pass_context
def silo_member_add(ctx: click.Context, siloname: str, accountname: str) -> None:
    """Add an account as a member of an authentication silo."""
    _out(_api(ctx).post(f"/api/v1/auth/silos/{siloname}/members", json_body={"accountname": accountname}))


@auth_silo_members.command("remove", help="Remove member from silo.")
@click.argument("siloname")
@click.option("--accountname", required=True, help="Account name to remove.")
@click.pass_context
def silo_member_remove(ctx: click.Context, siloname: str, accountname: str) -> None:
    """Remove an account from an authentication silo."""
    _out(_api(ctx).delete(f"/api/v1/auth/silos/{siloname}/members", json_body={"accountname": accountname}))


# ── Auth policies ─────────────────────────────────────────────────────


@auth.group("policies", help="Manage authentication policies.")
@click.pass_context
def auth_policies(ctx: click.Context) -> None:
    """Authentication policy commands."""


@auth_policies.command("list", help="List authentication policies.")
@click.pass_context
def policies_list(ctx: click.Context) -> None:
    """List all authentication policies in the domain."""
    _out(_api(ctx).get("/api/v1/auth/policies"))


@auth_policies.command("create", help="Create an authentication policy.")
@click.option("--policyname", required=True, help="Name of the policy.")
@click.option("--description", default=None, help="Description for the policy.")
@click.pass_context
def policies_create(ctx: click.Context, policyname: str, description: Optional[str]) -> None:
    """Create a new authentication policy."""
    body: Dict[str, Any] = {"policyname": policyname}
    if description is not None:
        body["description"] = description
    _out(_api(ctx).post("/api/v1/auth/policies", json_body=body))


@auth_policies.command("show", help="Show authentication policy details.")
@click.argument("policyname")
@click.pass_context
def policies_show(ctx: click.Context, policyname: str) -> None:
    """Show detailed information about an authentication policy."""
    _out(_api(ctx).get(f"/api/v1/auth/policies/{policyname}"))


@auth_policies.command("delete", help="Delete an authentication policy.")
@click.argument("policyname")
@click.pass_context
def policies_delete(ctx: click.Context, policyname: str) -> None:
    """Delete an authentication policy."""
    _out(_api(ctx).delete(f"/api/v1/auth/policies/{policyname}"))


# ═══════════════════════════════════════════════════════════════════════════
# MISC commands
# ═══════════════════════════════════════════════════════════════════════════


@cli.group("misc", help="Miscellaneous operations.")
@click.pass_context
def misc(ctx: click.Context) -> None:
    """Miscellaneous management commands."""


@misc.command("dbcheck", help="Run database consistency check.")
@click.option("--fix", is_flag=True, default=False, help="Fix errors found during check.")
@click.pass_context
def misc_dbcheck(ctx: click.Context, fix: bool) -> None:
    """Run a database consistency check.

    With --fix, also fixes errors found during the check.
    Both are background tasks; returns a task_id for polling.
    """
    if fix:
        _out(_api(ctx).post("/api/v1/misc/dbcheck/fix", json_body={"yes": True}))
    else:
        _out(_api(ctx).get("/api/v1/misc/dbcheck"))


@misc.command("testparm", help="Test Samba configuration.")
@click.pass_context
def misc_testparm(ctx: click.Context) -> None:
    """Test the Samba configuration file for correctness."""
    _out(_api(ctx).get("/api/v1/misc/testparm"))


@misc.command("processes", help="List Samba processes.")
@click.pass_context
def misc_processes(ctx: click.Context) -> None:
    """List all running Samba processes."""
    _out(_api(ctx).get("/api/v1/misc/processes"))


@misc.command("time", help="Get server time.")
@click.pass_context
def misc_time(ctx: click.Context) -> None:
    """Get the current server time from the domain controller."""
    _out(_api(ctx).get("/api/v1/misc/time"))


# ── SPN sub-group ─────────────────────────────────────────────────────


@misc.group("spn", help="Manage Service Principal Names.")
@click.pass_context
def misc_spn(ctx: click.Context) -> None:
    """SPN management commands."""


@misc_spn.command("list", help="List SPNs for an account.")
@click.option("--accountname", required=True, help="Account name.")
@click.pass_context
def spn_list(ctx: click.Context, accountname: str) -> None:
    """List Service Principal Names for an account."""
    _out(_api(ctx).get("/api/v1/misc/spn/list", params={"accountname": accountname}))


@misc_spn.command("add", help="Add an SPN.")
@click.option("--accountname", required=True, help="Account name.")
@click.option("--spn", required=True, help="Service Principal Name to add.")
@click.pass_context
def spn_add(ctx: click.Context, accountname: str, spn: str) -> None:
    """Add a Service Principal Name to an account."""
    _out(_api(ctx).post("/api/v1/misc/spn/add", json_body={"accountname": accountname, "spn": spn}))


@misc_spn.command("delete", help="Delete an SPN.")
@click.option("--accountname", required=True, help="Account name.")
@click.option("--spn", required=True, help="Service Principal Name to delete.")
@click.pass_context
def spn_delete(ctx: click.Context, accountname: str, spn: str) -> None:
    """Delete a Service Principal Name from an account."""
    _out(_api(ctx).delete("/api/v1/misc/spn/delete", json_body={"accountname": accountname, "spn": spn}))


# ── NTACL sub-group ───────────────────────────────────────────────────


@misc.group("ntacl", help="Manage NT ACLs.")
@click.pass_context
def misc_ntacl(ctx: click.Context) -> None:
    """NT ACL management commands."""


@misc_ntacl.command("get", help="Get NT ACL for a file.")
@click.option("--file-path", required=True, help="Path to the file or directory.")
@click.pass_context
def ntacl_get(ctx: click.Context, file_path: str) -> None:
    """Get the NT ACL for a file or directory."""
    _out(_api(ctx).get("/api/v1/misc/ntacl", params={"file_path": file_path}))


@misc_ntacl.command("set", help="Set NT ACL on a file.")
@click.option("--file-path", required=True, help="Path to the file or directory.")
@click.option("--sddl", required=True, help="SDDL string for the ACL.")
@click.pass_context
def ntacl_set(ctx: click.Context, file_path: str, sddl: str) -> None:
    """Set the NT ACL on a file or directory using an SDDL string."""
    _out(_api(ctx).post("/api/v1/misc/ntacl/set", json_body={"file_path": file_path, "sddl": sddl}))


@misc_ntacl.command("sysvolreset", help="Reset sysvol ACLs.")
@click.pass_context
def ntacl_sysvolreset(ctx: click.Context) -> None:
    """Reset sysvol ACLs as a background task.

    Returns a task_id for polling.
    """
    _out(_api(ctx).post("/api/v1/misc/ntacl/sysvolreset"))


# ── Forest info ───────────────────────────────────────────────────────


@misc.command("forest-info", help="Get forest information.")
@click.pass_context
def misc_forest_info(ctx: click.Context) -> None:
    """Retrieve information about the Active Directory forest."""
    _out(_api(ctx).get("/api/v1/misc/forest/info"))


# ═══════════════════════════════════════════════════════════════════════════
# Health check (bonus — no API key technically required)
# ═══════════════════════════════════════════════════════════════════════════


@cli.command("health", help="Check API server health (no auth required).")
@click.pass_context
def health(ctx: click.Context) -> None:
    """Lightweight liveness probe — no authentication required."""
    client = _api(ctx)
    try:
        resp = requests.get(f"{client.base_url}/health", timeout=10)
        _out(resp.json())
    except requests.ConnectionError as exc:
        raise click.ClickException(f"Cannot connect to server at {client.base_url}: {exc}") from exc
    except ValueError:
        raise click.ClickException(f"Invalid response from server: {resp.text}")


# ═══════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════


def main() -> None:
    """Entry point for the CLI."""
    try:
        cli(auto_envvar_prefix="SAMBA")
    except click.ClickException as exc:
        click.echo(f"Error: {exc.format_message()}", err=True)
        sys.exit(1)
    except requests.ConnectionError as exc:
        click.echo(f"Error: Cannot connect to API server: {exc}", err=True)
        sys.exit(1)
    except requests.Timeout as exc:
        click.echo(f"Error: Request timed out: {exc}", err=True)
        sys.exit(1)
    except KeyboardInterrupt:
        click.echo("\nAborted.", err=True)
        sys.exit(130)


if __name__ == "__main__":
    main()
