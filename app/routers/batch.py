"""
Batch execution router for the Samba AD DC Management API.

Provides a ``POST /api/v1/batch`` endpoint that accepts an array of
actions and executes them sequentially, returning the result of each
step.  Actions can reference results from previous steps via template
placeholders (``{{ step_id.field }}``).

Supported methods
-----------------
user.create, user.delete, user.enable, user.disable, user.unlock,
user.setpassword, user.getpassword, user.list, user.show,
user.getgroups, user.setexpiry, user.move, user.rename,
user.addunixattrs, user.sensitive,

group.create, group.delete, group.addmembers, group.removemembers,
group.listmembers, group.list, group.show, group.move, group.stats,

computer.create, computer.delete, computer.list, computer.show,
computer.move,

contact.create, contact.delete, contact.list, contact.show,
contact.move, contact.rename,

ou.create, ou.delete, ou.list, ou.move, ou.rename,

dns.zone.create, dns.zone.delete, dns.record.create,
dns.record.delete, dns.record.update, dns.zone.list, dns.zone.info,
dns.record.list, dns.serverinfo, dns.zone.options,

shell.exec, shell.script,

misc.spn.add, misc.spn.delete, misc.spn.list,
misc.ntacl.get, misc.ntacl.set,

domain.info, domain.level, domain.passwordsettings,

fsmo.show,

drs.showrepl, drs.bind, drs.options, drs.replicate, drs.uptodateness,

gpo.list, gpo.create, gpo.delete, gpo.show,
gpo.setlink, gpo.dellink, gpo.getinheritance, gpo.setinheritance,

sites.list, sites.create, sites.remove,
sites.subnet.create, sites.subnet.remove,

delegation.add, delegation.remove, delegation.for_account,

service_account.create, service_account.delete, service_account.list,
service_account.show, service_account.gmsa_members.add,
service_account.gmsa_members.remove, service_account.gmsa_members.list,

auth.silo.create, auth.silo.delete, auth.silo.list, auth.silo.show,
auth.silo.members.add, auth.silo.members.remove,
auth.policy.create, auth.policy.delete, auth.policy.list, auth.policy.show,
"""

from __future__ import annotations

import logging
import re
import uuid
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, HTTPException, status

from app.auth import ApiKeyDep
from app.config import get_settings
from app.executor import (
    build_samba_command,
    build_samba_command_deep,
    execute_samba_command,
    get_dc_hostname,
    raise_classified_error,
)
from app.models.batch import (
    BatchAction,
    BatchRequest,
    BatchResponse,
    BatchStepResult,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/batch", tags=["Batch"])


# ═══════════════════════════════════════════════════════════════════════
#  Template resolution
# ═══════════════════════════════════════════════════════════════════════

# Pattern: {{ step_id.field }}  or  {{ batch_id }}
_TEMPLATE_RE = re.compile(r"\{\{\s*(\w+)\.(\w+)\s*\}\}")
_TEMPLATE_SIMPLE_RE = re.compile(r"\{\{\s*(\w+)\s*\}\}")


def resolve_templates(
    value: Any,
    context: Dict[str, Any],
) -> Any:
    """Recursively resolve ``{{ … }}`` placeholders in *value*.

    Supported patterns::

        {{ batch_id }}           → context["batch_id"]
        {{ step1.username }}     → context["step1"]["username"]
        {{ step1.created_user }} → context["step1"]["created_user"]

    If a placeholder cannot be resolved, it is left as-is (no error).
    This allows optional forward references or placeholder passthrough.
    """
    if isinstance(value, str):
        # Resolve dotted references like {{ step1.field }}
        def _replace_dotted(match: re.Match) -> str:
            step_id = match.group(1)
            field_name = match.group(2)
            # Check for batch_id as a simple key
            if step_id == "batch_id" and "batch_id" in context:
                return str(context["batch_id"])
            # Look up step_id.field in context
            step_data = context.get(step_id)
            if isinstance(step_data, dict) and field_name in step_data:
                return str(step_data[field_name])
            # Cannot resolve — leave as-is
            return match.group(0)

        value = _TEMPLATE_RE.sub(_replace_dotted, value)

        # Resolve simple references like {{ batch_id }}
        def _replace_simple(match: re.Match) -> str:
            key = match.group(1)
            if key in context and not isinstance(context[key], dict):
                return str(context[key])
            return match.group(0)

        value = _TEMPLATE_SIMPLE_RE.sub(_replace_simple, value)
        return value

    if isinstance(value, dict):
        return {k: resolve_templates(v, context) for k, v in value.items()}

    if isinstance(value, list):
        return [resolve_templates(item, context) for item in value]

    return value


# ═══════════════════════════════════════════════════════════════════════
#  Context extraction — map method output to useful context fields
# ═══════════════════════════════════════════════════════════════════════


def extract_context_fields(
    method: str,
    params: Dict[str, Any],
    result: Any,
) -> Dict[str, Any]:
    """Extract useful fields from an action result into the context.

    After each successful action, certain fields are stored in the
    execution context so that subsequent actions can reference them
    via templates.  For example, after ``user.create`` the context
    stores ``username`` and ``password`` (if random_password was used).
    """
    ctx: Dict[str, Any] = {}

    if not isinstance(result, dict):
        # If result is not a dict, store it as 'output'
        ctx["output"] = result
        return ctx

    # ── user.create ─────────────────────────────────────────────────
    if method == "user.create":
        ctx["username"] = params.get("username", "")
        if params.get("random_password"):
            # samba-tool outputs: "User 'xxx' created successfully"
            # With direct SamDB: result may contain 'password' key
            if "password" in result:
                ctx["password"] = result["password"]
            # Try to extract password from output text
            output = result.get("output", "")
            pw_match = re.search(
                r"(?:password|Password)\s*[:=]\s*(\S+)", output
            )
            if pw_match:
                ctx["password"] = pw_match.group(1)
        # Extract DN if present
        if "dn" in result:
            ctx["dn"] = result["dn"]
        output = result.get("output", "")
        dn_match = re.search(r"dn:\s*(\S+)", output)
        if dn_match:
            ctx["dn"] = dn_match.group(1)
        ctx["created_user"] = ctx["username"]

    # ── group.create ────────────────────────────────────────────────
    elif method == "group.create":
        ctx["groupname"] = params.get("groupname", "")
        ctx["created_group"] = ctx["groupname"]

    # ── computer.create ─────────────────────────────────────────────
    elif method == "computer.create":
        ctx["computername"] = params.get("computername", "")
        ctx["created_computer"] = ctx["computername"]

    # ── contact.create ──────────────────────────────────────────────
    elif method == "contact.create":
        ctx["contactname"] = params.get("contactname", "")
        ctx["created_contact"] = ctx["contactname"]

    # ── ou.create ───────────────────────────────────────────────────
    elif method == "ou.create":
        ctx["ouname"] = params.get("ouname", "")
        ctx["created_ou"] = ctx["ouname"]

    # ── dns.zone.create ─────────────────────────────────────────────
    elif method == "dns.zone.create":
        ctx["zone"] = params.get("zone", "")
        ctx["created_zone"] = ctx["zone"]

    # ── dns.record.create ───────────────────────────────────────────
    elif method == "dns.record.create":
        ctx["record_name"] = params.get("name", "")
        ctx["record_type"] = params.get("record_type", "")
        ctx["record_data"] = params.get("data", "")

    # ── shell.exec / shell.script ───────────────────────────────────
    elif method in ("shell.exec", "shell.script"):
        if "data" in result:
            data = result["data"]
            if isinstance(data, dict):
                ctx["stdout"] = data.get("stdout", "")
                ctx["stderr"] = data.get("stderr", "")
                ctx["returncode"] = data.get("returncode", -1)

    # ── misc.spn.add ────────────────────────────────────────────────
    elif method == "misc.spn.add":
        ctx["spn"] = params.get("spn", "")

    # ── Generic: store result keys ──────────────────────────────────
    # Also store top-level keys from result that might be useful
    for key in ("username", "groupname", "computername", "contactname",
                "ouname", "dn", "password", "zone", "guid", "id"):
        if key in result and key not in ctx:
            ctx[key] = result[key]

    return ctx


# ═══════════════════════════════════════════════════════════════════════
#  Method dispatch — map method names to samba-tool / shell calls
# ═══════════════════════════════════════════════════════════════════════

# Methods that are NOT allowed in batch because they are too slow
# (they run as background tasks) or are too dangerous.
_BLOCKED_BATCH_METHODS: set[str] = {
    "domain.backup.online",
    "domain.backup.offline",
    "domain.join",
    "domain.leave",
    "domain.demote",
    "domain.provision",
    "gpo.backup",
    "gpo.restore",
    "misc.dbcheck",
    "misc.dbcheck.fix",
    "misc.ntacl.sysvolreset",
    "misc.testparm",
}


def _clean_args(args: dict[str, Any]) -> dict[str, Any]:
    """Remove keys whose values are *None* or empty strings."""
    return {k: v for k, v in args.items() if v is not None and v != ""}


async def dispatch_method(
    method: str,
    params: Dict[str, Any],
    timeout: int = 30,
) -> Any:
    """Execute a single batch action by dispatching to the appropriate
    samba-tool command or shell execution.

    Parameters
    ----------
    method:
        Dot-notation method name, e.g. ``user.create``.
    params:
        Resolved parameters for the method.
    timeout:
        Timeout for shell operations.

    Returns
    -------
    Any
        The result of the operation (dict from samba-tool JSON output,
        or a dict with structured data).

    Raises
    ------
    ValueError
        If the method is not recognised or is blocked.
    RuntimeError
        If the underlying samba-tool command fails.
    """
    # ── Check blocked methods ────────────────────────────────────────
    if method in _BLOCKED_BATCH_METHODS:
        raise ValueError(
            f"Method '{method}' is not allowed in batch operations. "
            f"This operation is either too long-running or too dangerous "
            f"for batch execution.  Use the dedicated endpoint instead."
        )

    settings = get_settings()

    # ══════════════════════════════════════════════════════════════════
    #  USER methods
    # ══════════════════════════════════════════════════════════════════

    if method == "user.create":
        username = params.get("username", "")
        password = params.get("password")
        random_password = params.get("random_password", False)
        args: dict[str, Any] = _clean_args({
            "--must-change-at-next-login": params.get("must_change_at_next_login"),
            "--random-password": random_password or None,
            "--smartcard-required": params.get("smartcard_required"),
            "--use-username-as-cn": params.get("use_username_as_cn"),
            "--userou": params.get("userou"),
            "--surname": params.get("surname"),
            "--given-name": params.get("given_name"),
            "--initials": params.get("initials"),
            "--profile-path": params.get("profile_path"),
            "--script-path": params.get("script_path"),
            "--home-drive": params.get("home_drive"),
            "--home-directory": params.get("home_directory"),
            "--job-title": params.get("job_title"),
            "--department": params.get("department"),
            "--company": params.get("company"),
            "--description": params.get("description"),
            "--mail-address": params.get("mail_address"),
            "--internet-address": params.get("internet_address"),
            "--telephone-number": params.get("telephone_number"),
            "--physical-delivery-office": params.get("physical_delivery_office"),
        })
        positionals = [username]
        if password is not None and not random_password:
            positionals.append(password)
        cmd = build_samba_command("user", "add", args, positionals=positionals)
        return await execute_samba_command(cmd)

    elif method == "user.delete":
        username = params.get("username", "")
        cmd = build_samba_command("user", "delete", {}, positionals=[username])
        return await execute_samba_command(cmd)

    elif method == "user.enable":
        username = params.get("username", "")
        cmd = build_samba_command("user", "enable", {}, positionals=[username])
        return await execute_samba_command(cmd)

    elif method == "user.disable":
        username = params.get("username", "")
        cmd = build_samba_command("user", "disable", {}, positionals=[username])
        return await execute_samba_command(cmd)

    elif method == "user.unlock":
        username = params.get("username", "")
        cmd = build_samba_command("user", "unlock", {}, positionals=[username])
        return await execute_samba_command(cmd)

    elif method == "user.setpassword":
        username = params.get("username", "")
        new_password = params.get("new_password", "")
        args = {"--newpassword": new_password}
        if params.get("must_change_at_next_login"):
            args["--must-change-at-next-login"] = True
        cmd = build_samba_command("user", "setpassword", args, positionals=[username])
        return await execute_samba_command(cmd)

    elif method == "user.getpassword":
        username = params.get("username", "")
        attributes = params.get("attributes", "virtualClearTextUTF16")
        tdb_url = None
        try:
            from app.executor import get_tdb_url
            tdb_url = get_tdb_url(settings)
        except Exception:
            pass
        args: dict[str, Any] = {"--attributes": attributes}
        if tdb_url:
            args["-H"] = tdb_url
        cmd = build_samba_command("user", "getpassword", args, positionals=[username])
        return await execute_samba_command(cmd)

    elif method == "user.list":
        args = _clean_args({
            "--verbose": params.get("verbose"),
            "--base-dn": params.get("base_dn"),
            "--full-dn": params.get("full_dn"),
            "-H": params.get("H"),
            "--json": True,
        })
        cmd = build_samba_command("user", "list", args)
        return await execute_samba_command(cmd)

    elif method == "user.show":
        username = params.get("username", "")
        args = _clean_args({
            "--attributes": params.get("attributes"),
            "-H": params.get("H"),
            "--json": True,
        })
        cmd = build_samba_command("user", "show", args, positionals=[username])
        return await execute_samba_command(cmd)

    elif method == "user.getgroups":
        username = params.get("username", "")
        args = _clean_args({"-H": params.get("H"), "--json": True})
        cmd = build_samba_command("user", "getgroups", args, positionals=[username])
        return await execute_samba_command(cmd)

    elif method == "user.setexpiry":
        username = params.get("username", "")
        days = params.get("days", 0)
        cmd = build_samba_command("user", "setexpiry", {"--days": days}, positionals=[username])
        return await execute_samba_command(cmd)

    elif method == "user.move":
        username = params.get("username", "")
        new_parent_dn = params.get("new_parent_dn", "")
        cmd = build_samba_command("user", "move", {}, positionals=[username, new_parent_dn])
        return await execute_samba_command(cmd)

    elif method == "user.rename":
        username = params.get("username", "")
        new_name = params.get("new_name", "")
        cmd = build_samba_command("user", "rename", {"--samaccountname": new_name}, positionals=[username])
        return await execute_samba_command(cmd)

    elif method == "user.addunixattrs":
        username = params.get("username", "")
        uid_number = params.get("uid_number", 0)
        args = _clean_args({
            "--gid-number": params.get("gid_number"),
            "--unix-home": params.get("unix_home"),
            "--login-shell": params.get("login_shell"),
            "--gecos": params.get("gecos"),
            "--nis-domain": params.get("nis_domain"),
            "--uid": params.get("uid"),
        })
        cmd = build_samba_command("user", "addunixattrs", args, positionals=[username, str(uid_number)])
        return await execute_samba_command(cmd)

    elif method == "user.sensitive":
        username = params.get("username", "")
        on = params.get("on", True)
        cmd = build_samba_command("user", "sensitive", {}, positionals=[username, "on" if on else "off"])
        return await execute_samba_command(cmd)

    # ══════════════════════════════════════════════════════════════════
    #  GROUP methods
    # ══════════════════════════════════════════════════════════════════

    elif method == "group.create":
        groupname = params.get("groupname", "")
        args = _clean_args({
            "--groupou": params.get("groupou"),
            "--group-scope": params.get("group_scope"),
            "--group-type": params.get("group_type"),
            "--description": params.get("description"),
            "--mail-address": params.get("mail_address"),
            "--notes": params.get("notes"),
            "--gid-number": params.get("gid_number"),
            "--nis-domain": params.get("nis_domain"),
            "--special": params.get("special"),
        })
        cmd = build_samba_command("group", "add", args, positionals=[groupname])
        return await execute_samba_command(cmd)

    elif method == "group.delete":
        groupname = params.get("groupname", "")
        cmd = build_samba_command("group", "delete", {}, positionals=[groupname])
        return await execute_samba_command(cmd)

    elif method == "group.addmembers":
        groupname = params.get("groupname", "")
        members = params.get("members", [])
        if isinstance(members, str):
            members = [members]
        args = _clean_args({
            "--object-types": params.get("object_types"),
            "--member-base-dn": params.get("member_base_dn"),
        })
        member_dn = params.get("member_dn")
        if member_dn:
            if isinstance(member_dn, str):
                member_dn = [member_dn]
            for dn in member_dn:
                args[f"--member-dn={dn}"] = True
        positionals = [groupname] + list(members)
        cmd = build_samba_command("group", "addmembers", args, positionals=positionals)
        return await execute_samba_command(cmd)

    elif method == "group.removemembers":
        groupname = params.get("groupname", "")
        members = params.get("members", [])
        if isinstance(members, str):
            members = [members]
        args = _clean_args({
            "--object-types": params.get("object_types"),
            "--member-base-dn": params.get("member_base_dn"),
        })
        member_dn = params.get("member_dn")
        if member_dn:
            if isinstance(member_dn, str):
                member_dn = [member_dn]
            for dn in member_dn:
                args[f"--member-dn={dn}"] = True
        positionals = [groupname] + list(members)
        cmd = build_samba_command("group", "removemembers", args, positionals=positionals)
        return await execute_samba_command(cmd)

    elif method == "group.listmembers":
        groupname = params.get("groupname", "")
        args = _clean_args({
            "--hide-expired": params.get("hide_expired"),
            "--hide-disabled": params.get("hide_disabled"),
            "--full-dn": params.get("full_dn"),
            "-H": params.get("H"),
            "--json": True,
        })
        cmd = build_samba_command("group", "listmembers", args, positionals=[groupname])
        return await execute_samba_command(cmd)

    elif method == "group.list":
        args = _clean_args({
            "--verbose": params.get("verbose"),
            "--base-dn": params.get("base_dn"),
            "--full-dn": params.get("full_dn"),
            "-H": params.get("H"),
            "--json": True,
        })
        cmd = build_samba_command("group", "list", args)
        return await execute_samba_command(cmd)

    elif method == "group.show":
        groupname = params.get("groupname", "")
        args = _clean_args({
            "--attributes": params.get("attributes"),
            "-H": params.get("H"),
            "--json": True,
        })
        cmd = build_samba_command("group", "show", args, positionals=[groupname])
        return await execute_samba_command(cmd)

    elif method == "group.move":
        groupname = params.get("groupname", "")
        new_parent_dn = params.get("new_parent_dn", "")
        cmd = build_samba_command("group", "move", {}, positionals=[groupname, new_parent_dn])
        return await execute_samba_command(cmd)

    elif method == "group.stats":
        args = _clean_args({"-H": params.get("H"), "--json": True})
        cmd = build_samba_command("group", "stats", args)
        return await execute_samba_command(cmd)

    # ══════════════════════════════════════════════════════════════════
    #  COMPUTER methods
    # ══════════════════════════════════════════════════════════════════

    elif method == "computer.create":
        computername = params.get("computername", "")
        args = _clean_args({
            "--computerou": params.get("computerou"),
            "--description": params.get("description"),
            "--prepare-oldjoin": params.get("prepare_oldjoin"),
        })
        cmd = build_samba_command("computer", "add", args, positionals=[computername])
        return await execute_samba_command(cmd)

    elif method == "computer.delete":
        computername = params.get("computername", "")
        cmd = build_samba_command("computer", "delete", {}, positionals=[computername])
        return await execute_samba_command(cmd)

    elif method == "computer.list":
        args = _clean_args({
            "--base-dn": params.get("base_dn"),
            "--full-dn": params.get("full_dn"),
            "-H": params.get("H"),
            "--json": True,
        })
        cmd = build_samba_command("computer", "list", args)
        return await execute_samba_command(cmd)

    elif method == "computer.show":
        computername = params.get("computername", "")
        args = _clean_args({
            "--attributes": params.get("attributes"),
            "-H": params.get("H"),
            "--json": True,
        })
        cmd = build_samba_command("computer", "show", args, positionals=[computername])
        return await execute_samba_command(cmd)

    elif method == "computer.move":
        computername = params.get("computername", "")
        new_ou_dn = params.get("new_ou_dn", "")
        cmd = build_samba_command("computer", "move", {}, positionals=[computername, new_ou_dn])
        return await execute_samba_command(cmd)

    # ══════════════════════════════════════════════════════════════════
    #  CONTACT methods
    # ══════════════════════════════════════════════════════════════════

    elif method == "contact.create":
        contactname = params.get("contactname", "")
        args = _clean_args({
            "--userou": params.get("userou"),
            "--surname": params.get("surname"),
            "--given-name": params.get("given_name"),
            "--initials": params.get("initials"),
            "--description": params.get("description"),
            "--mail-address": params.get("mail_address"),
        })
        cmd = build_samba_command("contact", "add", args, positionals=[contactname])
        return await execute_samba_command(cmd)

    elif method == "contact.delete":
        contactname = params.get("contactname", "")
        cmd = build_samba_command("contact", "delete", {}, positionals=[contactname])
        return await execute_samba_command(cmd)

    elif method == "contact.list":
        args = _clean_args({
            "--base-dn": params.get("base_dn"),
            "--full-dn": params.get("full_dn"),
            "-H": params.get("H"),
            "--json": True,
        })
        cmd = build_samba_command("contact", "list", args)
        return await execute_samba_command(cmd)

    elif method == "contact.show":
        contactname = params.get("contactname", "")
        args = _clean_args({
            "--attributes": params.get("attributes"),
            "-H": params.get("H"),
            "--json": True,
        })
        cmd = build_samba_command("contact", "show", args, positionals=[contactname])
        return await execute_samba_command(cmd)

    elif method == "contact.move":
        contactname = params.get("contactname", "")
        new_parent_dn = params.get("new_parent_dn", "")
        cmd = build_samba_command("contact", "move", {}, positionals=[contactname, new_parent_dn])
        return await execute_samba_command(cmd)

    elif method == "contact.rename":
        contactname = params.get("contactname", "")
        new_name = params.get("new_name", "")
        cmd = build_samba_command("contact", "rename", {"--new-name": new_name}, positionals=[contactname])
        return await execute_samba_command(cmd)

    # ══════════════════════════════════════════════════════════════════
    #  OU methods
    # ══════════════════════════════════════════════════════════════════

    elif method == "ou.create":
        ouname = params.get("ouname", "")
        args = _clean_args({
            "--description": params.get("description"),
        })
        cmd = build_samba_command("ou", "add", args, positionals=[ouname])
        return await execute_samba_command(cmd)

    elif method == "ou.delete":
        ouname = params.get("ouname", "")
        cmd = build_samba_command("ou", "delete", {}, positionals=[ouname])
        return await execute_samba_command(cmd)

    elif method == "ou.list":
        args = _clean_args({
            "--base-dn": params.get("base_dn"),
            "--full-dn": params.get("full_dn"),
            "-H": params.get("H"),
            "--json": True,
        })
        cmd = build_samba_command("ou", "list", args)
        return await execute_samba_command(cmd)

    elif method == "ou.move":
        ouname = params.get("ouname", "")
        new_parent_dn = params.get("new_parent_dn", "")
        cmd = build_samba_command("ou", "move", {}, positionals=[ouname, new_parent_dn])
        return await execute_samba_command(cmd)

    elif method == "ou.rename":
        ouname = params.get("ouname", "")
        new_name = params.get("new_name", "")
        cmd = build_samba_command("ou", "rename", {}, positionals=[ouname, new_name])
        return await execute_samba_command(cmd)

    # ══════════════════════════════════════════════════════════════════
    #  DNS methods
    # ══════════════════════════════════════════════════════════════════

    elif method == "dns.zone.create":
        zone = params.get("zone", "")
        srv = params.get("server") or get_dc_hostname(settings)
        dns_partition = params.get("dns_directory_partition", "domain")
        args = {"--dns-directory-partition": dns_partition}
        cmd = build_samba_command("dns", "zonecreate", args, positionals=[srv, zone])
        return await execute_samba_command(cmd, timeout=240)

    elif method == "dns.zone.delete":
        zone = params.get("zone", "")
        srv = params.get("server") or get_dc_hostname(settings)
        cmd = build_samba_command("dns", "zonedelete", {}, positionals=[srv, zone])
        return await execute_samba_command(cmd, timeout=240)

    elif method == "dns.zone.list":
        srv = params.get("server") or get_dc_hostname(settings)
        args = _clean_args({
            "--primary": params.get("primary"),
            "--secondary": params.get("secondary"),
            "--forward": params.get("forward"),
            "--reverse": params.get("reverse"),
        })
        cmd = build_samba_command("dns", "zonelist", args, positionals=[srv])
        return await execute_samba_command(cmd, timeout=120)

    elif method == "dns.zone.info":
        zone = params.get("zone", "")
        srv = params.get("server") or get_dc_hostname(settings)
        cmd = build_samba_command("dns", "zoneinfo", {}, positionals=[srv, zone])
        return await execute_samba_command(cmd, timeout=120)

    elif method == "dns.record.create":
        zone = params.get("zone", "")
        name = params.get("name", "")
        record_type = params.get("record_type", "A")
        data = params.get("data", "")
        srv = params.get("server") or get_dc_hostname(settings)
        cmd = build_samba_command("dns", "add", {}, positionals=[srv, zone, name, record_type, data])
        return await execute_samba_command(cmd, timeout=120)

    elif method == "dns.record.delete":
        zone = params.get("zone", "")
        name = params.get("name", "")
        record_type = params.get("record_type", "A")
        data = params.get("data", "")
        srv = params.get("server") or get_dc_hostname(settings)
        cmd = build_samba_command("dns", "delete", {}, positionals=[srv, zone, name, record_type, data])
        return await execute_samba_command(cmd, timeout=120)

    elif method == "dns.record.update":
        zone = params.get("zone", "")
        name = params.get("name", "")
        old_record_type = params.get("old_record_type", "A")
        old_data = params.get("old_data", "")
        new_data = params.get("new_data", "")
        srv = params.get("server") or get_dc_hostname(settings)
        cmd = build_samba_command("dns", "update", {}, positionals=[srv, zone, name, old_record_type, old_data, new_data])
        return await execute_samba_command(cmd, timeout=120)

    elif method == "dns.record.list":
        zone = params.get("zone", "")
        name = params.get("name", "@")
        record_type = params.get("record_type", "ALL")
        srv = params.get("server") or get_dc_hostname(settings)
        args = {"--json": True}
        cmd = build_samba_command("dns", "query", args, positionals=[srv, zone, name, record_type])
        return await execute_samba_command(cmd, timeout=120)

    elif method == "dns.serverinfo":
        srv = params.get("server") or get_dc_hostname(settings)
        args = _clean_args({"--client-version": params.get("client_version")})
        cmd = build_samba_command("dns", "serverinfo", args, positionals=[srv])
        return await execute_samba_command(cmd, timeout=120)

    elif method == "dns.zone.options":
        zone = params.get("zone", "")
        srv = params.get("server") or get_dc_hostname(settings)
        args: dict[str, Any] = {}
        options = params.get("options", {})
        for key, value in options.items():
            flag = f"--{key}"
            if isinstance(value, bool):
                args[flag] = 1 if value else 0
            else:
                args[flag] = str(value)
        cmd = build_samba_command("dns", "zoneoptions", args, positionals=[srv, zone])
        return await execute_samba_command(cmd, timeout=120)

    # ══════════════════════════════════════════════════════════════════
    #  SHELL methods
    # ══════════════════════════════════════════════════════════════════

    elif method == "shell.exec":
        from app.routers.shell import exec_command, _check_blocked, ShellExecRequest
        cmd_str = params.get("cmd", "")
        shell_name = params.get("shell", "bash")
        sudo = params.get("sudo", False)
        shell_timeout = params.get("timeout", timeout)
        env = params.get("env")

        # Check blocked commands for safety
        blocked_msg = _check_blocked(cmd_str)
        if blocked_msg:
            raise ValueError(blocked_msg)

        exec_req = ShellExecRequest(
            shell=shell_name,
            sudo=sudo,
            cmd=cmd_str,
            timeout=shell_timeout,
            env=env,
        )
        result = await exec_command(exec_req, api_key="batch")
        # Convert Pydantic model to dict for context extraction
        return result.model_dump()

    elif method == "shell.script":
        from app.routers.shell import exec_script, _check_blocked, ShellScriptRequest
        lines = params.get("lines", [])
        shell_name = params.get("shell", "bash")
        sudo = params.get("sudo", False)
        shell_timeout = params.get("timeout", timeout)
        env = params.get("env")

        # Check blocked commands for each line
        for line in lines:
            blocked_msg = _check_blocked(line)
            if blocked_msg:
                raise ValueError(blocked_msg)

        script_req = ShellScriptRequest(
            shell=shell_name,
            sudo=sudo,
            lines=lines,
            timeout=shell_timeout,
            env=env,
        )
        result = await exec_script(script_req, api_key="batch")
        return result.model_dump()

    # ══════════════════════════════════════════════════════════════════
    #  MISC methods (SPN, NTACL)
    # ══════════════════════════════════════════════════════════════════

    elif method == "misc.spn.add":
        accountname = params.get("accountname", "")
        spn = params.get("spn", "")
        cmd = build_samba_command_deep(["spn", "add"], positionals=[spn, accountname])
        return await execute_samba_command(cmd)

    elif method == "misc.spn.delete":
        accountname = params.get("accountname", "")
        spn = params.get("spn", "")
        cmd = build_samba_command_deep(["spn", "delete"], positionals=[spn, accountname])
        return await execute_samba_command(cmd)

    elif method == "misc.spn.list":
        accountname = params.get("accountname", "")
        cmd = build_samba_command_deep(["spn", "list"], positionals=[accountname])
        return await execute_samba_command(cmd)

    elif method == "misc.ntacl.get":
        file_path = params.get("file_path", "")
        cmd = build_samba_command_deep(["ntacl", "get"], positionals=[file_path])
        from app.executor import execute_samba_command_raw
        result = await execute_samba_command_raw(cmd)
        if result["returncode"] != 0:
            error_msg = result["stderr"].strip() or result["stdout"].strip()
            raise RuntimeError(f"samba-tool ntacl get failed: {error_msg}")
        return {"file_path": file_path, "output": result["stdout"].strip()}

    elif method == "misc.ntacl.set":
        file_path = params.get("file_path", "")
        sddl = params.get("sddl", "")
        cmd = build_samba_command_deep(["ntacl", "set"], positionals=[sddl, file_path])
        return await execute_samba_command(cmd)

    # ══════════════════════════════════════════════════════════════════
    #  DOMAIN methods (read-only / safe)
    # ══════════════════════════════════════════════════════════════════

    elif method == "domain.info":
        ip_address = params.get("ip_address", "127.0.0.1")
        cmd = build_samba_command_deep(["domain", "info"], positionals=[ip_address])
        return await execute_samba_command(cmd)

    elif method == "domain.level":
        cmd = build_samba_command_deep(["domain", "level"])
        return await execute_samba_command(cmd)

    elif method == "domain.passwordsettings":
        cmd = build_samba_command_deep(["domain", "passwordsettings"])
        return await execute_samba_command(cmd)

    # ══════════════════════════════════════════════════════════════════
    #  FSMO methods
    # ══════════════════════════════════════════════════════════════════

    elif method == "fsmo.show":
        cmd = build_samba_command("fsmo", "show", {"--json": True})
        return await execute_samba_command(cmd)

    # ══════════════════════════════════════════════════════════════════
    #  DRS methods
    # ══════════════════════════════════════════════════════════════════

    elif method == "drs.showrepl":
        srv = params.get("server") or get_dc_hostname(settings)
        cmd = build_samba_command("drs", "showrepl", {}, positionals=[srv])
        return await execute_samba_command(cmd, timeout=120)

    elif method == "drs.bind":
        srv = params.get("server") or get_dc_hostname(settings)
        cmd = build_samba_command("drs", "bind", {}, positionals=[srv])
        return await execute_samba_command(cmd, timeout=120)

    elif method == "drs.options":
        srv = params.get("server") or get_dc_hostname(settings)
        cmd = build_samba_command("drs", "options", {}, positionals=[srv])
        return await execute_samba_command(cmd, timeout=120)

    elif method == "drs.replicate":
        source_dsa = params.get("source_dsa", "")
        destination_dsa = params.get("destination_dsa", "")
        nc_dn = params.get("nc_dn", "")
        cmd = build_samba_command("drs", "replicate", {}, positionals=[source_dsa, destination_dsa, nc_dn])
        return await execute_samba_command(cmd, timeout=300)

    elif method == "drs.uptodateness":
        nc_dn = params.get("nc_dn", "")
        args = _clean_args({
            "--GUID": params.get("guid"),
        })
        cmd = build_samba_command("drs", "uptodateness", args, positionals=[nc_dn] if nc_dn else [])
        return await execute_samba_command(cmd, timeout=120)

    # ══════════════════════════════════════════════════════════════════
    #  GPO methods
    # ══════════════════════════════════════════════════════════════════

    elif method == "gpo.list":
        cmd = build_samba_command("gpo", "listall", {"--json": True})
        return await execute_samba_command(cmd)

    elif method == "gpo.create":
        displayname = params.get("displayname", "")
        cmd = build_samba_command("gpo", "create", {}, positionals=[displayname])
        return await execute_samba_command(cmd)

    elif method == "gpo.delete":
        gpo_id = params.get("gpo_id", params.get("id", ""))
        cmd = build_samba_command("gpo", "del", {}, positionals=[gpo_id])
        return await execute_samba_command(cmd)

    elif method == "gpo.show":
        gpo_id = params.get("gpo_id", params.get("id", ""))
        cmd = build_samba_command("gpo", "show", {}, positionals=[gpo_id])
        return await execute_samba_command(cmd, timeout=120)

    elif method == "gpo.setlink":
        gpo_id = params.get("gpo_id", params.get("id", ""))
        container_dn = params.get("container_dn", "")
        cmd = build_samba_command("gpo", "setlink", {}, positionals=[gpo_id, container_dn])
        return await execute_samba_command(cmd, timeout=120)

    elif method == "gpo.dellink":
        gpo_id = params.get("gpo_id", params.get("id", ""))
        container_dn = params.get("container_dn", "")
        cmd = build_samba_command("gpo", "dellink", {}, positionals=[gpo_id, container_dn])
        return await execute_samba_command(cmd, timeout=120)

    elif method == "gpo.getinheritance":
        container_dn = params.get("container_dn", "")
        cmd = build_samba_command("gpo", "getinheritance", {}, positionals=[container_dn])
        return await execute_samba_command(cmd, timeout=120)

    elif method == "gpo.setinheritance":
        container_dn = params.get("container_dn", "")
        block = params.get("block", True)
        from app.executor import build_samba_command_deep
        cmd = build_samba_command_deep(
            ["gpo", "setinheritance"],
            positionals=[container_dn, "block" if block else "inherit"],
        )
        return await execute_samba_command(cmd, timeout=120)

    # ══════════════════════════════════════════════════════════════════
    #  SITES methods
    # ══════════════════════════════════════════════════════════════════

    elif method == "sites.list":
        cmd = build_samba_command("site", "list", {"--json": True})
        return await execute_samba_command(cmd)

    elif method == "sites.create":
        sitename = params.get("sitename", "")
        cmd = build_samba_command_deep(["sites", "create"], positionals=[sitename])
        return await execute_samba_command(cmd)

    elif method == "sites.remove":
        sitename = params.get("sitename", "")
        cmd = build_samba_command_deep(["sites", "remove"], positionals=[sitename])
        return await execute_samba_command(cmd)

    elif method == "sites.subnet.create":
        subnetname = params.get("subnetname", "")
        site_of_subnet = params.get("site_of_subnet", "")
        cmd = build_samba_command_deep(
            ["sites", "subnet", "create"],
            positionals=[subnetname, site_of_subnet],
        )
        return await execute_samba_command(cmd)

    elif method == "sites.subnet.remove":
        subnetname = params.get("subnetname", "")
        cmd = build_samba_command_deep(
            ["sites", "subnet", "remove"],
            positionals=[subnetname],
        )
        return await execute_samba_command(cmd)

    # ══════════════════════════════════════════════════════════════════
    #  DELEGATION methods
    # ══════════════════════════════════════════════════════════════════

    elif method == "delegation.add":
        accountname = params.get("accountname", "")
        service = params.get("service", "")
        cmd = build_samba_command_deep(
            ["delegation", "add"],
            positionals=[accountname, service],
        )
        return await execute_samba_command(cmd)

    elif method == "delegation.remove":
        accountname = params.get("accountname", "")
        service = params.get("service", "")
        cmd = build_samba_command_deep(
            ["delegation", "remove"],
            positionals=[accountname, service],
        )
        return await execute_samba_command(cmd)

    elif method == "delegation.for_account":
        accountname = params.get("accountname", "")
        cmd = build_samba_command_deep(
            ["delegation", "for-account"],
            positionals=[accountname],
        )
        return await execute_samba_command(cmd)

    # ══════════════════════════════════════════════════════════════════
    #  SERVICE ACCOUNT methods
    # ══════════════════════════════════════════════════════════════════

    elif method == "service_account.create":
        accountname = params.get("accountname", "")
        dns_host_name = params.get("dns_host_name", "")
        cmd = build_samba_command_deep(
            ["user", "create"],
            positionals=[accountname],
            args=_clean_args({
                "--service-principal-name": f"host/{dns_host_name}" if dns_host_name else None,
            }),
        )
        return await execute_samba_command(cmd)

    elif method == "service_account.delete":
        accountname = params.get("accountname", "")
        cmd = build_samba_command("user", "delete", {}, positionals=[accountname])
        return await execute_samba_command(cmd)

    elif method == "service_account.list":
        cmd = build_samba_command("user", "list", {"--json": True})
        return await execute_samba_command(cmd)

    elif method == "service_account.show":
        accountname = params.get("accountname", "")
        cmd = build_samba_command("user", "show", {"--json": True}, positionals=[accountname])
        return await execute_samba_command(cmd)

    # ══════════════════════════════════════════════════════════════════
    #  AUTH POLICY / SILO methods
    # ══════════════════════════════════════════════════════════════════

    elif method == "auth.silo.create":
        siloname = params.get("siloname", "")
        cmd = build_samba_command_deep(
            ["domain", "auth", "silo", "create"],
            positionals=[siloname],
        )
        return await execute_samba_command(cmd)

    elif method == "auth.silo.delete":
        siloname = params.get("siloname", "")
        cmd = build_samba_command_deep(
            ["domain", "auth", "silo", "delete"],
            positionals=[siloname],
        )
        return await execute_samba_command(cmd)

    elif method == "auth.silo.list":
        cmd = build_samba_command_deep(["domain", "auth", "silo", "list"])
        return await execute_samba_command(cmd)

    elif method == "auth.silo.show":
        siloname = params.get("siloname", "")
        cmd = build_samba_command_deep(
            ["domain", "auth", "silo", "show"],
            positionals=[siloname],
        )
        return await execute_samba_command(cmd)

    elif method == "auth.policy.create":
        policyname = params.get("policyname", "")
        cmd = build_samba_command_deep(
            ["domain", "auth", "policy", "create"],
            positionals=[policyname],
        )
        return await execute_samba_command(cmd)

    elif method == "auth.policy.delete":
        policyname = params.get("policyname", "")
        cmd = build_samba_command_deep(
            ["domain", "auth", "policy", "delete"],
            positionals=[policyname],
        )
        return await execute_samba_command(cmd)

    elif method == "auth.policy.list":
        cmd = build_samba_command_deep(["domain", "auth", "policy", "list"])
        return await execute_samba_command(cmd)

    elif method == "auth.policy.show":
        policyname = params.get("policyname", "")
        cmd = build_samba_command_deep(
            ["domain", "auth", "policy", "show"],
            positionals=[policyname],
        )
        return await execute_samba_command(cmd)

    # ══════════════════════════════════════════════════════════════════
    #  Unknown method
    # ══════════════════════════════════════════════════════════════════

    else:
        raise ValueError(
            f"Unknown batch method: '{method}'.  Check the API "
            f"documentation for the list of supported methods."
        )


# ═══════════════════════════════════════════════════════════════════════
#  Rollback support
# ═══════════════════════════════════════════════════════════════════════

# Mapping from create methods to their corresponding delete methods
# and the parameter that holds the object name.
_ROLLBACK_MAP: Dict[str, Tuple[str, str]] = {
    "user.create": ("user.delete", "username"),
    "group.create": ("group.delete", "groupname"),
    "computer.create": ("computer.delete", "computername"),
    "contact.create": ("contact.delete", "contactname"),
    "ou.create": ("ou.delete", "ouname"),
    "dns.zone.create": ("dns.zone.delete", "zone"),
    "gpo.create": ("gpo.delete", "gpo_id"),
    "sites.create": ("sites.remove", "sitename"),
    "auth.silo.create": ("auth.silo.delete", "siloname"),
    "auth.policy.create": ("auth.policy.delete", "policyname"),
}

# Reverse operations for group membership
_ROLLBACK_MEMBERSHIP_MAP: Dict[str, str] = {
    "group.addmembers": "group.removemembers",
}


async def rollback_step(
    method: str,
    params: Dict[str, Any],
    context: Dict[str, Any],
) -> Tuple[bool, Optional[str]]:
    """Attempt to undo a previously successful batch step.

    Returns (success, error_message).
    """
    # Check create → delete rollback
    if method in _ROLLBACK_MAP:
        delete_method, name_key = _ROLLBACK_MAP[method]
        # Get the object name from params or context
        object_name = params.get(name_key, "")
        if not object_name:
            return False, f"Cannot rollback {method}: missing '{name_key}' parameter"
        try:
            await dispatch_method(
                delete_method,
                {name_key: object_name},
                timeout=30,
            )
            return True, None
        except Exception as exc:
            return False, str(exc)

    # Check addmembers → removemembers rollback
    if method in _ROLLBACK_MEMBERSHIP_MAP:
        reverse_method = _ROLLBACK_MEMBERSHIP_MAP[method]
        try:
            await dispatch_method(reverse_method, params, timeout=30)
            return True, None
        except Exception as exc:
            return False, str(exc)

    # No automatic rollback available for this method
    return False, f"No automatic rollback for method '{method}'"


# ═══════════════════════════════════════════════════════════════════════
#  Batch endpoint
# ═══════════════════════════════════════════════════════════════════════


@router.post(
    "/",
    summary="Execute batch operations",
    response_model=BatchResponse,
)
async def batch_endpoint(
    body: BatchRequest,
    _: ApiKeyDep,
) -> BatchResponse:
    """Execute multiple AD management operations in a single request.

    Actions are executed sequentially.  Each action can reference
    results from previous actions using template placeholders like
    ``{{ step1.username }}`` or ``{{ batch_id }}``.

    If ``stop_on_failure`` is True (default), execution halts on the
    first error.  If ``rollback_on_failure`` is True, previously
    successful steps are automatically undone in reverse order.
    """
    # Generate batch_id
    bid = body.batch_id or uuid.uuid4().hex[:12]
    logger.info("[BATCH %s] Starting batch with %d actions", bid, len(body.actions))

    # Execution context: stores batch_id + outputs from each step
    context: Dict[str, Any] = {"batch_id": bid}

    # Track completed steps for rollback
    completed_steps: List[Tuple[int, BatchAction, Dict[str, Any]]] = []

    results: List[BatchStepResult] = []
    has_failure = False

    for idx, action in enumerate(body.actions):
        # Resolve templates in params
        resolved_params = resolve_templates(action.params, context)

        logger.info(
            "[BATCH %s] Step %d: %s (id=%s)",
            bid, idx, action.method, action.id or "-",
        )

        try:
            action_timeout = action.timeout or body.default_timeout
            result = await dispatch_method(
                action.method,
                resolved_params,
                timeout=action_timeout,
            )

            # Store result in context
            step_ctx = extract_context_fields(action.method, resolved_params, result)
            if action.id:
                context[action.id] = step_ctx

            # Also store step result by index for convenience
            context[f"_step{idx}"] = step_ctx

            step_result = BatchStepResult(
                id=action.id,
                method=action.method,
                status="success",
                output=result,
                step=idx,
            )
            results.append(step_result)
            completed_steps.append((idx, action, resolved_params))

            logger.info(
                "[BATCH %s] Step %d: SUCCESS (%s)",
                bid, idx, action.method,
            )

        except Exception as exc:
            has_failure = True
            error_msg = str(exc)

            step_result = BatchStepResult(
                id=action.id,
                method=action.method,
                status="error",
                error=error_msg,
                step=idx,
            )
            results.append(step_result)

            logger.error(
                "[BATCH %s] Step %d: FAILED (%s): %s",
                bid, idx, action.method, error_msg,
            )

            # Rollback if requested
            if body.rollback_on_failure and completed_steps:
                logger.info(
                    "[BATCH %s] Rolling back %d completed steps",
                    bid, len(completed_steps),
                )
                # Rollback in reverse order
                for rb_idx, rb_action, rb_params in reversed(completed_steps):
                    rb_ok, rb_err = await rollback_step(
                        rb_action.method, rb_params, context,
                    )
                    # Update the step result with rollback status
                    for sr in results:
                        if sr.step == rb_idx:
                            if rb_ok:
                                sr.rollback_status = "rolled_back"
                            elif rb_err and "No automatic rollback" in rb_err:
                                sr.rollback_status = "no_rollback_needed"
                            else:
                                sr.rollback_status = "rollback_failed"
                                sr.rollback_error = rb_err

            # Stop on failure if requested
            if body.stop_on_failure:
                break

    # Determine overall batch status
    success_count = sum(1 for r in results if r.status == "success")
    fail_count = sum(1 for r in results if r.status == "error")

    if fail_count == 0:
        batch_status = "completed"
    elif success_count > 0 and not body.stop_on_failure:
        batch_status = "partial_failure"
    else:
        batch_status = "failed"

    rollback_performed = body.rollback_on_failure and has_failure and len(completed_steps) > 0

    logger.info(
        "[BATCH %s] Finished: status=%s, success=%d, failed=%d",
        bid, batch_status, success_count, fail_count,
    )

    return BatchResponse(
        batch_id=bid,
        status=batch_status,
        steps=results,
        total_steps=len(body.actions),
        successful_steps=success_count,
        failed_steps=fail_count,
        rollback_performed=rollback_performed,
    )
