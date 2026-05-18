"""
Extended user management router for the web interface.

Provides search, CSV import/export, LDAP edit, and batch operations
that go beyond the basic CRUD endpoints in ``app.routers.user``.

Every endpoint requires API-key authentication via ``ApiKeyDep``.
"""

from __future__ import annotations

import asyncio
import csv
import io
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, File, HTTPException, Query, UploadFile, status
from fastapi.responses import StreamingResponse

from app.auth import ApiKeyDep
from app.config import get_settings
from app.executor import (
    build_samba_command,
    execute_samba_command,
    raise_classified_error,
)
from app.models.user_mgmt import (
    UserEditRequest,
    UserImportResult,
    UserImportRowResult,
    UserSearchResult,
)
from app.tasks import get_task_manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/users", tags=["Users — Extended"])

# ── Constants ─────────────────────────────────────────────────────────────

_MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB
_REQUIRED_CSV_HEADERS = {"username", "password"}
_OPTIONAL_CSV_HEADERS = {
    "first_name", "last_name", "email", "department", "ou",
}
_ALL_CSV_HEADERS = _REQUIRED_CSV_HEADERS | _OPTIONAL_CSV_HEADERS


# ── LDAP filter helpers ──────────────────────────────────────────────────

def build_ldap_filter(
    search: Optional[str] = None,
    ldap_filter: Optional[str] = None,
) -> str:
    """Build an LDAP filter string for user search.

    Parameters
    ----------
    search:
        Simple substring to match against ``sAMAccountName``,
        ``givenName``, ``sn``, and ``mail``.
    ldap_filter:
        Raw LDAP filter supplied by the caller.  Used verbatim if
        provided; takes precedence over *search*.

    Returns
    -------
    str
        A valid LDAP filter expression.
    """
    if ldap_filter:
        return ldap_filter

    if search:
        # Substring match across common user attributes
        escaped = (
            search.replace("\\", "\\5c")
            .replace("*", "\\2a")
            .replace("(", "\\28")
            .replace(")", "\\29")
        )
        return (
            f"(|(sAMAccountName=*{escaped}*)"
            f"(givenName=*{escaped}*)"
            f"(sn=*{escaped}*)"
            f"(mail=*{escaped}*))"
        )

    # Default: all users
    return "(objectClass=user)"


# ── Endpoint 1: Search users ─────────────────────────────────────────────

@router.get("/search", summary="Search users by filter")
async def search_users(
    _: ApiKeyDep,
    search: Optional[str] = Query(
        default=None,
        description="Substring to match against username, name, or email.",
    ),
    filter: Optional[str] = Query(
        default=None,
        alias="filter",
        description="Raw LDAP filter expression.",
    ),
    attributes: Optional[str] = Query(
        default=None,
        description="Comma-separated LDAP attributes to return.",
    ),
    offset: int = Query(
        default=0,
        ge=0,
        description="Zero-based offset for pagination.",
    ),
    limit: int = Query(
        default=100,
        ge=1,
        le=1000,
        description="Maximum number of results to return.",
    ),
) -> Dict[str, Any]:
    """Search users with substring or raw LDAP filter, returning paginated results.

    Uses direct SamDB LDAP query if available for speed; otherwise falls
    back to ``samba-tool user list`` + ``user show``.
    """
    ldap_filter = build_ldap_filter(search=search, ldap_filter=filter)

    # Try direct SamDB search first (fast path)
    try:
        from app.samdb_direct import is_samba_available
        if is_samba_available():
            result = await _search_users_samdb(ldap_filter, attributes, offset, limit)
            if result is not None:
                return result
    except ImportError:
        pass
    except Exception as exc:
        logger.debug("Direct SamDB search failed, falling back: %s", exc)

    # Fallback: samba-tool user list + show
    return await _search_users_sambatool(ldap_filter, attributes, offset, limit)


async def _search_users_samdb(
    ldap_filter: str,
    attributes: Optional[str],
    offset: int,
    limit: int,
) -> Optional[Dict[str, Any]]:
    """Execute user search via direct SamDB LDAP query."""
    try:
        import functools
        from app.samdb_direct import _get_samdb, _ldb_escape
        from app.worker import get_worker_pool

        loop = asyncio.get_running_loop()
        pool = get_worker_pool()

        def _do_search() -> List[Dict[str, Any]]:
            from app.samdb_direct import ldb_msg_to_dict
            samdb = _get_samdb(for_write=False)
            if samdb is None:
                return []

            attrs = None
            if attributes:
                attrs = [a.strip() for a in attributes.split(",") if a.strip()]

            # Add objectClass to filter to ensure we only get user objects
            if "objectClass" not in ldap_filter:
                full_filter = f"(&{ldap_filter}(objectClass=user))"
            else:
                full_filter = ldap_filter

            settings = get_settings()
            base_dn = settings.DOMAIN_DN or ""

            # Build LDB expression and search
            import ldb as _ldb  # type: ignore[import-untyped]
            controls = []
            results = samdb.search(
                base_dn or None,
                expression=full_filter,
                scope=_ldb.SCOPE_SUBTREE,
                attrs=attrs,
                controls=controls,
            )

            # Fix v1.6.3: Use ldb_msg_to_dict() to avoid 'ldb.Dn' object
            # not iterable error when iterating over message keys.
            all_items = [ldb_msg_to_dict(msg) for msg in results]

            total = len(all_items)
            page = all_items[offset : offset + limit]
            return page, total

        func = functools.partial(_do_search)
        page_items, total = await loop.run_in_executor(pool._executor, func)

        return UserSearchResult(
            items=page_items,
            total=total,
            offset=offset,
            limit=limit,
        ).model_dump()

    except Exception as exc:
        logger.warning("SamDB search error: %s", exc)
        return None


async def _search_users_sambatool(
    ldap_filter: str,
    attributes: Optional[str],
    offset: int,
    limit: int,
) -> Dict[str, Any]:
    """Fallback: search users via samba-tool user list + show."""
    args: Dict[str, Any] = {"--json": True}
    cmd = build_samba_command("user", "list", args)
    try:
        list_result = await execute_samba_command(cmd)
    except RuntimeError as exc:
        raise_classified_error(exc)

    # Parse user list — samba-tool user list returns a list of usernames
    usernames: List[str] = []
    if isinstance(list_result, list):
        for entry in list_result:
            if isinstance(entry, dict):
                uname = entry.get("username") or entry.get("sAMAccountName") or entry.get("name", "")
                if uname:
                    usernames.append(str(uname))
            elif isinstance(entry, str):
                usernames.append(entry)
    elif isinstance(list_result, dict):
        # May be {"output": "user1\nuser2\n"} format
        output = list_result.get("output", "")
        if output:
            for line in output.strip().splitlines():
                line = line.strip()
                if line:
                    usernames.append(line)

    # Apply substring filter if simple search was requested
    if ldap_filter != "(objectClass=user)" and not ldap_filter.startswith("("):
        # Simple text match fallback
        pass  # usernames already filtered by samba-tool

    # Fetch details for each user in the page range
    total = len(usernames)
    page_users = usernames[offset : offset + limit]

    items: List[Dict[str, Any]] = []
    if page_users:
        show_args: Dict[str, Any] = {"--json": True}
        if attributes:
            show_args["--attributes"] = attributes

        async def _fetch_user(uname: str) -> Dict[str, Any]:
            try:
                cmd_show = build_samba_command(
                    "user", "show", show_args, positionals=[uname],
                )
                result = await execute_samba_command(cmd_show)
                if isinstance(result, dict):
                    result["_username"] = uname
                return result
            except Exception as exc:
                logger.warning("Failed to fetch user '%s': %s", uname, exc)
                return {"_username": uname, "error": str(exc)}

        results = await asyncio.gather(*[_fetch_user(u) for u in page_users])
        items = list(results)

    return UserSearchResult(
        items=items,
        total=total,
        offset=offset,
        limit=limit,
    ).model_dump()


# ── Endpoint 2: Import users from CSV ────────────────────────────────────

@router.post("/import", summary="Import users from CSV")
async def import_users(
    _: ApiKeyDep,
    file: UploadFile = File(..., description="CSV file with user records (max 10 MB)."),
) -> Dict[str, Any]:
    """Import users from a CSV file.

    CSV format
    ----------
    Required headers: ``username``, ``password``

    Optional headers: ``first_name``, ``last_name``, ``email``,
    ``department``, ``ou``

    The import runs as a background task.  The response includes a
    ``task_id`` that can be polled at ``/api/v1/tasks/{task_id}``.
    """
    # ── File size check ───────────────────────────────────────────────
    content = await file.read()
    if len(content) > _MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File too large ({len(content)} bytes). Maximum is {_MAX_UPLOAD_BYTES} bytes.",
        )

    # ── Parse CSV and validate headers ────────────────────────────────
    try:
        text = content.decode("utf-8-sig")  # handles BOM
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="CSV file must be UTF-8 encoded.",
        )

    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="CSV file is empty or has no headers.",
        )

    headers = set(reader.fieldnames)
    missing = _REQUIRED_CSV_HEADERS - headers
    if missing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Missing required CSV headers: {', '.join(sorted(missing))}. "
                   f"Required: {', '.join(sorted(_REQUIRED_CSV_HEADERS))}. "
                   f"Optional: {', '.join(sorted(_OPTIONAL_CSV_HEADERS))}.",
        )

    rows = list(reader)

    # ── Submit as background task ─────────────────────────────────────
    tm = get_task_manager()
    task_id = tm.submit_task(
        cmd=["__csv_import__"],  # sentinel — actual work is in _run_csv_import
    )

    # Override the task's run with our custom import logic
    task = tm._tasks.get(task_id)
    if task is not None:
        asyncio.get_running_loop().create_task(
            _run_csv_import(task_id, rows, tm),
        )

    settings = get_settings()
    api_prefix = "/api/v1"

    return {
        "status": "ok",
        "message": f"CSV import started with {len(rows)} rows",
        "task_id": task_id,
        "result_url": f"{api_prefix}/tasks/{task_id}",
        "total_rows": len(rows),
    }


async def _run_csv_import(
    task_id: str,
    rows: List[Dict[str, str]],
    tm: Any,
) -> None:
    """Execute the CSV import in the background and update the task."""
    from app.tasks import TaskState
    from datetime import datetime, timezone

    task = tm._tasks.get(task_id)
    if task is None:
        return

    task.state = TaskState.RUNNING
    task.started_at = datetime.now(timezone.utc)

    import_result = UserImportResult(total_rows=len(rows))

    for row in rows:
        username = row.get("username", "").strip()
        password = row.get("password", "").strip()

        if not username:
            import_result.failed += 1
            import_result.details.append(
                UserImportRowResult(username="(empty)", status="failed", reason="Empty username"),
            )
            continue

        if not password:
            import_result.failed += 1
            import_result.details.append(
                UserImportRowResult(username=username, status="failed", reason="Empty password"),
            )
            continue

        # Check if user already exists via samba-tool user show
        try:
            cmd_show = build_samba_command(
                "user", "show", {"--json": True}, positionals=[username],
            )
            show_result = await execute_samba_command(cmd_show)
            if isinstance(show_result, dict) and show_result:
                import_result.skipped += 1
                import_result.details.append(
                    UserImportRowResult(username=username, status="skipped", reason="User already exists"),
                )
                continue
        except RuntimeError:
            pass  # User not found — proceed with creation
        except Exception:
            pass

        # Build creation parameters
        first_name = row.get("first_name", "").strip() or None
        last_name = row.get("last_name", "").strip() or None
        email = row.get("email", "").strip() or None
        department = row.get("department", "").strip() or None
        ou = row.get("ou", "").strip() or None

        # Try direct SamDB create first
        created = False
        try:
            from app.samdb_direct import is_samba_available, async_user_create
            if is_samba_available():
                try:
                    await async_user_create(
                        username=username,
                        password=password,
                        given_name=first_name,
                        surname=last_name,
                        mail_address=email,
                        department=department,
                        userou=ou,
                    )
                    created = True
                except RuntimeError as exc:
                    exc_msg = str(exc).lower()
                    if "already exist" in exc_msg:
                        import_result.skipped += 1
                        import_result.details.append(
                            UserImportRowResult(username=username, status="skipped", reason="User already exists"),
                        )
                        continue
                    logger.debug("Direct create failed for '%s': %s", username, exc)
        except ImportError:
            pass

        # Fallback: samba-tool subprocess
        if not created:
            try:
                args: Dict[str, Any] = {}
                if first_name:
                    args["--given-name"] = first_name
                if last_name:
                    args["--surname"] = last_name
                if email:
                    args["--mail-address"] = email
                if department:
                    args["--department"] = department
                if ou:
                    args["--userou"] = ou

                cmd_create = build_samba_command(
                    "user", "add", args, positionals=[username, password],
                )
                await execute_samba_command(cmd_create)
                created = True
            except RuntimeError as exc:
                exc_msg = str(exc).lower()
                if "already exist" in exc_msg:
                    import_result.skipped += 1
                    import_result.details.append(
                        UserImportRowResult(username=username, status="skipped", reason="User already exists"),
                    )
                    continue

        if created:
            import_result.created += 1
            import_result.details.append(
                UserImportRowResult(username=username, status="created"),
            )
        else:
            import_result.failed += 1
            import_result.details.append(
                UserImportRowResult(username=username, status="failed", reason="Unknown error during creation"),
            )

    # Update task with results
    import json
    task.output = json.dumps(import_result.model_dump(), indent=2)
    task.state = TaskState.COMPLETED
    task.completed_at = datetime.now(timezone.utc)


# ── Endpoint 3: Export users to CSV ──────────────────────────────────────

@router.get("/export", summary="Export users to CSV/JSON")
async def export_users(
    _: ApiKeyDep,
    format: str = Query(
        default="csv",
        description="Export format: 'csv' or 'json'.",
    ),
    attributes: Optional[str] = Query(
        default=None,
        description="Comma-separated LDAP attributes to include in export. "
                    "Defaults to common user attributes.",
    ),
) -> StreamingResponse:
    """Export all users as a downloadable CSV or JSON file.

    Uses ``samba-tool user list`` to enumerate users, then fetches
    details for each user with ``samba-tool user show``.
    """
    if format not in ("csv", "json"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="format must be 'csv' or 'json'",
        )

    # Determine attributes to export
    default_attrs = "sAMAccountName,givenName,sn,mail,department,company,title,description,distinguishedName"
    attrs_str = attributes or default_attrs

    # Get user list
    args: Dict[str, Any] = {"--json": True, "--full-dn": True}
    cmd = build_samba_command("user", "list", args)
    try:
        list_result = await execute_samba_command(cmd)
    except RuntimeError as exc:
        raise_classified_error(exc)

    # Parse usernames
    usernames: List[str] = []
    if isinstance(list_result, list):
        for entry in list_result:
            if isinstance(entry, dict):
                uname = entry.get("username") or entry.get("sAMAccountName") or entry.get("name", "")
                if uname:
                    usernames.append(str(uname))
            elif isinstance(entry, str):
                usernames.append(entry)
    elif isinstance(list_result, dict):
        output = list_result.get("output", "")
        if output:
            for line in output.strip().splitlines():
                line = line.strip()
                if line:
                    usernames.append(line)

    # Fetch details for each user in parallel batches
    show_args: Dict[str, Any] = {
        "--json": True,
        "--attributes": attrs_str,
    }

    async def _fetch_user_detail(uname: str) -> Dict[str, Any]:
        try:
            cmd_show = build_samba_command(
                "user", "show", show_args, positionals=[uname],
            )
            result = await execute_samba_command(cmd_show)
            if isinstance(result, dict):
                result["sAMAccountName"] = result.get("sAMAccountName", uname)
            return result
        except Exception as exc:
            logger.warning("Export: failed to fetch user '%s': %s", uname, exc)
            return {"sAMAccountName": uname, "error": str(exc)}

    # Process in batches of 10 to avoid overwhelming the system
    user_details: List[Dict[str, Any]] = []
    batch_size = 10
    for i in range(0, len(usernames), batch_size):
        batch = usernames[i : i + batch_size]
        results = await asyncio.gather(*[_fetch_user_detail(u) for u in batch])
        user_details.extend(results)

    # Generate output
    if format == "json":
        import json

        output_buf = io.StringIO()
        json.dump(user_details, output_buf, indent=2, default=str)
        output_buf.seek(0)

        return StreamingResponse(
            output_buf,
            media_type="application/json",
            headers={
                "Content-Disposition": "attachment; filename=users_export.json",
            },
        )

    # CSV format
    output_buf = io.StringIO()
    if user_details:
        # Collect all unique keys for CSV headers
        all_keys: List[str] = []
        seen_keys = set()
        for user in user_details:
            for k in user:
                if k not in seen_keys:
                    all_keys.append(k)
                    seen_keys.add(k)

        writer = csv.DictWriter(output_buf, fieldnames=all_keys, extrasaction="ignore")
        writer.writeheader()
        for user in user_details:
            # Flatten list values
            flat = {}
            for k, v in user.items():
                if isinstance(v, list):
                    flat[k] = "; ".join(str(x) for x in v)
                else:
                    flat[k] = v
            writer.writerow(flat)

    output_buf.seek(0)

    return StreamingResponse(
        output_buf,
        media_type="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=users_export.csv",
        },
    )


# ── Endpoint 4: Edit user via LDAP ──────────────────────────────────────

# Mapping of UserEditRequest field names to LDAP attribute names
_EDIT_FIELD_TO_LDAP: Dict[str, str] = {
    "given_name": "givenName",
    "surname": "sn",
    "initials": "initials",
    "display_name": "displayName",
    "description": "description",
    "mail": "mail",
    "telephone_number": "telephoneNumber",
    "department": "department",
    "company": "company",
    "job_title": "title",
    "profile_path": "profilePath",
    "script_path": "scriptPath",
    "home_drive": "homeDrive",
    "home_directory": "homeDirectory",
    "physical_delivery_office": "physicalDeliveryOfficeName",
    "internet_address": "wWWHomePage",
    "street_address": "streetAddress",
    "city": "l",
    "state": "st",
    "postal_code": "postalCode",
    "country": "c",
}


@router.put("/{username}/edit", summary="Edit user attributes via LDAP")
async def edit_user_ldap(
    username: str,
    body: UserEditRequest,
    _: ApiKeyDep,
) -> Dict[str, Any]:
    """Modify user attributes using direct LDAP modify operations.

    Only attributes explicitly provided in the request body are modified.
    Attempts direct SamDB LDAP modify first; falls back to ``samba-tool``
    subprocess if unavailable.
    """
    # Build list of modifications
    modifications: Dict[str, str] = {}
    for field_name, ldap_attr in _EDIT_FIELD_TO_LDAP.items():
        value = getattr(body, field_name, None)
        if value is not None:
            modifications[ldap_attr] = value

    if not modifications:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No attributes provided for modification.",
        )

    # Try direct SamDB modify first
    try:
        from app.samdb_direct import is_samba_available
        if is_samba_available():
            result = await _edit_user_samdb(username, modifications)
            if result is not None:
                return result
    except ImportError:
        pass
    except Exception as exc:
        logger.debug("Direct SamDB edit failed, falling back: %s", exc)

    # Fallback: use ldbmodify via samba-tool subprocess
    return await _edit_user_sambatool(username, modifications)


async def _edit_user_samdb(
    username: str,
    modifications: Dict[str, str],
) -> Optional[Dict[str, Any]]:
    """Modify user attributes via direct SamDB LDAP modify."""
    try:
        import functools
        from app.samdb_direct import _get_samdb, _ldb_escape
        from app.worker import get_worker_pool

        loop = asyncio.get_running_loop()
        pool = get_worker_pool()

        def _do_modify() -> Dict[str, Any]:
            samdb = _get_samdb(for_write=True)
            if samdb is None:
                return None

            import ldb as _ldb  # type: ignore[import-untyped]

            # Find user DN
            settings = get_settings()
            base_dn = settings.DOMAIN_DN or ""
            res = samdb.search(
                base_dn or None,
                expression=f"(sAMAccountName={_ldb_escape(username)})",
                scope=_ldb.SCOPE_SUBTREE,
                attrs=["dn"],
            )
            if len(res) == 0:
                raise RuntimeError(f"User '{username}' not found")

            user_dn = str(res[0].dn)

            # Build modify message
            msg = _ldb.Message()
            msg.dn = _ldb.Dn(samdb, user_dn)

            for attr, value in modifications.items():
                msg[attr] = _ldb.MessageElement(
                    value, _ldb.FLAG_MOD_REPLACE, attr,
                )

            samdb.modify(msg)
            return {"message": f"User '{username}' modified successfully", "modified_attributes": list(modifications.keys())}

        func = functools.partial(_do_modify)
        result = await loop.run_in_executor(pool._executor, func)
        return result

    except RuntimeError as exc:
        exc_msg = str(exc).lower()
        if "not found" in exc_msg:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User '{username}' not found",
            )
        raise
    except Exception as exc:
        logger.warning("SamDB modify error: %s", exc)
        return None


async def _edit_user_sambatool(
    username: str,
    modifications: Dict[str, str],
) -> Dict[str, Any]:
    """Fallback: modify user attributes via samba-tool subprocess.

    Since ``samba-tool user edit`` opens an interactive editor, we
    construct an LDIF and apply it with ``ldbmodify`` instead.
    """
    # First, look up the user DN
    args: Dict[str, Any] = {"--json": True, "--attributes": "distinguishedName"}
    cmd = build_samba_command("user", "show", args, positionals=[username])
    try:
        show_result = await execute_samba_command(cmd)
    except RuntimeError as exc:
        raise_classified_error(exc)

    user_dn = None
    if isinstance(show_result, dict):
        user_dn = show_result.get("distinguishedName")

    if not user_dn:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{username}' not found or DN could not be determined.",
        )

    # Build LDIF for modify
    ldif_lines = [f"dn: {user_dn}", "changetype: modify"]
    for attr, value in modifications.items():
        ldif_lines.append(f"replace: {attr}")
        ldif_lines.append(f"{attr}: {value}")
        ldif_lines.append("-")

    ldif_content = "\n".join(ldif_lines) + "\n"

    # Write LDIF to a temp file and apply with ldbmodify
    import tempfile
    import os

    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".ldif", prefix="user_edit_")
    try:
        with os.fdopen(tmp_fd, "w") as f:
            f.write(ldif_content)

        # Determine sam.ldb path
        settings = get_settings()
        sam_ldb = "/var/lib/samba/private/sam.ldb"
        if settings.TDB_SAM_LDB_PATH:
            sam_ldb = settings.TDB_SAM_LDB_PATH

        # Run ldbmodify
        cmd_modify = ["ldbmodify", "-H", sam_ldb, tmp_path]
        from app.worker import get_worker_pool
        pool = get_worker_pool()
        rc, stdout, stderr = await pool.run_command(cmd_modify, timeout=30)

        if rc != 0:
            error_detail = stderr.strip() or f"ldbmodify exited with code {rc}"
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to modify user '{username}': {error_detail}",
            )
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    return {
        "status": "ok",
        "message": f"User '{username}' modified successfully",
        "modified_attributes": list(modifications.keys()),
    }


# ── Endpoint 5: Batch get users ──────────────────────────────────────────

@router.get("/batch", summary="Batch get multiple users")
async def batch_get_users(
    _: ApiKeyDep,
    usernames: str = Query(
        ...,
        description="Comma-separated list of usernames to fetch.",
    ),
    attributes: Optional[str] = Query(
        default=None,
        description="Comma-separated LDAP attributes to return.",
    ),
) -> Dict[str, Any]:
    """Fetch details for multiple users in parallel.

    Returns a dictionary mapping each username to its user details.
    Users that are not found or cause errors are included with an
    ``error`` key instead of details.
    """
    username_list = [u.strip() for u in usernames.split(",") if u.strip()]
    if not username_list:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No usernames provided.",
        )

    if len(username_list) > 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum 100 usernames per batch request.",
        )

    show_args: Dict[str, Any] = {"--json": True}
    if attributes:
        show_args["--attributes"] = attributes

    async def _fetch_one(uname: str) -> tuple[str, Dict[str, Any]]:
        try:
            cmd = build_samba_command(
                "user", "show", show_args, positionals=[uname],
            )
            result = await execute_samba_command(cmd)
            return uname, result
        except Exception as exc:
            logger.warning("Batch: failed to fetch user '%s': %s", uname, exc)
            return uname, {"error": str(exc)}

    results = await asyncio.gather(*[_fetch_one(u) for u in username_list])

    users_map: Dict[str, Any] = {}
    for uname, details in results:
        users_map[uname] = details

    return {
        "status": "ok",
        "message": f"Retrieved {len(username_list)} users",
        "users": users_map,
        "requested": len(username_list),
        "found": sum(1 for v in users_map.values() if "error" not in v),
    }
