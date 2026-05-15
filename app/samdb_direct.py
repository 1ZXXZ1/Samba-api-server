"""
Direct SamDB/LDB API operations — bypasses samba-tool subprocess overhead.

This module provides an alternative execution path for common CRUD operations
that avoids spawning a new ``samba-tool`` process for each request.  Instead,
it uses the ``samba.samdb.SamDB`` Python API directly, which connects to the
local LDB database in-process.

Performance impact
------------------
A typical ``samba-tool user add`` invocation takes 30-45 seconds because:
1. A new Python interpreter is spawned (~3s startup)
2. The samba package is imported (~15s for all C extensions)
3. The command executes (~1-2s for the actual LDAP operation)
4. The process exits and resources are cleaned up (~2s)

Using the SamDB API directly reduces this to ~1-2 seconds total because:
1. The samba package is imported once at module load time
2. The SamDB connection is reused across requests
3. No subprocess overhead

Architecture
------------
The module is designed as an **optional** optimization layer:

- If the ``samba`` Python package is available, direct API calls are used.
- If not available (e.g. API server running on a separate machine),
  the caller should fall back to the existing ``samba-tool`` subprocess
  approach via ``app.executor``.

Thread safety: SamDB/LDB are NOT thread-safe.  All direct API calls
are executed in the worker process pool (same as samba-tool subprocesses)
to avoid concurrency issues.

Fix v23: CRITICAL BUG FIX — Method 1: Pass Kerberos credentials to SamDB.
--------------------------------------------------------------------------
The v22 implementation used ``tdb://`` (direct file access) for ALL
operations, including writes.  This caused process pool crashes because:

1. The Samba server process holds an exclusive write lock on ``sam.ldb``.
2. Opening ``sam.ldb`` via ``tdb://`` for writing from another process
   (even a ProcessPoolExecutor worker) results in a lock conflict.
3. The worker process is terminated abruptly.

The initial v23 fix switched writes to ``ldapi://``, but this also failed
because ``SamDB(url=ldapi://, lp=lp)`` in a ProcessPoolExecutor worker
lacks authentication credentials.  The error was:

    LDAP error 1 LDAP_OPERATIONS_ERROR -
    <00002020: Operation unavailable without authentication>

Method 1 Fix: Pass explicit Kerberos/NTLM credentials to SamDB via the
``creds`` parameter (or ``session_info`` for system session).  This gives
the ldapi:// connection the authentication context it needs.

Two credential modes are supported:

1. **Explicit credentials** (preferred when SAMBA_CREDENTIALS_USER and
   SAMBA_CREDENTIALS_PASSWORD are set):
   Create a ``Credentials`` object with username/password, which SamDB
   uses for LDAP SASL bind over ldapi://.

2. **System session** (fallback when no explicit credentials):
   Use ``system_session()`` which represents the process's Unix identity
   (typically root on a DC).  This works because ldapi:// can authenticate
   via SO_PEERCRED (Unix socket credential passing).

If neither method works, the router falls back to ``samba-tool`` subprocess
which handles authentication internally.

The routers already have try/except fallback to ``samba-tool`` subprocess,
so if direct SamDB writes fail for any reason, the fallback is automatic.
"""

from __future__ import annotations

import asyncio
import functools
import logging
import os
# v1.2.6 fix: Removed direct import of BrokenProcessPool from concurrent.futures.
# In Python 3.12 on some platforms (ALT Linux), BrokenProcessPool is not
# exported from concurrent.futures.__init__.py, causing:
#   "cannot import name 'BrokenProcessPool' from 'concurrent.futures'"
# This ImportError propagates through samdb_direct.py into ou_mgmt.py
# which uses _get_samdb() from this module.
# Instead, we catch generic Exception in async wrappers — the worker pool
# uses ProcessPoolExecutor which raises RuntimeError on pool crashes,
# not BrokenProcessPool directly.
try:
    from concurrent.futures import BrokenProcessPool as _BrokenProcessPool
except ImportError:
    _BrokenProcessPool = None  # type: ignore[misc,assignment]
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Try to import samba package — this will fail if the API server
# is running on a machine without the samba Python bindings installed.
_SAMBA_AVAILABLE: bool = False
_SAMDB_MODULE: Any = None
_LDB_MODULE: Any = None
_CREDENTIALS_CLASS: Any = None
_SYSTEM_SESSION_FUNC: Any = None

try:
    import samba  # noqa: F401
    from samba.samdb import SamDB
    from samba import param as samba_param
    import ldb as _ldb_mod
    _SAMBA_AVAILABLE = True
    _SAMDB_MODULE = SamDB
    _LDB_MODULE = _ldb_mod
    logger.info("samba Python package available — direct SamDB API enabled")
except ImportError:
    logger.info(
        "samba Python package not available — "
        "direct SamDB API disabled, falling back to samba-tool subprocess"
    )

# Try to import credentials and system_session for Method 1.
# These are needed for ldapi:// write operations to authenticate.
try:
    from samba.credentials import Credentials
    _CREDENTIALS_CLASS = Credentials
    logger.debug("samba.credentials.Credentials imported successfully")
except ImportError:
    logger.debug(
        "samba.credentials.Credentials not available — "
        "explicit credentials mode disabled"
    )

try:
    from samba.auth import system_session
    _SYSTEM_SESSION_FUNC = system_session
    logger.debug("samba.auth.system_session imported successfully")
except ImportError:
    logger.debug(
        "samba.auth.system_session not available — "
        "system session mode disabled"
    )


def is_samba_available() -> bool:
    """Return True if the samba Python package is available for direct API calls."""
    return _SAMBA_AVAILABLE


# ── SamDB connection management ──────────────────────────────────────────
# Fix v23 Method 1: Separate connections for READ and WRITE operations.
#
# READ connection: uses tdb:// (direct file access, fast, no auth needed).
# WRITE connection: uses ldapi:// with explicit creds/session_info
#   (routes through Samba server for safe concurrent writes — the server
#   holds the exclusive write lock on sam.ldb and serializes all
#   modifications through its LDAP interface).
#
# Both connections are cached at module level and reused across calls.
# They are NOT thread-safe — callers must execute in the worker pool.

_samdb_read_connection: Optional[Any] = None   # tdb:// connection for reads
_samdb_write_connection: Optional[Any] = None   # ldapi:// connection for writes
_lp_ctx: Optional[Any] = None


def _get_samdb_url(for_write: bool = False) -> Optional[str]:
    """Get the LDB URL for SamDB connection from settings.

    Fix v23: Returns different URLs depending on operation type:
    - for_write=False (READ): prefers tdb:// (fast, no auth, parallel-safe)
    - for_write=True (WRITE): uses ldapi:// (safe concurrent writes via server)

    Using tdb:// for writes causes process crashes because the Samba
    server holds an exclusive write lock on sam.ldb.  ldapi:// routes
    writes through the Samba server process which properly serializes
    concurrent modifications.

    Parameters
    ----------
    for_write:
        If True, return a URL suitable for write operations (ldapi://).
        If False (default), return a URL suitable for read operations (tdb://).
    """
    try:
        from app.config import get_settings
        settings = get_settings()

        if for_write:
            if settings.LDAPI_URL:
                return settings.LDAPI_URL
            # Try to auto-detect LDAPI socket
            import urllib.parse
            for socket_path in [
                "/var/lib/samba/private/ldapi",
                "/var/lib/samba/private/ldap_priv/ldapi",
                "/var/run/samba/ldapi",
            ]:
                if os.path.exists(socket_path):
                    return f"ldapi://{urllib.parse.quote(socket_path, safe='')}"
            logger.warning(
                "No ldapi:// URL available for write operations — "
                "write operations via direct SamDB API may fail. "
                "Set SAMBA_LDAPI_URL or ensure LDAPI socket exists."
            )
            return None

        # READ operations: prefer tdb:// (fast, no auth needed)
        if settings.TDB_URL:
            return settings.TDB_URL
        # Fall back to LDAPI for reads too
        if settings.LDAPI_URL:
            return settings.LDAPI_URL
        # Try to auto-detect tdb:// path
        sam_ldb_path = getattr(settings, 'TDB_SAM_LDB_PATH', None)
        if sam_ldb_path and os.path.exists(sam_ldb_path):
            return f"tdb://{sam_ldb_path}"
        # Common default paths
        for path in [
            "/var/lib/samba/private/sam.ldb",
            "/var/lib/samba/sam.ldb",
        ]:
            if os.path.exists(path):
                return f"tdb://{path}"
        return None
    except Exception:
        return None


def _get_lp_ctx() -> Any:
    """Get or create a Samba LoadParm context."""
    global _lp_ctx
    if _lp_ctx is not None:
        return _lp_ctx
    try:
        from app.config import get_settings
        settings = get_settings()
        _lp_ctx = samba_param.LoadParm()
        if settings.SMB_CONF and os.path.exists(settings.SMB_CONF):
            _lp_ctx.load(settings.SMB_CONF)
        else:
            _lp_ctx.load_default()
        return _lp_ctx
    except Exception as exc:
        logger.warning("Failed to create LoadParm context: %s", exc)
        return None


def _get_creds() -> Any:
    """Create a Credentials object for SamDB write operations.

    Fix v23 Method 1: This function creates authentication credentials
    that are passed to SamDB when connecting via ldapi:// for writes.

    Two modes are supported:

    1. **Explicit credentials** (when SAMBA_CREDENTIALS_USER and
       SAMBA_CREDENTIALS_PASSWORD are set in the environment):
       Create a Credentials object with username/password.  This is the
       most reliable method because it explicitly authenticates as the
       specified user (typically Administrator).

    2. **System session** (fallback when no explicit credentials):
       Return None, and let the caller use ``system_session()`` instead
       of a Credentials object.  system_session() represents the process's
       Unix identity (root on a DC), which ldapi:// accepts via SO_PEERCRED.

    Returns
    -------
    Credentials or None
        A Credentials object if explicit credentials are configured,
        or None if system session should be used instead.
    """
    try:
        from app.config import get_settings
        settings = get_settings()

        if settings.CREDENTIALS_USER and settings.CREDENTIALS_PASSWORD:
            if _CREDENTIALS_CLASS is not None:
                creds = _CREDENTIALS_CLASS()
                creds.set_username(settings.CREDENTIALS_USER)
                creds.set_password(settings.CREDENTIALS_PASSWORD)
                if settings.REALM:
                    creds.set_domain(settings.REALM.upper())
                # Fix v1.6.3: Kerberos state for LDAPI connections.
                # LDAPI on a Samba AD DC does NOT support NTLM authentication.
                # Setting DONT_USE_KERBEROS forces NTLM, which causes
                # NT_STATUS_INVALID_PARAMETER on LDAPI bind.
                #
                # The fix: when USE_KERBEROS=False, do NOT force DONT_USE_KERBEROS
                # for LDAPI connections. Instead, leave the default (AUTO) state
                # so Samba can negotiate the appropriate auth method. Only force
                # DONT_USE_KERBEROS when connecting via non-LDAPI URLs (ldap://,
                # ldaps://) where NTLM is actually supported.
                try:
                    from samba.credentials import MUST_USE_KERBEROS, DONT_USE_KERBEROS
                    if settings.USE_KERBEROS:
                        creds.set_kerberos_state(MUST_USE_KERBEROS)
                    else:
                        # Don't force DONT_USE_KERBEROS — let Samba auto-detect.
                        # For LDAPI, AUTO will use SO_PEERCRED or SASL/GSSAPI.
                        # DONT_USE_KERBEROS would force NTLM which fails on LDAPI.
                        pass
                except ImportError:
                    pass  # Older Samba versions may not have these constants
                logger.info(
                    "Created explicit Credentials for SamDB write: user=%s domain=%s",
                    settings.CREDENTIALS_USER,
                    settings.REALM or "(none)",
                )
                return creds
            else:
                logger.warning(
                    "Explicit credentials configured but samba.credentials.Credentials "
                    "is not available — falling back to system session"
                )
                return None
    except Exception as exc:
        logger.warning("Failed to create Credentials: %s", exc)

    return None


def _get_samdb(for_write: bool = False) -> Any:
    """Get or create a SamDB connection for direct API access.

    Fix v1.6.3: Reordered write connection methods to prefer
    system_session over explicit credentials.

    - for_write=False: returns tdb:// connection (fast reads, no auth needed)
    - for_write=True: returns ldapi:// connection with session_info/creds

    The ldapi:// connection authenticates using one of (in order):

    1. system_session() (Unix process identity — works for root via
       SO_PEERCRED on LDAPI).  This is the preferred method for local
       DC operations because it bypasses Kerberos/NTLM negotiation
       entirely and uses the kernel's Unix socket credential passing.

    2. Explicit Credentials (username/password from settings).  Used
       when system_session is unavailable or fails (e.g. non-root
       process).  Kerberos state is left at AUTO (not forced to
       DONT_USE_KERBEROS) because LDAPI does not support NTLM.

    3. No explicit auth (last resort — may work via SO_PEERCRED on
       some systems even without system_session).

    If all methods fail, RuntimeError is raised so the router
    falls back to samba-tool subprocess automatically.

    Parameters
    ----------
    for_write:
        If True, return ldapi:// connection with auth credentials.
        If False (default), return tdb:// connection for reads.
    """
    if for_write:
        global _samdb_write_connection
        if _samdb_write_connection is not None:
            return _samdb_write_connection

        if not _SAMBA_AVAILABLE:
            raise RuntimeError("samba Python package not available")

        url = _get_samdb_url(for_write=True)
        if not url:
            raise RuntimeError(
                "No ldapi:// URL available for SamDB write connection — "
                "cannot perform direct SamDB write operations. "
                "Set SAMBA_LDAPI_URL or ensure LDAPI socket exists."
            )

        lp = _get_lp_ctx()
        if not lp:
            raise RuntimeError("Failed to create LoadParm context")

        logger.info("Connecting to SamDB for WRITES at %s (with auth)", url)

        # Fix v1.6.3: Reordered connection methods — try system_session FIRST.
        #
        # The v1.6.2 order was: explicit credentials → system_session → no auth.
        # This caused NT_STATUS_INVALID_PARAMETER because:
        #
        #   1. When USE_KERBEROS=False (the default), explicit credentials
        #      force DONT_USE_KERBEROS (NTLM) via set_kerberos_state().
        #   2. LDAPI on a Samba AD DC does NOT support NTLM authentication.
        #   3. The NT_STATUS_INVALID_PARAMETER error from the failed bind
        #      causes the entire try block to abort, so system_session
        #      (which WOULD work for root via SO_PEERCRED) is never tried.
        #
        # The v1.6.3 fix reorders to: system_session → explicit credentials
        # → no auth.  On a DC running as root, system_session() via LDAPI
        # uses SO_PEERCRED (Unix socket credential passing) and always
        # works.  Explicit credentials are tried as a fallback for
        # non-root processes or remote connections.

        # Method 1 (preferred for local DC): system_session via LDAPI SO_PEERCRED
        if _SYSTEM_SESSION_FUNC is not None:
            try:
                logger.debug("Using system_session() for SamDB write connection")
                session = _SYSTEM_SESSION_FUNC()
                _samdb_write_connection = SamDB(
                    url=url, lp=lp, session_info=session,
                )
                # Validate the connection by performing a simple search
                try:
                    _samdb_write_connection.search(
                        "", scope=0, attrs=["dn"],
                        expression="(objectClass=*)",
                    )
                except Exception as verify_exc:
                    logger.warning(
                        "SamDB write connection (system_session) verification failed: %s",
                        str(verify_exc)[:200],
                    )
                    _samdb_write_connection = None
                    raise
                logger.info("SamDB write connection established (system session)")
                return _samdb_write_connection
            except Exception as exc:
                _samdb_write_connection = None
                logger.debug(
                    "system_session() connection failed: %s — "
                    "trying explicit credentials next",
                    str(exc)[:200],
                )

        # Method 2: Explicit credentials with auto Kerberos detection
        creds = _get_creds()
        if creds is not None:
            try:
                logger.debug("Using explicit Credentials for SamDB write connection")
                # Fix v1.6.3: Changed 'creds=' to 'credentials=' — the SamDB
                # constructor expects 'credentials', not 'creds'.
                _samdb_write_connection = SamDB(url=url, lp=lp, credentials=creds)
                logger.info("SamDB write connection established (explicit credentials)")
                return _samdb_write_connection
            except Exception as exc:
                _samdb_write_connection = None
                logger.debug(
                    "Explicit credentials connection failed: %s — "
                    "trying no-auth fallback next",
                    str(exc)[:200],
                )

        # Method 3: Last resort — try without creds/session_info.
        # This works on some systems where ldapi:// uses SO_PEERCRED
        # (Unix socket credential passing) to authenticate the process.
        try:
            logger.warning(
                "No system_session or Credentials worked — "
                "attempting SamDB write connection without explicit auth. "
                "This may fail with LDAP_OPERATIONS_ERROR."
            )
            _samdb_write_connection = SamDB(url=url, lp=lp)
            logger.info("SamDB write connection established (no explicit auth)")
            return _samdb_write_connection
        except Exception as exc:
            _samdb_write_connection = None
            exc_msg = str(exc)
            # Check for the specific auth error
            if "Operation unavailable without authentication" in exc_msg or \
               "LDAP_OPERATIONS_ERROR" in exc_msg:
                logger.warning(
                    "SamDB write connection failed: LDAP auth error — "
                    "falling back to samba-tool subprocess. Error: %s",
                    exc_msg[:200],
                )
                raise RuntimeError(
                    "Direct SamDB write failed: LDAP authentication error. "
                    "Falling back to samba-tool subprocess. "
                    f"Original error: {exc_msg}"
                ) from exc
            # Other errors (e.g. connection refused, permission denied)
            logger.warning(
                "SamDB write connection failed: %s — "
                "falling back to samba-tool subprocess",
                exc_msg[:200],
            )
            raise RuntimeError(
                f"Direct SamDB write connection failed: {exc_msg}"
            ) from exc

    else:
        global _samdb_read_connection
        if _samdb_read_connection is not None:
            return _samdb_read_connection

        if not _SAMBA_AVAILABLE:
            raise RuntimeError("samba Python package not available")

        url = _get_samdb_url(for_write=False)
        if not url:
            raise RuntimeError("No LDB URL available for SamDB read connection")

        lp = _get_lp_ctx()
        if not lp:
            raise RuntimeError("Failed to create LoadParm context")

        logger.info("Connecting to SamDB for READS at %s", url)
        _samdb_read_connection = SamDB(url=url, lp=lp)
        return _samdb_read_connection


def reset_samdb_connection(for_write: bool = False) -> None:
    """Reset the cached SamDB connection (e.g. after an error).

    Parameters
    ----------
    for_write:
        If True, reset the write connection (ldapi://).
        If False, reset the read connection (tdb://).
    """
    global _samdb_read_connection, _samdb_write_connection
    if for_write:
        _samdb_write_connection = None
    else:
        _samdb_read_connection = None


def reset_all_samdb_connections() -> None:
    """Reset all cached SamDB connections (both read and write)."""
    global _samdb_read_connection, _samdb_write_connection
    _samdb_read_connection = None
    _samdb_write_connection = None


# ── Direct API operations ────────────────────────────────────────────────
# These functions mirror the samba-tool commands but use the SamDB API
# directly, avoiding subprocess overhead.
#
# They are designed to be called from the worker pool via run_in_executor().
# All functions are synchronous (not async) because they interact with
# the LDB database which is not asyncio-compatible.
#
# Fix v23 Method 1: WRITE operations use _get_samdb(for_write=True) which
# connects via ldapi:// with proper authentication credentials (either
# explicit Credentials or system_session).  This resolves the
# "Operation unavailable without authentication" error.


def direct_user_create(
    username: str,
    password: Optional[str] = None,
    userou: Optional[str] = None,
    surname: Optional[str] = None,
    given_name: Optional[str] = None,
    initials: Optional[str] = None,
    profile_path: Optional[str] = None,
    script_path: Optional[str] = None,
    home_drive: Optional[str] = None,
    home_directory: Optional[str] = None,
    job_title: Optional[str] = None,
    department: Optional[str] = None,
    company: Optional[str] = None,
    description: Optional[str] = None,
    mail_address: Optional[str] = None,
    internet_address: Optional[str] = None,
    telephone_number: Optional[str] = None,
    physical_delivery_office: Optional[str] = None,
    must_change_at_next_login: bool = False,
    use_username_as_cn: bool = False,
    random_password: bool = False,
    smartcard_required: bool = False,
    uid_number: Optional[int] = None,
    gid_number: Optional[int] = None,
    gecos: Optional[str] = None,
    login_shell: Optional[str] = None,
    uid: Optional[str] = None,
    nis_domain: Optional[str] = None,
    unix_home: Optional[str] = None,
) -> dict[str, Any]:
    """Create a user via direct SamDB API call.

    Fix v23 Method 1: Uses ldapi:// with authentication credentials
    for write operations instead of disabling writes entirely.
    """
    if not _SAMBA_AVAILABLE:
        raise RuntimeError("samba Python package not available")

    import secrets
    import string

    # Fix v23 Method 1: Use WRITE connection (ldapi:// with creds)
    samdb = _get_samdb(for_write=True)

    # Generate random password if requested
    if random_password and not password:
        alphabet = string.ascii_letters + string.digits + "!@#$%"
        password = ''.join(secrets.choice(alphabet) for _ in range(16))

    # Use empty password if not provided and not random
    if password is None:
        password = ""

    try:
        samdb.newuser(
            username,
            password,
            force_password_change_at_next_login_req=must_change_at_next_login,
            useusernameascn=use_username_as_cn,
            userou=userou,
            surname=surname,
            givenname=given_name,
            initials=initials,
            profilepath=profile_path,
            scriptpath=script_path,
            homedrive=home_drive,
            homedirectory=home_directory,
            jobtitle=job_title,
            department=department,
            company=company,
            description=description,
            mailaddress=mail_address,
            internetaddress=internet_address,
            telephonenumber=telephone_number,
            physicaldeliveryoffice=physical_delivery_office,
            setpassword=bool(password),
            uidnumber=uid_number,
            gidnumber=gid_number,
            gecos=gecos,
            loginshell=login_shell,
            uid=uid,
            nisdomain=nis_domain,
            unixhome=unix_home,
            smartcard_required=smartcard_required,
        )
        result_msg = f"User '{username}' created successfully"
        if random_password:
            result_msg += f" with random password"
        return {"message": result_msg, "username": username}
    except Exception as exc:
        # Reset write connection on error — it may be stale
        reset_samdb_connection(for_write=True)
        # Re-raise as RuntimeError for consistent error handling
        raise RuntimeError(str(exc)) from exc


def direct_user_delete(username: str) -> dict[str, Any]:
    """Delete a user via direct SamDB API call.

    Fix v23 Method 1: Uses ldapi:// with auth credentials for writes.
    """
    if not _SAMBA_AVAILABLE:
        raise RuntimeError("samba Python package not available")

    samdb = _get_samdb(for_write=True)
    try:
        samdb.deleteuser(username)
        return {"message": f"User '{username}' deleted successfully"}
    except Exception as exc:
        reset_samdb_connection(for_write=True)
        raise RuntimeError(str(exc)) from exc


def direct_user_enable(username: str) -> dict[str, Any]:
    """Enable a user account via direct SamDB API call.

    Fix v23 Method 1: Uses ldapi:// with auth credentials for writes.
    """
    if not _SAMBA_AVAILABLE:
        raise RuntimeError("samba Python package not available")

    samdb = _get_samdb(for_write=True)
    try:
        samdb.enable_account(f"(sAMAccountName={_ldb_escape(username)})")
        return {"message": f"User '{username}' enabled successfully"}
    except Exception as exc:
        reset_samdb_connection(for_write=True)
        raise RuntimeError(str(exc)) from exc


def direct_user_disable(username: str) -> dict[str, Any]:
    """Disable a user account via direct SamDB API call.

    Fix v23 Method 1: Uses ldapi:// with auth credentials for writes.
    """
    if not _SAMBA_AVAILABLE:
        raise RuntimeError("samba Python package not available")

    samdb = _get_samdb(for_write=True)
    try:
        samdb.disable_account(f"(sAMAccountName={_ldb_escape(username)})")
        return {"message": f"User '{username}' disabled successfully"}
    except Exception as exc:
        reset_samdb_connection(for_write=True)
        raise RuntimeError(str(exc)) from exc


def direct_user_setpassword(
    username: str,
    new_password: str,
    must_change_at_next_login: bool = False,
) -> dict[str, Any]:
    """Set a user's password via direct SamDB API call.

    Fix v23 Method 1: Uses ldapi:// with auth credentials for writes.
    """
    if not _SAMBA_AVAILABLE:
        raise RuntimeError("samba Python package not available")

    samdb = _get_samdb(for_write=True)
    try:
        samdb.setpassword(
            f"(sAMAccountName={_ldb_escape(username)})",
            new_password,
            force_change_at_next_login=must_change_at_next_login,
            username=username,
        )
        return {"message": f"Password set for user '{username}'"}
    except Exception as exc:
        reset_samdb_connection(for_write=True)
        raise RuntimeError(str(exc)) from exc


def direct_user_unlock(username: str) -> dict[str, Any]:
    """Unlock a user account via direct SamDB API call.

    Fix v23 Method 1: Uses ldapi:// with auth credentials for writes.
    """
    if not _SAMBA_AVAILABLE:
        raise RuntimeError("samba Python package not available")

    samdb = _get_samdb(for_write=True)
    try:
        samdb.unlock_account(f"(sAMAccountName={_ldb_escape(username)})")
        return {"message": f"User '{username}' unlocked successfully"}
    except Exception as exc:
        reset_samdb_connection(for_write=True)
        raise RuntimeError(str(exc)) from exc


def direct_user_setexpiry(
    username: str,
    days: int,
    no_expiry: bool = False,
) -> dict[str, Any]:
    """Set user account expiry via direct SamDB API call.

    Fix v23 Method 1: Uses ldapi:// with auth credentials for writes.
    """
    if not _SAMBA_AVAILABLE:
        raise RuntimeError("samba Python package not available")

    samdb = _get_samdb(for_write=True)
    try:
        expiry_seconds = days * 86400  # days to seconds
        samdb.setexpiry(
            f"(sAMAccountName={_ldb_escape(username)})",
            expiry_seconds,
            no_expiry_req=no_expiry,
        )
        return {"message": f"Expiry set for user '{username}'"}
    except Exception as exc:
        reset_samdb_connection(for_write=True)
        raise RuntimeError(str(exc)) from exc


# ── Helper functions ─────────────────────────────────────────────────────


def _ldb_escape(value: str) -> str:
    """Escape a value for use in LDB/LDAP filter expressions.

    Escapes special characters: ``*``, ``(``, ``)``, ``\\``,
    and null bytes according to LDAP filter rules.
    """
    if _LDB_MODULE is not None:
        return _LDB_MODULE.binary_encode(value)
    # Fallback: manual escaping
    result = []
    for ch in value:
        if ch in ('*', '(', ')', '\\', '\0'):
            result.append(f"\\{ord(ch):02x}")
        else:
            result.append(ch)
    return ''.join(result)


def ldb_msg_to_dict(msg: Any) -> dict[str, Any]:
    """Convert an ldb.Message object to a plain Python dict.

    Fix v1.6.3: The ``dn`` key in an ldb.Message is a special
    ``ldb.Dn`` object that is not iterable and does not support
    ``len()``.  When iterating over ``msg`` with ``for k in msg``,
    the ``dn`` key is included, and accessing ``msg["dn"]`` returns
    the ``ldb.Dn`` object.  Trying to call ``len()`` or iterate
    over this object raises ``TypeError: 'ldb.Dn' object is not
    iterable``.

    This function safely converts an ldb.Message to a dict by:
    1. Skipping the ``dn`` key during attribute iteration
    2. Using ``msg.dn`` (the proper property) to get the DN string
    3. Handling ``ldb.MessageElement`` values correctly

    Parameters
    ----------
    msg:
        An ``ldb.Message`` object from a search result.

    Returns
    -------
    dict[str, Any]
        A plain dict with string keys and string/list-of-string values.
        The DN is always available under the ``"dn"`` key.
    """
    item: dict[str, Any] = {}
    for k in msg:
        # Skip 'dn' — it's an ldb.Dn object, not an attribute value.
        # We handle it separately via msg.dn below.
        if k == "dn":
            continue
        val = msg[k]
        try:
            if len(val) == 1:
                item[k] = str(val[0])
            else:
                item[k] = [str(v) for v in val]
        except TypeError:
            # Fallback for non-iterable values
            item[k] = str(val)
    # Always add DN from the proper property
    item["dn"] = str(msg.dn)
    return item


# ── Async wrappers ───────────────────────────────────────────────────────
# These async functions run the direct SamDB operations in the worker pool,
# maintaining the same isolation guarantees as samba-tool subprocess calls.
#
# Fix v23 Method 1: Async wrappers now actually execute the direct_*
# functions via run_in_executor with functools.partial (to handle
# keyword arguments, since run_in_executor only supports positional args).
#
# If the direct SamDB call fails (e.g. LDAP auth error), RuntimeError
# is raised, and the router catches it and falls back to samba-tool
# subprocess automatically.
#
# v1.2.6 fix: BrokenProcessPool import was removed because it fails
# on Python 3.12 / ALT Linux.  We now catch generic Exception instead.
# ProcessPoolExecutor raises RuntimeError when the pool is broken,
# which is caught by the generic except clause.


async def async_user_create(
    username: str,
    password: Optional[str] = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Async wrapper for direct_user_create.

    Fix v23 Method 1: Executes direct_user_create in the worker pool
    via functools.partial (to pass keyword arguments through
    run_in_executor which only accepts positional args).
    """
    if not _SAMBA_AVAILABLE:
        raise RuntimeError("samba Python package not available")

    loop = asyncio.get_running_loop()
    try:
        from app.worker import get_worker_pool
        pool = get_worker_pool()

        func = functools.partial(
            direct_user_create,
            username=username,
            password=password,
            **kwargs,
        )
        result = await loop.run_in_executor(pool._executor, func)
        return result
    except Exception as _pool_exc:
        # v1.2.6: Replaced BrokenProcessPool with generic Exception.
        # BrokenProcessPool is not available in Python 3.12 on some
        # platforms (ALT Linux), causing ImportError at module load.
        reset_samdb_connection(for_write=True)
        _exc_name = type(_pool_exc).__name__
        raise RuntimeError(
            f"Pool error ({_exc_name}) during direct SamDB user create — "
            "falling back to samba-tool subprocess."
        ) from _pool_exc


async def async_user_delete(username: str) -> dict[str, Any]:
    """Async wrapper for direct_user_delete.

    Fix v23 Method 1: Executes in worker pool with functools.partial.
    """
    if not _SAMBA_AVAILABLE:
        raise RuntimeError("samba Python package not available")

    loop = asyncio.get_running_loop()
    try:
        from app.worker import get_worker_pool
        pool = get_worker_pool()

        func = functools.partial(direct_user_delete, username=username)
        result = await loop.run_in_executor(pool._executor, func)
        return result
    except Exception as _pool_exc:
        # v1.2.6: Replaced BrokenProcessPool with generic Exception.
        reset_samdb_connection(for_write=True)
        _exc_name = type(_pool_exc).__name__
        raise RuntimeError(
            f"Pool error ({_exc_name}) during direct SamDB user delete — "
            "falling back to samba-tool subprocess."
        ) from _pool_exc


async def async_user_setpassword(
    username: str,
    new_password: str,
    must_change_at_next_login: bool = False,
) -> dict[str, Any]:
    """Async wrapper for direct_user_setpassword.

    Fix v23 Method 1: Executes in worker pool with functools.partial.
    """
    if not _SAMBA_AVAILABLE:
        raise RuntimeError("samba Python package not available")

    loop = asyncio.get_running_loop()
    try:
        from app.worker import get_worker_pool
        pool = get_worker_pool()

        func = functools.partial(
            direct_user_setpassword,
            username=username,
            new_password=new_password,
            must_change_at_next_login=must_change_at_next_login,
        )
        result = await loop.run_in_executor(pool._executor, func)
        return result
    except Exception as _pool_exc:
        # v1.2.6: Replaced BrokenProcessPool with generic Exception.
        reset_samdb_connection(for_write=True)
        _exc_name = type(_pool_exc).__name__
        raise RuntimeError(
            f"Pool error ({_exc_name}) during direct SamDB set password — "
            "falling back to samba-tool subprocess."
        ) from _pool_exc


async def async_user_enable(username: str) -> dict[str, Any]:
    """Async wrapper for direct_user_enable.

    Fix v23 Method 1: Executes in worker pool with functools.partial.
    """
    if not _SAMBA_AVAILABLE:
        raise RuntimeError("samba Python package not available")

    loop = asyncio.get_running_loop()
    try:
        from app.worker import get_worker_pool
        pool = get_worker_pool()

        func = functools.partial(direct_user_enable, username=username)
        result = await loop.run_in_executor(pool._executor, func)
        return result
    except Exception as _pool_exc:
        # v1.2.6: Replaced BrokenProcessPool with generic Exception.
        reset_samdb_connection(for_write=True)
        _exc_name = type(_pool_exc).__name__
        raise RuntimeError(
            f"Pool error ({_exc_name}) during direct SamDB user enable — "
            "falling back to samba-tool subprocess."
        ) from _pool_exc


async def async_user_disable(username: str) -> dict[str, Any]:
    """Async wrapper for direct_user_disable.

    Fix v23 Method 1: Executes in worker pool with functools.partial.
    """
    if not _SAMBA_AVAILABLE:
        raise RuntimeError("samba Python package not available")

    loop = asyncio.get_running_loop()
    try:
        from app.worker import get_worker_pool
        pool = get_worker_pool()

        func = functools.partial(direct_user_disable, username=username)
        result = await loop.run_in_executor(pool._executor, func)
        return result
    except Exception as _pool_exc:
        # v1.2.6: Replaced BrokenProcessPool with generic Exception.
        reset_samdb_connection(for_write=True)
        _exc_name = type(_pool_exc).__name__
        raise RuntimeError(
            f"Pool error ({_exc_name}) during direct SamDB user disable — "
            "falling back to samba-tool subprocess."
        ) from _pool_exc


async def async_user_unlock(username: str) -> dict[str, Any]:
    """Async wrapper for direct_user_unlock.

    Fix v23 Method 1: Executes in worker pool with functools.partial.
    """
    if not _SAMBA_AVAILABLE:
        raise RuntimeError("samba Python package not available")

    loop = asyncio.get_running_loop()
    try:
        from app.worker import get_worker_pool
        pool = get_worker_pool()

        func = functools.partial(direct_user_unlock, username=username)
        result = await loop.run_in_executor(pool._executor, func)
        return result
    except Exception as _pool_exc:
        # v1.2.6: Replaced BrokenProcessPool with generic Exception.
        reset_samdb_connection(for_write=True)
        _exc_name = type(_pool_exc).__name__
        raise RuntimeError(
            f"Pool error ({_exc_name}) during direct SamDB user unlock — "
            "falling back to samba-tool subprocess."
        ) from _pool_exc


async def async_user_setexpiry(
    username: str,
    days: int,
    no_expiry: bool = False,
) -> dict[str, Any]:
    """Async wrapper for direct_user_setexpiry.

    Fix v23 Method 1: Executes in worker pool with functools.partial.
    """
    if not _SAMBA_AVAILABLE:
        raise RuntimeError("samba Python package not available")

    loop = asyncio.get_running_loop()
    try:
        from app.worker import get_worker_pool
        pool = get_worker_pool()

        func = functools.partial(
            direct_user_setexpiry,
            username=username,
            days=days,
            no_expiry=no_expiry,
        )
        result = await loop.run_in_executor(pool._executor, func)
        return result
    except Exception as _pool_exc:
        # v1.2.6: Replaced BrokenProcessPool with generic Exception.
        reset_samdb_connection(for_write=True)
        _exc_name = type(_pool_exc).__name__
        raise RuntimeError(
            f"Pool error ({_exc_name}) during direct SamDB user setexpiry — "
            "falling back to samba-tool subprocess."
        ) from _pool_exc
