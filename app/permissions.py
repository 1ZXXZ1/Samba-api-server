"""
Granular permission definitions for the Samba AD DC Management API.

Defines 150+ individual permissions organized by resource category,
default role-permission mappings, and a helper to map request paths
to the required permission.

Roles are fully customisable via the management API.  The three
built-in roles (``admin``, ``operator``, ``auditor``) are seeded
on first database initialisation and can be modified afterwards.

v1.2.5_fix: Added 9 new permissions for ``/full`` endpoints and
dashboard:

- ``user.full``, ``group.full``, ``computer.full``, ``contact.full``,
  ``ou.full``, ``gpo.full``, ``domain.full``, ``fsmo.full`` —
  correspond to the fast ldbsearch ``/full`` GET endpoints added
  in v1.2.1.
- ``dashboard.full`` — corresponds to the ``GET /api/v1/dashboard/full``
  endpoint.

All new permissions are included in ``READ_PERMISSIONS`` (operator
role) and the ``auditor`` role.  Path → permission mappings added
for all ``/full`` routes.  The ``resolve_permission()`` longest-prefix
match ensures ``/full`` is matched before the generic list prefix
(e.g. ``/api/v1/users/full`` → ``user.full``, not ``user.list``).
"""

from __future__ import annotations

from typing import Dict, FrozenSet, List, Optional, Set, Tuple

# ═══════════════════════════════════════════════════════════════════════
# 1. Permission constants  (dot-separated:  resource.action)
# ═══════════════════════════════════════════════════════════════════════

# -- Users ---------------------------------------------------------------
PERM_USER_FULL              = "user.full"
PERM_USER_LIST              = "user.list"
PERM_USER_CREATE            = "user.create"
PERM_USER_SHOW              = "user.show"
PERM_USER_DELETE            = "user.delete"
PERM_USER_ENABLE            = "user.enable"
PERM_USER_DISABLE           = "user.disable"
PERM_USER_UNLOCK            = "user.unlock"
PERM_USER_SETPASSWORD       = "user.setpassword"
PERM_USER_GETPASSWORD       = "user.getpassword"
PERM_USER_GETGROUPS         = "user.getgroups"
PERM_USER_SETEXPIRY         = "user.setexpiry"
PERM_USER_SETPRIMARYGROUP   = "user.setprimarygroup"
PERM_USER_ADDUNIXATTRS      = "user.addunixattrs"
PERM_USER_SENSITIVE         = "user.sensitive"
PERM_USER_MOVE              = "user.move"
PERM_USER_RENAME            = "user.rename"
PERM_USER_GETKERBEROSTICKET = "user.getkerberosticket"
PERM_USER_SEARCH            = "user.search"
PERM_USER_IMPORT            = "user.import"
PERM_USER_EXPORT            = "user.export"

# -- Groups --------------------------------------------------------------
PERM_GROUP_FULL           = "group.full"
PERM_GROUP_LIST           = "group.list"
PERM_GROUP_CREATE         = "group.create"
PERM_GROUP_SHOW           = "group.show"
PERM_GROUP_DELETE         = "group.delete"
PERM_GROUP_STATS          = "group.stats"
PERM_GROUP_ADDMEMBERS     = "group.addmembers"
PERM_GROUP_REMOVEMEMBERS  = "group.removemembers"
PERM_GROUP_LISTMEMBERS    = "group.listmembers"
PERM_GROUP_MOVE           = "group.move"
PERM_GROUP_RENAME         = "group.rename"

# -- Computers -----------------------------------------------------------
PERM_COMPUTER_FULL   = "computer.full"
PERM_COMPUTER_LIST   = "computer.list"
PERM_COMPUTER_CREATE = "computer.create"
PERM_COMPUTER_SHOW   = "computer.show"
PERM_COMPUTER_DELETE = "computer.delete"
PERM_COMPUTER_MOVE   = "computer.move"

# -- Contacts ------------------------------------------------------------
PERM_CONTACT_FULL   = "contact.full"
PERM_CONTACT_LIST   = "contact.list"
PERM_CONTACT_CREATE = "contact.create"
PERM_CONTACT_SHOW   = "contact.show"
PERM_CONTACT_DELETE = "contact.delete"
PERM_CONTACT_MOVE   = "contact.move"
PERM_CONTACT_RENAME = "contact.rename"
PERM_CONTACT_SEARCH = "contact.search"

# -- Organizational Units ------------------------------------------------
PERM_OU_FULL         = "ou.full"
PERM_OU_LIST         = "ou.list"
PERM_OU_CREATE       = "ou.create"
PERM_OU_DELETE       = "ou.delete"
PERM_OU_MOVE         = "ou.move"
PERM_OU_RENAME       = "ou.rename"
PERM_OU_LISTOBJECTS  = "ou.listobjects"
PERM_OU_TREE         = "ou.tree"
PERM_OU_STATS        = "ou.stats"
PERM_OU_SEARCH       = "ou.search"

# -- DNS -----------------------------------------------------------------
PERM_DNS_SERVERINFO   = "dns.serverinfo"
PERM_DNS_ZONELIST     = "dns.zonelist"
PERM_DNS_ZONEINFO     = "dns.zoneinfo"
PERM_DNS_ZONECREATE   = "dns.zonecreate"
PERM_DNS_ZONEDELETE   = "dns.zonedelete"
PERM_DNS_RECORDLIST   = "dns.recordlist"
PERM_DNS_RECORDCREATE = "dns.recordcreate"
PERM_DNS_RECORDDELETE = "dns.recorddelete"
PERM_DNS_RECORDUPDATE = "dns.recordupdate"
PERM_DNS_RORECORDS    = "dns.rorecords"
PERM_DNS_ZONEOPTIONS  = "dns.zoneoptions"

# -- Group Policy (GPO) --------------------------------------------------
PERM_GPO_FULL        = "gpo.full"
PERM_GPO_LIST        = "gpo.list"
PERM_GPO_CREATE      = "gpo.create"
PERM_GPO_SHOW        = "gpo.show"
PERM_GPO_DELETE      = "gpo.delete"
PERM_GPO_DELETEBYNAME = "gpo.deletebyname"
PERM_GPO_LINK        = "gpo.link"
PERM_GPO_UNLINK      = "gpo.unlink"
PERM_GPO_GETINHERIT  = "gpo.getinherit"
PERM_GPO_SETINHERIT  = "gpo.setinherit"
PERM_GPO_BACKUP      = "gpo.backup"
PERM_GPO_RESTORE     = "gpo.restore"
PERM_GPO_FETCH       = "gpo.fetch"

# -- Domain --------------------------------------------------------------
PERM_DOMAIN_FULL             = "domain.full"
PERM_DOMAIN_INFO             = "domain.info"
PERM_DOMAIN_LEVEL            = "domain.level"
PERM_DOMAIN_PASSWORDSETTINGS = "domain.passwordsettings"
PERM_DOMAIN_SCHEMAS          = "domain.schemas"
PERM_DOMAIN_PROVISION        = "domain.provision"
PERM_DOMAIN_JOIN             = "domain.join"
PERM_DOMAIN_DEMOTE           = "domain.demote"
PERM_DOMAIN_RENAME           = "domain.rename"
PERM_DOMAIN_TRUSTLIST        = "domain.trustlist"
PERM_DOMAIN_TRUSTCREATE      = "domain.trustcreate"
PERM_DOMAIN_TRUSTDELETE      = "domain.trustdelete"

# -- DRS (Directory Replication Service) ---------------------------------
PERM_DRS_SHOWREPL = "drs.showrepl"
PERM_DRS_BIND     = "drs.bind"
PERM_DRS_UNBIND   = "drs.unbind"
PERM_DRS_OPTIONS  = "drs.options"
PERM_DRS_KCC      = "drs.kcc"

# -- Sites ---------------------------------------------------------------
PERM_SITES_LIST   = "sites.list"
PERM_SITES_CREATE = "sites.create"
PERM_SITES_SHOW   = "sites.show"
PERM_SITES_DELETE = "sites.delete"
PERM_SITES_SUBNETLIST = "sites.subnetlist"

# -- FSMO ----------------------------------------------------------------
PERM_FSMO_FULL     = "fsmo.full"
PERM_FSMO_SHOW     = "fsmo.show"
PERM_FSMO_SEIZE    = "fsmo.seize"
PERM_FSMO_TRANSFER = "fsmo.transfer"
PERM_FSMO_ROLES    = "fsmo.roles"

# -- Schema --------------------------------------------------------------
PERM_SCHEMA_LIST  = "schema.list"
PERM_SCHEMA_SHOW  = "schema.show"
PERM_SCHEMA_QUERY = "schema.query"

# -- Delegation ----------------------------------------------------------
PERM_DELEGATION_LIST   = "delegation.list"
PERM_DELEGATION_SET    = "delegation.set"
PERM_DELEGATION_DELETE = "delegation.delete"

# -- Service accounts ----------------------------------------------------
PERM_SERVICEACCOUNT_LIST   = "serviceaccount.list"
PERM_SERVICEACCOUNT_CREATE = "serviceaccount.create"
PERM_SERVICEACCOUNT_SHOW   = "serviceaccount.show"
PERM_SERVICEACCOUNT_DELETE = "serviceaccount.delete"

# -- Authentication policies ---------------------------------------------
PERM_AUTHPOLICY_LIST   = "authpolicy.list"
PERM_AUTHPOLICY_SHOW   = "authpolicy.show"
PERM_AUTHPOLICY_CREATE = "authpolicy.create"
PERM_AUTHPOLICY_DELETE = "authpolicy.delete"
PERM_AUTHPOLICY_UPDATE = "authpolicy.update"

# -- Batch operations ----------------------------------------------------
PERM_BATCH_EXECUTE = "batch.execute"
PERM_BATCH_STATUS  = "batch.status"

# -- Shell execution (v1.4.3) ---------------------------------------------
PERM_SHELL_EXECUTE = "shell.execute"
PERM_SHELL_SUDO    = "shell.sudo"

# -- Shell Project (v1.6.4) -----------------------------------------------
PERM_SHELL_PROJET_CREATE = "shell.projet.create"
PERM_SHELL_PROJET_RUN    = "shell.projet.run"
PERM_SHELL_PROJET_SHOW   = "shell.projet.show"
PERM_SHELL_PROJET_LIST   = "shell.projet.list"
PERM_SHELL_PROJET_DELETE = "shell.projet.delete"
PERM_SHELL_PROJET_UPLOAD = "shell.projet.upload"
PERM_SHELL_PROJET_ABORT  = "shell.projet.abort"  # v1.6.5

# -- Management API (admin panel) ----------------------------------------
PERM_MGMT_USERS_LIST   = "mgmt.users.list"
PERM_MGMT_USERS_CREATE = "mgmt.users.create"
PERM_MGMT_USERS_SHOW   = "mgmt.users.show"
PERM_MGMT_USERS_UPDATE = "mgmt.users.update"
PERM_MGMT_USERS_DELETE = "mgmt.users.delete"
PERM_MGMT_KEYS_LIST    = "mgmt.keys.list"
PERM_MGMT_KEYS_CREATE  = "mgmt.keys.create"
PERM_MGMT_KEYS_SHOW    = "mgmt.keys.show"
PERM_MGMT_KEYS_UPDATE  = "mgmt.keys.update"
PERM_MGMT_KEYS_DELETE  = "mgmt.keys.delete"
PERM_MGMT_KEYS_ROTATE  = "mgmt.keys.rotate"
PERM_MGMT_AUDIT_VIEW   = "mgmt.audit.view"
PERM_MGMT_ROLES_LIST   = "mgmt.roles.list"
PERM_MGMT_ROLES_CREATE = "mgmt.roles.create"
PERM_MGMT_ROLES_UPDATE = "mgmt.roles.update"
PERM_MGMT_ROLES_DELETE = "mgmt.roles.delete"
PERM_MGMT_PERMS_LIST   = "mgmt.perms.list"
PERM_MGMT_PERMS_ASSIGN = "mgmt.perms.assign"
PERM_MGMT_PERMS_REVOKE = "mgmt.perms.revoke"

# -- Dashboard ----------------------------------------------------------
PERM_DASHBOARD_FULL = "dashboard.full"

# -- System / monitoring -------------------------------------------------
PERM_SYSTEM_HEALTH = "system.health"
PERM_SYSTEM_STATS  = "system.stats"
PERM_SYSTEM_METRICS = "system.metrics"
PERM_SYSTEM_TASKS  = "system.tasks"

# -- Tasks ---------------------------------------------------------------
PERM_TASKS_LIST = "tasks.list"
PERM_TASKS_VIEW = "tasks.view"

# -- Authentication ------------------------------------------------------
PERM_AUTH_ME    = "auth.me"
PERM_AUTH_CHECK = "auth.check"

# -- Misc ----------------------------------------------------------------
PERM_MISC_TIME      = "misc.time"
PERM_MISC_PROCESSES = "misc.processes"
PERM_MISC_TESTPARAM = "misc.testparm"

# ═══════════════════════════════════════════════════════════════════════
# 2. All permissions set
# ═══════════════════════════════════════════════════════════════════════

ALL_PERMISSIONS: FrozenSet[str] = frozenset({
    # Users (21)
    PERM_USER_FULL,
    PERM_USER_LIST, PERM_USER_CREATE, PERM_USER_SHOW, PERM_USER_DELETE,
    PERM_USER_ENABLE, PERM_USER_DISABLE, PERM_USER_UNLOCK,
    PERM_USER_SETPASSWORD, PERM_USER_GETPASSWORD, PERM_USER_GETGROUPS,
    PERM_USER_SETEXPIRY, PERM_USER_SETPRIMARYGROUP, PERM_USER_ADDUNIXATTRS,
    PERM_USER_SENSITIVE, PERM_USER_MOVE, PERM_USER_RENAME,
    PERM_USER_GETKERBEROSTICKET, PERM_USER_SEARCH, PERM_USER_IMPORT,
    PERM_USER_EXPORT,
    # Groups (11)
    PERM_GROUP_FULL,
    PERM_GROUP_LIST, PERM_GROUP_CREATE, PERM_GROUP_SHOW, PERM_GROUP_DELETE,
    PERM_GROUP_STATS, PERM_GROUP_ADDMEMBERS, PERM_GROUP_REMOVEMEMBERS,
    PERM_GROUP_LISTMEMBERS, PERM_GROUP_MOVE, PERM_GROUP_RENAME,
    # Computers (6)
    PERM_COMPUTER_FULL,
    PERM_COMPUTER_LIST, PERM_COMPUTER_CREATE, PERM_COMPUTER_SHOW,
    PERM_COMPUTER_DELETE, PERM_COMPUTER_MOVE,
    # Contacts (8)
    PERM_CONTACT_FULL,
    PERM_CONTACT_LIST, PERM_CONTACT_CREATE, PERM_CONTACT_SHOW,
    PERM_CONTACT_DELETE, PERM_CONTACT_MOVE, PERM_CONTACT_RENAME,
    PERM_CONTACT_SEARCH,
    # OUs (10)
    PERM_OU_FULL,
    PERM_OU_LIST, PERM_OU_CREATE, PERM_OU_DELETE, PERM_OU_MOVE,
    PERM_OU_RENAME, PERM_OU_LISTOBJECTS, PERM_OU_TREE, PERM_OU_STATS,
    PERM_OU_SEARCH,
    # DNS (11)
    PERM_DNS_SERVERINFO, PERM_DNS_ZONELIST, PERM_DNS_ZONEINFO,
    PERM_DNS_ZONECREATE, PERM_DNS_ZONEDELETE, PERM_DNS_RECORDLIST,
    PERM_DNS_RECORDCREATE, PERM_DNS_RECORDDELETE, PERM_DNS_RECORDUPDATE,
    PERM_DNS_RORECORDS, PERM_DNS_ZONEOPTIONS,
    # GPO (14)
    PERM_GPO_FULL,
    PERM_GPO_LIST, PERM_GPO_CREATE, PERM_GPO_SHOW, PERM_GPO_DELETE,
    PERM_GPO_DELETEBYNAME, PERM_GPO_LINK, PERM_GPO_UNLINK,
    PERM_GPO_GETINHERIT, PERM_GPO_SETINHERIT, PERM_GPO_BACKUP,
    PERM_GPO_RESTORE, PERM_GPO_FETCH,
    # Domain (12)
    PERM_DOMAIN_FULL,
    PERM_DOMAIN_INFO, PERM_DOMAIN_LEVEL, PERM_DOMAIN_PASSWORDSETTINGS,
    PERM_DOMAIN_SCHEMAS, PERM_DOMAIN_PROVISION, PERM_DOMAIN_JOIN,
    PERM_DOMAIN_DEMOTE, PERM_DOMAIN_RENAME, PERM_DOMAIN_TRUSTLIST,
    PERM_DOMAIN_TRUSTCREATE, PERM_DOMAIN_TRUSTDELETE,
    # DRS (5)
    PERM_DRS_SHOWREPL, PERM_DRS_BIND, PERM_DRS_UNBIND, PERM_DRS_OPTIONS,
    PERM_DRS_KCC,
    # Sites (5)
    PERM_SITES_LIST, PERM_SITES_CREATE, PERM_SITES_SHOW,
    PERM_SITES_DELETE, PERM_SITES_SUBNETLIST,
    # FSMO (5)
    PERM_FSMO_FULL, PERM_FSMO_SHOW, PERM_FSMO_SEIZE, PERM_FSMO_TRANSFER, PERM_FSMO_ROLES,
    # Schema (3)
    PERM_SCHEMA_LIST, PERM_SCHEMA_SHOW, PERM_SCHEMA_QUERY,
    # Delegation (3)
    PERM_DELEGATION_LIST, PERM_DELEGATION_SET, PERM_DELEGATION_DELETE,
    # Service accounts (4)
    PERM_SERVICEACCOUNT_LIST, PERM_SERVICEACCOUNT_CREATE,
    PERM_SERVICEACCOUNT_SHOW, PERM_SERVICEACCOUNT_DELETE,
    # Auth policies (5)
    PERM_AUTHPOLICY_LIST, PERM_AUTHPOLICY_SHOW, PERM_AUTHPOLICY_CREATE,
    PERM_AUTHPOLICY_DELETE, PERM_AUTHPOLICY_UPDATE,
    # Shell (2)
    PERM_SHELL_EXECUTE, PERM_SHELL_SUDO,
    # Shell Project (6) — v1.6.4
    PERM_SHELL_PROJET_CREATE, PERM_SHELL_PROJET_RUN,
    PERM_SHELL_PROJET_SHOW, PERM_SHELL_PROJET_LIST,
    PERM_SHELL_PROJET_DELETE, PERM_SHELL_PROJET_UPLOAD,
    PERM_SHELL_PROJET_ABORT,  # v1.6.5
    # Batch (2)
    PERM_BATCH_EXECUTE, PERM_BATCH_STATUS,
    # Management (17)
    PERM_MGMT_USERS_LIST, PERM_MGMT_USERS_CREATE, PERM_MGMT_USERS_SHOW,
    PERM_MGMT_USERS_UPDATE, PERM_MGMT_USERS_DELETE,
    PERM_MGMT_KEYS_LIST, PERM_MGMT_KEYS_CREATE, PERM_MGMT_KEYS_SHOW,
    PERM_MGMT_KEYS_UPDATE, PERM_MGMT_KEYS_DELETE, PERM_MGMT_KEYS_ROTATE,
    PERM_MGMT_AUDIT_VIEW,
    PERM_MGMT_ROLES_LIST, PERM_MGMT_ROLES_CREATE, PERM_MGMT_ROLES_UPDATE,
    PERM_MGMT_ROLES_DELETE,
    PERM_MGMT_PERMS_LIST, PERM_MGMT_PERMS_ASSIGN, PERM_MGMT_PERMS_REVOKE,
    # Dashboard (1)
    PERM_DASHBOARD_FULL,
    # System (4)
    PERM_SYSTEM_HEALTH, PERM_SYSTEM_STATS, PERM_SYSTEM_METRICS,
    PERM_SYSTEM_TASKS,
    # Tasks (2)
    PERM_TASKS_LIST, PERM_TASKS_VIEW,
    # Misc (3)
    PERM_MISC_TIME, PERM_MISC_PROCESSES, PERM_MISC_TESTPARAM,
    # Auth (2)
    PERM_AUTH_ME, PERM_AUTH_CHECK,
})

# ═══════════════════════════════════════════════════════════════════════
# 3. Read-only permissions subset (for operator/auditor default roles)
# ═══════════════════════════════════════════════════════════════════════

READ_PERMISSIONS: FrozenSet[str] = frozenset({
    # /full endpoints (ldbsearch fast reads)
    PERM_USER_FULL, PERM_GROUP_FULL, PERM_COMPUTER_FULL,
    PERM_CONTACT_FULL, PERM_OU_FULL, PERM_GPO_FULL,
    PERM_DOMAIN_FULL, PERM_FSMO_FULL, PERM_DASHBOARD_FULL,
    # Regular list/show reads
    PERM_USER_LIST, PERM_USER_SHOW, PERM_USER_GETGROUPS,
    PERM_GROUP_LIST, PERM_GROUP_SHOW, PERM_GROUP_STATS, PERM_GROUP_LISTMEMBERS,
    PERM_COMPUTER_LIST, PERM_COMPUTER_SHOW,
    PERM_CONTACT_LIST, PERM_CONTACT_SHOW,
    PERM_OU_LIST, PERM_OU_LISTOBJECTS, PERM_OU_TREE, PERM_OU_STATS,
    PERM_DNS_SERVERINFO, PERM_DNS_ZONELIST, PERM_DNS_ZONEINFO,
    PERM_DNS_RECORDLIST, PERM_DNS_RORECORDS,
    PERM_GPO_LIST, PERM_GPO_SHOW, PERM_GPO_GETINHERIT, PERM_GPO_FETCH,
    PERM_DOMAIN_INFO, PERM_DOMAIN_LEVEL, PERM_DOMAIN_PASSWORDSETTINGS,
    PERM_DOMAIN_SCHEMAS, PERM_DOMAIN_TRUSTLIST,
    PERM_DRS_SHOWREPL,
    PERM_SITES_LIST, PERM_SITES_SHOW, PERM_SITES_SUBNETLIST,
    PERM_FSMO_SHOW, PERM_FSMO_ROLES,
    PERM_SCHEMA_LIST, PERM_SCHEMA_SHOW, PERM_SCHEMA_QUERY,
    PERM_DELEGATION_LIST,
    PERM_SERVICEACCOUNT_LIST, PERM_SERVICEACCOUNT_SHOW,
    PERM_AUTHPOLICY_LIST, PERM_AUTHPOLICY_SHOW,
    PERM_SYSTEM_HEALTH, PERM_SYSTEM_STATS, PERM_SYSTEM_METRICS,
    PERM_SYSTEM_TASKS, PERM_TASKS_LIST, PERM_TASKS_VIEW,
    PERM_MISC_TIME, PERM_MISC_PROCESSES, PERM_MISC_TESTPARAM,
    PERM_AUTH_ME, PERM_AUTH_CHECK,
})

# ═══════════════════════════════════════════════════════════════════════
# 4. Default role → permission mapping
# ═══════════════════════════════════════════════════════════════════════

DEFAULT_ROLE_PERMISSIONS: Dict[str, FrozenSet[str]] = {
    "admin": ALL_PERMISSIONS,
    "operator": READ_PERMISSIONS,
    "auditor": frozenset({
        # /full endpoints (ldbsearch fast reads) — auditor gets ALL of these
        PERM_USER_FULL, PERM_GROUP_FULL, PERM_COMPUTER_FULL,
        PERM_CONTACT_FULL, PERM_OU_FULL, PERM_GPO_FULL,
        PERM_DOMAIN_FULL, PERM_FSMO_FULL, PERM_DASHBOARD_FULL,
        # Regular read-only permissions
        PERM_USER_LIST, PERM_USER_SHOW, PERM_USER_GETGROUPS,
        PERM_GROUP_LIST, PERM_GROUP_SHOW, PERM_GROUP_STATS, PERM_GROUP_LISTMEMBERS,
        PERM_COMPUTER_LIST, PERM_COMPUTER_SHOW,
        PERM_CONTACT_LIST, PERM_CONTACT_SHOW,
        PERM_OU_LIST, PERM_OU_LISTOBJECTS, PERM_OU_TREE, PERM_OU_STATS,
        PERM_DNS_SERVERINFO, PERM_DNS_ZONELIST, PERM_DNS_ZONEINFO,
        PERM_DNS_RECORDLIST, PERM_DNS_RORECORDS,
        PERM_GPO_LIST, PERM_GPO_SHOW, PERM_GPO_GETINHERIT, PERM_GPO_FETCH,
        PERM_DOMAIN_INFO, PERM_DOMAIN_LEVEL, PERM_DOMAIN_PASSWORDSETTINGS,
        PERM_DOMAIN_SCHEMAS, PERM_DOMAIN_TRUSTLIST,
        PERM_DRS_SHOWREPL,
        PERM_SITES_LIST, PERM_SITES_SHOW, PERM_SITES_SUBNETLIST,
        PERM_FSMO_SHOW, PERM_FSMO_ROLES,
        PERM_SCHEMA_LIST, PERM_SCHEMA_SHOW,
        PERM_DELEGATION_LIST,
        PERM_SERVICEACCOUNT_LIST, PERM_SERVICEACCOUNT_SHOW,
        PERM_AUTHPOLICY_LIST, PERM_AUTHPOLICY_SHOW,
        PERM_SYSTEM_HEALTH, PERM_SYSTEM_STATS, PERM_SYSTEM_METRICS,
        PERM_SYSTEM_TASKS, PERM_TASKS_LIST, PERM_TASKS_VIEW,
        PERM_MISC_TIME, PERM_MISC_PROCESSES,
        PERM_MGMT_AUDIT_VIEW,
        PERM_AUTH_ME, PERM_AUTH_CHECK,
    }),
}

# ═══════════════════════════════════════════════════════════════════════
# 5. Path → permission mapping
#    (method, path_prefix) → required permission
# ═══════════════════════════════════════════════════════════════════════

_PATH_PERM_MAP: List[Tuple[str, str, str]] = [
    # -- Users (/api/v1/users)
    ("GET",    "/api/v1/users/full",               PERM_USER_FULL),
    ("GET",    "/api/v1/users/",                   PERM_USER_LIST),
    ("POST",   "/api/v1/users/",                   PERM_USER_CREATE),
    ("GET",    "/api/v1/users/search",             PERM_USER_SEARCH),
    ("POST",   "/api/v1/users/import",             PERM_USER_IMPORT),
    ("GET",    "/api/v1/users/export",             PERM_USER_EXPORT),
    ("GET",    "/api/v1/users_mgmt/search",        PERM_USER_SEARCH),
    ("POST",   "/api/v1/users_mgmt/import",        PERM_USER_IMPORT),
    ("GET",    "/api/v1/users_mgmt/export",        PERM_USER_EXPORT),
    # Dynamic paths with {username} — matched by prefix + suffix
    ("GET",    "/api/v1/users/getpassword",        PERM_USER_GETPASSWORD),
    # The following catch dynamic username paths
    ("DELETE", "/api/v1/users/",                   PERM_USER_DELETE),
    ("POST",   "/api/v1/users/enable",             PERM_USER_ENABLE),
    ("POST",   "/api/v1/users/disable",            PERM_USER_DISABLE),
    ("POST",   "/api/v1/users/unlock",             PERM_USER_UNLOCK),
    ("PUT",    "/api/v1/users/password",            PERM_USER_SETPASSWORD),
    ("GET",    "/api/v1/users/groups",              PERM_USER_GETGROUPS),
    ("PUT",    "/api/v1/users/setexpiry",           PERM_USER_SETEXPIRY),
    ("PUT",    "/api/v1/users/setprimarygroup",     PERM_USER_SETPRIMARYGROUP),
    ("POST",   "/api/v1/users/addunixattrs",        PERM_USER_ADDUNIXATTRS),
    ("PUT",    "/api/v1/users/sensitive",           PERM_USER_SENSITIVE),
    ("POST",   "/api/v1/users/move",                PERM_USER_MOVE),
    ("POST",   "/api/v1/users/rename",              PERM_USER_RENAME),
    ("GET",    "/api/v1/users/kerberos",            PERM_USER_GETKERBEROSTICKET),

    # -- Groups (/api/v1/groups)
    ("GET",    "/api/v1/groups/full",               PERM_GROUP_FULL),
    ("GET",    "/api/v1/groups/",                   PERM_GROUP_LIST),
    ("POST",   "/api/v1/groups/",                   PERM_GROUP_CREATE),
    ("GET",    "/api/v1/groups/stats",              PERM_GROUP_STATS),
    ("DELETE", "/api/v1/groups/",                   PERM_GROUP_DELETE),
    ("POST",   "/api/v1/groups/members",            PERM_GROUP_ADDMEMBERS),
    ("DELETE", "/api/v1/groups/members",            PERM_GROUP_REMOVEMEMBERS),
    ("GET",    "/api/v1/groups/members",            PERM_GROUP_LISTMEMBERS),
    ("POST",   "/api/v1/groups/move",               PERM_GROUP_MOVE),

    # -- Computers (/api/v1/computers)
    ("GET",    "/api/v1/computers/full",            PERM_COMPUTER_FULL),
    ("GET",    "/api/v1/computers/",                PERM_COMPUTER_LIST),
    ("POST",   "/api/v1/computers/",                PERM_COMPUTER_CREATE),
    ("DELETE", "/api/v1/computers/",                PERM_COMPUTER_DELETE),
    ("POST",   "/api/v1/computers/move",            PERM_COMPUTER_MOVE),

    # -- Contacts (/api/v1/contacts)
    ("GET",    "/api/v1/contacts/full",             PERM_CONTACT_FULL),
    ("GET",    "/api/v1/contacts/",                 PERM_CONTACT_LIST),
    ("POST",   "/api/v1/contacts/",                 PERM_CONTACT_CREATE),
    ("DELETE", "/api/v1/contacts/",                 PERM_CONTACT_DELETE),
    ("POST",   "/api/v1/contacts/move",             PERM_CONTACT_MOVE),
    ("POST",   "/api/v1/contacts/rename",           PERM_CONTACT_RENAME),
    ("GET",    "/api/v1/contacts/search",           PERM_CONTACT_SEARCH),

    # -- OUs (/api/v1/ous)
    ("GET",    "/api/v1/ous/full",                  PERM_OU_FULL),
    ("GET",    "/api/v1/ous/",                      PERM_OU_LIST),
    ("POST",   "/api/v1/ous/",                      PERM_OU_CREATE),
    ("DELETE", "/api/v1/ous/",                      PERM_OU_DELETE),
    ("POST",   "/api/v1/ous/move",                  PERM_OU_MOVE),
    ("POST",   "/api/v1/ous/rename",                PERM_OU_RENAME),
    ("GET",    "/api/v1/ous/objects",               PERM_OU_LISTOBJECTS),
    ("GET",    "/api/v1/ous/tree",                  PERM_OU_TREE),
    ("GET",    "/api/v1/ous/stats",                 PERM_OU_STATS),
    ("GET",    "/api/v1/ous/search",                PERM_OU_SEARCH),
    ("GET",    "/api/v1/ous_mgmt/tree",             PERM_OU_TREE),
    ("GET",    "/api/v1/ous_mgmt/stats",            PERM_OU_STATS),
    ("GET",    "/api/v1/ous_mgmt/search",           PERM_OU_SEARCH),

    # -- DNS (/api/v1/dns)
    ("GET",    "/api/v1/dns/serverinfo",            PERM_DNS_SERVERINFO),
    ("GET",    "/api/v1/dns/zones",                 PERM_DNS_ZONELIST),
    ("POST",   "/api/v1/dns/zones",                 PERM_DNS_ZONECREATE),
    ("DELETE", "/api/v1/dns/zones/",                PERM_DNS_ZONEDELETE),
    ("GET",    "/api/v1/dns/zoneinfo",              PERM_DNS_ZONEINFO),
    ("GET",    "/api/v1/dns/records",               PERM_DNS_RECORDLIST),
    ("POST",   "/api/v1/dns/records",               PERM_DNS_RECORDCREATE),
    ("DELETE", "/api/v1/dns/records",               PERM_DNS_RECORDDELETE),
    ("PUT",    "/api/v1/dns/records",               PERM_DNS_RECORDUPDATE),
    ("GET",    "/api/v1/dns/rorecords",             PERM_DNS_RORECORDS),
    ("PUT",    "/api/v1/dns/options",               PERM_DNS_ZONEOPTIONS),

    # -- GPO (/api/v1/gpo)
    ("GET",    "/api/v1/gpo/full",                  PERM_GPO_FULL),
    ("GET",    "/api/v1/gpo/",                      PERM_GPO_LIST),
    ("POST",   "/api/v1/gpo/",                      PERM_GPO_CREATE),
    ("DELETE", "/api/v1/gpo/",                      PERM_GPO_DELETE),
    ("DELETE", "/api/v1/gpo/by-name/",              PERM_GPO_DELETEBYNAME),
    ("POST",   "/api/v1/gpo/link",                  PERM_GPO_LINK),
    ("DELETE", "/api/v1/gpo/link",                  PERM_GPO_UNLINK),
    ("GET",    "/api/v1/gpo/inherit",               PERM_GPO_GETINHERIT),
    ("PUT",    "/api/v1/gpo/inherit",               PERM_GPO_SETINHERIT),
    ("POST",   "/api/v1/gpo/backup",                PERM_GPO_BACKUP),
    ("POST",   "/api/v1/gpo/restore",               PERM_GPO_RESTORE),
    ("GET",    "/api/v1/gpo/fetch",                 PERM_GPO_FETCH),

    # -- Domain (/api/v1/domain)
    ("GET",    "/api/v1/domain/full",               PERM_DOMAIN_FULL),
    ("GET",    "/api/v1/domain/",                   PERM_DOMAIN_INFO),
    ("PUT",    "/api/v1/domain/level",              PERM_DOMAIN_LEVEL),
    ("GET",    "/api/v1/domain/passwordsettings",   PERM_DOMAIN_PASSWORDSETTINGS),
    ("GET",    "/api/v1/domain/schemas",            PERM_DOMAIN_SCHEMAS),
    ("POST",   "/api/v1/domain/provision",          PERM_DOMAIN_PROVISION),
    ("POST",   "/api/v1/domain/join",               PERM_DOMAIN_JOIN),
    ("POST",   "/api/v1/domain/demote",             PERM_DOMAIN_DEMOTE),
    ("GET",    "/api/v1/domain/trusts",             PERM_DOMAIN_TRUSTLIST),
    ("POST",   "/api/v1/domain/trusts",             PERM_DOMAIN_TRUSTCREATE),
    ("DELETE", "/api/v1/domain/trusts",             PERM_DOMAIN_TRUSTDELETE),

    # -- DRS (/api/v1/drs)
    ("GET",    "/api/v1/drs/showrepl",              PERM_DRS_SHOWREPL),
    ("POST",   "/api/v1/drs/bind",                  PERM_DRS_BIND),
    ("POST",   "/api/v1/drs/unbind",                PERM_DRS_UNBIND),
    ("GET",    "/api/v1/drs/options",               PERM_DRS_OPTIONS),
    ("POST",   "/api/v1/drs/kcc",                   PERM_DRS_KCC),

    # -- Sites (/api/v1/sites)
    ("GET",    "/api/v1/sites/",                    PERM_SITES_LIST),
    ("POST",   "/api/v1/sites/",                    PERM_SITES_CREATE),
    ("DELETE", "/api/v1/sites/",                    PERM_SITES_DELETE),
    ("GET",    "/api/v1/sites/subnets",             PERM_SITES_SUBNETLIST),

    # -- FSMO (/api/v1/fsmo)
    ("GET",    "/api/v1/fsmo/full",                 PERM_FSMO_FULL),
    ("GET",    "/api/v1/fsmo/",                     PERM_FSMO_SHOW),
    ("POST",   "/api/v1/fsmo/seize",                PERM_FSMO_SEIZE),
    ("POST",   "/api/v1/fsmo/transfer",             PERM_FSMO_TRANSFER),
    ("GET",    "/api/v1/fsmo/roles",                PERM_FSMO_ROLES),

    # -- Schema (/api/v1/schema)
    ("GET",    "/api/v1/schema/",                   PERM_SCHEMA_LIST),
    ("GET",    "/api/v1/schema/query",              PERM_SCHEMA_QUERY),

    # -- Delegation (/api/v1/delegation)
    ("GET",    "/api/v1/delegation/",               PERM_DELEGATION_LIST),
    ("POST",   "/api/v1/delegation/",               PERM_DELEGATION_SET),
    ("DELETE", "/api/v1/delegation/",               PERM_DELEGATION_DELETE),

    # -- Service accounts (/api/v1/service-accounts)
    ("GET",    "/api/v1/service-accounts/",         PERM_SERVICEACCOUNT_LIST),
    ("POST",   "/api/v1/service-accounts/",         PERM_SERVICEACCOUNT_CREATE),
    ("DELETE", "/api/v1/service-accounts/",         PERM_SERVICEACCOUNT_DELETE),

    # -- Auth policies (/api/v1/auth-policies)
    ("GET",    "/api/v1/auth-policies/",            PERM_AUTHPOLICY_LIST),
    ("POST",   "/api/v1/auth-policies/",            PERM_AUTHPOLICY_CREATE),
    ("DELETE", "/api/v1/auth-policies/",            PERM_AUTHPOLICY_DELETE),
    ("PUT",    "/api/v1/auth-policies/",            PERM_AUTHPOLICY_UPDATE),

    # -- Shell (/api/v1/shell)
    ("POST",   "/api/v1/shell/",                    PERM_SHELL_EXECUTE),
    ("POST",   "/api/v1/shell/sudo",                PERM_SHELL_SUDO),

    # -- Shell Project (/api/v1/shell/projet) — v1.6.4
    ("POST",   "/api/v1/shell/projet/",             PERM_SHELL_PROJET_CREATE),
    ("POST",   "/api/v1/shell/projet/upload",       PERM_SHELL_PROJET_UPLOAD),
    ("POST",   "/api/v1/shell/projet/abort",       PERM_SHELL_PROJET_ABORT),  # v1.6.5
    ("POST",   "/api/v1/shell/projet/run",          PERM_SHELL_PROJET_RUN),
    ("GET",    "/api/v1/shell/projet/show",          PERM_SHELL_PROJET_SHOW),
    ("GET",    "/api/v1/shell/projet/list",          PERM_SHELL_PROJET_LIST),
    ("DELETE", "/api/v1/shell/projet/",              PERM_SHELL_PROJET_DELETE),

    # -- Batch (/api/v1/batch)
    ("POST",   "/api/v1/batch/",                    PERM_BATCH_EXECUTE),

    # -- Management (/api/v1/mgmt)
    ("GET",    "/api/v1/mgmt/users",                PERM_MGMT_USERS_LIST),
    ("POST",   "/api/v1/mgmt/users",                PERM_MGMT_USERS_CREATE),
    ("PUT",    "/api/v1/mgmt/users/",               PERM_MGMT_USERS_UPDATE),
    ("DELETE", "/api/v1/mgmt/users/",               PERM_MGMT_USERS_DELETE),
    ("GET",    "/api/v1/mgmt/keys",                 PERM_MGMT_KEYS_LIST),
    ("POST",   "/api/v1/mgmt/keys",                 PERM_MGMT_KEYS_CREATE),
    ("PUT",    "/api/v1/mgmt/keys/",                PERM_MGMT_KEYS_UPDATE),
    ("DELETE", "/api/v1/mgmt/keys/",                PERM_MGMT_KEYS_DELETE),
    ("POST",   "/api/v1/mgmt/keys/rotate",          PERM_MGMT_KEYS_ROTATE),
    ("GET",    "/api/v1/mgmt/audit",                PERM_MGMT_AUDIT_VIEW),
    ("GET",    "/api/v1/mgmt/roles",                PERM_MGMT_ROLES_LIST),
    ("POST",   "/api/v1/mgmt/roles",                PERM_MGMT_ROLES_CREATE),
    ("PUT",    "/api/v1/mgmt/roles/",               PERM_MGMT_ROLES_UPDATE),
    ("DELETE", "/api/v1/mgmt/roles/",               PERM_MGMT_ROLES_DELETE),
    ("GET",    "/api/v1/mgmt/permissions",          PERM_MGMT_PERMS_LIST),
    ("POST",   "/api/v1/mgmt/permissions/assign",   PERM_MGMT_PERMS_ASSIGN),
    ("POST",   "/api/v1/mgmt/permissions/revoke",   PERM_MGMT_PERMS_REVOKE),

    # -- Auth (/api/v1/auth)
    ("GET",    "/api/v1/auth/me",                  PERM_AUTH_ME),
    # /api/v1/auth/check is public — no permission required

    # -- Dashboard (/api/v1/dashboard)
    ("GET",    "/api/v1/dashboard/full",             PERM_DASHBOARD_FULL),

    # -- System
    ("GET",    "/health/detailed",                  PERM_SYSTEM_HEALTH),
    ("GET",    "/api/v1/system/stats",              PERM_SYSTEM_STATS),
    ("GET",    "/metrics",                          PERM_SYSTEM_METRICS),
    ("GET",    "/api/v1/tasks",                     PERM_TASKS_LIST),

    # -- Misc
    ("GET",    "/api/v1/misc/time",                 PERM_MISC_TIME),
    ("GET",    "/api/v1/misc/processes",            PERM_MISC_PROCESSES),
    ("GET",    "/api/v1/misc/testparm",             PERM_MISC_TESTPARAM),
]


def resolve_permission(method: str, path: str) -> Optional[str]:
    """Determine the required permission for a given HTTP request.

    Parameters
    ----------
    method : str
        HTTP method (GET, POST, PUT, DELETE, PATCH).
    path : str
        Request path (e.g. ``/api/v1/users/john``).

    Returns
    -------
    str or None
        The permission string required, or ``None`` if no specific
        permission is defined (public endpoints, health checks, etc.).
    """
    method = method.upper()

    # Public paths that need no permission
    _PUBLIC = frozenset({
        "/health", "/docs", "/openapi.json", "/redoc",
        "/api/v1/auth/login", "/api/v1/auth/refresh", "/api/v1/auth/check",
    })
    if path in _PUBLIC:
        return None
    if path.startswith("/docs") or path.startswith("/ws/"):
        return None
    if method == "OPTIONS":
        return None

    # Try exact prefix matching — longest match wins
    best_match: Optional[str] = None
    best_len = 0
    for m, prefix, perm in _PATH_PERM_MAP:
        if m != method:
            continue
        if path.startswith(prefix) and len(prefix) > best_len:
            best_match = perm
            best_len = len(prefix)

    return best_match


def validate_permission_name(perm: str) -> bool:
    """Return True if *perm* is a known permission string."""
    return perm in ALL_PERMISSIONS


def get_permissions_by_category() -> Dict[str, List[str]]:
    """Return all permissions grouped by resource category."""
    cats: Dict[str, List[str]] = {}
    for p in sorted(ALL_PERMISSIONS):
        cat = p.split(".")[0]
        cats.setdefault(cat, []).append(p)
    return cats
