"""
API routers for the Samba AD DC Management API.

Each router encapsulates a distinct samba-tool domain and exposes
RESTful endpoints that translate to the corresponding CLI commands.
The shell router provides direct shell command execution capabilities.
v2.7: Added management, user_mgmt, and ou_mgmt routers.
"""

from app.routers.schema import router as schema_router
from app.routers.delegation import router as delegation_router
from app.routers.service_account import router as service_account_router
from app.routers.auth_policy import router as auth_policy_router
from app.routers.misc import router as misc_router
from app.routers.shell import router as shell_router
from app.routers.user_mgmt import router as user_mgmt_router
from app.routers.ou_mgmt import router as ou_mgmt_router
from app.routers import mgmt

__all__ = [
    "schema_router",
    "delegation_router",
    "service_account_router",
    "auth_policy_router",
    "misc_router",
    "shell_router",
    "user_mgmt_router",
    "ou_mgmt_router",
    "mgmt",
]
