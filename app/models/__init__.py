"""
Models package — extended with shell execution models.
"""

from app.models.common import (
    APIResponse,
    ErrorResponse,
    PaginatedResponse,
    SuccessResponse,
    TaskResponse,
    TaskStatusResponse,
)
from app.models.group import (
    GroupCreateRequest,
    GroupMembersRequest,
    GroupMoveRequest,
)
from app.models.user import (
    UserAddUnixAttrsRequest,
    UserCreateRequest,
    UserPasswordRequest,
    UserSensitiveRequest,
    UserSetExpiryRequest,
    UserUpdateRequest,
)
from app.models.shell import (
    ShellExecRequest,
    ShellExecResponse,
    ShellExecResult,
    ShellListResponse,
    ShellScriptRequest,
)
from app.models.user_mgmt import (
    OUTreeNode,
    OUStats,
    UserEditRequest,
    UserImportResult,
    UserImportRowResult,
    UserSearchResult,
)

__all__ = [
    # Common
    "APIResponse",
    "ErrorResponse",
    "PaginatedResponse",
    "SuccessResponse",
    "TaskResponse",
    "TaskStatusResponse",
    # Group
    "GroupCreateRequest",
    "GroupMembersRequest",
    "GroupMoveRequest",
    # User
    "UserAddUnixAttrsRequest",
    "UserCreateRequest",
    "UserPasswordRequest",
    "UserSensitiveRequest",
    "UserSetExpiryRequest",
    "UserUpdateRequest",
    # Shell
    "ShellExecRequest",
    "ShellExecResponse",
    "ShellExecResult",
    "ShellListResponse",
    "ShellScriptRequest",
    # User management (extended)
    "OUTreeNode",
    "OUStats",
    "UserEditRequest",
    "UserImportResult",
    "UserImportRowResult",
    "UserSearchResult",
]
