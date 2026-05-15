"""
Shared Pydantic models for standardised API responses.

Every endpoint returns one of these models so that consumers can rely
on a consistent JSON envelope.
"""

from __future__ import annotations

from typing import Any, Generic, List, Optional, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


# ── Base envelope ──────────────────────────────────────────────────────

class APIResponse(BaseModel):
    """Base response envelope.

    All specific response models inherit from this so that every payload
    contains at least ``status`` and ``message`` keys.
    """

    status: str = Field(
        ...,
        description="One of 'ok' or 'error'.",
    )
    message: str = Field(
        default="",
        description="Human-readable summary of the result.",
    )


# ── Success ────────────────────────────────────────────────────────────

class SuccessResponse(APIResponse):
    """Returned when an operation succeeds."""

    status: str = "ok"


# ── Error ──────────────────────────────────────────────────────────────

class ErrorResponse(APIResponse):
    """Returned when an operation fails."""

    status: str = "error"
    details: Optional[Any] = Field(
        default=None,
        description="Optional structured error details.",
    )


# ── Paginated ──────────────────────────────────────────────────────────

class PaginatedResponse(APIResponse, Generic[T]):
    """A page of items from a larger collection."""

    status: str = "ok"
    items: List[T] = Field(
        default_factory=list,
        description="The items on this page.",
    )
    total: int = Field(
        ...,
        description="Total number of items across all pages.",
    )
    offset: int = Field(
        default=0,
        description="Zero-based index of the first item in this page.",
    )
    limit: int = Field(
        default=100,
        description="Maximum number of items requested per page.",
    )


# ── Task / async ───────────────────────────────────────────────────────

class TaskResponse(APIResponse):
    """Returned immediately when a long-running task is submitted."""

    status: str = "ok"
    task_id: str = Field(
        ...,
        description="Unique identifier for the background task.",
    )
    result_url: str = Field(
        ...,
        description="URL to poll for task status and results.",
    )


class TaskStatusResponse(APIResponse):
    """Current state of a background task."""

    task_id: str = Field(
        ...,
        description="Unique identifier for the task.",
    )
    status: str = Field(
        ...,
        description="One of PENDING, RUNNING, COMPLETED, FAILED.",
    )
    output: Optional[str] = Field(
        default=None,
        description="stdout from samba-tool (available when COMPLETED).",
    )
    error: Optional[str] = Field(
        default=None,
        description="Error message (available when FAILED).",
    )
    created_at: Optional[str] = Field(
        default=None,
        description="ISO-8601 timestamp when the task was created.",
    )
    completed_at: Optional[str] = Field(
        default=None,
        description="ISO-8601 timestamp when the task finished.",
    )
