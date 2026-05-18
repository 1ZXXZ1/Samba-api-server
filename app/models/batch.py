"""
Pydantic models for the Batch execution API.

Provides request/response schemas for executing multiple samba-tool /
shell operations in a single HTTP request with template substitution,
sequential execution, and optional rollback.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# ── Request models ──────────────────────────────────────────────────────


class BatchAction(BaseModel):
    """A single action within a batch request.

    Each action maps to an existing API endpoint through a short
    *method* notation (e.g. ``user.create``, ``group.addmembers``,
    ``shell.exec``).  Parameters are passed as a dict whose keys
    correspond to the Pydantic request body fields of the target
    endpoint.

    Placeholders like ``{{ step1.username }}`` inside *params* values
    are resolved against the execution context before the action runs.
    """

    id: Optional[str] = Field(
        default=None,
        description=(
            "Optional step identifier.  When set, the output of this "
            "action is stored in the execution context under this key, "
            "making it available for template substitution in subsequent "
            "steps.  Must be unique within the batch."
        ),
    )
    method: str = Field(
        ...,
        description=(
            "Dot-notation method name, e.g. 'user.create', "
            "'group.addmembers', 'shell.exec'.  See the batch "
            "endpoint documentation for the full list."
        ),
    )
    params: Dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Parameters for the method.  Values can contain "
            "placeholders like {{ step_id.field }} which are "
            "resolved from the execution context before the "
            "action runs."
        ),
    )
    timeout: Optional[int] = Field(
        default=None,
        ge=1,
        le=600,
        description=(
            "Per-action timeout in seconds.  Overrides the batch-level "
            "default.  Only applies to shell.exec / shell.script."
        ),
    )


class BatchRequest(BaseModel):
    """Request body for ``POST /api/v1/batch``.

    Accepts a list of actions to execute sequentially, with optional
    template substitution between steps and rollback on failure.
    """

    actions: List[BatchAction] = Field(
        ...,
        min_length=1,
        max_length=100,
        description=(
            "Ordered list of actions to execute sequentially.  "
            "Maximum 100 actions per batch."
        ),
    )
    batch_id: Optional[str] = Field(
        default=None,
        description=(
            "Optional custom prefix for the batch.  Available in "
            "templates as ``{{ batch_id }}``.  If not provided, a "
            "short UUID is generated."
        ),
    )
    rollback_on_failure: bool = Field(
        default=False,
        description=(
            "If True, when a step fails, attempt to undo all "
            "previously successful steps in reverse order.  "
            "Rollback is best-effort — some operations (e.g. "
            "shell.exec) cannot be automatically rolled back."
        ),
    )
    stop_on_failure: bool = Field(
        default=True,
        description=(
            "If True (default), stop executing remaining steps "
            "after the first failure.  If False, continue "
            "executing remaining steps and mark the batch as "
            "'partial_failure'."
        ),
    )
    default_timeout: int = Field(
        default=30,
        ge=1,
        le=600,
        description=(
            "Default timeout in seconds for shell.exec / "
            "shell.script actions that don't specify their "
            "own timeout."
        ),
    )

    @field_validator("actions")
    @classmethod
    def _validate_unique_ids(cls, v: List[BatchAction]) -> List[BatchAction]:
        """Ensure action IDs are unique within the batch."""
        seen: set[str] = set()
        for action in v:
            if action.id is not None:
                if action.id in seen:
                    raise ValueError(
                        f"Duplicate action id '{action.id}'. "
                        f"Each action id must be unique within the batch."
                    )
                seen.add(action.id)
        # Also check that 'batch_id' is not used as a step id
        for action in v:
            if action.id == "batch_id":
                raise ValueError(
                    "Action id 'batch_id' is reserved and cannot be used."
                )
        return v


# ── Response models ─────────────────────────────────────────────────────


class BatchStepResult(BaseModel):
    """Result of a single action within a batch."""

    id: Optional[str] = Field(
        default=None,
        description="The action's id (if it was set in the request).",
    )
    method: str = Field(
        description="The method that was executed.",
    )
    status: str = Field(
        description="One of 'success' or 'error'.",
    )
    output: Optional[Any] = Field(
        default=None,
        description="The result of the action on success.",
    )
    error: Optional[str] = Field(
        default=None,
        description="Error message on failure.",
    )
    step: int = Field(
        description="0-based index of this step in the batch.",
    )
    rollback_status: Optional[str] = Field(
        default=None,
        description=(
            "If rollback was attempted, one of 'rolled_back', "
            "'rollback_failed', 'no_rollback_needed'."
        ),
    )
    rollback_error: Optional[str] = Field(
        default=None,
        description="Error message if rollback failed for this step.",
    )


class BatchResponse(BaseModel):
    """Full API response for a batch execution."""

    batch_id: str = Field(
        description="The batch identifier (custom prefix or generated UUID).",
    )
    status: str = Field(
        description=(
            "One of 'completed' (all steps succeeded), "
            "'partial_failure' (some steps failed but "
            "execution continued), or 'failed' (a step "
            "failed and stop_on_failure is True)."
        ),
    )
    steps: List[BatchStepResult] = Field(
        default_factory=list,
        description="Results for each action in order.",
    )
    total_steps: int = Field(
        description="Total number of actions in the request.",
    )
    successful_steps: int = Field(
        description="Number of actions that succeeded.",
    )
    failed_steps: int = Field(
        description="Number of actions that failed.",
    )
    rollback_performed: bool = Field(
        default=False,
        description="Whether rollback was attempted.",
    )
