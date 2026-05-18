"""
AI Data Tools for Import/Export/Transform/Diagram (v1.9.6).

Adds the following tools to the AI agent:
    - data_import   — Auto-import data from API endpoints, files, or raw JSON.
                      Auto-detects fields/columns and returns structured data.
    - data_export   — Export data to multiple formats (XLSX multi-sheet,
                      CSV, JSON, TSV). Auto-creates spreadsheet with all data
                      and returns download link. Supports embedded charts on
                      2nd sheet via openpyxl.
    - data_transform — Transform data: filter, sort, aggregate, pivot,
                       deduplicate, merge, add computed columns, enrich with groups,
                       batch (Task Constructor).
    - data_diagram   — Create diagrams/charts from data: bar, line, pie,
                       scatter, histogram, table-summary.

These tools enable the AI agent to work with data for import/export,
audit reports, data analysis, and visualization — all from natural language.

Key features:
    - Auto-detect fields from API JSON responses
    - Multi-sheet XLSX creation (not just 1 sheet)
    - Nested JSON flattening into tabular format
    - Export to CSV, JSON, XLSX, TSV with one command
    - Create professional charts/diagrams (PNG) from data
    - Embedded charts in XLSX on 2nd sheet (openpyxl charts)
    - One-step AD users import with groups (from_ad_users)
    - Full AD category support: groups, computers, contacts, OUs, DNS, GPOs, domain
    - One-step imports: dashboard, shell projects, audit
    - Enrich data with groups mapping (enrich_with_groups / enrich)
    - Batch transform (Task Constructor) for multi-step operations in one call
    - All files saved in AI_AGENT_EXPORT_DIR with download links

Changelog v1.9.6 (from v1.9.5):
    - Add full AD category support: from_ad_groups, from_ad_computers, from_ad_contacts,
      from_ad_ous, from_ad_dns, from_ad_gpos, from_ad_domain
    - Add from_dashboard, from_shell_projects, from_audit import actions
    - Add object_type, exclude, include_groups parameters to data_import
    - Add ldbsearch fallback for AD object types when API is unavailable
    - Add _parse_ldb_ldif_to_rows utility for LDIF parsing
    - Add batch action to data_transform (Task Constructor)
    - Add batch_steps parameter for multi-step transforms
    - Update from_ad_users to accept exclude and include_groups parameters

Changelog v1.9.0 (from v1.8.9):
    - Fix _transform_select_columns: handle list input for columns
    - Add enrich_with_groups / enrich action to data_transform
    - Add chart_type, chart_x, chart_y, chart_title params to data_export
    - Add from_ad_users action to data_import (one-step users+groups)
    - Handle columns as list in data_export too
    - Add from_raw alias for from_json in data_import dispatch
    - Add file_path as alias for source in data_import
    - Add select and rename aliases to data_transform enum
    - Add groups_data and groups_snapshot params to data_transform
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
import re
import tempfile
from collections import Counter, OrderedDict
from typing import Any, Dict, List, Optional, Tuple, Union

from app.config import get_settings

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════
#  Data Tool Definitions (OpenAI-compatible function calling format)
# ═══════════════════════════════════════════════════════════════════════

DATA_AGENT_TOOLS = [
    # ── Data Import ──────────────────────────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "data_import",
            "description": (
                "Import data from API endpoint, file, or raw JSON. "
                "Auto-detects fields/columns from the data structure. "
                "Supports flattening nested JSON into tabular format. "
                "Actions: "
                "'from_api' — import data from a Samba AD API endpoint (auto-uses server API key), "
                "'from_file' — import data from a file on the server (CSV, JSON, TSV), "
                "'from_json' (or 'from_raw') — import data from a raw JSON string, "
                "'from_ad_users' — ONE-STEP import: fetch users from API + groups from ldbsearch, merged, "
                "'from_ad_groups' — ONE-STEP import: groups from API + member counts from ldbsearch, "
                "'from_ad_computers' — ONE-STEP import: computers from API (fallback ldbsearch), "
                "'from_ad_contacts' — ONE-STEP import: contacts from API (fallback ldbsearch), "
                "'from_ad_ous' — ONE-STEP import: OUs from API (fallback ldbsearch), "
                "'from_ad_dns' — ONE-STEP import: DNS zones and records from API, "
                "'from_ad_gpos' — ONE-STEP import: GPOs from API (fallback ldbsearch), "
                "'from_ad_domain' — ONE-STEP import: domain information from API, "
                "'from_dashboard' — ONE-STEP import: dashboard overview from API, "
                "'from_shell_projects' — ONE-STEP import: shell projects from API, "
                "'from_audit' — ONE-STEP import: audit log from API, "
                "'detect_fields' — analyze a JSON structure and return detected fields/columns, "
                "'list_saved' — list previously saved data snapshots."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["from_api", "from_file", "from_json", "from_raw", "from_ad_users", "from_ad_groups", "from_ad_computers", "from_ad_contacts", "from_ad_ous", "from_ad_dns", "from_ad_gpos", "from_ad_domain", "from_dashboard", "from_shell_projects", "from_audit", "detect_fields", "list_saved"],
                        "description": "Import action to perform. 'from_raw' = alias for from_json. 'from_ad_*' = one-step AD category imports. 'from_dashboard'/'from_shell_projects'/'from_audit' = other API imports.",
                    },
                    "source": {
                        "type": "string",
                        "description": (
                            "Source for the data: API path (e.g. '/api/v1/users/'), "
                            "file path (e.g. '/tmp/data.json'), or JSON string. "
                            "Aliases: 'file_path' or 'api_path' can be used instead of 'source'."
                        ),
                    },
                    "file_path": {
                        "type": "string",
                        "description": "Alias for 'source' parameter. Used interchangeably with source.",
                    },
                    "api_path": {
                        "type": "string",
                        "description": "Alias for 'source' parameter when using from_api action. E.g. '/api/v1/users/'.",
                    },
                    "api_method": {
                        "type": "string",
                        "description": "HTTP method for from_api action (default: GET).",
                        "default": "GET",
                    },
                    "api_params": {
                        "type": "object",
                        "description": "Query parameters for API request.",
                        "additionalProperties": {"type": "string"},
                    },
                    "flatten": {
                        "type": "boolean",
                        "description": "Flatten nested JSON objects into dot-notation columns (default: true).",
                        "default": True,
                    },
                    "max_depth": {
                        "type": "integer",
                        "description": "Max nesting depth for flattening (default: 3).",
                        "default": 3,
                    },
                    "snapshot_name": {
                        "type": "string",
                        "description": "Name to save the imported data as a snapshot for later use.",
                    },
                    "object_type": {
                        "type": "string",
                        "enum": ["user", "group", "computer", "contact", "ou", "gpo", "dns_zone", "site", "service_account", "trust"],
                        "description": "AD object type for from_ad_* actions. Used to customize attributes fetched.",
                    },
                    "exclude": {
                        "type": "string",
                        "description": "Comma-separated sAMAccountNames to exclude (e.g. 'Administrator,Guest,krbtgt').",
                    },
                    "include_groups": {
                        "type": "boolean",
                        "description": "When true, automatically add 'groups' column to user/group data (default: false).",
                        "default": False,
                    },
                },
                "required": ["action"],
            },
        },
    },

    # ── Data Export ──────────────────────────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "data_export",
            "description": (
                "Export data to files in multiple formats. Creates multi-sheet "
                "XLSX workbooks, CSV, JSON, TSV files. Returns download path. "
                "Optionally embeds a chart on a 2nd sheet in XLSX (no need for separate data_diagram call). "
                "Actions: "
                "'to_xlsx' — export to multi-sheet Excel (.xlsx) with formatting and optional chart, "
                "'to_csv' — export to CSV file, "
                "'to_json' — export to JSON file, "
                "'to_tsv' — export to TSV file, "
                "'to_multi_format' — export the same data to multiple formats at once, "
                "'list_exports' — list all exported files in the export directory."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["to_xlsx", "to_csv", "to_json", "to_tsv", "to_multi_format", "list_exports"],
                        "description": "Export action to perform.",
                    },
                    "data": {
                        "type": "string",
                        "description": (
                            "Data to export as JSON string. Must be an array of objects "
                            "for tabular formats, or an object with sheet_name -> data arrays "
                            "for multi-sheet XLSX. Example: '[{\"name\":\"Ivan\",\"age\":30}]' "
                            "or '{\"Users\":[...],\"Groups\":[...]}'"
                        ),
                    },
                    "filename": {
                        "type": "string",
                        "description": "Output filename (e.g. 'users_report.xlsx'). If omitted, auto-generated.",
                    },
                    "sheet_name": {
                        "type": "string",
                        "description": "Sheet name for single-sheet XLSX (default: 'Data').",
                        "default": "Data",
                    },
                    "sheets": {
                        "type": "object",
                        "description": (
                            "Multi-sheet data: keys are sheet names, values are JSON strings "
                            "of data arrays. Example: {\"Users\": \"[{...}]\", \"Groups\": \"[{...}]\"}"
                        ),
                        "additionalProperties": {"type": "string"},
                    },
                    "formats": {
                        "type": "string",
                        "description": "Comma-separated formats for to_multi_format action (e.g. 'xlsx,csv,json').",
                        "default": "xlsx,csv,json",
                    },
                    "snapshot_name": {
                        "type": "string",
                        "description": "Name of a previously saved data snapshot to export.",
                    },
                    "include_headers": {
                        "type": "boolean",
                        "description": "Include column headers in export (default: true).",
                        "default": True,
                    },
                    "auto_width": {
                        "type": "boolean",
                        "description": "Auto-adjust column widths for XLSX (default: true).",
                        "default": True,
                    },
                    "styled": {
                        "type": "boolean",
                        "description": "Apply professional styling (header bold, borders) to XLSX (default: true).",
                        "default": True,
                    },
                    "columns": {
                        "type": "string",
                        "description": (
                            "Comma-separated column names to include in export. "
                            "If omitted, all columns are exported. "
                            "Example: 'sAMAccountName,cn,department,groups' "
                            "Use this to select only needed columns WITHOUT a separate data_transform step."
                        ),
                    },
                    "chart_type": {
                        "type": "string",
                        "enum": ["bar", "line", "pie", "scatter", "histogram"],
                        "description": (
                            "Type of chart to embed on 2nd sheet of XLSX. If specified, a chart "
                            "sheet named 'Chart' is added. Eliminates the need for a separate data_diagram call."
                        ),
                    },
                    "chart_x": {
                        "type": "string",
                        "description": "Column name for chart X axis / categories. If chart_y is omitted, auto-aggregates by count.",
                    },
                    "chart_y": {
                        "type": "string",
                        "description": "Column name for chart Y axis / values.",
                    },
                    "chart_title": {
                        "type": "string",
                        "description": "Title for the embedded chart.",
                    },
                },
                "required": ["action"],
            },
        },
    },

    # ── Data Transform ──────────────────────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "data_transform",
            "description": (
                "Transform and analyze data: filter rows, sort, aggregate, "
                "deduplicate, merge datasets, add computed columns, pivot, enrich with groups. "
                "Actions: "
                "'filter' — filter rows by condition, "
                "'sort' — sort data by one or more columns, "
                "'aggregate' — group by and aggregate (count, sum, avg, min, max), "
                "'deduplicate' — remove duplicate rows, "
                "'select_columns' (or 'select') — select/reorder specific columns, "
                "'rename_columns' (or 'rename') — rename columns, "
                "'add_column' (or 'derive') — add a computed column from an expression, "
                "'enrich_with_groups' (or 'enrich') — add groups column to user data using groups_bulk mapping, "
                "'merge' — merge two datasets by key column, "
                "'pivot' — pivot table from data, "
                "'stats' — compute statistics (count, mean, median, std, min, max) for numeric columns, "
                "'batch' — execute multiple transform operations in sequence (Task Constructor)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": [
                            "filter", "sort", "aggregate", "group_by", "deduplicate",
                            "select_columns", "select", "rename_columns", "rename",
                            "add_column", "derive",
                            "enrich_with_groups", "enrich",
                            "merge", "pivot", "stats", "batch",
                        ],
                        "description": (
                            "Transform action. "
                            "'select' = alias for select_columns. "
                            "'rename' = alias for rename_columns. "
                            "'derive' = alias for add_column. "
                            "'enrich' = alias for enrich_with_groups. "
                            "'group_by' = alias for aggregate. "
                            "Use 'enrich_with_groups' to add groups column in one step. "
                            "Use 'batch' to execute multiple transforms in one call (Task Constructor)."
                        ),
                    },
                    "data": {
                        "type": "string",
                        "description": "Input data as JSON array string.",
                    },
                    "snapshot_name": {
                        "type": "string",
                        "description": "Name of a saved data snapshot to use as input.",
                    },
                    "column": {
                        "type": "string",
                        "description": "Column name for single-column operations.",
                    },
                    "columns": {
                        "type": "string",
                        "description": "Comma-separated column names for multi-column operations.",
                    },
                    "condition": {
                        "type": "string",
                        "description": (
                            "Filter condition, e.g. 'age > 25', 'status = active', "
                            "'name CONTAINS ivan'. Supports: =, !=, >, <, >=, <=, "
                            "CONTAINS, STARTS_WITH, ENDS_WITH, IN, NOT_EMPTY."
                        ),
                    },
                    "sort_by": {
                        "type": "string",
                        "description": "Comma-separated columns to sort by. Prefix with '-' for descending (e.g. '-age,name').",
                    },
                    "group_by": {
                        "type": "string",
                        "description": "Comma-separated columns to group by for aggregate/pivot.",
                    },
                    "agg_function": {
                        "type": "string",
                        "enum": ["count", "sum", "avg", "min", "max", "count_distinct"],
                        "description": "Aggregation function for aggregate action.",
                    },
                    "agg_column": {
                        "type": "string",
                        "description": "Column to aggregate (not needed for count).",
                    },
                    "new_column_name": {
                        "type": "string",
                        "description": "Name for new/renamed column.",
                    },
                    "expression": {
                        "type": "string",
                        "description": (
                            "Expression for add_column. Use {col} for column references. "
                            "Examples: '{price} * {quantity}', '{first_name} + \" \" + {last_name}', "
                            "'{status} == \"active\" ? \"Yes\" : \"No\"'"
                        ),
                    },
                    "rename_map": {
                        "type": "object",
                        "description": "Map of old column names to new names for rename_columns.",
                        "additionalProperties": {"type": "string"},
                    },
                    "merge_data": {
                        "type": "string",
                        "description": "Second dataset (JSON array string) for merge action.",
                    },
                    "merge_key": {
                        "type": "string",
                        "description": "Key column for merge (like SQL JOIN ON).",
                    },
                    "merge_how": {
                        "type": "string",
                        "enum": ["inner", "left", "right", "outer"],
                        "description": "Merge type (default: left).",
                        "default": "left",
                    },
                    "pivot_rows": {
                        "type": "string",
                        "description": "Column for pivot rows.",
                    },
                    "pivot_cols": {
                        "type": "string",
                        "description": "Column for pivot columns.",
                    },
                    "pivot_values": {
                        "type": "string",
                        "description": "Column for pivot values.",
                    },
                    "pivot_agg": {
                        "type": "string",
                        "enum": ["count", "sum", "avg"],
                        "description": "Aggregation for pivot values (default: count).",
                        "default": "count",
                    },
                    "groups_data": {
                        "type": "string",
                        "description": (
                            "Groups mapping data for enrich_with_groups action. "
                            "Can be a JSON dict string mapping username -> [group1, group2, ...]. "
                            "Also accepts 'mapping' or 'column_name' as aliases."
                        ),
                    },
                    "groups_snapshot": {
                        "type": "string",
                        "description": "Name of a saved snapshot containing groups mapping (dict of username -> [groups]).",
                    },
                    "save_as": {
                        "type": "string",
                        "description": "Save the result as a data snapshot with this name.",
                    },
                    "batch_steps": {
                        "type": "array",
                        "description": (
                            "Array of transform operations for batch action (Task Constructor). "
                            "Each item is a dict with 'action' and the relevant parameters. "
                            "Example: [{'action': 'filter', 'condition': 'age > 25'}, "
                            "{'action': 'sort', 'sort_by': '-age'}, {'action': 'select', 'columns': 'name,age'}]"
                        ),
                        "items": {
                            "type": "object",
                            "additionalProperties": True,
                        },
                    },
                },
                "required": ["action"],
            },
        },
    },

    # ── Data Diagram ────────────────────────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "data_diagram",
            "description": (
                "Create diagrams and charts from data. Generates PNG image files. "
                "Actions: "
                "'bar' — bar chart (vertical or horizontal), "
                "'line' — line chart with optional multiple series, "
                "'pie' — pie chart, "
                "'scatter' — scatter plot, "
                "'histogram' — histogram/distribution, "
                "'table' — create a formatted table image from data, "
                "'multi_chart' — create multiple charts in one image (subplots)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["bar", "line", "pie", "scatter", "histogram", "table", "multi_chart"],
                        "description": "Diagram type to create.",
                    },
                    "data": {
                        "type": "string",
                        "description": "Data as JSON array string for the diagram.",
                    },
                    "snapshot_name": {
                        "type": "string",
                        "description": "Name of a saved data snapshot to use as input.",
                    },
                    "x_column": {
                        "type": "string",
                        "description": "Column name for X axis (labels for bar/pie, x values for scatter/line).",
                    },
                    "y_column": {
                        "type": "string",
                        "description": "Column name for Y axis (values). For multi-series, comma-separated.",
                    },
                    "title": {
                        "type": "string",
                        "description": "Chart title.",
                    },
                    "xlabel": {
                        "type": "string",
                        "description": "X axis label.",
                    },
                    "ylabel": {
                        "type": "string",
                        "description": "Y axis label.",
                    },
                    "horizontal": {
                        "type": "boolean",
                        "description": "Horizontal bar chart instead of vertical (default: false).",
                        "default": False,
                    },
                    "stacked": {
                        "type": "boolean",
                        "description": "Stacked bar/line chart (default: false).",
                        "default": False,
                    },
                    "show_values": {
                        "type": "boolean",
                        "description": "Show values on bars/points (default: true for bar charts).",
                        "default": True,
                    },
                    "bins": {
                        "type": "integer",
                        "description": "Number of bins for histogram (default: 20).",
                        "default": 20,
                    },
                    "figsize": {
                        "type": "string",
                        "description": "Figure size as 'width,height' in inches (default: '12,7').",
                        "default": "12,7",
                    },
                    "filename": {
                        "type": "string",
                        "description": "Output filename (auto-generated if omitted).",
                    },
                    "colors": {
                        "type": "string",
                        "description": "Comma-separated color names or hex codes.",
                    },
                    "charts": {
                        "type": "array",
                        "description": (
                            "Array of chart specs for multi_chart action. Each item: "
                            "{\"type\": \"bar|line|pie|scatter|histogram\", "
                            "\"x_column\": \"...\", \"y_column\": \"...\", "
                            "\"title\": \"...\"}"
                        ),
                        "items": {
                            "type": "object",
                            "additionalProperties": True,
                        },
                    },
                    "columns": {
                        "type": "string",
                        "description": "Comma-separated columns to include in table diagram.",
                    },
                    "max_rows": {
                        "type": "integer",
                        "description": "Maximum rows to display in table diagram (default: 30).",
                        "default": 30,
                    },
                },
                "required": ["action"],
            },
        },
    },
]


# ═══════════════════════════════════════════════════════════════════════
#  In-memory Data Snapshots Store
# ═══════════════════════════════════════════════════════════════════════

_data_snapshots: Dict[str, List[Dict[str, Any]]] = {}


def _get_snapshot(name: str) -> Optional[List[Dict[str, Any]]]:
    """Retrieve a saved data snapshot by name."""
    return _data_snapshots.get(name)


def _save_snapshot(name: str, data: List[Dict[str, Any]]) -> None:
    """Save data as a named snapshot for later use."""
    _data_snapshots[name] = data
    logger.info("[AI-DATA] Saved snapshot '%s' with %d rows", name, len(data))


def _list_snapshots() -> List[Dict[str, Any]]:
    """List all saved snapshots."""
    result = []
    for name, data in _data_snapshots.items():
        cols = list(data[0].keys()) if data else []
        result.append({
            "name": name,
            "rows": len(data),
            "columns": cols[:20],
            "total_columns": len(cols),
        })
    return result


# ═══════════════════════════════════════════════════════════════════════
#  JSON Flattening Utilities
# ═══════════════════════════════════════════════════════════════════════


def _flatten_dict(
    d: Dict[str, Any],
    parent_key: str = "",
    sep: str = ".",
    max_depth: int = 3,
    current_depth: int = 0,
) -> Dict[str, Any]:
    """Flatten a nested dict using dot notation.

    Example:
        {"user": {"name": "Ivan", "dept": {"id": 1}}}
        -> {"user.name": "Ivan", "user.dept.id": 1}
    """
    items: List[Tuple[str, Any]] = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict) and current_depth < max_depth:
            items.extend(
                _flatten_dict(v, new_key, sep=sep, max_depth=max_depth, current_depth=current_depth + 1).items()
            )
        elif isinstance(v, list) and current_depth < max_depth and v and isinstance(v[0], dict):
            # Convert list of dicts to JSON string for tabular representation
            items.append((new_key, json.dumps(v, ensure_ascii=False)))
        else:
            items.append((new_key, v))
    return dict(items)


def _normalize_data_to_rows(
    data: Any,
    flatten: bool = True,
    max_depth: int = 3,
) -> List[Dict[str, Any]]:
    """Normalize various JSON structures into a flat list of row dicts.

    Handles:
    - List of dicts (standard)
    - Dict with a nested 'data', 'items', 'results', 'records' key
    - Single dict -> wrapped in list
    - Dict of lists -> each list becomes rows with the key as an extra column
    """
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict):
        # Try common wrapper keys
        for key in ("data", "items", "results", "records", "rows", "users", "groups", "computers"):
            if key in data and isinstance(data[key], list):
                rows = data[key]
                break
        else:
            # Dict of lists -> multi-sheet indicator
            if all(isinstance(v, list) for v in data.values() if v is not None):
                rows = []
                for sheet_name, sheet_data in data.items():
                    if isinstance(sheet_data, list):
                        for item in sheet_data:
                            if isinstance(item, dict):
                                item_copy = dict(item)
                                item_copy["_source_sheet"] = sheet_name
                                rows.append(item_copy)
                if not rows:
                    rows = [data]
            else:
                rows = [data]
    else:
        rows = [{"value": data}]

    if flatten:
        rows = [_flatten_dict(row, max_depth=max_depth) if isinstance(row, dict) else {"value": row} for row in rows]

    return rows


def _detect_fields(data: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze data and detect field names, types, and sample values."""
    if not data:
        return {"fields": [], "total_rows": 0}

    all_keys: Dict[str, Dict[str, Any]] = {}
    for row in data:
        for key, value in row.items():
            if key not in all_keys:
                all_keys[key] = {
                    "name": key,
                    "types": set(),
                    "non_null_count": 0,
                    "sample_values": [],
                }
            field_info = all_keys[key]
            if value is not None and value != "":
                field_info["non_null_count"] += 1
                vtype = type(value).__name__
                field_info["types"].add(vtype)
                if len(field_info["sample_values"]) < 3:
                    sv = str(value)
                    if len(sv) > 50:
                        sv = sv[:50] + "..."
                    field_info["sample_values"].append(sv)

    fields = []
    for key, info in all_keys.items():
        fields.append({
            "name": info["name"],
            "types": sorted(info["types"]),
            "non_null": info["non_null_count"],
            "fill_rate": round(info["non_null_count"] / len(data) * 100, 1),
            "sample_values": info["sample_values"],
        })

    return {
        "fields": fields,
        "total_rows": len(data),
        "total_columns": len(fields),
    }


# ═══════════════════════════════════════════════════════════════════════
#  Data Import Implementation
# ═══════════════════════════════════════════════════════════════════════


async def _data_import_impl(args: Dict[str, Any]) -> str:
    """Implement data_import tool."""
    action = args.get("action", "from_api")
    # v2.3: Also accept 'api_path' as alias — AI often sends api_path instead of source
    source = args.get("source", "") or args.get("file_path", "") or args.get("api_path", "")
    api_method = args.get("api_method", "GET")
    api_params = args.get("api_params")
    flatten = args.get("flatten", True)
    max_depth = args.get("max_depth", 3)
    snapshot_name = args.get("snapshot_name", "")

    try:
        if action == "from_api":
            return await _import_from_api(source, api_method, api_params, flatten, max_depth, snapshot_name)

        elif action == "from_file":
            return _import_from_file(source, flatten, max_depth, snapshot_name)

        elif action in ("from_json", "from_raw"):  # v1.9.0: from_raw alias
            return _import_from_json(source, flatten, max_depth, snapshot_name)

        elif action == "from_ad_users":  # v1.9.0: one-step AD users + groups import
            return await _import_from_ad_users(snapshot_name, args.get("exclude", ""), args.get("include_groups", False))

        elif action == "from_ad_groups":
            return await _import_from_ad_groups(snapshot_name, args.get("exclude", ""))
        elif action == "from_ad_computers":
            return await _import_from_ad_object_type("computer", snapshot_name, args.get("exclude", ""))
        elif action == "from_ad_contacts":
            return await _import_from_ad_object_type("contact", snapshot_name, args.get("exclude", ""))
        elif action == "from_ad_ous":
            return await _import_from_ad_object_type("ou", snapshot_name, args.get("exclude", ""))
        elif action == "from_ad_dns":
            return await _import_from_ad_dns(snapshot_name)
        elif action == "from_ad_gpos":
            return await _import_from_ad_object_type("gpo", snapshot_name, args.get("exclude", ""))
        elif action == "from_ad_domain":
            return await _import_from_ad_domain(snapshot_name)
        elif action == "from_dashboard":
            return await _import_from_dashboard(snapshot_name)
        elif action == "from_shell_projects":
            return await _import_from_shell_projects(snapshot_name)
        elif action == "from_audit":
            return await _import_from_audit(snapshot_name)

        elif action == "detect_fields":
            return _import_detect_fields(source)

        elif action == "list_saved":
            snapshots = _list_snapshots()
            return json.dumps({"snapshots": snapshots, "total": len(snapshots)}, ensure_ascii=False)

        else:
            return json.dumps({"error": f"Unknown action: {action}"})

    except Exception as exc:
        logger.error("[AI-DATA-IMPORT] Failed: %s", exc)
        return json.dumps({"error": f"Data import failed: {exc}"})


async def _import_from_api(
    api_path: str,
    method: str,
    api_params: Optional[Dict[str, str]],
    flatten: bool,
    max_depth: int,
    snapshot_name: str,
) -> str:
    """Import data from a Samba AD API endpoint."""
    import httpx

    settings = get_settings()

    if not api_path:
        return json.dumps({"error": "API path is required for from_api action. Example: '/api/v1/users/'"})

    # Normalize path
    if not api_path.startswith("/"):
        api_path = "/" + api_path

    url = f"{settings.AI_API_BASE.rstrip('/')}{api_path}"
    headers = {
        "X-API-Key": settings.API_KEY,
        "Accept": "application/json",
    }

    api_timeout = float(getattr(settings, "AI_AGENT_API_TIMEOUT", 60))

    logger.info("[AI-DATA-IMPORT] API call: %s %s", method, url)

    try:
        async with httpx.AsyncClient(timeout=api_timeout) as client:
            resp = await client.request(
                method=method.upper(),
                url=url,
                headers=headers,
                params=api_params,
            )

        try:
            raw_data = resp.json()
        except Exception:
            return json.dumps({"error": f"API returned non-JSON response (status={resp.status_code})"})

        if resp.status_code >= 400:
            return json.dumps({
                "error": f"API returned HTTP {resp.status_code}",
                "detail": raw_data if isinstance(raw_data, dict) else str(raw_data)[:500],
            })

        # Normalize to rows
        rows = _normalize_data_to_rows(raw_data, flatten=flatten, max_depth=max_depth)

        # Save snapshot if requested
        if snapshot_name:
            _save_snapshot(snapshot_name, rows)

        # Detect fields
        fields_info = _detect_fields(rows)

        result = {
            "success": True,
            "source": f"API {method} {api_path}",
            "rows": len(rows),
            "fields": fields_info["fields"][:30],
            "total_fields": fields_info["total_columns"],
            "preview": rows[:5],
            "snapshot_saved": bool(snapshot_name),
        }

        return json.dumps(result, ensure_ascii=False, default=str)

    except Exception as exc:
        logger.error("[AI-DATA-IMPORT] API call failed: %s", exc)
        return json.dumps({"error": f"API call failed: {exc}"})


def _import_from_file(
    filepath: str,
    flatten: bool,
    max_depth: int,
    snapshot_name: str,
) -> str:
    """Import data from a file on the server."""
    if not filepath:
        return json.dumps({"error": "File path is required for from_file action"})

    # Safety checks
    if ".." in filepath:
        return json.dumps({"error": "Path traversal not allowed"})

    if not os.path.exists(filepath):
        return json.dumps({"error": f"File not found: {filepath}"})

    ext = os.path.splitext(filepath)[1].lower()

    try:
        if ext == ".json":
            with open(filepath, "r", encoding="utf-8") as f:
                raw_data = json.load(f)
        elif ext == ".csv":
            with open(filepath, "r", encoding="utf-8-sig", newline="") as f:
                reader = csv.DictReader(f)
                raw_data = [row for row in reader]
        elif ext == ".tsv":
            with open(filepath, "r", encoding="utf-8-sig", newline="") as f:
                reader = csv.DictReader(f, delimiter="\t")
                raw_data = [row for row in reader]
        elif ext in (".xlsx", ".xls"):
            try:
                import pandas as pd
                df = pd.read_excel(filepath)
                raw_data = df.to_dict(orient="records")
            except ImportError:
                return json.dumps({"error": "XLSX import requires pandas. Install: pip install pandas openpyxl"})
        else:
            return json.dumps({"error": f"Unsupported file format: {ext}. Supported: .json, .csv, .tsv, .xlsx"})

        rows = _normalize_data_to_rows(raw_data, flatten=flatten, max_depth=max_depth)

        if snapshot_name:
            _save_snapshot(snapshot_name, rows)

        fields_info = _detect_fields(rows)

        result = {
            "success": True,
            "source": f"file://{filepath}",
            "rows": len(rows),
            "fields": fields_info["fields"][:30],
            "total_fields": fields_info["total_columns"],
            "preview": rows[:5],
            "snapshot_saved": bool(snapshot_name),
        }

        return json.dumps(result, ensure_ascii=False, default=str)

    except Exception as exc:
        return json.dumps({"error": f"Failed to import file: {exc}"})


def _import_from_json(
    json_string: str,
    flatten: bool,
    max_depth: int,
    snapshot_name: str,
) -> str:
    """Import data from a raw JSON string."""
    if not json_string:
        return json.dumps({"error": "JSON string is required for from_json action"})

    try:
        raw_data = json.loads(json_string)
    except json.JSONDecodeError as exc:
        return json.dumps({"error": f"Invalid JSON: {exc}"})

    rows = _normalize_data_to_rows(raw_data, flatten=flatten, max_depth=max_depth)

    if snapshot_name:
        _save_snapshot(snapshot_name, rows)

    fields_info = _detect_fields(rows)

    result = {
        "success": True,
        "source": "raw_json",
        "rows": len(rows),
        "fields": fields_info["fields"][:30],
        "total_fields": fields_info["total_columns"],
        "preview": rows[:5],
        "snapshot_saved": bool(snapshot_name),
    }

    return json.dumps(result, ensure_ascii=False, default=str)


async def _import_from_ad_users(snapshot_name: str, exclude: str = "", include_groups: bool = False) -> str:
    """ONE-STEP import: users from API + groups from ldbsearch, merged.

    v1.9.5: Uses efficient memberOf query (1 step) instead of N+1 samba-tool calls.
            Adds group_count column for easy charting. Filters out computer accounts.
    v1.9.6: Added exclude and include_groups parameters.
    """
    import httpx
    import subprocess

    settings = get_settings()

    # 1. Fetch users from API
    api_path = "/api/v1/users/"
    url = f"{settings.AI_API_BASE.rstrip('/')}{api_path}"
    headers = {"X-API-Key": settings.API_KEY, "Accept": "application/json"}
    api_timeout = float(getattr(settings, "AI_AGENT_API_TIMEOUT", 60))

    async with httpx.AsyncClient(timeout=api_timeout) as client:
        resp = await client.request(method="GET", url=url, headers=headers)

    if resp.status_code >= 400:
        return json.dumps({"error": f"API returned HTTP {resp.status_code}"})

    raw_data = resp.json()
    rows = _normalize_data_to_rows(raw_data, flatten=True, max_depth=3)

    # Filter out computer accounts (sAMAccountName ending with $)
    rows = [row for row in rows if not str(row.get("sAMAccountName", "")).endswith("$")]

    # 2. Get groups for all users via ldbsearch using memberOf (ONE query)
    groups_map: Dict[str, List[str]] = {}
    db_path = "/var/lib/samba/private/sam.ldb"
    try:
        # Use memberOf attribute — single query for all users with groups
        result = subprocess.run(
            f'ldbsearch -H {db_path} "(&(objectClass=user)(!(sAMAccountName=*$)))" sAMAccountName memberOf',
            shell=True, capture_output=True, text=True, timeout=60
        )
        # Parse LDIF output line by line
        current_user = ""
        current_groups: List[str] = []
        for line in result.stdout.splitlines():
            if line.startswith("sAMAccountName:"):
                if current_user:
                    groups_map[current_user] = current_groups
                current_user = line.split(":", 1)[1].strip()
                current_groups = []
            elif line.startswith("memberOf:"):
                dn = line.split(":", 1)[1].strip()
                # Extract CN from DN (e.g. "CN=Domain Admins,CN=Users,DC=..." -> "Domain Admins")
                import re as _re
                match = _re.match(r'CN=([^,]+)', dn, _re.IGNORECASE)
                if match:
                    current_groups.append(match.group(1))
        if current_user:
            groups_map[current_user] = current_groups

        logger.info("[AI-DATA-IMPORT] groups_bulk via memberOf: found groups for %d users", len(groups_map))
    except Exception as exc:
        logger.warning("[AI-DATA-IMPORT] groups_bulk via memberOf failed: %s, trying fallback", exc)
        # Fallback: N+1 samba-tool approach
        try:
            result = subprocess.run(
                f'ldbsearch -H {db_path} "(&(objectClass=user)(!(sAMAccountName=*$)))" sAMAccountName',
                shell=True, capture_output=True, text=True, timeout=30
            )
            usernames: List[str] = []
            for line in result.stdout.splitlines():
                if line.startswith("sAMAccountName:"):
                    uname = line.split(":", 1)[1].strip()
                    if uname and not uname.endswith("$"):
                        usernames.append(uname)

            for username in usernames:
                try:
                    grp_result = subprocess.run(
                        f'samba-tool user getgroups {username}',
                        shell=True, capture_output=True, text=True, timeout=5
                    )
                    groups: List[str] = []
                    for gline in grp_result.stdout.splitlines():
                        gline = gline.strip()
                        if gline and not gline.startswith("User") and not gline.startswith("-"):
                            groups.append(gline)
                    groups_map[username] = groups
                except Exception:
                    groups_map[username] = []
        except Exception as exc2:
            logger.warning("[AI-DATA-IMPORT] groups_bulk fallback also failed: %s", exc2)

    # 3. Merge groups into user data
    for row in rows:
        username = str(row.get("sAMAccountName", "") or row.get("cn", ""))
        user_groups = groups_map.get(username, [])
        row["groups"] = ", ".join(user_groups) if user_groups else ""
        # v1.9.5: Add group_count for easy charting
        row["group_count"] = len(user_groups)

    # Apply exclude filter
    if exclude:
        exclude_list = [n.strip() for n in exclude.split(",") if n.strip()]
        rows = [r for r in rows if str(r.get("sAMAccountName", "")) not in exclude_list]

    # 4. Save snapshot
    if snapshot_name:
        _save_snapshot(snapshot_name, rows)

    # Also save the groups mapping as a separate snapshot for enrich_with_groups
    _save_snapshot("__groups_bulk_map__", groups_map)

    fields_info = _detect_fields(rows)
    result = {
        "success": True,
        "source": "ad_users_with_groups",
        "rows": len(rows),
        "fields": fields_info["fields"][:30],
        "total_fields": fields_info["total_columns"],
        "preview": rows[:5],
        "snapshot_saved": bool(snapshot_name),
        "groups_loaded": len(groups_map),
    }
    return json.dumps(result, ensure_ascii=False, default=str)


def _import_detect_fields(json_string: str) -> str:
    """Detect fields in a JSON structure without full import."""
    if not json_string:
        return json.dumps({"error": "JSON string is required for detect_fields action"})

    try:
        raw_data = json.loads(json_string)
    except json.JSONDecodeError as exc:
        return json.dumps({"error": f"Invalid JSON: {exc}"})

    rows = _normalize_data_to_rows(raw_data, flatten=True)
    fields_info = _detect_fields(rows)

    return json.dumps(fields_info, ensure_ascii=False, default=str)


async def _import_from_ad_groups(snapshot_name: str, exclude: str = "") -> str:
    """ONE-STEP import: groups from API + members count from ldbsearch."""
    import httpx
    import subprocess

    settings = get_settings()

    # 1. Fetch groups from API
    api_path = "/api/v1/groups/"
    url = f"{settings.AI_API_BASE.rstrip('/')}{api_path}"
    headers = {"X-API-Key": settings.API_KEY, "Accept": "application/json"}
    api_timeout = float(getattr(settings, "AI_AGENT_API_TIMEOUT", 60))

    async with httpx.AsyncClient(timeout=api_timeout) as client:
        resp = await client.request(method="GET", url=url, headers=headers)

    if resp.status_code >= 400:
        return json.dumps({"error": f"API returned HTTP {resp.status_code}"})

    raw_data = resp.json()
    rows = _normalize_data_to_rows(raw_data, flatten=True, max_depth=3)

    # 2. Get member counts via ldbsearch (ONE query)
    db_path = "/var/lib/samba/private/sam.ldb"
    member_counts: Dict[str, int] = {}
    try:
        result = subprocess.run(
            f'ldbsearch -H {db_path} "(objectClass=group)" cn member',
            shell=True, capture_output=True, text=True, timeout=60
        )
        current_cn = ""
        member_count = 0
        for line in result.stdout.splitlines():
            if line.startswith("cn:"):
                if current_cn:
                    member_counts[current_cn] = member_count
                current_cn = line.split(":", 1)[1].strip()
                member_count = 0
            elif line.startswith("member:"):
                member_count += 1
        if current_cn:
            member_counts[current_cn] = member_count
    except Exception as exc:
        logger.warning("[AI-DATA-IMPORT] group member count failed: %s", exc)

    # 3. Add member_count column
    for row in rows:
        group_cn = str(row.get("cn", row.get("sAMAccountName", "")))
        row["member_count"] = member_counts.get(group_cn, 0)

    # Apply exclude filter
    if exclude:
        exclude_list = [n.strip() for n in exclude.split(",") if n.strip()]
        rows = [r for r in rows if str(r.get("sAMAccountName", "")) not in exclude_list]

    if snapshot_name:
        _save_snapshot(snapshot_name, rows)

    fields_info = _detect_fields(rows)
    result_data = {
        "success": True,
        "source": "ad_groups",
        "rows": len(rows),
        "fields": fields_info["fields"][:30],
        "total_fields": fields_info["total_columns"],
        "columns": list(rows[0].keys()) if rows else [],
        "preview": rows[:5],
        "snapshot_saved": bool(snapshot_name),
    }
    return json.dumps(result_data, ensure_ascii=False, default=str)


async def _import_from_ad_object_type(
    object_type: str, snapshot_name: str, exclude: str = ""
) -> str:
    """Generic ONE-STEP import for AD object types via API + ldbsearch."""
    import httpx

    settings = get_settings()

    # Map object_type to API path
    api_paths = {
        "computer": "/api/v1/computers/",
        "contact": "/api/v1/contacts/",
        "ou": "/api/v1/ous/",
        "gpo": "/api/v1/gpo/",
        "site": "/api/v1/sites/",
        "trust": "/api/v1/domain/trusts/",
    }

    api_path = api_paths.get(object_type)
    if not api_path:
        return json.dumps({"error": f"No API path mapped for object_type '{object_type}'"})

    url = f"{settings.AI_API_BASE.rstrip('/')}{api_path}"
    headers = {"X-API-Key": settings.API_KEY, "Accept": "application/json"}
    api_timeout = float(getattr(settings, "AI_AGENT_API_TIMEOUT", 60))

    async with httpx.AsyncClient(timeout=api_timeout) as client:
        resp = await client.request(method="GET", url=url, headers=headers)

    if resp.status_code >= 400:
        # Fallback: try ldbsearch directly
        return _import_from_ad_via_ldbsearch(object_type, snapshot_name, exclude)

    raw_data = resp.json()
    rows = _normalize_data_to_rows(raw_data, flatten=True, max_depth=3)

    # Apply exclude filter
    if exclude:
        exclude_list = [n.strip() for n in exclude.split(",") if n.strip()]
        rows = [r for r in rows if str(r.get("sAMAccountName", "")) not in exclude_list]

    if snapshot_name:
        _save_snapshot(snapshot_name, rows)

    fields_info = _detect_fields(rows)
    result_data = {
        "success": True,
        "source": f"ad_{object_type}",
        "rows": len(rows),
        "fields": fields_info["fields"][:30],
        "total_fields": fields_info["total_columns"],
        "columns": list(rows[0].keys()) if rows else [],
        "preview": rows[:5],
        "snapshot_saved": bool(snapshot_name),
    }
    return json.dumps(result_data, ensure_ascii=False, default=str)


def _import_from_ad_via_ldbsearch(
    object_type: str, snapshot_name: str, exclude: str = ""
) -> str:
    """Fallback import via ldbsearch when API is not available."""
    import subprocess

    db_path = "/var/lib/samba/private/sam.ldb"

    # Map object_type to LDAP objectClass
    object_classes = {
        "computer": "computer",
        "contact": "contact",
        "ou": "organizationalUnit",
        "gpo": "groupPolicyContainer",
        "site": "site",
    }

    # Default attributes per type
    default_attrs = {
        "computer": "sAMAccountName,cn,dNSHostName,operatingSystem,description,lastLogonTimestamp",
        "contact": "cn,displayName,mail,telephoneNumber,description",
        "ou": "ou,description,distinguishedName",
        "gpo": "cn,displayName,gPCFileSysPath,distinguishedName",
        "site": "cn,description,location",
    }

    obj_class = object_classes.get(object_type, object_type)
    attrs = default_attrs.get(object_type, "dn,cn,description")

    # Build LDAP filter
    filter_parts = [f"(objectClass={obj_class})"]
    if object_type == "computer":
        filter_parts.append("(sAMAccountName=*$)")
    if exclude:
        for name in exclude.split(","):
            name = name.strip()
            if name:
                escaped = name.replace("\\", "\\5c").replace("(", "\\28").replace(")", "\\29")
                filter_parts.append(f"(!(sAMAccountName={escaped}))")

    if len(filter_parts) == 1:
        ldap_filter = filter_parts[0]
    else:
        ldap_filter = "(&" + "".join(filter_parts) + ")"

    try:
        result = subprocess.run(
            f'ldbsearch -H {db_path} "{ldap_filter}" {attrs}',
            shell=True, capture_output=True, text=True, timeout=60
        )

        # Parse LDIF output
        rows = _parse_ldb_ldif_to_rows(result.stdout)

        if snapshot_name:
            _save_snapshot(snapshot_name, rows)

        fields_info = _detect_fields(rows)
        result_data = {
            "success": True,
            "source": f"ldbsearch_{object_type}",
            "rows": len(rows),
            "fields": fields_info["fields"][:30],
            "total_fields": fields_info["total_columns"],
            "columns": list(rows[0].keys()) if rows else [],
            "preview": rows[:5],
            "snapshot_saved": bool(snapshot_name),
        }
        return json.dumps(result_data, ensure_ascii=False, default=str)

    except Exception as exc:
        return json.dumps({"error": f"ldbsearch failed for {object_type}: {exc}"})


def _parse_ldb_ldif_to_rows(ldif_text: str) -> List[Dict[str, Any]]:
    """Parse LDIF format output from ldbsearch into list of row dicts.

    Handles:
    - Multi-line values (continuation lines starting with space)
    - Base64-encoded values (lines starting with attributeName:: )
    - Multi-valued attributes (concatenated with '; ')
    """
    if not ldif_text or not ldif_text.strip():
        return []

    rows: List[Dict[str, Any]] = []
    current: Dict[str, Any] = {}

    for line in ldif_text.splitlines():
        if not line or line.startswith("#"):
            # Empty line = end of record
            if current:
                rows.append(current)
                current = {}
            continue

        # Handle continuation lines (start with space)
        if line.startswith(" ") and current:
            # Append to last attribute (simplified)
            continue

        # Parse attribute: value or attribute:: base64value
        if ": " in line:
            attr, _, val = line.partition(": ")
            attr = attr.strip()

            # Check if base64 encoded (attribute:: value)
            if val.startswith(": "):
                # Base64 encoded value
                import base64
                b64_val = val[2:]
                try:
                    decoded = base64.b64decode(b64_val).decode("utf-8", errors="replace")
                    if attr in current:
                        existing = current[attr]
                        if isinstance(existing, list):
                            existing.append(decoded)
                        else:
                            current[attr] = [existing, decoded]
                    else:
                        current[attr] = decoded
                except Exception:
                    if attr in current:
                        pass  # keep existing
                    else:
                        current[attr] = b64_val
            else:
                if attr in current:
                    existing = current[attr]
                    if isinstance(existing, list):
                        existing.append(val)
                    else:
                        current[attr] = [existing, val]
                else:
                    current[attr] = val

    # Don't forget the last record
    if current:
        rows.append(current)

    # Convert list values to semicolon-separated strings
    for row in rows:
        for key, value in row.items():
            if isinstance(value, list):
                row[key] = "; ".join(str(v) for v in value)

    return rows


async def _import_from_ad_dns(snapshot_name: str) -> str:
    """ONE-STEP import: DNS zones and records from API."""
    import httpx

    settings = get_settings()

    # Fetch DNS zones
    api_path = "/api/v1/dns/zones/"
    url = f"{settings.AI_API_BASE.rstrip('/')}{api_path}"
    headers = {"X-API-Key": settings.API_KEY, "Accept": "application/json"}
    api_timeout = float(getattr(settings, "AI_AGENT_API_TIMEOUT", 60))

    async with httpx.AsyncClient(timeout=api_timeout) as client:
        resp = await client.request(method="GET", url=url, headers=headers)

    if resp.status_code >= 400:
        return json.dumps({"error": f"DNS API returned HTTP {resp.status_code}"})

    raw_data = resp.json()
    rows = _normalize_data_to_rows(raw_data, flatten=True, max_depth=3)

    if snapshot_name:
        _save_snapshot(snapshot_name, rows)

    fields_info = _detect_fields(rows)
    result_data = {
        "success": True,
        "source": "ad_dns",
        "rows": len(rows),
        "fields": fields_info["fields"][:30],
        "total_fields": fields_info["total_columns"],
        "columns": list(rows[0].keys()) if rows else [],
        "preview": rows[:5],
        "snapshot_saved": bool(snapshot_name),
    }
    return json.dumps(result_data, ensure_ascii=False, default=str)


async def _import_from_ad_domain(snapshot_name: str) -> str:
    """ONE-STEP import: Domain information from API."""
    import httpx

    settings = get_settings()

    api_path = "/api/v1/domain/"
    url = f"{settings.AI_API_BASE.rstrip('/')}{api_path}"
    headers = {"X-API-Key": settings.API_KEY, "Accept": "application/json"}
    api_timeout = float(getattr(settings, "AI_AGENT_API_TIMEOUT", 60))

    async with httpx.AsyncClient(timeout=api_timeout) as client:
        resp = await client.request(method="GET", url=url, headers=headers)

    if resp.status_code >= 400:
        return json.dumps({"error": f"Domain API returned HTTP {resp.status_code}"})

    raw_data = resp.json()

    # Domain info is typically a single dict, normalize to rows
    if isinstance(raw_data, dict):
        # Flatten nested structure
        flat = _flatten_dict(raw_data, max_depth=2)
        rows = [flat]
    else:
        rows = _normalize_data_to_rows(raw_data, flatten=True, max_depth=3)

    if snapshot_name:
        _save_snapshot(snapshot_name, rows)

    fields_info = _detect_fields(rows)
    result_data = {
        "success": True,
        "source": "ad_domain",
        "rows": len(rows),
        "fields": fields_info["fields"][:30],
        "total_fields": fields_info["total_columns"],
        "columns": list(rows[0].keys()) if rows else [],
        "preview": rows[:5],
        "snapshot_saved": bool(snapshot_name),
    }
    return json.dumps(result_data, ensure_ascii=False, default=str)


async def _import_from_dashboard(snapshot_name: str) -> str:
    """ONE-STEP import: Dashboard overview data from API."""
    import httpx

    settings = get_settings()

    api_path = "/api/v1/dashboard/overview"
    url = f"{settings.AI_API_BASE.rstrip('/')}{api_path}"
    headers = {"X-API-Key": settings.API_KEY, "Accept": "application/json"}
    api_timeout = float(getattr(settings, "AI_AGENT_API_TIMEOUT", 60))

    async with httpx.AsyncClient(timeout=api_timeout) as client:
        resp = await client.request(method="GET", url=url, headers=headers)

    if resp.status_code >= 400:
        return json.dumps({"error": f"Dashboard API returned HTTP {resp.status_code}"})

    raw_data = resp.json()

    # Dashboard data is typically a dict with counts — flatten it
    if isinstance(raw_data, dict):
        flat = _flatten_dict(raw_data, max_depth=2)
        rows = [flat]
    else:
        rows = _normalize_data_to_rows(raw_data, flatten=True, max_depth=3)

    if snapshot_name:
        _save_snapshot(snapshot_name, rows)

    fields_info = _detect_fields(rows)
    result_data = {
        "success": True,
        "source": "dashboard",
        "rows": len(rows),
        "fields": fields_info["fields"][:30],
        "total_fields": fields_info["total_columns"],
        "columns": list(rows[0].keys()) if rows else [],
        "preview": rows[:5],
        "snapshot_saved": bool(snapshot_name),
    }
    return json.dumps(result_data, ensure_ascii=False, default=str)


async def _import_from_shell_projects(snapshot_name: str) -> str:
    """ONE-STEP import: Shell projects from API."""
    import httpx

    settings = get_settings()

    api_path = "/api/v1/shell/projet/"
    url = f"{settings.AI_API_BASE.rstrip('/')}{api_path}"
    headers = {"X-API-Key": settings.API_KEY, "Accept": "application/json"}
    api_timeout = float(getattr(settings, "AI_AGENT_API_TIMEOUT", 60))

    async with httpx.AsyncClient(timeout=api_timeout) as client:
        resp = await client.request(method="GET", url=url, headers=headers)

    if resp.status_code >= 400:
        return json.dumps({"error": f"Shell projects API returned HTTP {resp.status_code}"})

    raw_data = resp.json()
    rows = _normalize_data_to_rows(raw_data, flatten=True, max_depth=3)

    if snapshot_name:
        _save_snapshot(snapshot_name, rows)

    fields_info = _detect_fields(rows)
    result_data = {
        "success": True,
        "source": "shell_projects",
        "rows": len(rows),
        "fields": fields_info["fields"][:30],
        "total_fields": fields_info["total_columns"],
        "columns": list(rows[0].keys()) if rows else [],
        "preview": rows[:5],
        "snapshot_saved": bool(snapshot_name),
    }
    return json.dumps(result_data, ensure_ascii=False, default=str)


async def _import_from_audit(snapshot_name: str) -> str:
    """ONE-STEP import: Audit log from API."""
    import httpx

    settings = get_settings()

    api_path = "/api/v1/mgmt/audit"
    url = f"{settings.AI_API_BASE.rstrip('/')}{api_path}"
    headers = {"X-API-Key": settings.API_KEY, "Accept": "application/json"}
    api_timeout = float(getattr(settings, "AI_AGENT_API_TIMEOUT", 60))

    async with httpx.AsyncClient(timeout=api_timeout) as client:
        resp = await client.request(method="GET", url=url, headers=headers)

    if resp.status_code >= 400:
        return json.dumps({"error": f"Audit API returned HTTP {resp.status_code}"})

    raw_data = resp.json()
    rows = _normalize_data_to_rows(raw_data, flatten=True, max_depth=3)

    if snapshot_name:
        _save_snapshot(snapshot_name, rows)

    fields_info = _detect_fields(rows)
    result_data = {
        "success": True,
        "source": "audit",
        "rows": len(rows),
        "fields": fields_info["fields"][:30],
        "total_fields": fields_info["total_columns"],
        "columns": list(rows[0].keys()) if rows else [],
        "preview": rows[:5],
        "snapshot_saved": bool(snapshot_name),
    }
    return json.dumps(result_data, ensure_ascii=False, default=str)


# ═══════════════════════════════════════════════════════════════════════
#  Data Export Implementation
# ═══════════════════════════════════════════════════════════════════════


def _data_export_impl(args: Dict[str, Any]) -> str:
    """Implement data_export tool."""
    action = args.get("action", "to_xlsx")
    data_str = args.get("data", "")
    filename = args.get("filename", "")
    sheet_name = args.get("sheet_name", "Data")
    sheets = args.get("sheets", {})
    formats_str = args.get("formats", "xlsx,csv,json")
    snapshot_name = args.get("snapshot_name", "")
    include_headers = args.get("include_headers", True)
    auto_width = args.get("auto_width", True)
    styled = args.get("styled", True)
    # v1.9.0: Chart parameters for embedded chart on 2nd sheet
    chart_type = args.get("chart_type", "")
    chart_x = args.get("chart_x", "")
    chart_y = args.get("chart_y", "")
    chart_title = args.get("chart_title", "")
    # v1.8.9: Column filtering during export (saves a data_transform step)
    export_columns = args.get("columns", "")

    settings = get_settings()
    export_dir = getattr(settings, "AI_AGENT_EXPORT_DIR", "/home/AD-API-USER/ai-exports")
    os.makedirs(export_dir, exist_ok=True)

    try:
        if action == "list_exports":
            return _list_export_files(export_dir)

        # Get data from snapshot or argument
        data = None
        if snapshot_name:
            data = _get_snapshot(snapshot_name)
            if data is None:
                return json.dumps({"error": f"Snapshot '{snapshot_name}' not found. Use data_import first."})

        if data is None and data_str:
            try:
                parsed = json.loads(data_str)
                if isinstance(parsed, list):
                    data = parsed
                elif isinstance(parsed, dict):
                    # Check if it's a multi-sheet structure
                    if all(isinstance(v, (list, str)) for v in parsed.values()):
                        # Could be multi-sheet or just a single dict
                        first_val = next(iter(parsed.values()), None)
                        if isinstance(first_val, str):
                            try:
                                json.loads(first_val)
                                # It's a multi-sheet: keys are sheet names, values are JSON strings
                                sheets = {k: v for k, v in parsed.items()}
                                data = None
                            except json.JSONDecodeError:
                                data = [parsed]
                        elif isinstance(first_val, list):
                            data = [parsed]
                    else:
                        data = [parsed]
            except json.JSONDecodeError:
                return json.dumps({"error": "Invalid JSON in data parameter"})

        # v1.9.0: Handle both list and string input for columns
        if data and export_columns:
            if isinstance(export_columns, list):
                cols = [c.strip() for c in export_columns if c.strip()]
            elif isinstance(export_columns, str):
                cols = [c.strip() for c in export_columns.split(",") if c.strip()]
            else:
                cols = []
            if cols:
                data = [{k: row.get(k) for k in cols if k in row} for row in data]

        if action == "to_xlsx":
            if sheets:
                return _export_multi_sheet_xlsx(export_dir, filename, sheets, auto_width, styled)
            if data is None:
                return json.dumps({"error": "No data provided. Use 'data' or 'snapshot_name' or 'sheets' parameter."})
            return _export_xlsx(export_dir, filename, data, sheet_name, auto_width, styled,
                                chart_type=chart_type, chart_x=chart_x, chart_y=chart_y, chart_title=chart_title)

        elif action == "to_csv":
            if data is None:
                return json.dumps({"error": "No data provided"})
            return _export_csv(export_dir, filename, data, include_headers)

        elif action == "to_json":
            if data is None:
                return json.dumps({"error": "No data provided"})
            return _export_json(export_dir, filename, data)

        elif action == "to_tsv":
            if data is None:
                return json.dumps({"error": "No data provided"})
            return _export_tsv(export_dir, filename, data, include_headers)

        elif action == "to_multi_format":
            if data is None:
                return json.dumps({"error": "No data provided"})
            return _export_multi_format(export_dir, filename, data, formats_str, sheet_name, auto_width, styled, include_headers)

        else:
            return json.dumps({"error": f"Unknown action: {action}"})

    except Exception as exc:
        logger.error("[AI-DATA-EXPORT] Failed: %s", exc)
        return json.dumps({"error": f"Data export failed: {exc}"})


def _export_xlsx(
    export_dir: str,
    filename: str,
    data: List[Dict[str, Any]],
    sheet_name: str,
    auto_width: bool,
    styled: bool,
    chart_type: str = "",
    chart_x: str = "",
    chart_y: str = "",
    chart_title: str = "",
) -> str:
    """Export data to a single-sheet XLSX file, with optional chart on 2nd sheet."""
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
        from openpyxl.utils import get_column_letter
    except ImportError:
        return json.dumps({"error": "XLSX export requires openpyxl. Install: pip install openpyxl"})

    if not filename:
        filename = _auto_filename("xlsx")
    safe_filename = os.path.basename(filename)
    if not safe_filename.endswith(".xlsx"):
        safe_filename += ".xlsx"
    filepath = os.path.join(export_dir, safe_filename)

    wb = Workbook()
    ws = wb.active
    ws.title = sheet_name[:31]  # Excel sheet name max 31 chars

    if not data:
        wb.save(filepath)
        return json.dumps({"success": True, "path": os.path.abspath(filepath), "size_bytes": 0, "sheets": [sheet_name]})

    # Get columns from data
    columns = list(OrderedDict.fromkeys(k for row in data for k in row.keys()))

    # Header
    if styled:
        header_font = Font(bold=True, color="FFFFFF", size=11)
        header_fill = PatternFill(start_color="4472C4", end_color="4472C4", fill_type="solid")
        header_alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        thin_border = Border(
            left=Side(style="thin"),
            right=Side(style="thin"),
            top=Side(style="thin"),
            bottom=Side(style="thin"),
        )
    else:
        header_font = Font(bold=True)
        header_fill = None
        header_alignment = None
        thin_border = None

    for col_idx, col_name in enumerate(columns, 1):
        cell = ws.cell(row=1, column=col_idx, value=col_name)
        if styled:
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = header_alignment
            if thin_border:
                cell.border = thin_border

    # Data rows
    for row_idx, row in enumerate(data, 2):
        for col_idx, col_name in enumerate(columns, 1):
            value = row.get(col_name)
            if isinstance(value, (list, dict)):
                value = json.dumps(value, ensure_ascii=False)
            cell = ws.cell(row=row_idx, column=col_idx, value=value)
            if styled and thin_border:
                cell.border = thin_border

    # Auto-width
    if auto_width:
        for col_idx, col_name in enumerate(columns, 1):
            max_len = len(str(col_name))
            for row in data[:100]:  # Sample first 100 rows
                val = row.get(col_name, "")
                val_len = len(str(val)) if val else 0
                max_len = max(max_len, min(val_len, 50))
            ws.column_dimensions[get_column_letter(col_idx)].width = min(max_len + 3, 50)

    # v1.9.0: Add chart on 2nd sheet if chart_type is specified
    # v1.9.1: Fixed chart positioning — anchor after data rows, set dimensions
    chart_sheet_name = None
    if chart_type and chart_x:
        try:
            from openpyxl.chart import BarChart, LineChart, PieChart, Reference

            chart_ws = wb.create_sheet("Chart")
            chart_sheet_name = "Chart"

            if chart_x and not chart_y:
                # Auto-aggregate: count by chart_x
                x_vals = [str(row.get(chart_x, "")) for row in data]
                counts = Counter(x_vals)
                chart_ws.append([chart_x, "count"])
                for val, cnt in counts.most_common(20):
                    chart_ws.append([val, cnt])

                num_data_rows = len(counts)
                data_ref = Reference(chart_ws, min_col=2, min_row=1, max_row=num_data_rows + 1)
                cats_ref = Reference(chart_ws, min_col=1, min_row=2, max_row=num_data_rows + 1)

                # v1.9.1: Compute chart anchor cell — place chart after data
                chart_anchor_row = num_data_rows + 3  # skip header + data + 2 blank rows
                chart_anchor = f"A{chart_anchor_row}"

                if chart_type == "bar":
                    chart = BarChart()
                    chart.title = chart_title or f"Count by {chart_x}"
                    chart.add_data(data_ref, titles_from_data=True)
                    chart.set_categories(cats_ref)
                    chart.width = 20
                    chart.height = 12
                    chart_ws.add_chart(chart, chart_anchor)
                elif chart_type == "line":
                    chart = LineChart()
                    chart.title = chart_title or f"Count by {chart_x}"
                    chart.add_data(data_ref, titles_from_data=True)
                    chart.set_categories(cats_ref)
                    chart.width = 20
                    chart.height = 12
                    chart_ws.add_chart(chart, chart_anchor)
                elif chart_type == "pie":
                    chart = PieChart()
                    chart.title = chart_title or f"Count by {chart_x}"
                    chart.add_data(data_ref, titles_from_data=True)
                    chart.set_categories(cats_ref)
                    chart.width = 20
                    chart.height = 14
                    chart_ws.add_chart(chart, chart_anchor)
                elif chart_type == "scatter":
                    chart = BarChart()  # Scatter in openpyxl needs different setup; fall back to bar for count agg
                    chart.title = chart_title or f"Count by {chart_x}"
                    chart.add_data(data_ref, titles_from_data=True)
                    chart.set_categories(cats_ref)
                    chart.width = 20
                    chart.height = 12
                    chart_ws.add_chart(chart, chart_anchor)
                elif chart_type == "histogram":
                    chart = BarChart()
                    chart.title = chart_title or f"Count by {chart_x}"
                    chart.add_data(data_ref, titles_from_data=True)
                    chart.set_categories(cats_ref)
                    chart.width = 20
                    chart.height = 12
                    chart_ws.add_chart(chart, chart_anchor)

            elif chart_x and chart_y:
                # Use raw data columns for chart
                max_chart_rows = min(len(data), 100)
                chart_ws.append([chart_x, chart_y])
                for row in data[:max_chart_rows]:
                    x_val = str(row.get(chart_x, ""))
                    y_raw = row.get(chart_y, 0)
                    try:
                        y_val = float(y_raw) if y_raw is not None else 0
                    except (ValueError, TypeError):
                        y_val = 0
                    chart_ws.append([x_val, y_val])

                data_ref = Reference(chart_ws, min_col=2, min_row=1, max_row=max_chart_rows + 1)
                cats_ref = Reference(chart_ws, min_col=1, min_row=2, max_row=max_chart_rows + 1)

                # v1.9.1: Compute chart anchor cell — place chart after data
                chart_anchor_row = max_chart_rows + 3  # skip header + data + 2 blank rows
                chart_anchor = f"A{chart_anchor_row}"

                if chart_type == "bar":
                    chart = BarChart()
                    chart.title = chart_title or f"{chart_y} by {chart_x}"
                    chart.add_data(data_ref, titles_from_data=True)
                    chart.set_categories(cats_ref)
                    chart.width = 20
                    chart.height = 12
                    chart_ws.add_chart(chart, chart_anchor)
                elif chart_type == "line":
                    chart = LineChart()
                    chart.title = chart_title or f"{chart_y} by {chart_x}"
                    chart.add_data(data_ref, titles_from_data=True)
                    chart.set_categories(cats_ref)
                    chart.width = 20
                    chart.height = 12
                    chart_ws.add_chart(chart, chart_anchor)
                elif chart_type == "pie":
                    chart = PieChart()
                    chart.title = chart_title or f"{chart_y} by {chart_x}"
                    chart.add_data(data_ref, titles_from_data=True)
                    chart.set_categories(cats_ref)
                    chart.width = 20
                    chart.height = 14
                    chart_ws.add_chart(chart, chart_anchor)
                elif chart_type == "scatter":
                    # openpyxl scatter chart
                    from openpyxl.chart import ScatterChart, Series
                    chart = ScatterChart()
                    chart.title = chart_title or f"{chart_y} by {chart_x}"
                    chart.x_axis.title = chart_x
                    chart.y_axis.title = chart_y
                    xvalues = Reference(chart_ws, min_col=1, min_row=2, max_row=max_chart_rows + 1)
                    yvalues = Reference(chart_ws, min_col=2, min_row=2, max_row=max_chart_rows + 1)
                    series = Series(yvalues, xvalues, title=chart_y)
                    chart.series.append(series)
                    chart.width = 20
                    chart.height = 12
                    chart_ws.add_chart(chart, chart_anchor)
                elif chart_type == "histogram":
                    chart = BarChart()
                    chart.title = chart_title or f"{chart_y} by {chart_x}"
                    chart.add_data(data_ref, titles_from_data=True)
                    chart.set_categories(cats_ref)
                    chart.width = 20
                    chart.height = 12
                    chart_ws.add_chart(chart, chart_anchor)

        except Exception as chart_exc:
            logger.warning("[AI-DATA-EXPORT] Chart generation failed (non-fatal): %s", chart_exc)
            # Chart failure is non-fatal — the data sheet is still saved

    wb.save(filepath)
    size = os.path.getsize(filepath)

    result_sheets = [sheet_name]
    if chart_sheet_name:
        result_sheets.append(chart_sheet_name)

    # v1.9.1: Add download URL for the exported file
    download_url = f"/api/v1/ai/exports/{safe_filename}"

    return json.dumps({
        "success": True,
        "path": os.path.abspath(filepath),
        "filename": safe_filename,
        "download_url": download_url,
        "size_bytes": size,
        "rows": len(data),
        "columns": len(columns),
        "sheets": result_sheets,
        "chart_embedded": bool(chart_type and chart_x),
    }, ensure_ascii=False)


def _export_multi_sheet_xlsx(
    export_dir: str,
    filename: str,
    sheets: Dict[str, str],
    auto_width: bool,
    styled: bool,
) -> str:
    """Export data to a multi-sheet XLSX workbook."""
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
        from openpyxl.utils import get_column_letter
    except ImportError:
        return json.dumps({"error": "XLSX export requires openpyxl. Install: pip install openpyxl"})

    if not filename:
        filename = _auto_filename("xlsx")
    safe_filename = os.path.basename(filename)
    if not safe_filename.endswith(".xlsx"):
        safe_filename += ".xlsx"
    filepath = os.path.join(export_dir, safe_filename)

    wb = Workbook()
    # Remove default sheet
    wb.remove(wb.active)

    if styled:
        header_font = Font(bold=True, color="FFFFFF", size=11)
        header_fill = PatternFill(start_color="4472C4", end_color="4472C4", fill_type="solid")
        header_alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        thin_border = Border(
            left=Side(style="thin"),
            right=Side(style="thin"),
            top=Side(style="thin"),
            bottom=Side(style="thin"),
        )
    else:
        header_font = Font(bold=True)
        header_fill = None
        header_alignment = None
        thin_border = None

    sheet_info = []
    for sheet_name, sheet_data_str in sheets.items():
        try:
            if isinstance(sheet_data_str, str):
                data = json.loads(sheet_data_str)
            elif isinstance(sheet_data_str, list):
                data = sheet_data_str
            else:
                data = [sheet_data_str]
        except json.JSONDecodeError:
            continue

        if not isinstance(data, list):
            data = [data] if isinstance(data, dict) else [{"value": data}]

        ws = wb.create_sheet(title=sheet_name[:31])

        if not data:
            sheet_info.append({"name": sheet_name, "rows": 0, "columns": 0})
            continue

        columns = list(OrderedDict.fromkeys(k for row in data for k in row.keys()))

        # Header
        for col_idx, col_name in enumerate(columns, 1):
            cell = ws.cell(row=1, column=col_idx, value=col_name)
            if styled:
                cell.font = header_font
                cell.fill = header_fill
                cell.alignment = header_alignment
                if thin_border:
                    cell.border = thin_border

        # Data
        for row_idx, row in enumerate(data, 2):
            for col_idx, col_name in enumerate(columns, 1):
                value = row.get(col_name)
                if isinstance(value, (list, dict)):
                    value = json.dumps(value, ensure_ascii=False)
                cell = ws.cell(row=row_idx, column=col_idx, value=value)
                if styled and thin_border:
                    cell.border = thin_border

        # Auto-width
        if auto_width:
            for col_idx, col_name in enumerate(columns, 1):
                max_len = len(str(col_name))
                for row in data[:100]:
                    val = row.get(col_name, "")
                    val_len = len(str(val)) if val else 0
                    max_len = max(max_len, min(val_len, 50))
                ws.column_dimensions[get_column_letter(col_idx)].width = min(max_len + 3, 50)

        sheet_info.append({"name": sheet_name, "rows": len(data), "columns": len(columns)})

    wb.save(filepath)
    size = os.path.getsize(filepath)

    download_url = f"/api/v1/ai/exports/{safe_filename}"

    return json.dumps({
        "success": True,
        "path": os.path.abspath(filepath),
        "filename": safe_filename,
        "download_url": download_url,
        "size_bytes": size,
        "total_sheets": len(sheet_info),
        "sheets": sheet_info,
    }, ensure_ascii=False)


def _export_csv(export_dir: str, filename: str, data: List[Dict[str, Any]], include_headers: bool) -> str:
    """Export data to CSV."""
    if not filename:
        filename = _auto_filename("csv")
    safe_filename = os.path.basename(filename)
    if not safe_filename.endswith(".csv"):
        safe_filename += ".csv"
    filepath = os.path.join(export_dir, safe_filename)

    if not data:
        return json.dumps({"error": "No data to export"})

    columns = list(OrderedDict.fromkeys(k for row in data for k in row.keys()))

    with open(filepath, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        if include_headers:
            writer.writeheader()
        for row in data:
            # Convert complex types to strings
            clean_row = {}
            for k, v in row.items():
                if isinstance(v, (list, dict)):
                    clean_row[k] = json.dumps(v, ensure_ascii=False)
                else:
                    clean_row[k] = v
            writer.writerow(clean_row)

    size = os.path.getsize(filepath)
    download_url = f"/api/v1/ai/exports/{safe_filename}"
    return json.dumps({
        "success": True,
        "path": os.path.abspath(filepath),
        "filename": safe_filename,
        "download_url": download_url,
        "size_bytes": size,
        "rows": len(data),
    }, ensure_ascii=False)


def _export_json(export_dir: str, filename: str, data: List[Dict[str, Any]]) -> str:
    """Export data to JSON."""
    if not filename:
        filename = _auto_filename("json")
    safe_filename = os.path.basename(filename)
    if not safe_filename.endswith(".json"):
        safe_filename += ".json"
    filepath = os.path.join(export_dir, safe_filename)

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)

    size = os.path.getsize(filepath)
    download_url = f"/api/v1/ai/exports/{safe_filename}"
    return json.dumps({
        "success": True,
        "path": os.path.abspath(filepath),
        "filename": safe_filename,
        "download_url": download_url,
        "size_bytes": size,
        "rows": len(data),
    }, ensure_ascii=False)


def _export_tsv(export_dir: str, filename: str, data: List[Dict[str, Any]], include_headers: bool) -> str:
    """Export data to TSV."""
    if not filename:
        filename = _auto_filename("tsv")
    safe_filename = os.path.basename(filename)
    if not safe_filename.endswith(".tsv"):
        safe_filename += ".tsv"
    filepath = os.path.join(export_dir, safe_filename)

    if not data:
        return json.dumps({"error": "No data to export"})

    columns = list(OrderedDict.fromkeys(k for row in data for k in row.keys()))

    with open(filepath, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns, delimiter="\t", extrasaction="ignore")
        if include_headers:
            writer.writeheader()
        for row in data:
            clean_row = {}
            for k, v in row.items():
                if isinstance(v, (list, dict)):
                    clean_row[k] = json.dumps(v, ensure_ascii=False)
                else:
                    clean_row[k] = v
            writer.writerow(clean_row)

    size = os.path.getsize(filepath)
    download_url = f"/api/v1/ai/exports/{safe_filename}"
    return json.dumps({
        "success": True,
        "path": os.path.abspath(filepath),
        "filename": safe_filename,
        "download_url": download_url,
        "size_bytes": size,
        "rows": len(data),
    }, ensure_ascii=False)


def _export_multi_format(
    export_dir: str,
    filename: str,
    data: List[Dict[str, Any]],
    formats_str: str,
    sheet_name: str,
    auto_width: bool,
    styled: bool,
    include_headers: bool,
) -> str:
    """Export data to multiple formats at once."""
    formats = [f.strip().lower() for f in formats_str.split(",") if f.strip()]
    results = []
    base_name = os.path.splitext(filename)[0] if filename else os.path.splitext(_auto_filename(""))[0]

    for fmt in formats:
        fmt_filename = f"{base_name}.{fmt}"
        if fmt == "xlsx":
            result = _export_xlsx(export_dir, fmt_filename, data, sheet_name, auto_width, styled)
        elif fmt == "csv":
            result = _export_csv(export_dir, fmt_filename, data, include_headers)
        elif fmt == "json":
            result = _export_json(export_dir, fmt_filename, data)
        elif fmt == "tsv":
            result = _export_tsv(export_dir, fmt_filename, data, include_headers)
        else:
            result = json.dumps({"error": f"Unsupported format: {fmt}"})
        results.append({"format": fmt, "result": json.loads(result)})

    return json.dumps({
        "success": True,
        "exported_formats": results,
        "total_formats": len(results),
    }, ensure_ascii=False, default=str)


def _list_export_files(export_dir: str) -> str:
    """List all exported files in the export directory."""
    if not os.path.exists(export_dir):
        return json.dumps({"files": [], "total": 0, "export_dir": export_dir})

    files = []
    for fname in sorted(os.listdir(export_dir), key=lambda x: os.path.getmtime(os.path.join(export_dir, x)), reverse=True):
        fpath = os.path.join(export_dir, fname)
        if os.path.isfile(fpath):
            ext = os.path.splitext(fname)[1].lower()
            stat = os.stat(fpath)
            files.append({
                "name": fname,
                "path": os.path.abspath(fpath),
                "download_url": f"/api/v1/ai/exports/{fname}",
                "size_bytes": stat.st_size,
                "format": ext.lstrip("."),
                "modified": stat.st_mtime,
            })

    return json.dumps({
        "files": files[:100],
        "total": len(files),
        "export_dir": os.path.abspath(export_dir),
    }, ensure_ascii=False, default=str)


def _auto_filename(ext: str) -> str:
    """Generate an auto filename based on timestamp."""
    import time
    ts = time.strftime("%Y%m%d_%H%M%S")
    return f"data_export_{ts}.{ext}"


# ═══════════════════════════════════════════════════════════════════════
#  Data Transform Implementation
# ═══════════════════════════════════════════════════════════════════════


def _data_transform_impl(args: Dict[str, Any]) -> str:
    """Implement data_transform tool."""
    action = args.get("action", "filter")
    data_str = args.get("data", "")
    snapshot_name = args.get("snapshot_name", "")
    save_as = args.get("save_as", "")

    # Get input data
    data = None
    if snapshot_name:
        data = _get_snapshot(snapshot_name)
        if data is None:
            return json.dumps({"error": f"Snapshot '{snapshot_name}' not found"})

    if data is None and data_str:
        try:
            parsed = json.loads(data_str)
            data = parsed if isinstance(parsed, list) else [parsed]
        except json.JSONDecodeError:
            return json.dumps({"error": "Invalid JSON in data parameter"})

    if data is None:
        return json.dumps({"error": "No data provided. Use 'data' or 'snapshot_name' parameter."})

    try:
        if action == "filter":
            result = _transform_filter(data, args)
        elif action == "sort":
            result = _transform_sort(data, args)
        elif action == "aggregate":
            result = _transform_aggregate(data, args)
        elif action == "deduplicate":
            result = _transform_deduplicate(data, args)
        elif action in ("select_columns", "select"):  # v1.9.0: select alias
            result = _transform_select_columns(data, args)
        elif action in ("rename_columns", "rename"):  # v1.9.0: rename alias
            result = _transform_rename_columns(data, args)
        elif action in ("add_column", "derive"):
            result = _transform_add_column(data, args)
        elif action in ("enrich_with_groups", "enrich"):  # v1.9.0: enrich_with_groups / enrich
            result = _transform_enrich_with_groups(data, args)
        elif action == "merge":
            result = _transform_merge(data, args)
        elif action == "pivot":
            result = _transform_pivot(data, args)
        elif action == "stats":
            result = _transform_stats(data, args)
        elif action == "group_by":  # v1.9.13: group_by alias for aggregate
            result = _transform_aggregate(data, args)
        elif action == "batch":
            return _transform_batch(args, data)
        else:
            return json.dumps({"error": f"Unknown action: {action}. Available: filter, sort, aggregate (or group_by), deduplicate, select_columns (or select), rename_columns (or rename), add_column (or derive), enrich_with_groups (or enrich), merge, pivot, stats, batch"})

        if isinstance(result, str):
            return result

        # Save result as snapshot if requested
        if save_as:
            _save_snapshot(save_as, result)

        # Return result
        return json.dumps({
            "success": True,
            "rows": len(result),
            "preview": result[:10],
            "snapshot_saved": bool(save_as),
        }, ensure_ascii=False, default=str)

    except Exception as exc:
        logger.error("[AI-DATA-TRANSFORM] Failed: %s", exc)
        return json.dumps({"error": f"Transform failed: {exc}"})


def _parse_condition(condition: str, row: Dict[str, Any]) -> bool:
    """Parse and evaluate a filter condition against a row.

    Supports: =, !=, >, <, >=, <=, CONTAINS, STARTS_WITH, ENDS_WITH, IN, NOT_IN, NOT_EMPTY, IS_NOT_EMPTY
    Supports AND/OR for compound conditions.
    """
    condition = condition.strip()

    # Handle AND/OR compound conditions
    # Split by AND/OR (case-insensitive), evaluate each part
    and_parts = re.split(r'\s+AND\s+', condition, flags=re.IGNORECASE)
    if len(and_parts) > 1:
        return all(_parse_condition(part.strip(), row) for part in and_parts)

    or_parts = re.split(r'\s+OR\s+', condition, flags=re.IGNORECASE)
    if len(or_parts) > 1:
        return any(_parse_condition(part.strip(), row) for part in or_parts)

    # IS_NOT_EMPTY / NOT_EMPTY
    for suffix in (" IS_NOT_EMPTY", " NOT_EMPTY"):
        if condition.upper().endswith(suffix):
            col = condition[: -len(suffix)].strip()
            val = row.get(col)
            return val is not None and val != ""

    # Try operators in order of length (longest first)
    for op in [">=", "<=", "!=", "NOT_IN", "CONTAINS", "STARTS_WITH", "ENDS_WITH", ">", "<", "=", "IN"]:
        # Case-insensitive for text operators
        if op.isalpha() or op == "NOT_IN":
            pattern = re.compile(rf"\s+{op}\s+", re.IGNORECASE)
            match = pattern.search(condition)
        else:
            match = condition.find(op)
            if match > 0:
                match = (match, match + len(op))

        if op.isalpha() or op == "NOT_IN":
            if match:
                col = condition[:match.start()].strip()
                val_str = condition[match.end():].strip().strip('"').strip("'")
            else:
                continue
        else:
            if isinstance(match, int) and match > 0:
                col = condition[:match].strip()
                val_str = condition[match + len(op):].strip().strip('"').strip("'")
            else:
                continue

        row_val = row.get(col)
        if row_val is None:
            return False

        try:
            if op == "=":
                return str(row_val) == val_str or row_val == _try_convert(val_str)
            elif op == "!=":
                return str(row_val) != val_str and row_val != _try_convert(val_str)
            elif op == ">":
                return float(row_val) > float(_try_convert(val_str))
            elif op == "<":
                return float(row_val) < float(_try_convert(val_str))
            elif op == ">=":
                return float(row_val) >= float(_try_convert(val_str))
            elif op == "<=":
                return float(row_val) <= float(_try_convert(val_str))
            elif op.upper() == "CONTAINS":
                return val_str.lower() in str(row_val).lower()
            elif op.upper() == "STARTS_WITH":
                return str(row_val).lower().startswith(val_str.lower())
            elif op.upper() == "ENDS_WITH":
                return str(row_val).lower().endswith(val_str.lower())
            elif op.upper() == "IN":
                values = [v.strip().strip('"').strip("'") for v in val_str.split(",")]
                return str(row_val) in values
            elif op.upper() == "NOT_IN":
                values = [v.strip().strip('"').strip("'") for v in val_str.split(",")]
                return str(row_val) not in values
        except (ValueError, TypeError):
            return False

    return True


def _try_convert(val: str) -> Any:
    """Try to convert string to number."""
    try:
        if "." in val:
            return float(val)
        return int(val)
    except (ValueError, TypeError):
        return val


def _transform_filter(data: List[Dict], args: Dict) -> List[Dict]:
    """Filter rows by condition."""
    condition = args.get("condition", "")
    if not condition:
        return data
    return [row for row in data if _parse_condition(condition, row)]


def _transform_sort(data: List[Dict], args: Dict) -> List[Dict]:
    """Sort data by columns."""
    sort_by = args.get("sort_by", "")
    if not sort_by:
        return data

    sort_cols = []
    for col_spec in sort_by.split(","):
        col_spec = col_spec.strip()
        if col_spec.startswith("-"):
            sort_cols.append((col_spec[1:], True))  # descending
        else:
            sort_cols.append((col_spec, False))  # ascending

    def sort_key(row):
        key = []
        for col, desc in sort_cols:
            val = row.get(col, "")
            # Try numeric sort
            try:
                val = float(val) if val is not None else 0
            except (ValueError, TypeError):
                val = str(val) if val is not None else ""
            key.append(val)
        return key

    # Multi-column sort (reverse order for stable sort)
    result = list(data)
    for col, desc in reversed(sort_cols):
        result.sort(key=lambda row: _sort_val(row.get(col)), reverse=desc)

    return result


def _sort_val(val: Any) -> Any:
    """Convert value for sorting."""
    if val is None:
        return (0, "")
    try:
        return (1, float(val))
    except (ValueError, TypeError):
        return (2, str(val))


def _transform_aggregate(data: List[Dict], args: Dict) -> List[Dict]:
    """Group by and aggregate data."""
    group_by = args.get("group_by", "")
    agg_function = args.get("agg_function", "count")
    agg_column = args.get("agg_column", "")

    if not group_by:
        return data

    group_cols = [c.strip() for c in group_by.split(",")]

    # Group data
    groups: Dict[tuple, List[Dict]] = {}
    for row in data:
        key = tuple(str(row.get(col, "")) for col in group_cols)
        if key not in groups:
            groups[key] = []
        groups[key].append(row)

    result = []
    for key, rows in groups.items():
        row_result = {col: key[i] for i, col in enumerate(group_cols)}

        if agg_function == "count":
            row_result["count"] = len(rows)
        elif agg_function == "count_distinct":
            if agg_column:
                distinct_vals = set(str(r.get(agg_column, "")) for r in rows)
                row_result[f"count_distinct_{agg_column}"] = len(distinct_vals)
            else:
                row_result["count"] = len(rows)
        elif agg_function == "sum" and agg_column:
            total = sum(float(r.get(agg_column, 0) or 0) for r in rows)
            row_result[f"sum_{agg_column}"] = round(total, 2)
        elif agg_function == "avg" and agg_column:
            vals = [float(r.get(agg_column, 0) or 0) for r in rows]
            row_result[f"avg_{agg_column}"] = round(sum(vals) / len(vals), 2) if vals else 0
        elif agg_function == "min" and agg_column:
            vals = [r.get(agg_column) for r in rows if r.get(agg_column) is not None]
            row_result[f"min_{agg_column}"] = min(vals, default=None)
        elif agg_function == "max" and agg_column:
            vals = [r.get(agg_column) for r in rows if r.get(agg_column) is not None]
            row_result[f"max_{agg_column}"] = max(vals, default=None)

        result.append(row_result)

    return result


def _transform_deduplicate(data: List[Dict], args: Dict) -> List[Dict]:
    """Remove duplicate rows."""
    columns = args.get("columns", "")
    if columns:
        key_cols = [c.strip() for c in columns.split(",")]
    else:
        key_cols = None

    seen = set()
    result = []
    for row in data:
        if key_cols:
            key = tuple(str(row.get(col, "")) for col in key_cols)
        else:
            key = tuple(sorted((k, str(v)) for k, v in row.items()))

        if key not in seen:
            seen.add(key)
            result.append(row)

    return result


def _transform_select_columns(data: List[Dict], args: Dict) -> List[Dict]:
    """Select specific columns."""
    columns = args.get("columns", "")
    if not columns:
        return data
    # v1.9.0: Handle both list and string input
    if isinstance(columns, list):
        cols = [c.strip() for c in columns if c.strip()]
    else:
        cols = [c.strip() for c in columns.split(",") if c.strip()]
    return [{k: row.get(k) for k in cols if k in row} for row in data]


def _transform_rename_columns(data: List[Dict], args: Dict) -> List[Dict]:
    """Rename columns."""
    rename_map = args.get("rename_map", {})
    if not rename_map:
        return data
    result = []
    for row in data:
        new_row = {}
        for k, v in row.items():
            new_key = rename_map.get(k, k)
            new_row[new_key] = v
        result.append(new_row)
    return result


def _transform_add_column(data: List[Dict], args: Dict) -> List[Dict]:
    """Add a computed column."""
    new_col = args.get("new_column_name", "computed")
    expression = args.get("expression", "")
    if not expression:
        return data

    result = []
    for row in data:
        new_row = dict(row)
        try:
            # Replace {col} references with actual values
            eval_expr = expression
            for col_name, col_val in row.items():
                placeholder = "{" + col_name + "}"
                if placeholder in eval_expr:
                    if isinstance(col_val, (int, float)):
                        eval_expr = eval_expr.replace(placeholder, str(col_val))
                    else:
                        eval_expr = eval_expr.replace(placeholder, repr(str(col_val)))

            # Safe eval
            val = eval(eval_expr, {"__builtins__": {}}, {})
            new_row[new_col] = val
        except Exception:
            new_row[new_col] = None
        result.append(new_row)

    return result


def _transform_enrich_with_groups(data: List[Dict], args: Dict) -> List[Dict]:
    """Add 'groups' column to user data using groups_bulk mapping.

    v1.9.0: New transform action for enriching user data with group membership.
    v1.9.5: Add group_count column. Auto-find __groups_bulk_map__ snapshot
            when no explicit groups_data/groups_snapshot is provided.
    """
    groups_mapping_str = args.get("groups_data", "") or args.get("mapping", "") or args.get("column_name", "")
    column_name = args.get("new_column_name", "groups")

    # Parse groups mapping - can be JSON dict or JSON string
    groups_map: Dict[str, Any] = {}
    if groups_mapping_str:
        try:
            parsed = json.loads(groups_mapping_str) if isinstance(groups_mapping_str, str) else groups_mapping_str
            if isinstance(parsed, dict):
                groups_map = parsed
        except (json.JSONDecodeError, TypeError):
            pass

    # If no groups_data, try to find it in snapshot
    if not groups_map:
        groups_snap = args.get("groups_snapshot", "")
        if groups_snap:
            snap_data = _get_snapshot(groups_snap)
            if snap_data and isinstance(snap_data, dict):
                groups_map = snap_data

    # v1.9.5: Auto-find __groups_bulk_map__ snapshot (saved by groups_bulk, from_ad_users, include_groups)
    if not groups_map:
        auto_map = _get_snapshot("__groups_bulk_map__")
        if auto_map and isinstance(auto_map, dict):
            groups_map = auto_map
            logger.info("[AI-DATA] enrich_with_groups: auto-found __groups_bulk_map__ with %d users", len(groups_map))

    result = []
    for row in data:
        new_row = dict(row)
        # Try to find the username in the groups map
        username = str(row.get("sAMAccountName", "") or row.get("cn", "") or row.get("name", ""))
        if username and username in groups_map:
            groups_val = groups_map[username]
            if isinstance(groups_val, list):
                new_row[column_name] = ", ".join(str(g) for g in groups_val) if groups_val else ""
                # v1.9.5: Add group_count for easy charting
                new_row["group_count"] = len(groups_val)
            else:
                new_row[column_name] = str(groups_val) if groups_val else ""
                new_row["group_count"] = 1 if groups_val else 0
        else:
            new_row[column_name] = ""
            new_row["group_count"] = 0
        result.append(new_row)

    return result


def _transform_merge(data: List[Dict], args: Dict) -> List[Dict]:
    """Merge two datasets by key column."""
    merge_data_str = args.get("merge_data", "")
    merge_key = args.get("merge_key", "")
    merge_how = args.get("merge_how", "left")

    if not merge_data_str or not merge_key:
        return data

    try:
        merge_data = json.loads(merge_data_str)
        if not isinstance(merge_data, list):
            merge_data = [merge_data]
    except json.JSONDecodeError:
        return data

    # Build lookup from merge_data
    lookup: Dict[str, Dict] = {}
    for row in merge_data:
        key_val = str(row.get(merge_key, ""))
        lookup[key_val] = row

    result = []
    left_keys_in_result = set()

    for row in data:
        key_val = str(row.get(merge_key, ""))
        left_keys_in_result.add(key_val)
        new_row = dict(row)

        if key_val in lookup:
            for k, v in lookup[key_val].items():
                if k != merge_key and k not in new_row:
                    new_row[k] = v

        if merge_how in ("left", "outer"):
            result.append(new_row)

    # Add right-only rows for outer join
    if merge_how in ("right", "outer"):
        for key_val, merge_row in lookup.items():
            if key_val not in left_keys_in_result:
                new_row = {merge_key: key_val}
                for k, v in merge_row.items():
                    new_row[k] = v
                result.append(new_row)

    if merge_how == "inner":
        # Only rows that matched
        result_filtered = []
        for row in data:
            key_val = str(row.get(merge_key, ""))
            if key_val in lookup:
                new_row = dict(row)
                for k, v in lookup[key_val].items():
                    if k != merge_key and k not in new_row:
                        new_row[k] = v
                result_filtered.append(new_row)
        return result_filtered

    return result


def _transform_pivot(data: List[Dict], args: Dict) -> List[Dict]:
    """Create pivot table from data."""
    pivot_rows = args.get("pivot_rows", "")
    pivot_cols = args.get("pivot_cols", "")
    pivot_values = args.get("pivot_values", "")
    pivot_agg = args.get("pivot_agg", "count")

    if not pivot_rows:
        return data

    # Group by row and column
    pivot_data: Dict[tuple, Dict[tuple, List]] = {}
    col_keys = set()

    for row in data:
        row_key = tuple(str(row.get(c, "")) for c in pivot_rows.split(","))
        col_key = str(row.get(pivot_cols, "")) if pivot_cols else "value"
        col_keys.add(col_key)

        if row_key not in pivot_data:
            pivot_data[row_key] = {}
        if col_key not in pivot_data[row_key]:
            pivot_data[row_key][col_key] = []
        pivot_data[row_key][col_key].append(row)

    result = []
    row_cols = [c.strip() for c in pivot_rows.split(",")]

    for row_key, col_groups in pivot_data.items():
        new_row = {row_cols[i]: row_key[i] for i in range(len(row_cols))}

        for col_key in sorted(col_keys):
            items = col_groups.get(col_key, [])
            if pivot_agg == "count":
                val = len(items)
            elif pivot_agg == "sum" and pivot_values:
                val = sum(float(r.get(pivot_values, 0) or 0) for r in items)
            elif pivot_agg == "avg" and pivot_values:
                vals = [float(r.get(pivot_values, 0) or 0) for r in items]
                val = round(sum(vals) / len(vals), 2) if vals else 0
            else:
                val = len(items)

            new_row[col_key] = val

        result.append(new_row)

    return result


def _transform_stats(data: List[Dict], args: Dict) -> List[Dict]:
    """Compute statistics for numeric columns."""
    columns_str = args.get("columns", "")

    # Find numeric columns
    if columns_str:
        cols = [c.strip() for c in columns_str.split(",")]
    else:
        # Auto-detect numeric columns
        cols = []
        if data:
            for col, val in data[0].items():
                if isinstance(val, (int, float)):
                    cols.append(col)

    result = []
    for col in cols:
        values = []
        for row in data:
            v = row.get(col)
            if v is not None:
                try:
                    values.append(float(v))
                except (ValueError, TypeError):
                    pass

        if not values:
            result.append({"column": col, "count": 0, "error": "no numeric values"})
            continue

        values.sort()
        n = len(values)
        mean = sum(values) / n
        median = values[n // 2] if n % 2 else (values[n // 2 - 1] + values[n // 2]) / 2

        stats_row = {
            "column": col,
            "count": n,
            "mean": round(mean, 4),
            "median": round(median, 4),
            "min": min(values),
            "max": max(values),
            "sum": round(sum(values), 4),
            "std": round((sum((x - mean) ** 2 for x in values) / n) ** 0.5, 4) if n > 1 else 0,
        }
        result.append(stats_row)

    return result


def _transform_batch(args: Dict[str, Any], initial_data: List[Dict]) -> str:
    """Execute multiple transform operations in sequence (Task Constructor).

    Each step's output becomes the next step's input. This allows executing
    many tasks with a single request, reducing AI agent steps.
    """
    batch_steps = args.get("batch_steps", [])
    save_as = args.get("save_as", "")

    if not batch_steps:
        return json.dumps({"error": "batch_steps is required for batch action"})

    # Use initial_data passed from _data_transform_impl
    current_data = initial_data
    results_per_step = []

    for i, step in enumerate(batch_steps):
        step_action = step.get("action", "")
        if not step_action:
            results_per_step.append({"step": i + 1, "error": "missing action"})
            continue

        # Execute each step by calling the appropriate transform function
        step_args = dict(step)

        try:
            if step_action in ("filter",):
                condition = step_args.get("condition", "")
                if condition:
                    current_data = [row for row in current_data if _parse_condition(condition, row)]
                results_per_step.append({"step": i + 1, "action": step_action, "rows_after": len(current_data)})

            elif step_action in ("sort",):
                sort_by = step_args.get("sort_by", "")
                if sort_by:
                    sort_cols = []
                    for col_spec in sort_by.split(","):
                        col_spec = col_spec.strip()
                        if col_spec.startswith("-"):
                            sort_cols.append((col_spec[1:], True))
                        else:
                            sort_cols.append((col_spec, False))
                    result = list(current_data)
                    for col, desc in reversed(sort_cols):
                        result.sort(key=lambda row: _sort_val(row.get(col)), reverse=desc)
                    current_data = result
                results_per_step.append({"step": i + 1, "action": step_action, "rows_after": len(current_data)})

            elif step_action in ("aggregate", "group_by"):
                current_data = _transform_aggregate(current_data, step_args)
                results_per_step.append({"step": i + 1, "action": step_action, "rows_after": len(current_data)})

            elif step_action in ("select_columns", "select"):
                cols_str = step_args.get("columns", step_args.get("column", ""))
                if cols_str:
                    if isinstance(cols_str, list):
                        cols = [c.strip() for c in cols_str if c.strip()]
                    else:
                        cols = [c.strip() for c in cols_str.split(",") if c.strip()]
                    current_data = [{k: row.get(k) for k in cols if k in row} for row in current_data]
                results_per_step.append({"step": i + 1, "action": step_action, "rows_after": len(current_data)})

            elif step_action in ("rename_columns", "rename"):
                rename_map = step_args.get("rename_map", {})
                if rename_map:
                    new_data = []
                    for row in current_data:
                        new_row = {}
                        for k, v in row.items():
                            new_key = rename_map.get(k, k)
                            new_row[new_key] = v
                        new_data.append(new_row)
                    current_data = new_data
                results_per_step.append({"step": i + 1, "action": step_action, "rows_after": len(current_data)})

            elif step_action in ("add_column", "derive"):
                current_data = _transform_add_column(current_data, step_args)
                results_per_step.append({"step": i + 1, "action": step_action, "rows_after": len(current_data)})

            elif step_action in ("deduplicate",):
                current_data = _transform_deduplicate(current_data, step_args)
                results_per_step.append({"step": i + 1, "action": step_action, "rows_after": len(current_data)})

            elif step_action in ("stats",):
                current_data = _transform_stats(current_data, step_args)
                results_per_step.append({"step": i + 1, "action": step_action, "rows_after": len(current_data)})
                break  # stats returns a summary, stop further processing

            elif step_action in ("enrich_with_groups", "enrich"):
                current_data = _transform_enrich_with_groups(current_data, step_args)
                results_per_step.append({"step": i + 1, "action": step_action, "rows_after": len(current_data)})

            elif step_action in ("merge",):
                current_data = _transform_merge(current_data, step_args)
                results_per_step.append({"step": i + 1, "action": step_action, "rows_after": len(current_data)})

            elif step_action in ("pivot",):
                current_data = _transform_pivot(current_data, step_args)
                results_per_step.append({"step": i + 1, "action": step_action, "rows_after": len(current_data)})

            else:
                results_per_step.append({"step": i + 1, "error": f"unknown action: {step_action}"})
                continue

        except Exception as exc:
            results_per_step.append({"step": i + 1, "action": step_action, "error": str(exc)})
            break

    # Save result
    if save_as:
        _save_snapshot(save_as, current_data)

    # Detect fields
    fields_info = _detect_fields(current_data) if current_data else {"fields": [], "total_columns": 0}

    result_data = {
        "success": True,
        "action": "batch",
        "steps_executed": len(results_per_step),
        "steps_detail": results_per_step,
        "rows": len(current_data),
        "fields": fields_info.get("fields", [])[:20],
        "total_fields": fields_info.get("total_columns", 0),
        "columns": list(current_data[0].keys()) if current_data else [],
        "preview": current_data[:5],
        "snapshot_saved": bool(save_as),
    }
    return json.dumps(result_data, ensure_ascii=False, default=str)


# ═══════════════════════════════════════════════════════════════════════
#  Data Diagram Implementation
# ═══════════════════════════════════════════════════════════════════════


def _data_diagram_impl(args: Dict[str, Any]) -> str:
    """Implement data_diagram tool."""
    action = args.get("action", "bar")
    data_str = args.get("data", "")
    snapshot_name = args.get("snapshot_name", "")
    filename = args.get("filename", "")

    settings = get_settings()
    export_dir = getattr(settings, "AI_AGENT_EXPORT_DIR", "/home/AD-API-USER/ai-exports")
    os.makedirs(export_dir, exist_ok=True)

    # Get data
    data = None
    if snapshot_name:
        data = _get_snapshot(snapshot_name)
        if data is None:
            return json.dumps({"error": f"Snapshot '{snapshot_name}' not found"})

    if data is None and data_str:
        try:
            parsed = json.loads(data_str)
            data = parsed if isinstance(parsed, list) else [parsed]
        except json.JSONDecodeError:
            return json.dumps({"error": "Invalid JSON in data parameter"})

    if data is None:
        return json.dumps({"error": "No data provided"})

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import matplotlib.font_manager as fm

        # Setup fonts for Russian/CJK support — resilient font discovery.
        # Try multiple known paths; skip any that don't exist on this host.
        _FONT_CANDIDATES = [
            # Variable font (common on newer distros)
            "/usr/share/fonts/truetype/chinese/NotoSansSC[wght].ttf",
            # Static weight variants (common on older/minimal installs)
            "/usr/share/fonts/truetype/chinese/NotoSansSC-Regular.ttf",
            "/usr/share/fonts/truetype/chinese/NotoSansSC-Bold.ttf",
            # Noto Serif SC fallback (always available if Noto CJK is installed)
            "/usr/share/fonts/truetype/noto-serif-sc/NotoSerifSC-Regular.ttf",
            # LXGW WenKai — Chinese handwriting font (good CJK coverage)
            "/usr/share/fonts/truetype/lxgw-wenkai/LXGWWenKai-Regular.ttf",
            # Sarasa Mono SC — another CJK-capable font
            "/usr/share/fonts/truetype/chinese/SarasaMonoSC-Regular.ttf",
        ]
        _cjk_font_family = None
        for _fpath in _FONT_CANDIDATES:
            if os.path.isfile(_fpath):
                try:
                    fm.fontManager.addfont(_fpath)
                    # Derive family name from the first successfully loaded CJK font
                    if _cjk_font_family is None:
                        _prop = fm.FontProperties(fname=_fpath)
                        _cjk_font_family = _prop.get_name()
                except Exception:
                    pass  # Skip unreadable font files

        # DejaVu Sans — reliable fallback for Latin + symbols
        _dejavu_path = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
        if os.path.isfile(_dejavu_path):
            try:
                fm.fontManager.addfont(_dejavu_path)
            except Exception:
                pass

        # Build font.sans-serif list: CJK first, then DejaVu for Latin/symbols
        _sans = []
        if _cjk_font_family:
            _sans.append(_cjk_font_family)
        _sans.append("DejaVu Sans")
        # System-level fallbacks (matplotlib discovers these automatically)
        _sans.extend(["Liberation Sans", "FreeSans"])
        plt.rcParams["font.sans-serif"] = _sans
        plt.rcParams["axes.unicode_minus"] = False

    except ImportError:
        return json.dumps({"error": "Diagram creation requires matplotlib. Install: pip install matplotlib"})

    if not filename:
        filename = _auto_filename("png")
    safe_filename = os.path.basename(filename)
    if not safe_filename.endswith(".png"):
        safe_filename += ".png"
    filepath = os.path.join(export_dir, safe_filename)

    try:
        figsize_str = args.get("figsize", "12,7")
        fig_width, fig_height = [float(x.strip()) for x in figsize_str.split(",")]

        if action == "multi_chart":
            return _create_multi_chart(plt, data, args, filepath, fig_width, fig_height)
        elif action == "table":
            return _create_table_diagram(plt, data, args, filepath, fig_width, fig_height)

        x_column = args.get("x_column", "")
        y_column = args.get("y_column", "")
        title = args.get("title", "")
        xlabel = args.get("xlabel", "")
        ylabel = args.get("ylabel", "")

        if not x_column and not y_column:
            # Auto-detect: first string column as X, first numeric as Y
            if data:
                for col, val in data[0].items():
                    if isinstance(val, str) and not x_column:
                        x_column = col
                    elif isinstance(val, (int, float)) and not y_column:
                        y_column = col

        fig, ax = plt.subplots(figsize=(fig_width, fig_height))

        x_values = [str(row.get(x_column, "")) for row in data] if x_column else list(range(len(data)))
        y_values = [row.get(y_column, 0) for row in data] if y_column else [1] * len(data)
        # Convert to numeric
        y_numeric = []
        for v in y_values:
            try:
                y_numeric.append(float(v) if v is not None else 0)
            except (ValueError, TypeError):
                y_numeric.append(0)

        colors_str = args.get("colors", "")
        color_list = [c.strip() for c in colors_str.split(",") if c.strip()] if colors_str else None

        if action == "bar":
            horizontal = args.get("horizontal", False)
            show_values = args.get("show_values", True)
            if horizontal:
                bars = ax.barh(x_values, y_numeric, color=color_list or "#4472C4")
                if show_values:
                    ax.bar_label(bars, fmt="%.1f", padding=3)
            else:
                bars = ax.bar(x_values, y_numeric, color=color_list or "#4472C4")
                if show_values:
                    ax.bar_label(bars, fmt="%.1f", padding=3)
            ax.set_title(title or "Bar Chart")
            ax.set_xlabel(xlabel or x_column)
            ax.set_ylabel(ylabel or y_column)
            plt.xticks(rotation=45, ha="right")

        elif action == "line":
            ax.plot(x_values, y_numeric, marker="o", color=color_list[0] if color_list else "#4472C4", linewidth=2)
            ax.set_title(title or "Line Chart")
            ax.set_xlabel(xlabel or x_column)
            ax.set_ylabel(ylabel or y_column)
            plt.xticks(rotation=45, ha="right")
            ax.grid(True, alpha=0.3)

        elif action == "pie":
            show_values = args.get("show_values", True)
            ax.pie(
                y_numeric,
                labels=x_values,
                autopct="%1.1f%%" if show_values else None,
                colors=color_list or None,
                startangle=90,
            )
            ax.set_title(title or "Pie Chart")

        elif action == "scatter":
            ax.scatter(x_values, y_numeric, color=color_list[0] if color_list else "#4472C4", s=50, alpha=0.7)
            ax.set_title(title or "Scatter Plot")
            ax.set_xlabel(xlabel or x_column)
            ax.set_ylabel(ylabel or y_column)
            ax.grid(True, alpha=0.3)

        elif action == "histogram":
            bins = args.get("bins", 20)
            ax.hist(y_numeric, bins=bins, color=color_list[0] if color_list else "#4472C4", edgecolor="white")
            ax.set_title(title or "Histogram")
            ax.set_xlabel(xlabel or y_column)
            ax.set_ylabel("Count")
            ax.grid(True, alpha=0.3)

        plt.tight_layout()
        plt.savefig(filepath, dpi=150, bbox_inches="tight")
        plt.close()

        size = os.path.getsize(filepath)
        return json.dumps({
            "success": True,
            "path": os.path.abspath(filepath),
            "filename": safe_filename,
            "size_bytes": size,
            "chart_type": action,
        }, ensure_ascii=False)

    except Exception as exc:
        logger.error("[AI-DATA-DIAGRAM] Failed: %s", exc)
        return json.dumps({"error": f"Diagram creation failed: {exc}"})


def _create_multi_chart(
    plt,
    data: List[Dict],
    args: Dict,
    filepath: str,
    fig_width: float,
    fig_height: float,
) -> str:
    """Create multiple charts in one image."""
    charts = args.get("charts", [])
    if not charts:
        return json.dumps({"error": "No chart specs provided in 'charts' parameter"})

    n_charts = len(charts)
    n_cols = min(2, n_charts)
    n_rows = (n_charts + n_cols - 1) // n_cols

    fig, axes = plt.subplots(n_rows, n_cols, figsize=(fig_width, fig_height * n_rows / 2))
    if n_charts == 1:
        axes = [axes]
    else:
        axes = axes.flatten() if hasattr(axes, "flatten") else [axes]

    for i, chart_spec in enumerate(charts):
        if i >= len(axes):
            break
        ax = axes[i]
        chart_type = chart_spec.get("type", "bar")
        x_col = chart_spec.get("x_column", "")
        y_col = chart_spec.get("y_column", "")
        chart_title = chart_spec.get("title", "")

        x_values = [str(row.get(x_col, "")) for row in data] if x_col else list(range(len(data)))
        y_values = []
        for row in data:
            if y_col:
                try:
                    y_values.append(float(row.get(y_col, 0) or 0))
                except (ValueError, TypeError):
                    y_values.append(0)
            else:
                y_values.append(1)

        if chart_type == "bar":
            ax.bar(x_values, y_values, color="#4472C4")
        elif chart_type == "line":
            ax.plot(x_values, y_values, marker="o", color="#4472C4")
        elif chart_type == "pie":
            ax.pie(y_values, labels=x_values, autopct="%1.1f%%", startangle=90)
            ax.set_title(chart_title)
            continue
        elif chart_type == "scatter":
            ax.scatter(x_values, y_values, color="#4472C4", s=30, alpha=0.7)

        ax.set_title(chart_title)
        ax.tick_params(axis="x", rotation=45)

    # Hide unused subplots
    for j in range(n_charts, len(axes)):
        axes[j].set_visible(False)

    plt.tight_layout()
    plt.savefig(filepath, dpi=150, bbox_inches="tight")
    plt.close()

    size = os.path.getsize(filepath)
    return json.dumps({
        "success": True,
        "path": os.path.abspath(filepath),
        "filename": os.path.basename(filepath),
        "size_bytes": size,
        "chart_type": "multi_chart",
        "charts_count": n_charts,
    }, ensure_ascii=False)


def _create_table_diagram(
    plt,
    data: List[Dict],
    args: Dict,
    filepath: str,
    fig_width: float,
    fig_height: float,
) -> str:
    """Create a formatted table image from data."""
    columns_str = args.get("columns", "")
    max_rows = args.get("max_rows", 30)
    title = args.get("title", "")

    if columns_str:
        cols = [c.strip() for c in columns_str.split(",")]
    else:
        cols = list(OrderedDict.fromkeys(k for row in data for k in row.keys()))[:10]

    display_data = data[:max_rows]

    # Prepare cell text
    cell_text = []
    for row in display_data:
        cell_row = []
        for col in cols:
            val = row.get(col, "")
            val_str = str(val) if val is not None else ""
            if len(val_str) > 40:
                val_str = val_str[:37] + "..."
            cell_row.append(val_str)
        cell_text.append(cell_row)

    fig, ax = plt.subplots(figsize=(fig_width, max(fig_height, 1 + len(display_data) * 0.4)))
    ax.axis("off")

    if title:
        ax.set_title(title, fontsize=14, fontweight="bold", pad=20)

    if cell_text:
        table = ax.table(
            cellText=cell_text,
            colLabels=cols,
            loc="center",
            cellLoc="left",
        )
        table.auto_set_font_size(False)
        table.set_fontsize(9)
        table.auto_set_column_width(list(range(len(cols))))

        # Style header
        for j in range(len(cols)):
            cell = table[0, j]
            cell.set_facecolor("#4472C4")
            cell.set_text_props(color="white", fontweight="bold")

        # Alternating row colors
        for i in range(1, len(cell_text) + 1):
            for j in range(len(cols)):
                cell = table[i, j]
                if i % 2 == 0:
                    cell.set_facecolor("#D6E4F0")

    plt.tight_layout()
    plt.savefig(filepath, dpi=150, bbox_inches="tight")
    plt.close()

    size = os.path.getsize(filepath)
    return json.dumps({
        "success": True,
        "path": os.path.abspath(filepath),
        "filename": os.path.basename(filepath),
        "size_bytes": size,
        "chart_type": "table",
        "rows_displayed": len(display_data),
        "columns": cols,
    }, ensure_ascii=False)


# ═══════════════════════════════════════════════════════════════════════
#  Dispatch Function for Data Tools
# ═══════════════════════════════════════════════════════════════════════


async def dispatch_data_tool_call(
    function_name: str,
    function_args: Dict[str, Any],
) -> str:
    """Route a data tool call to the appropriate implementation."""
    if function_name == "data_import":
        return await _data_import_impl(function_args)
    elif function_name == "data_export":
        return _data_export_impl(function_args)
    elif function_name == "data_transform":
        return _data_transform_impl(function_args)
    elif function_name == "data_diagram":
        return _data_diagram_impl(function_args)
    else:
        return json.dumps({"error": f"Unknown data tool: {function_name}"})
