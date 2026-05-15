"""
Prometheus-style metrics collection and system statistics for the
Samba AD DC Management API server.

All metrics are held in memory — no external time-series dependency is
required.  The ``MetricsCollector`` exposes counters, histograms and gauges
with label support, and can emit data in the Prometheus exposition format
so that a Prometheus server can scrape ``/metrics`` directly.

System-level statistics (CPU, memory, disk, Samba processes) and
Samba-specific statistics (samdb size, replication, object counts) are
collected on demand from ``/proc``, ``ps`` and the local sam.ldb.
"""

from __future__ import annotations

import logging
import os
import subprocess
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Application start time (used for uptime calculation) ────────────────
_APP_START_TIME: float = time.monotonic()
_APP_START_EPOCH: float = time.time()


# =====================================================================
# MetricsCollector — in-memory Prometheus-compatible metrics
# =====================================================================

class MetricsCollector:
    """Thread-safe, in-memory metrics store that can render the
    Prometheus text exposition format.

    Three metric families are supported:

    * **Counter** — monotonically increasing value (e.g. request_count).
    * **Histogram** — distribution of observations with configurable
      buckets (e.g. request_duration).
    * **Gauge** — point-in-time value that can go up or down
      (e.g. active_tasks).

    Each metric is identified by *name* and an optional set of *labels*
    (key-value pairs).  Internally, every unique (name, label-set)
    combination is stored as a separate series.
    """

    # Default histogram buckets (seconds) — matching Prometheus conventions.
    DEFAULT_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0,
                       2.5, 5.0, 10.0, 30.0, 60.0)

    def __init__(self, buckets: Optional[tuple] = None) -> None:
        self._lock = threading.Lock()
        self._counters: Dict[str, Dict[str, float]] = {}
        self._gauges: Dict[str, Dict[str, float]] = {}
        self._histograms: Dict[str, Dict[str, Any]] = {}
        self._buckets = buckets or self.DEFAULT_BUCKETS

    # ── Label helper ──────────────────────────────────────────────────

    @staticmethod
    def _label_key(labels: Dict[str, str]) -> str:
        """Return a deterministic string key from a label dict."""
        if not labels:
            return ""
        return ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))

    @staticmethod
    def _label_str(labels: Dict[str, str]) -> str:
        """Return Prometheus-format label string (including braces)."""
        if not labels:
            return ""
        pairs = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
        return "{" + pairs + "}"

    # ── Counter ───────────────────────────────────────────────────────

    def increment_counter(self, name: str, labels: Optional[Dict[str, str]] = None,
                          value: float = 1.0) -> None:
        """Increment a labelled counter by *value* (default 1)."""
        labels = labels or {}
        key = self._label_key(labels)
        with self._lock:
            series = self._counters.setdefault(name, {})
            series[key] = series.get(key, 0.0) + value

    # ── Histogram ─────────────────────────────────────────────────────

    def observe_histogram(self, name: str, value: float,
                          labels: Optional[Dict[str, str]] = None) -> None:
        """Record *value* into a labelled histogram.

        For each observation the sum, count and per-bucket counts are
        updated.
        """
        labels = labels or {}
        key = self._label_key(labels)
        with self._lock:
            if name not in self._histograms:
                self._histograms[name] = {}
            series = self._histograms[name]
            if key not in series:
                series[key] = {
                    "labels": labels,
                    "buckets": {b: 0 for b in self._buckets},
                    "sum": 0.0,
                    "count": 0,
                    "inf_count": 0,
                }
            entry = series[key]
            entry["sum"] += value
            entry["count"] += 1
            for b in self._buckets:
                if value <= b:
                    entry["buckets"][b] += 1
            entry["inf_count"] += 1  # always in +Inf

    # ── Gauge ─────────────────────────────────────────────────────────

    def set_gauge(self, name: str, value: float,
                  labels: Optional[Dict[str, str]] = None) -> None:
        """Set a labelled gauge to *value*."""
        labels = labels or {}
        key = self._label_key(labels)
        with self._lock:
            series = self._gauges.setdefault(name, {})
            series[key] = value

    # ── Prometheus exposition format ──────────────────────────────────

    def format_prometheus(self) -> str:
        """Render all metrics in the Prometheus text exposition format.

        Output example::

            # HELP http_request_count Total HTTP requests
            # TYPE http_request_count counter
            http_request_count{endpoint="/api/v1/users",method="GET",status="200"} 42

            # HELP http_request_duration Request duration in seconds
            # TYPE http_request_duration histogram
            http_request_duration_bucket{endpoint="/api/v1/users",le="0.1"} 30
            http_request_duration_bucket{endpoint="/api/v1/users",le="+Inf"} 42
            http_request_duration_sum{endpoint="/api/v1/users"} 12.5
            http_request_duration_count{endpoint="/api/v1/users"} 42

            # TYPE active_tasks gauge
            active_tasks 3
        """
        lines: List[str] = []

        with self._lock:
            # Counters
            for name, series in sorted(self._counters.items()):
                lines.append(f"# HELP {name} Total count")
                lines.append(f"# TYPE {name} counter")
                for label_key, val in sorted(series.items()):
                    # Reconstruct label string from stored key
                    label_str = self._reconstruct_labels(name, label_key, "counter")
                    lines.append(f"{name}{label_str} {val}")

            # Histograms
            for name, series in sorted(self._histograms.items()):
                lines.append(f"# HELP {name} Histogram distribution")
                lines.append(f"# TYPE {name} histogram")
                for label_key, entry in sorted(series.items()):
                    labels = entry.get("labels", {})
                    label_prefix = self._label_str(labels)
                    # Replace closing brace to prepend le= bucket label
                    if label_prefix:
                        base = label_prefix[:-1] + ","
                    else:
                        base = "{"
                    for b in self._buckets:
                        bucket_label = f'{base}le="{b}"}}'
                        lines.append(
                            f"{name}_bucket{bucket_label} {entry['buckets'][b]}"
                        )
                    # +Inf bucket
                    inf_label = f'{base}le="+Inf"}}'
                    lines.append(
                        f"{name}_bucket{inf_label} {entry['inf_count']}"
                    )
                    # Sum and count
                    lines.append(f"{name}_sum{label_prefix} {entry['sum']}")
                    lines.append(f"{name}_count{label_prefix} {entry['count']}")

            # Gauges
            for name, series in sorted(self._gauges.items()):
                lines.append(f"# HELP {name} Current value")
                lines.append(f"# TYPE {name} gauge")
                for label_key, val in sorted(series.items()):
                    label_str = self._reconstruct_labels(name, label_key, "gauge")
                    lines.append(f"{name}{label_str} {val}")

        lines.append("")  # trailing newline
        return "\n".join(lines)

    def _reconstruct_labels(self, name: str, label_key: str,
                            metric_type: str) -> str:
        """Try to reconstruct a Prometheus label string from the stored key.

        Falls back to raw key wrapped in braces if parsing fails.
        """
        if not label_key:
            return ""
        # The label key is stored as 'k1="v1",k2="v2"'
        return "{" + label_key + "}"

    # ── Stats dict ────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        """Return a plain-dict summary of all metrics (useful for JSON
        endpoints that don't want Prometheus format)."""
        with self._lock:
            result: Dict[str, Any] = {
                "counters": {
                    name: dict(series)
                    for name, series in self._counters.items()
                },
                "gauges": {
                    name: dict(series)
                    for name, series in self._gauges.items()
                },
                "histograms": {},
            }
            for name, series in self._histograms.items():
                result["histograms"][name] = {
                    lk: {
                        "sum": e["sum"],
                        "count": e["count"],
                        "buckets": dict(e["buckets"]),
                    }
                    for lk, e in series.items()
                }
        return result


# ── Module-level singleton ────────────────────────────────────────────

_metrics: Optional[MetricsCollector] = None


def get_metrics() -> MetricsCollector:
    """Return (and lazily create) the global :class:`MetricsCollector`."""
    global _metrics
    if _metrics is None:
        _metrics = MetricsCollector()
    return _metrics


# =====================================================================
# System-level statistics
# =====================================================================

def get_system_stats() -> Dict[str, Any]:
    """Collect host-level resource statistics.

    Returns a dict with:
      - cpu_percent: float
      - memory_total_mb, memory_used_mb, memory_percent: float
      - disk_total_gb, disk_used_gb, disk_percent: float  (for /var/lib/samba)
      - uptime_seconds: float
      - load_average: str
      - samba_processes: int
    """
    stats: Dict[str, Any] = {}

    # ── CPU ───────────────────────────────────────────────────────────
    try:
        import psutil  # type: ignore
        stats["cpu_percent"] = psutil.cpu_percent(interval=0.5)
    except ImportError:
        # Fallback: read from /proc/stat (Linux-only)
        try:
            stats["cpu_percent"] = _cpu_percent_proc()
        except Exception:
            stats["cpu_percent"] = 0.0

    # ── Memory ────────────────────────────────────────────────────────
    try:
        import psutil  # type: ignore
        mem = psutil.virtual_memory()
        stats["memory_total_mb"] = round(mem.total / (1024 * 1024), 1)
        stats["memory_used_mb"] = round(mem.used / (1024 * 1024), 1)
        stats["memory_percent"] = round(mem.percent, 1)
    except ImportError:
        try:
            mt, mu, mp = _memory_info_proc()
            stats["memory_total_mb"] = mt
            stats["memory_used_mb"] = mu
            stats["memory_percent"] = mp
        except Exception:
            stats["memory_total_mb"] = 0.0
            stats["memory_used_mb"] = 0.0
            stats["memory_percent"] = 0.0

    # ── Disk (/var/lib/samba) ────────────────────────────────────────
    samba_path = "/var/lib/samba"
    try:
        import psutil  # type: ignore
        disk = psutil.disk_usage(samba_path)
        stats["disk_total_gb"] = round(disk.total / (1024 ** 3), 2)
        stats["disk_used_gb"] = round(disk.used / (1024 ** 3), 2)
        stats["disk_percent"] = round(disk.percent, 1)
    except ImportError:
        try:
            dt, du, dp = _disk_usage_statvfs(samba_path)
            stats["disk_total_gb"] = dt
            stats["disk_used_gb"] = du
            stats["disk_percent"] = dp
        except Exception:
            stats["disk_total_gb"] = 0.0
            stats["disk_used_gb"] = 0.0
            stats["disk_percent"] = 0.0

    # ── Uptime ────────────────────────────────────────────────────────
    stats["uptime_seconds"] = round(time.monotonic() - _APP_START_TIME, 1)

    # ── Load average ──────────────────────────────────────────────────
    try:
        load1, load5, load15 = os.getloadavg()
        stats["load_average"] = f"{load1:.2f} {load5:.2f} {load15:.2f}"
    except Exception:
        stats["load_average"] = "N/A"

    # ── Samba processes ───────────────────────────────────────────────
    stats["samba_processes"] = _count_samba_processes()

    return stats


def _cpu_percent_proc() -> float:
    """Calculate CPU usage from /proc/stat (Linux fallback)."""
    def _read_cpu_times() -> list[int]:
        with open("/proc/stat", "r") as f:
            line = f.readline()
        parts = line.split()[1:]  # skip "cpu"
        return [int(p) for p in parts]

    t1 = _read_cpu_times()
    time.sleep(0.5)
    t2 = _read_cpu_times()

    d_idle = t2[3] - t1[3]
    d_total = sum(t2) - sum(t1)
    if d_total == 0:
        return 0.0
    return round((1.0 - d_idle / d_total) * 100.0, 1)


def _memory_info_proc() -> tuple[float, float, float]:
    """Read memory info from /proc/meminfo (Linux fallback)."""
    info: Dict[str, int] = {}
    with open("/proc/meminfo", "r") as f:
        for line in f:
            parts = line.split()
            key = parts[0].rstrip(":")
            value = int(parts[1])  # in kB
            info[key] = value
    total = info.get("MemTotal", 0) / 1024  # kB -> MB
    available = info.get("MemAvailable", 0) / 1024
    used = total - available
    percent = round((used / total) * 100, 1) if total > 0 else 0.0
    return round(total, 1), round(used, 1), percent


def _disk_usage_statvfs(path: str) -> tuple[float, float, float]:
    """Read disk usage via os.statvfs (portable fallback)."""
    st = os.statvfs(path)
    total = st.f_blocks * st.f_frsize
    free = st.f_bfree * st.f_frsize
    used = total - free
    percent = round((used / total) * 100, 1) if total > 0 else 0.0
    return (
        round(total / (1024 ** 3), 2),
        round(used / (1024 ** 3), 2),
        percent,
    )


def _count_samba_processes() -> int:
    """Count running samba, smbd, and winbindd processes."""
    count = 0
    try:
        result = subprocess.run(
            ["ps", "-eo", "comm"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                name = line.strip()
                if name in ("samba", "smbd", "winbindd", "samba_dc"):
                    count += 1
    except Exception:
        pass
    return count


# =====================================================================
# Samba-specific statistics
# =====================================================================

def get_samba_stats() -> Dict[str, Any]:
    """Collect Samba AD DC specific statistics.

    Returns a dict with:
      - samdb_size_mb: float
      - ldb_connections: int
      - replication_status: str
      - user_count, group_count, computer_count, ou_count: int
      - dc_hostname, realm, server_role: str
      - forest_functional_level, domain_functional_level: str
        (Fix v1.6.2: Now populated from msDS-Behavior-Version)

    Fix v1.6.2: Added forest_functional_level and domain_functional_level
    by querying msDS-Behavior-Version from the Partitions container
    (forest level) and the domain head object (domain level), matching
    the approach in ldb_reader.fetch_domain_level().
    """
    stats: Dict[str, Any] = {}

    # ── Functional levels (Fix v1.6.2) ────────────────────────────────
    _LEVEL_MAP: Dict[str, str] = {
        "0": "Windows 2000 Mixed/Native",
        "1": "Windows 2003 Interim",
        "2": "Windows 2003",
        "3": "Windows 2008",
        "4": "Windows 2008 R2",
        "5": "Windows 2012",
        "6": "Windows 2012 R2",
        "7": "Windows 2016",
    }
    stats["forest_functional_level"] = ""
    stats["domain_functional_level"] = ""
    try:
        result = subprocess.run(
            [
                "sudo", "ldbsearch", "-H", "/var/lib/samba/private/sam.ldb",
                "-s", "sub",
                "(|(objectClass=domain)(cn=Partitions))",
                "msDS-Behavior-Version", "dn",
            ],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("msDS-Behavior-Version:"):
                    ver = line.split(":", 1)[1].strip()
                    # We need to determine which object this belongs to
                    # Store temporarily and classify by DN below
                elif line.startswith("dn:"):
                    current_dn = line.split(":", 1)[1].strip()
            # Parse LDIF more carefully
            current_dn = ""
            for line in result.stdout.splitlines():
                stripped = line.strip()
                if stripped.startswith("dn:"):
                    current_dn = stripped.split(":", 1)[1].strip()
                elif stripped.startswith("msDS-Behavior-Version:"):
                    ver = stripped.split(":", 1)[1].strip()
                    level_name = _LEVEL_MAP.get(ver, f"Unknown ({ver})")
                    if "CN=Partitions,CN=Configuration" in current_dn:
                        stats["forest_functional_level"] = level_name
                    elif current_dn.upper().startswith("DC=") and "CN=" not in current_dn.split(",")[0]:
                        stats["domain_functional_level"] = level_name
    except Exception as exc:
        logger.debug("Failed to fetch functional levels: %s", exc)

    # ── samdb size ────────────────────────────────────────────────────
    stats["samdb_size_mb"] = _samdb_size_mb()

    # ── LDB connections ───────────────────────────────────────────────
    stats["ldb_connections"] = _ldb_connection_count()

    # ── Replication status ────────────────────────────────────────────
    stats["replication_status"] = _replication_status()

    # ── Object counts from samdb_direct (if available) ────────────────
    counts = _samdb_object_counts()
    stats["user_count"] = counts.get("user_count", 0)
    stats["group_count"] = counts.get("group_count", 0)
    stats["computer_count"] = counts.get("computer_count", 0)
    stats["ou_count"] = counts.get("ou_count", 0)

    # ── DC identity ───────────────────────────────────────────────────
    try:
        from app.config import get_settings
        settings = get_settings()
        stats["dc_hostname"] = settings.DC_HOSTNAME or os.uname().nodename
        stats["realm"] = settings.REALM or ""
        stats["server_role"] = settings.ensure_server_role()
    except Exception:
        stats["dc_hostname"] = os.uname().nodename
        stats["realm"] = ""
        stats["server_role"] = "unknown"

    return stats


def _samdb_size_mb() -> float:
    """Return the size of sam.ldb in megabytes."""
    for path in (
        "/var/lib/samba/private/sam.ldb",
        "/var/lib/samba/sam.ldb",
    ):
        try:
            size = os.path.getsize(path)
            return round(size / (1024 * 1024), 2)
        except OSError:
            continue
    return 0.0


def _ldb_connection_count() -> int:
    """Count the number of LDB-related file descriptors in the Samba
    process (a rough proxy for active LDAP connections)."""
    count = 0
    try:
        result = subprocess.run(
            ["lsof", "-c", "samba", "-c", "smbd"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if "sam.ldb" in line or "ldapi" in line:
                    count += 1
    except Exception:
        pass
    return count


def _replication_status() -> str:
    """Check the replication status via ``samba-tool drs showrepl``."""
    try:
        result = subprocess.run(
            ["samba-tool", "drs", "showrepl", "--suppress-prompt"],
            capture_output=True, text=True, timeout=30,
        )
        output = result.stdout.lower()
        if result.returncode == 0 and "successful" in output:
            return "ok"
        if "error" in output or "failed" in output:
            return "error"
        if result.returncode != 0:
            return "error"
        return "unknown"
    except FileNotFoundError:
        return "unavailable"
    except subprocess.TimeoutExpired:
        return "timeout"
    except Exception:
        return "unknown"


def _samdb_object_counts() -> Dict[str, int]:
    """Retrieve user, group, computer, and OU counts from the local
    sam.ldb.  Uses ``samdb_direct`` when the samba Python bindings are
    available; falls back to ``samba-tool`` subprocess calls."""
    counts: Dict[str, int] = {}

    # Try direct samdb access first
    try:
        from app.samdb_direct import is_samba_available, _get_samdb
        if is_samba_available():
            samdb = _get_samdb(for_write=False)
            if samdb is not None:
                for attr, ldap_filter in [
                    ("user_count", "(objectClass=user)"),
                    ("group_count", "(objectClass=group)"),
                    ("computer_count", "(objectClass=computer)"),
                    ("ou_count", "(objectClass=organizationalUnit)"),
                ]:
                    try:
                        res = samdb.search(
                            expression=ldap_filter,
                            attrs=["dn"],
                            controls=["domain_scope:1:0"],
                        )
                        counts[attr] = len(res)
                    except Exception:
                        counts[attr] = 0
                return counts
    except Exception:
        pass

    # Fallback: samba-tool subprocess
    for attr, subcmd in [
        ("user_count", ["user", "list"]),
        ("group_count", ["group", "list"]),
        ("computer_count", ["computer", "list"]),
        ("ou_count", ["ou", "list"]),
    ]:
        try:
            result = subprocess.run(
                ["samba-tool", *subcmd, "--suppress-prompt"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                # Each line is one object (skip empty trailing line)
                lines = [l for l in result.stdout.strip().splitlines() if l.strip()]
                counts[attr] = len(lines)
            else:
                counts[attr] = 0
        except Exception:
            counts[attr] = 0

    return counts


# =====================================================================
# Enhanced health check
# =====================================================================

def get_health_detailed() -> Dict[str, Any]:
    """Return a detailed health-check result.

    The dict contains:
      - status: "ok" | "degraded" | "error"
      - ldap_available: bool  (try connecting to samdb)
      - ldap_url_used: str
      - server_role: str
      - worker_pool_size: int
      - active_tasks: int
      - uptime_seconds: float
      - version: str
    """
    result: Dict[str, Any] = {
        "status": "ok",
        "ldap_available": False,
        "ldap_url_used": "",
        "server_role": "unknown",
        "worker_pool_size": 0,
        "active_tasks": 0,
        "uptime_seconds": round(time.monotonic() - _APP_START_TIME, 1),
        "version": "2.8.0",
    }

    issues: List[str] = []

    # ── LDAP availability ─────────────────────────────────────────────
    try:
        from app.config import get_settings
        settings = get_settings()
        ldap_url = settings.LDAPI_URL or settings.LDAP_URL or ""
        result["ldap_url_used"] = ldap_url

        # Try connecting to samdb
        try:
            from app.samdb_direct import is_samba_available, _get_samdb
            if is_samba_available():
                samdb = _get_samdb(for_write=False)
                if samdb is not None:
                    # Perform a trivial search to confirm connectivity
                    samdb.search(expression="(objectClass=*)", attrs=["dn"],
                                 controls=["domain_scope:1:0"], limit=1)
                    result["ldap_available"] = True
                else:
                    issues.append("samdb connection returned None")
            else:
                issues.append("samba Python package not available")
        except RuntimeError as exc:
            issues.append(f"samdb connection error: {exc}")
        except Exception as exc:
            issues.append(f"samdb query error: {exc}")

        result["server_role"] = settings.ensure_server_role()
    except Exception as exc:
        issues.append(f"settings error: {exc}")

    # ── Worker pool ───────────────────────────────────────────────────
    try:
        from app.config import get_settings
        result["worker_pool_size"] = get_settings().WORKER_POOL_SIZE
    except Exception:
        pass

    # ── Active tasks ──────────────────────────────────────────────────
    try:
        from app.tasks import get_task_manager
        tm = get_task_manager()
        task_list = tm.list_tasks()
        result["active_tasks"] = sum(
            1 for t in task_list if t.get("state") in ("PENDING", "RUNNING")
        )
    except Exception:
        pass

    # ── Determine overall status ──────────────────────────────────────
    if not result["ldap_available"]:
        result["status"] = "error" if not issues else "degraded"
    elif issues:
        result["status"] = "degraded"
    else:
        result["status"] = "ok"

    return result
