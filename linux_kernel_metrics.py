"""Read optional, read-only telemetry from the AgentOS Linux kernel module."""

from __future__ import annotations

import csv
import os
import sys
from pathlib import Path
from typing import Any


APP_DIR = Path(__file__).resolve().parent
KERNEL_PROJECT_DIR = APP_DIR / "linux-kernel-module-mychardev" / "linux-kernel-module-mychardev"
DEFAULT_DEVICE = Path("/dev/sysmetrics")
DEFAULT_HISTORY = KERNEL_PROJECT_DIR / "system_metrics.csv"


def _integer(value: str, field: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise ValueError(f"{field} cannot be negative")
    return parsed


def _parse_snapshot(payload: str) -> dict[str, Any]:
    lines = payload.splitlines()
    if not lines or lines[0].strip() != "SYS_METRICS_V1":
        raise ValueError("Unknown sysmetrics device format")
    values: dict[str, str] = {}
    process_entries = 0
    for line in lines[1:]:
        if line.startswith("pid="):
            process_entries += 1
            continue
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    required = ("cpu_online", "cpu_possible", "ram_total_bytes", "ram_free_bytes", "ram_used_bytes", "process_count")
    if any(key not in values for key in required):
        raise ValueError("Incomplete sysmetrics device response")
    return {
        "available": True,
        "source": "kernel module /dev/sysmetrics",
        "cpu_online": _integer(values["cpu_online"], "cpu_online"),
        "cpu_possible": _integer(values["cpu_possible"], "cpu_possible"),
        "ram_total_bytes": _integer(values["ram_total_bytes"], "ram_total_bytes"),
        "ram_free_bytes": _integer(values["ram_free_bytes"], "ram_free_bytes"),
        "ram_used_bytes": _integer(values["ram_used_bytes"], "ram_used_bytes"),
        "process_count": _integer(values["process_count"], "process_count"),
        "listed_processes": process_entries,
        "process_list_truncated": values.get("process_list_truncated") == "yes",
    }


def read_kernel_device(device_path: Path | None = None) -> dict[str, Any]:
    """Return validated kernel telemetry or a non-fatal fallback status."""
    if sys.platform != "linux":
        return {"available": False, "source": "unsupported", "reason": "AgentOS kernel telemetry is Linux-only."}
    selected = device_path or Path(os.getenv("AGENTOS_SYSMETRICS_DEVICE", str(DEFAULT_DEVICE)))
    try:
        # The driver limits a single snapshot to 64 KiB. Limit our read too.
        payload = selected.read_text(encoding="utf-8", errors="replace")[: 64 * 1024]
        data = _parse_snapshot(payload)
        data["device"] = str(selected)
        return data
    except FileNotFoundError:
        return {"available": False, "source": "psutil fallback", "reason": f"Kernel module device {selected} is not loaded."}
    except PermissionError:
        return {"available": False, "source": "psutil fallback", "reason": f"Current user cannot read {selected}."}
    except (OSError, ValueError) as error:
        return {"available": False, "source": "psutil fallback", "reason": f"Kernel telemetry unavailable: {error}"}


def read_recent_monitor_history(history_path: Path | None = None) -> dict[str, Any] | None:
    """Summarise fresh samples from the supplied Linux /proc monitor CSV.

    Stale sample files are deliberately ignored so an old demo CSV cannot
    influence current AgentOS recommendations.
    """
    if sys.platform != "linux":
        return None
    path = history_path or Path(os.getenv("AGENTOS_METRICS_HISTORY", str(DEFAULT_HISTORY)))
    try:
        if not path.is_file() or (path.stat().st_mtime < __import__("time").time() - 300):
            return None
        with path.open(newline="", encoding="utf-8") as file:
            rows = list(csv.DictReader(file))[-12:]
        memory = [float(row["memory_percent"]) for row in rows if row.get("memory_percent")]
        cpu = [float(row["cpu_percent"]) for row in rows if row.get("cpu_percent")]
        if not memory:
            return None
        return {
            "source": str(path),
            "samples": len(memory),
            "memory_average": round(sum(memory) / len(memory), 1),
            "memory_latest": round(memory[-1], 1),
            "memory_change": round(memory[-1] - memory[0], 1),
            "cpu_average": round(sum(cpu) / len(cpu), 1) if cpu else None,
        }
    except (OSError, ValueError, csv.Error):
        return None


def collect_kernel_evidence() -> dict[str, Any]:
    evidence = read_kernel_device()
    evidence["history"] = read_recent_monitor_history()
    return evidence
