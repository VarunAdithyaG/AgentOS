"""A robust, local CPU baseline model trained from system_metrics.csv."""

from __future__ import annotations

import csv
import json
import math
import os
import statistics
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any


APP_DIR = Path(__file__).resolve().parent
DEFAULT_HISTORY = APP_DIR / "linux-kernel-module-mychardev" / "linux-kernel-module-mychardev" / "system_metrics.csv"
DEFAULT_USAGE = APP_DIR / "data" / "cpu_agent_usage.json"
MIN_SAMPLES = 30
MIN_HOURLY_SAMPLES = 20
APP_HISTORY_LIMIT = 240
AUTO_STOP_COOLDOWN_SECONDS = 600
TRUSTED_APP_SCORE = 60
TRUST_HISTORY_DAYS = 60


def _quantile(values: list[float], percentile: float) -> float:
    """Return a linearly interpolated quantile without a third-party dependency."""
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * percentile
    lower, upper = math.floor(position), math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


@dataclass(frozen=True)
class CpuProfile:
    source: str
    sample_count: int
    global_median: float
    global_p95: float
    global_mad: float
    hourly: dict[int, tuple[float, float, float, int]]
    trained_at: float


class CpuAgent:
    """Trains and serves a validated CPU-load baseline from local CSV history."""

    def __init__(self, history_path: Path | None = None, usage_path: Path | None = None) -> None:
        self.history_path = history_path or Path(os.getenv("AGENTOS_METRICS_HISTORY", str(DEFAULT_HISTORY)))
        self.usage_path = usage_path or DEFAULT_USAGE
        self._profile: CpuProfile | None = None
        self._file_signature: tuple[int, int] | None = None
        self._policy = self._load_policy()
        self._last_auto_stop: dict[str, float] = {}
        self._policy_dirty = False
        self._last_policy_save = 0.0

    def _load_policy(self) -> dict[str, Any]:
        default = {"auto_stop_enabled": True, "protected_apps": [], "app_samples": {}, "process_samples": {}, "app_trust": {}}
        try:
            with self.usage_path.open(encoding="utf-8") as file:
                stored = json.load(file)
            if not isinstance(stored, dict):
                return default
            protected = [str(name).lower() for name in stored.get("protected_apps", []) if str(name).strip()]
            samples = {
                str(name).lower(): [float(value) for value in values if math.isfinite(float(value)) and float(value) >= 0]
                for name, values in stored.get("app_samples", {}).items()
                if isinstance(values, list)
            }
            process_samples = {
                str(key): [float(value) for value in values if math.isfinite(float(value)) and float(value) >= 0]
                for key, values in stored.get("process_samples", {}).items()
                if isinstance(values, list)
            }
            trust: dict[str, dict[str, Any]] = {}
            raw_trust = stored.get("app_trust", {})
            for raw_name, raw_record in (raw_trust.items() if isinstance(raw_trust, dict) else []):
                if not isinstance(raw_record, dict):
                    continue
                name = str(raw_name).strip().lower()
                if not name:
                    continue
                days = [str(day) for day in raw_record.get("days", []) if str(day).strip()][-TRUST_HISTORY_DAYS:]
                trust[name] = {
                    "days": sorted(set(days)),
                    "normal_checks": max(0, int(raw_record.get("normal_checks", 0))),
                    "high_checks": max(0, int(raw_record.get("high_checks", 0))),
                    "last_seen": str(raw_record.get("last_seen", "")),
                }
            return {
                "auto_stop_enabled": bool(stored.get("auto_stop_enabled", True)),
                "protected_apps": sorted(set(protected)),
                "app_samples": samples,
                "process_samples": process_samples,
                "app_trust": trust,
            }
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return default

    def _save_policy(self, force: bool = False) -> None:
        if not self._policy_dirty and not force:
            return
        if not force and time.time() - self._last_policy_save < 60:
            return
        try:
            self.usage_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.usage_path.with_suffix(".tmp")
            temporary.write_text(json.dumps(self._policy, indent=2, sort_keys=True), encoding="utf-8")
            temporary.replace(self.usage_path)
            self._policy_dirty = False
            self._last_policy_save = time.time()
        except OSError:
            pass

    def protect_app(self, name: str) -> bool:
        normalized = name.strip().lower()
        if not normalized:
            return False
        protected = set(self._policy["protected_apps"])
        protected.add(normalized)
        self._policy["protected_apps"] = sorted(protected)
        self._policy_dirty = True
        self._save_policy(force=True)
        return True

    def _record_app_usage(self, processes: list[dict[str, Any]]) -> None:
        app_samples: dict[str, list[float]] = self._policy["app_samples"]
        process_samples: dict[str, list[float]] = self._policy["process_samples"]
        trust_records: dict[str, dict[str, Any]] = self._policy["app_trust"]
        today = datetime.now().date().isoformat()
        for process in processes:
            try:
                name = str(process["name"]).lower()
                pid = int(process["pid"])
                cpu = float(process["cpu"])
            except (KeyError, TypeError, ValueError):
                continue
            if not name or not math.isfinite(cpu) or cpu < 0:
                continue
            # Evaluate before adding the current sample so a short CPU spike is
            # not immediately learned as the application's normal behaviour.
            was_normal = len(app_samples.get(name, [])) < MIN_HOURLY_SAMPLES or cpu <= self._app_limit(name)
            values = app_samples.setdefault(name, [])
            values.append(cpu)
            del values[:-APP_HISTORY_LIMIT]
            process_key = f"{name}:{pid}"
            pid_values = process_samples.setdefault(process_key, [])
            pid_values.append(cpu)
            del pid_values[:-APP_HISTORY_LIMIT]
            record = trust_records.setdefault(name, {"days": [], "normal_checks": 0, "high_checks": 0, "last_seen": ""})
            days = [str(day) for day in record.get("days", []) if str(day).strip()]
            if today not in days:
                days.append(today)
            record["days"] = sorted(set(days))[-TRUST_HISTORY_DAYS:]
            record["normal_checks"] = min(10_000, int(record.get("normal_checks", 0)) + int(was_normal))
            record["high_checks"] = min(10_000, int(record.get("high_checks", 0)) + int(not was_normal))
            record["last_seen"] = today
            self._policy_dirty = True

    def _ingest_csv_app_usage(self) -> None:
        """Add repeat-use days from newly appended monitor rows to app trust.

        CSV rows identify the top apps but do not contain per-PID CPU values.
        They therefore train daily-use trust only; live process readings remain
        the source of each process's CPU baseline.
        """
        try:
            with self.history_path.open(newline="", encoding="utf-8") as file:
                for row in csv.DictReader(file):
                    try:
                        day = datetime.strptime(str(row.get("timestamp", "")), "%Y-%m-%d %H:%M:%S").date().isoformat()
                    except (TypeError, ValueError):
                        continue
                    for raw_name in str(row.get("top_apps", "")).split(","):
                        name = raw_name.strip().lower()
                        if not name:
                            continue
                        record = self._policy["app_trust"].setdefault(name, {"days": [], "normal_checks": 0, "high_checks": 0, "last_seen": ""})
                        days = [str(value) for value in record.get("days", []) if str(value).strip()]
                        if day not in days:
                            days.append(day)
                            record["days"] = sorted(set(days))[-TRUST_HISTORY_DAYS:]
                            self._policy_dirty = True
                        record["last_seen"] = max(str(record.get("last_seen", "")), day)
        except (OSError, csv.Error):
            return

    def _trust(self, name: str) -> dict[str, Any]:
        """Score repeat, normal day-to-day use without treating a CPU spike as trust."""
        record = self._policy["app_trust"].get(name.lower(), {})
        days = len(record.get("days", []))
        normal_checks = int(record.get("normal_checks", 0))
        high_checks = int(record.get("high_checks", 0))
        # Repeated days are deliberately worth far more than a single long session.
        score = max(0, min(100, min(60, days * 5) + min(25, normal_checks // 30) - min(30, high_checks * 2)))
        level = "trusted" if score >= TRUSTED_APP_SCORE else "learning" if days >= 3 else "new"
        return {"score": score, "level": level, "days_used": days, "normal_checks": normal_checks}

    def _app_limit(self, name: str) -> float:
        values = self._policy["app_samples"].get(name.lower(), [])
        if len(values) < MIN_HOURLY_SAMPLES:
            return 30.0
        median, _p95, mad = self._stats(values)
        # A median/MAD limit resists a short burst being learned as normal use.
        return max(30.0, median + max(5.0, 3 * 1.4826 * mad))

    def _process_limit(self, name: str, pid: int) -> float:
        values = self._policy["process_samples"].get(f"{name.lower()}:{pid}", [])
        if len(values) < MIN_HOURLY_SAMPLES:
            return 30.0
        median, _p95, mad = self._stats(values)
        return max(30.0, median + max(5.0, 3 * 1.4826 * mad))

    def _auto_stop_candidate(self, current_cpu: float, upper_limit: float,
                             processes: list[dict[str, Any]]) -> dict[str, Any] | None:
        self._record_app_usage(processes)
        # The trigger is the user's learned total-CPU boundary, not a fixed
        # percentage. A process is assessed only when this computer is outside
        # its normal range for the current time of day.
        if not self._policy["auto_stop_enabled"] or current_cpu <= upper_limit:
            self._save_policy()
            return None

        protected = set(self._policy["protected_apps"])
        for process in processes:
            try:
                pid = int(process["pid"])
                name = str(process["name"])
                cpu = float(process["cpu"])
            except (KeyError, TypeError, ValueError):
                continue
            process_history = self._policy["process_samples"].get(f"{name.lower()}:{pid}", [])
            trust = self._trust(name)
            limit = self._process_limit(name, pid)
            trusted = trust["score"] >= TRUSTED_APP_SCORE
            new_process = len(process_history) < MIN_HOURLY_SAMPLES
            # A new PID has no personal range. It is anomalous only if it is
            # responsible for a substantial share of this user's current,
            # already-abnormal CPU load. This is relative to live usage, not a
            # fixed CPU percentage. Browser PIDs are handled the same way.
            new_process_breach = new_process and cpu >= current_cpu * 0.5
            if (name.lower() in protected or not math.isfinite(cpu) or
                    trusted or
                    (new_process and not new_process_breach) or
                    (not new_process and cpu <= limit)):
                continue
            if time.time() - self._last_auto_stop.get(name.lower(), 0) < AUTO_STOP_COOLDOWN_SECONDS:
                continue
            self._last_auto_stop[name.lower()] = time.time()
            self._save_policy(force=True)
            return {
                "pid": pid,
                "name": name,
                "cpu": round(cpu, 1),
                "trust_score": trust["score"],
                "reason": (f"New process accounted for a large share of the unusual {current_cpu:.1f}% total CPU load."
                           if new_process else f"CPU exceeded its learned PID limit of {limit:.1f}% while total CPU was {current_cpu:.1f}%.")
            }
        self._save_policy()
        return None

    @staticmethod
    def _read_samples(path: Path) -> list[tuple[int, float]]:
        now = datetime.now()
        samples: list[tuple[int, float]] = []
        with path.open(newline="", encoding="utf-8") as file:
            for row in csv.DictReader(file):
                try:
                    timestamp = datetime.strptime(str(row["timestamp"]), "%Y-%m-%d %H:%M:%S")
                    cpu = float(str(row["cpu_percent"]))
                except (KeyError, TypeError, ValueError):
                    continue
                # Invalid and future records cannot represent a usable baseline.
                if not math.isfinite(cpu) or cpu < 0 or cpu > 100 or timestamp > now + timedelta(minutes=5):
                    continue
                samples.append((timestamp.hour, cpu))
        return samples

    @staticmethod
    def _stats(values: list[float]) -> tuple[float, float, float]:
        median = float(statistics.median(values))
        mad = float(statistics.median([abs(value - median) for value in values]))
        return median, _quantile(values, 0.95), mad

    def train(self) -> CpuProfile | None:
        """Train the robust baseline, returning None when history is insufficient."""
        try:
            samples = self._read_samples(self.history_path)
        except (OSError, csv.Error):
            self._profile = None
            return None
        if len(samples) < MIN_SAMPLES:
            self._profile = None
            return None

        self._ingest_csv_app_usage()
        all_cpu = [cpu for _, cpu in samples]
        buckets: dict[int, list[float]] = {hour: [] for hour in range(24)}
        for hour, cpu in samples:
            buckets[hour].append(cpu)
        hourly = {
            hour: (*self._stats(values), len(values))
            for hour, values in buckets.items()
            if len(values) >= MIN_HOURLY_SAMPLES
        }
        median, p95, mad = self._stats(all_cpu)
        self._profile = CpuProfile(
            source=str(self.history_path),
            sample_count=len(samples),
            global_median=median,
            global_p95=p95,
            global_mad=mad,
            hourly=hourly,
            trained_at=time.time(),
        )
        return self._profile

    def _current_profile(self) -> CpuProfile | None:
        try:
            stat = self.history_path.stat()
            signature = (stat.st_mtime_ns, stat.st_size)
        except OSError:
            self._profile = None
            self._file_signature = None
            return None
        if self._profile is None or signature != self._file_signature:
            self._file_signature = signature
            return self.train()
        return self._profile

    def assess(self, current_cpu: float, processes: list[dict[str, Any]]) -> dict[str, Any]:
        """Compare a current CPU reading with the trained baseline and explain it."""
        if not math.isfinite(current_cpu) or current_cpu < 0 or current_cpu > 100:
            return {
                "available": False,
                "summary": "CPU Agent rejected an invalid live CPU reading.",
            }
        profile = self._current_profile()
        top = processes[0] if processes else None
        if profile is None:
            return {
                "available": False,
                "summary": "CPU Agent needs at least 30 valid CSV CPU samples before it can train a baseline.",
            }

        hour = datetime.now().hour
        median, p95, mad, hour_samples = profile.hourly.get(
            hour,
            (profile.global_median, profile.global_p95, profile.global_mad, profile.sample_count),
        )
        # MAD is scaled to a normal-distribution equivalent and paired with p95.
        robust_upper = median + 3 * 1.4826 * mad
        upper_limit = min(100.0, max(p95, robust_upper, median + 5.0))
        deviation = current_cpu - median
        status = "elevated" if current_cpu > upper_limit else "above baseline" if current_cpu > median else "normal"
        try:
            source_age = max(0.0, time.time() - self.history_path.stat().st_mtime)
        except OSError:
            source_age = float("inf")
        summary = (
            f"CPU Agent: {current_cpu:.1f}% is {status}. "
            f"Trained baseline for this hour is {median:.1f}%; alert threshold is {upper_limit:.1f}% "
            f"from {hour_samples} validated samples."
        )
        if top:
            summary += f" Top listed process: {top.get('name', 'Unknown')} (PID {top.get('pid', 'unknown')}, {top.get('cpu', 0)}% CPU)."
        candidate = self._auto_stop_candidate(current_cpu, upper_limit, processes)
        app_trust = {
            str(process.get("name", "Unknown")): self._trust(str(process.get("name", "")))
            for process in processes
        }
        preferred_apps = [
            {"pid": int(process["pid"]), "name": str(process["name"]), "trust_score": app_trust[str(process.get("name", "Unknown"))]["score"]}
            for process in processes
            if app_trust[str(process.get("name", "Unknown"))]["score"] >= TRUSTED_APP_SCORE
        ]
        return {
            "available": True,
            "summary": summary,
            "status": status,
            "current_cpu": round(current_cpu, 1),
            "baseline_cpu": round(median, 1),
            "upper_limit": round(upper_limit, 1),
            "deviation": round(deviation, 1),
            "sample_count": profile.sample_count,
            "hour_sample_count": hour_samples,
            "history_fresh": source_age <= 300,
            "source": profile.source,
            "auto_stop_candidate": candidate,
            "protected_apps": list(self._policy["protected_apps"]),
            "app_trust": app_trust,
            "resource_preferences": preferred_apps,
        }
