"""AgentOS Phase 1: a local, native desktop assistant.

This application intentionally keeps its intelligence and records on the local
computer. It does not send system data to a cloud service and it never executes
an operating-system change without a visible approval step.
"""

from __future__ import annotations

import html
import os
import re
import sqlite3
import sys
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import psutil
from PySide6.QtCore import QEasingCurve, QParallelAnimationGroup, QPropertyAnimation, QRect, Qt, QTimer, QUrl
from PySide6.QtGui import QAction, QDesktopServices
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QSplitter,
    QStyle,
    QSystemTrayIcon,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from agentos_graph import AgentOrchestrator
from cpu_agent import CpuAgent
from linux_kernel_metrics import collect_kernel_evidence


APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "data"
REPORTS_DIR = APP_DIR / "reports"
DB_PATH = DATA_DIR / "agentos.db"
CRITICAL_PROCESS_NAMES = {"system", "system idle process", "init", "systemd", "kthreadd"}


@dataclass
class AgentReply:
    intent: str
    summary: str
    findings: list[str]
    recommendation: str
    proposed_pid: int | None = None
    proposed_name: str | None = None


class LocalAgent:
    """Monitoring, intent routing, safety policy, and local storage."""

    def __init__(self) -> None:
        DATA_DIR.mkdir(exist_ok=True)
        REPORTS_DIR.mkdir(exist_ok=True)
        self.cpu_agent = CpuAgent()
        with closing(sqlite3.connect(DB_PATH)) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS desktop_activity_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    command TEXT NOT NULL,
                    intent TEXT NOT NULL,
                    result TEXT NOT NULL
                )
                """
            )
            connection.commit()

    @staticmethod
    def timestamp() -> str:
        return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")

    def snapshot(self) -> dict[str, Any]:
        cpu = round(psutil.cpu_percent(interval=0.12), 1)
        memory = psutil.virtual_memory()
        drive = Path.cwd().anchor or "/"
        disk = psutil.disk_usage(drive)
        battery = psutil.sensors_battery()
        kernel = collect_kernel_evidence()
        boot = datetime.fromtimestamp(psutil.boot_time()).astimezone().strftime("%d %b, %H:%M")
        processes = self.processes()
        cpu_assessment = self.cpu_agent.assess(cpu, processes)
        auto_stop_action = self._apply_cpu_auto_stop(cpu_assessment)
        if auto_stop_action:
            cpu_assessment["auto_stop_action"] = auto_stop_action
        return {
            "time": self.timestamp(),
            "cpu": cpu,
            "cores": psutil.cpu_count(logical=True) or 1,
            "memory": round(memory.percent, 1),
            "memory_used": round(memory.used / 1024**3, 2),
            "memory_total": round(memory.total / 1024**3, 2),
            "disk": round(disk.percent, 1),
            "disk_used": round(disk.used / 1024**3, 2),
            "disk_total": round(disk.total / 1024**3, 2),
            "battery": None if battery is None else round(battery.percent, 1),
            "plugged": None if battery is None else battery.power_plugged,
            "boot": boot,
            "kernel": kernel,
            "processes": processes,
            "cpu_agent": cpu_assessment,
        }

    def _apply_cpu_auto_stop(self, assessment: dict[str, Any]) -> str | None:
        candidate = assessment.get("auto_stop_candidate")
        if not candidate:
            return None
        success, message = self.stop_process(int(candidate["pid"]), automatic=True)
        if success:
            return f"{message} Reason: {candidate['reason']}"
        return f"CPU Agent did not stop {candidate['name']} (PID {candidate['pid']}): {message}"

    @staticmethod
    def processes(limit: int = 12) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for process in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent", "username", "status"]):
            try:
                info = process.info
                if info["pid"] == 0:
                    continue
                name = info["name"] or "Unknown"
                result.append({"pid": int(info["pid"]), "name": name, "cpu": round(float(info["cpu_percent"] or 0), 1), "memory": round(float(info["memory_percent"] or 0), 1), "user": info["username"] or "unknown", "status": info["status"] or "unknown"})
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue
        return sorted(result, key=lambda item: (item["cpu"], item["memory"]), reverse=True)[:limit]

    @staticmethod
    def risk(value: float) -> str:
        if value >= 85:
            return "high"
        if value >= 65:
            return "moderate"
        return "normal"

    @staticmethod
    def classify(command: str) -> str:
        text = command.lower()
        explicit_report = re.search(r"\b(?:generate|create|make|save|export|produce|write)\b.{0,40}\breport\b", text)
        report_negated = re.search(r"\b(?:don't|do not|never|without|no)\b.{0,40}\breport\b", text)
        if explicit_report and not report_negated:
            return "generate_report"
        if any(word in text for word in ("priority", "slow down", "reduce cpu")):
            return "lower_priority"
        if any(word in text for word in ("slow", "performance", "optimize", "why")):
            return "performance_analysis"
        if any(word in text for word in ("disk", "storage", "space")):
            return "disk_analysis"
        if any(word in text for word in ("memory", "ram")):
            return "memory_analysis"
        if any(word in text for word in ("process", "cpu", "application", "app")):
            return "process_analysis"
        return "system_status"

    @staticmethod
    def find_named_process(command: str, processes: list[dict[str, Any]]) -> dict[str, Any] | None:
        query = command.lower()
        candidates = [item for item in processes if item["name"].lower() in query]
        return candidates[0] if candidates else (processes[0] if processes else None)

    def answer(self, command: str, snapshot: dict[str, Any]) -> AgentReply:
        intent = self.classify(command)
        processes = snapshot["processes"]
        top = processes[0] if processes else None
        cpu, memory, disk = snapshot["cpu"], snapshot["memory"], snapshot["disk"]
        if intent == "generate_report":
            filename = self.generate_report(snapshot, command)
            reply = AgentReply(intent, "I created a detailed local system report.", [f"Report saved as: {filename}", "The report stays inside the AgentOS project folder."], "Use ‘Open reports folder’ if you want to inspect the report.")
        elif intent == "performance_analysis":
            findings = [f"CPU usage: {cpu}% ({self.risk(cpu)}).", f"Memory usage: {memory}% ({self.risk(memory)})."]
            if top:
                findings.append(f"Current highest listed process: {top['name']} (PID {top['pid']}, {top['cpu']}% CPU).")
            recommendation = "Review unused applications and browser tabs." if max(cpu, memory) >= 65 else "Current resource usage is normal. No corrective action is needed."
            reply = AgentReply(intent, "I checked the current performance state.", findings, recommendation)
        elif intent == "disk_analysis":
            reply = AgentReply(intent, "I checked local storage.", [f"Disk usage: {disk}% ({self.risk(disk)}).", f"Used: {snapshot['disk_used']} GB of {snapshot['disk_total']} GB."], "Review large personal files and application caches." if disk >= 75 else "Disk capacity is currently adequate.")
        elif intent == "memory_analysis":
            findings = [f"Memory usage: {memory}% ({self.risk(memory)})."]
            if top:
                top_memory = max(processes, key=lambda item: item["memory"])
                findings.append(f"Highest listed memory process: {top_memory['name']} (PID {top_memory['pid']}, {top_memory['memory']}% RAM).")
            reply = AgentReply(intent, "I checked memory usage.", findings, "Close unused applications if memory usage remains high.")
        elif intent == "process_analysis":
            findings = ["The process list is ordered by current CPU usage."]
            if top:
                findings.append(f"Top listed process: {top['name']} (PID {top['pid']}).")
            reply = AgentReply(intent, "I inspected running processes.", findings, "Select a non-critical process below to request a lower priority. AgentOS will ask before changing it.")
        elif intent == "lower_priority":
            target = self.find_named_process(command, processes)
            if target is None:
                reply = AgentReply(intent, "I could not find an eligible process.", [], "Select a process in the list, then choose ‘Lower selected process priority’.")
            else:
                reply = AgentReply(intent, "I prepared a safe action request.", [f"Proposed process: {target['name']} (PID {target['pid']}).", "Lowering priority lets other applications receive more CPU time."], "Review the proposed action, then approve it with the button. AgentOS will not run it automatically.", target["pid"], target["name"])
        else:
            reply = AgentReply(intent, "Here is the current local system status.", [f"CPU: {cpu}%.", f"Memory: {memory}%.", f"Disk: {disk}%.", f"Boot time: {snapshot['boot']}."], "Ask about performance, processes, memory, disk usage, or request a local report.")
        self.log(command, reply.intent, reply.recommendation)
        return reply

    def log(self, command: str, intent: str, result: str) -> None:
        try:
            with closing(sqlite3.connect(DB_PATH)) as connection:
                connection.execute("INSERT INTO desktop_activity_log (created_at, command, intent, result) VALUES (?, ?, ?, ?)", (self.timestamp(), command, intent, result))
                connection.commit()
        except (OSError, sqlite3.Error):
            # Monitoring and process termination must not be reported as failed
            # solely because an optional local activity record cannot be saved.
            return

    def generate_report(self, snapshot: dict[str, Any], command: str) -> str:
        filename = f"agentos-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.txt"
        path = REPORTS_DIR / filename
        process_lines = [f"- {item['name']} (PID {item['pid']}): {item['cpu']}% CPU, {item['memory']}% RAM" for item in snapshot["processes"][:5]]
        content = "\n".join(["AgentOS Local System Report", f"Generated: {snapshot['time']}", f"Requested task: {command}", "", "Live resource state", f"CPU: {snapshot['cpu']}%", f"Memory: {snapshot['memory']}% ({snapshot['memory_used']} GB / {snapshot['memory_total']} GB)", f"Disk: {snapshot['disk']}% ({snapshot['disk_used']} GB / {snapshot['disk_total']} GB)", "", "Top listed processes", *process_lines, "", "Safety", "This report was generated locally. AgentOS did not change any system setting."])
        path.write_text(content, encoding="utf-8")
        return filename

    def lower_priority(self, pid: int) -> tuple[bool, str]:
        try:
            if sys.platform != "linux":
                return False, "AgentOS process-priority actions are available only on Linux."
            process = psutil.Process(pid)
            name = process.name() or "Unknown"
            if pid <= 100 or name.lower() in CRITICAL_PROCESS_NAMES:
                return False, f"Safety policy blocked a priority change for the critical process {name} (PID {pid})."
            current = int(process.nice())
            target = min(current + 5, 19)
            if current == target:
                return False, f"{name} already has the lowest user-level priority ({current})."
            process.nice(target)
            outcome = f"changed from nice {current} to {target}"
            result = f"Completed: priority for {name} (PID {pid}) was {outcome}."
            self.log(f"Approved priority change for PID {pid}", "approved_action", result)
            return True, result
        except psutil.NoSuchProcess:
            return False, "The selected process has already stopped. No action was taken."
        except psutil.AccessDenied:
            return False, "Linux denied this priority change. Select a process owned by the current user."
        except Exception as error:
            return False, f"The action could not be completed: {error}"

    @staticmethod
    def _protected_process_reason(process: psutil.Process, name: str) -> str | None:
        """Block system, session, and other processes unsafe for AgentOS to stop."""
        try:
            current = psutil.Process()
            protected_pids = {current.pid, *[parent.pid for parent in current.parents()]}
            if process.pid <= 100 or process.pid in protected_pids:
                return "AgentOS cannot stop a system or AgentOS-session process."
            if name.lower() in CRITICAL_PROCESS_NAMES:
                return f"AgentOS cannot stop the protected process {name}."
            if process.username() != current.username():
                return "AgentOS can stop only a process owned by the current desktop user."
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return "AgentOS could not verify that this process is safe to stop."
        return None

    def stop_process(self, pid: int, automatic: bool = False) -> tuple[bool, str]:
        """Stop an eligible PID; automatic actions escalate only when needed."""
        try:
            if sys.platform != "linux":
                return False, "Process stopping is available only on Linux."
            process = psutil.Process(pid)
            name = process.name() or "Unknown"
            blocked = self._protected_process_reason(process, name)
            if blocked:
                return False, blocked
            process.terminate()
            try:
                process.wait(timeout=1.5 if automatic else 3)
            except psutil.TimeoutExpired:
                if not automatic:
                    return False, f"{name} did not close within 3 seconds. AgentOS did not force-kill it."
                # Ported from sysmon-'s kill path: automatic, already-warned
                # anomalous PIDs are force-stopped only after SIGTERM failed.
                process.kill()
                try:
                    process.wait(timeout=1.5)
                except psutil.TimeoutExpired:
                    return False, f"{name} (PID {pid}) ignored both the stop and force-stop requests."
                result = f"CPU Agent automatically force-stopped {name} (PID {pid}) after its graceful stop request timed out."
                self.log(f"CPU Agent automatic force-stop for PID {pid}", "cpu_auto_force_stop", result)
                return True, result
            result = (f"CPU Agent automatically stopped {name} (PID {pid})." if automatic
                      else f"Stopped {name} (PID {pid}) after your approval.")
            command = f"CPU Agent auto-stop for PID {pid}" if automatic else f"Approved process stop for PID {pid}"
            self.log(command, "cpu_auto_stop" if automatic else "approved_action", result)
            return True, result
        except psutil.NoSuchProcess:
            return False, "The selected process has already stopped. No action was taken."
        except psutil.AccessDenied:
            return False, "Linux denied this request. Select a process owned by the current user."
        except Exception as error:
            return False, f"The process could not be stopped: {error}"


class MetricCard(QFrame):
    def __init__(self, label: str) -> None:
        super().__init__()
        self.setObjectName("metricCard")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        title = QLabel(label.upper())
        title.setObjectName("metricLabel")
        self.value = QLabel("—")
        self.value.setObjectName("metricValue")
        self.detail = QLabel("Waiting for data")
        self.detail.setObjectName("metricDetail")
        layout.addWidget(title)
        layout.addWidget(self.value)
        layout.addWidget(self.detail)

    def update(self, value: str, detail: str) -> None:
        self.value.setText(value)
        self.detail.setText(detail)


class AgentOSWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.agent = LocalAgent()
        self.orchestrator = AgentOrchestrator(self.agent)
        self.pending_process: tuple[int, str] | None = None
        self.compact_mode = True
        self._is_animating_close = False
        self._has_opened = False
        self.setWindowTitle("AgentOS · Local Linux Assistant")
        self.setMinimumSize(1050, 680)
        self.resize(1200, 760)
        self.setWindowIcon(QApplication.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon))
        self.build_ui()
        self.create_tray()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh_snapshot)
        self.timer.start(2500)
        self.refresh_snapshot()
        self.append_chat("AgentOS", "I am running locally. I can monitor your computer, explain what I find, generate a report, and only run an approved safe action.")
        self.set_compact_mode(True)

    def build_ui(self) -> None:
        root = QWidget()
        root.setObjectName("root")
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(20, 18, 20, 20)
        layout.setSpacing(14)
        heading = QHBoxLayout()
        title_box = QVBoxLayout()
        title = QLabel("AgentOS")
        title.setObjectName("appTitle")
        subtitle = QLabel("Local intelligent system assistant · monitoring, reasoning, approved actions")
        subtitle.setWordWrap(True)
        subtitle.setObjectName("subtitle")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        heading.addLayout(title_box)
        heading.addStretch()
        self.expand_button = QPushButton("Expand ↗")
        self.expand_button.setObjectName("secondaryButton")
        self.expand_button.clicked.connect(self.toggle_compact_mode)
        heading.addWidget(self.expand_button, alignment=Qt.AlignmentFlag.AlignTop)
        local_state = QLabel("● LOCAL ONLY")
        local_state.setObjectName("localState")
        heading.addWidget(local_state, alignment=Qt.AlignmentFlag.AlignTop)
        self.kernel_state = QLabel("○ KERNEL MODULE: CHECKING")
        self.kernel_state.setObjectName("kernelState")
        heading.addWidget(self.kernel_state, alignment=Qt.AlignmentFlag.AlignTop)
        layout.addLayout(heading)
        metrics = QGridLayout()
        metrics.setSpacing(10)
        self.cpu_card, self.memory_card = MetricCard("CPU"), MetricCard("Memory")
        self.disk_card, self.battery_card = MetricCard("Disk"), MetricCard("Battery")
        for column, card in enumerate((self.cpu_card, self.memory_card, self.disk_card, self.battery_card)):
            metrics.addWidget(card, 0, column)
        self.metrics_view = QWidget()
        self.metrics_view.setLayout(metrics)
        layout.addWidget(self.metrics_view)
        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self.splitter.setChildrenCollapsible(False)
        self.splitter.addWidget(self.chat_panel())
        self.control_view = self.control_panel()
        self.splitter.addWidget(self.control_view)
        self.splitter.setSizes([510, 640])
        layout.addWidget(self.splitter, 1)

    def chat_panel(self) -> QWidget:
        box = QWidget()
        box.setObjectName("chatPanel")
        layout = QVBoxLayout(box)
        self.chat = QTextBrowser()
        self.chat.setOpenExternalLinks(False)
        self.chat.setObjectName("chat")
        layout.addWidget(self.chat, 1)
        suggestion_row = QHBoxLayout()
        for text in ("System status", "Check memory usage"):
            button = QPushButton(text)
            button.setObjectName("suggestion")
            button.clicked.connect(lambda _checked=False, value=text: self.run_command(value))
            suggestion_row.addWidget(button)
        layout.addLayout(suggestion_row)
        entry_row = QHBoxLayout()
        self.command_entry = QLineEdit()
        self.command_entry.setPlaceholderText("Ask about this computer or request a safe task…")
        self.command_entry.returnPressed.connect(self.submit_command)
        send = QPushButton("Send")
        send.clicked.connect(self.submit_command)
        entry_row.addWidget(self.command_entry, 1)
        entry_row.addWidget(send)
        layout.addLayout(entry_row)
        return box

    def control_panel(self) -> QWidget:
        panel = QWidget()
        panel.setObjectName("controlPanel")
        layout = QVBoxLayout(panel)
        status = QLabel("Current processes by CPU usage")
        status.setObjectName("sectionTitle")
        layout.addWidget(status)
        architecture = QLabel("LangGraph: Intent Router → System Observer → CPU Agent → Diagnosis Agent → Safety Guardian → Execution Agent → Response Agent")
        architecture.setObjectName("architecture")
        architecture.setWordWrap(True)
        layout.addWidget(architecture)
        self.trace_view = QListWidget()
        self.trace_view.setObjectName("traceView")
        self.trace_view.setMaximumHeight(128)
        layout.addWidget(self.trace_view)
        self.process_table = QTableWidget(0, 6)
        self.process_table.setHorizontalHeaderLabels(["Process", "PID", "CPU", "RAM", "Trust", "Status"])
        self.process_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.process_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.process_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.process_table.verticalHeader().setVisible(False)
        self.process_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for col in range(1, 6):
            self.process_table.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        layout.addWidget(self.process_table, 1)
        self.action_status = QLabel("Read-only monitoring active. Select a non-critical process to request a safe priority change.")
        self.action_status.setObjectName("actionStatus")
        self.action_status.setWordWrap(True)
        layout.addWidget(self.action_status)
        actions = QHBoxLayout()
        priority = QPushButton("Lower selected process priority")
        priority.setObjectName("warningButton")
        priority.clicked.connect(self.request_priority_change)
        actions.addWidget(priority)
        stop = QPushButton("Stop selected process")
        stop.setObjectName("dangerButton")
        stop.clicked.connect(self.request_process_stop)
        actions.addWidget(stop)
        protect = QPushButton("Protect selected app")
        protect.setObjectName("secondaryButton")
        protect.clicked.connect(self.protect_selected_process)
        actions.addWidget(protect)
        refresh = QPushButton("Refresh now")
        refresh.setObjectName("secondaryButton")
        refresh.clicked.connect(self.refresh_snapshot)
        actions.addWidget(refresh)
        layout.addLayout(actions)
        report_row = QHBoxLayout()
        report = QPushButton("Generate local report")
        report.clicked.connect(lambda: self.run_command("Generate local report"))
        folder = QPushButton("Open reports folder")
        folder.setObjectName("secondaryButton")
        folder.clicked.connect(self.open_reports_folder)
        report_row.addWidget(report)
        report_row.addWidget(folder)
        layout.addLayout(report_row)
        return panel

    def create_tray(self) -> None:
        self.tray = QSystemTrayIcon(self.windowIcon(), self)
        self.tray.setToolTip("AgentOS · Local intelligent system assistant")
        menu = QMenu(self)
        open_action = QAction("Open AgentOS", self)
        open_action.triggered.connect(self.show_compact)
        status_action = QAction("Show system status", self)
        status_action.triggered.connect(lambda: self.run_command("Show system status"))
        report_action = QAction("Generate local report", self)
        report_action.triggered.connect(lambda: self.run_command("Generate local report"))
        quit_action = QAction("Quit AgentOS", self)
        quit_action.triggered.connect(QApplication.instance().quit)
        menu.addAction(open_action)
        menu.addAction(status_action)
        menu.addAction(report_action)
        menu.addSeparator()
        menu.addAction(quit_action)
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(lambda reason: self.show_compact() if reason == QSystemTrayIcon.ActivationReason.Trigger else None)
        self.tray.show()

    def show_window(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def show_compact(self) -> None:
        self.stop_window_animations()
        self._has_opened = True
        self.set_compact_mode(True, animate=False)
        self.animate_open()

    def toggle_compact_mode(self) -> None:
        self.set_compact_mode(not self.compact_mode, animate=True)

    def set_compact_mode(self, compact: bool, animate: bool = False) -> None:
        self.compact_mode = compact
        self.metrics_view.setVisible(not compact)
        self.control_view.setVisible(not compact)
        self.kernel_state.setVisible(not compact)
        if compact:
            self.setMinimumSize(420, 520)
            self.expand_button.setText("Expand ↗")
            target_size = (470, 640)
        else:
            self.setMinimumSize(420, 520)
            self.expand_button.setText("Compact ↓")
            target_size = (1200, 760)
        if animate and self.isVisible():
            self.animate_resize(*target_size)
        else:
            self.resize(*target_size)

    def animate_resize(self, width: int, height: int) -> None:
        self.stop_window_animations()
        center = self.frameGeometry().center()
        target = QRect(center.x() - width // 2, center.y() - height // 2, width, height)
        animation = QPropertyAnimation(self, b"geometry", self)
        animation.setDuration(280)
        animation.setStartValue(self.geometry())
        animation.setEndValue(target)
        animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._resize_animation = animation
        animation.start()

    def animate_open(self) -> None:
        self.stop_window_animations()
        self.show_window()
        target = self.geometry()
        start = QRect(target.x() + 18, target.y() + 18, max(380, int(target.width() * 0.94)), max(480, int(target.height() * 0.94)))
        self.setGeometry(start)
        self.setWindowOpacity(0.0)
        fade = QPropertyAnimation(self, b"windowOpacity", self)
        fade.setDuration(220)
        fade.setStartValue(0.0)
        fade.setEndValue(1.0)
        fade.setEasingCurve(QEasingCurve.Type.OutCubic)
        grow = QPropertyAnimation(self, b"geometry", self)
        grow.setDuration(260)
        grow.setStartValue(start)
        grow.setEndValue(target)
        grow.setEasingCurve(QEasingCurve.Type.OutCubic)
        group = QParallelAnimationGroup(self)
        group.addAnimation(fade)
        group.addAnimation(grow)
        self._open_animation = group
        group.start()

    def animate_close_to_tray(self) -> None:
        if self._is_animating_close:
            return
        self.stop_window_animations()
        self._is_animating_close = True
        current = self.geometry()
        target = QRect(current.x() + 18, current.y() + 18, max(380, int(current.width() * 0.94)), max(480, int(current.height() * 0.94)))
        fade = QPropertyAnimation(self, b"windowOpacity", self)
        fade.setDuration(180)
        fade.setStartValue(self.windowOpacity())
        fade.setEndValue(0.0)
        fade.setEasingCurve(QEasingCurve.Type.InCubic)
        shrink = QPropertyAnimation(self, b"geometry", self)
        shrink.setDuration(200)
        shrink.setStartValue(current)
        shrink.setEndValue(target)
        shrink.setEasingCurve(QEasingCurve.Type.InCubic)
        group = QParallelAnimationGroup(self)
        group.addAnimation(fade)
        group.addAnimation(shrink)
        group.finished.connect(self.finish_close_to_tray)
        self._close_animation = group
        group.start()

    def stop_window_animations(self) -> None:
        for name in ("_open_animation", "_close_animation", "_resize_animation"):
            animation = getattr(self, name, None)
            if animation is not None:
                animation.stop()
        self._is_animating_close = False
        self.setWindowOpacity(1.0)

    def finish_close_to_tray(self) -> None:
        self.hide()
        self.setWindowOpacity(1.0)
        self._is_animating_close = False

    def closeEvent(self, event) -> None:  # type: ignore[override]
        if self.tray.isVisible():
            event.ignore()
            self.animate_close_to_tray()
            self.tray.showMessage("AgentOS", "AgentOS is still running locally in the system tray.", QSystemTrayIcon.MessageIcon.Information, 2500)
        else:
            event.accept()

    def showEvent(self, event) -> None:  # type: ignore[override]
        super().showEvent(event)
        if not self._has_opened:
            self._has_opened = True
            QTimer.singleShot(60, self.animate_open)

    def refresh_snapshot(self) -> None:
        self.current_snapshot = self.agent.snapshot()
        self.render_snapshot(self.current_snapshot)
        auto_stop_action = self.current_snapshot["cpu_agent"].get("auto_stop_action")
        if auto_stop_action:
            self.action_status.setText(auto_stop_action)
            self.append_chat("CPU Agent", auto_stop_action)

    def render_snapshot(self, data: dict[str, Any]) -> None:
        cpu_agent = data["cpu_agent"]
        if cpu_agent.get("available"):
            preferred = len(cpu_agent.get("resource_preferences", []))
            cpu_detail = f"Baseline {cpu_agent['baseline_cpu']}% · limit {cpu_agent['upper_limit']}% · {preferred} trusted"
        else:
            cpu_detail = f"{data['cores']} logical cores · baseline training pending"
        self.cpu_card.update(f"{data['cpu']}%", cpu_detail)
        self.memory_card.update(f"{data['memory']}%", f"{data['memory_used']} / {data['memory_total']} GB")
        self.disk_card.update(f"{data['disk']}%", f"{data['disk_used']} / {data['disk_total']} GB")
        battery = "Not available" if data["battery"] is None else f"{data['battery']}%"
        power = "Desktop / no battery" if data["battery"] is None else ("Plugged in" if data["plugged"] else "On battery")
        self.battery_card.update(battery, power)
        kernel = data["kernel"]
        if kernel["available"]:
            self.kernel_state.setText(f"● KERNEL VERIFIED · {kernel['process_count']} processes")
            self.kernel_state.setToolTip(f"Read-only data from {kernel['device']}")
        else:
            self.kernel_state.setText("○ PSUTIL FALLBACK")
            self.kernel_state.setToolTip(kernel["reason"])
        self.populate_processes(data["processes"], cpu_agent.get("app_trust", {}))

    def populate_processes(self, processes: list[dict[str, Any]], app_trust: dict[str, dict[str, Any]]) -> None:
        selected = self.selected_process()
        selected_pid = selected[0] if selected else None
        self.process_table.setRowCount(len(processes))
        for row, process in enumerate(processes):
            trust = app_trust.get(process["name"], {})
            trust_text = f"{trust.get('score', 0)} · {trust.get('level', 'new')}"
            values = [process["name"], str(process["pid"]), f"{process['cpu']}%", f"{process['memory']}%", trust_text, process["status"]]
            for column, value in enumerate(values):
                self.process_table.setItem(row, column, QTableWidgetItem(value))
            if process["pid"] == selected_pid:
                self.process_table.selectRow(row)

    def selected_process(self) -> tuple[int, str] | None:
        row = self.process_table.currentRow()
        if row < 0:
            return None
        pid_item = self.process_table.item(row, 1)
        name_item = self.process_table.item(row, 0)
        return (int(pid_item.text()), name_item.text()) if pid_item and name_item else None

    def submit_command(self) -> None:
        command = self.command_entry.text().strip()
        if command:
            self.command_entry.clear()
            self.run_command(command)

    def run_command(self, command: str) -> None:
        self.show_window()
        self.append_chat("You", command)
        result = self.orchestrator.run(command)
        self.current_snapshot = result.snapshot
        self.render_snapshot(self.current_snapshot)
        findings = "<br>".join(f"• {html.escape(finding)}" for finding in result.findings)
        report_line = f"<br><br><b>Created:</b> {html.escape(result.report_file)}" if result.report_file else ""
        text = f"<b>{html.escape(result.summary)}</b><br>{findings}<br><br><b>Recommendation:</b> {html.escape(result.recommendation)}<br><br><b>Safety:</b> {html.escape(result.risk)} · {html.escape(result.execution)}{report_line}"
        self.append_chat("AgentOS", text, is_html=True)
        self.update_trace(result.trace)
        if result.proposed_pid is not None and result.proposed_name is not None:
            self.pending_process = (result.proposed_pid, result.proposed_name)
            self.action_status.setText(f"Action ready: lower priority for {result.proposed_name} (PID {result.proposed_pid}). Select it or click the priority button to review and approve.")

    def update_trace(self, trace: list[dict[str, str]]) -> None:
        self.trace_view.clear()
        symbols = {"complete": "✓", "approval required": "!", "waiting": "…", "blocked": "×"}
        for event in trace:
            symbol = symbols.get(event["status"], "•")
            self.trace_view.addItem(f"{symbol} {event['agent']}: {event['detail']}")

    def append_chat(self, speaker: str, content: str, is_html: bool = False) -> None:
        safe_content = content if is_html else html.escape(content)
        color = "#111111"
        self.chat.append(f"<p style='margin: 0 0 12px 0'><span style='color:{color}; font-weight:700'>{speaker}</span><br>{safe_content}</p>")
        self.chat.verticalScrollBar().setValue(self.chat.verticalScrollBar().maximum())

    def request_priority_change(self) -> None:
        selected = self.selected_process() or self.pending_process
        if selected is None:
            self.action_status.setText("Select a process first. AgentOS will not choose one and change it automatically.")
            return
        pid, name = selected
        if pid <= 100 or name.lower() in CRITICAL_PROCESS_NAMES:
            self.action_status.setText("Safety policy blocked this critical process. Select a normal user application instead.")
            return
        confirmation = QMessageBox.question(self, "Approve local system action", f"AgentOS will lower the CPU scheduling priority of:\n\n{name} (PID {pid})\n\nThis does not stop the application. It gives other programs more opportunity to use CPU.\n\nDo you approve this action?", QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes, QMessageBox.StandardButton.Cancel)
        if confirmation != QMessageBox.StandardButton.Yes:
            self.action_status.setText("Action cancelled. No system setting was changed.")
            self.append_chat("AgentOS", "You cancelled the priority change. No system setting was changed.")
            return
        success, message = self.agent.lower_priority(pid)
        self.action_status.setText(message)
        self.append_chat("AgentOS", message)
        if success:
            self.pending_process = None
            self.tray.showMessage("AgentOS action completed", message, QSystemTrayIcon.MessageIcon.Information, 3500)
        self.refresh_snapshot()

    def request_process_stop(self) -> None:
        selected = self.selected_process()
        if selected is None:
            self.action_status.setText("Select a non-critical process first. AgentOS will not choose one automatically.")
            return
        pid, name = selected
        if pid <= 100 or name.lower() in CRITICAL_PROCESS_NAMES:
            self.action_status.setText("Safety policy blocked this critical process. Select a normal user application instead.")
            return
        confirmation = QMessageBox.question(
            self,
            "Approve process stop",
            f"AgentOS will request that this application closes:\n\n{name} (PID {pid})\n\n"
            "Unsaved work in that application may be lost. AgentOS sends a graceful stop request and will not force-kill it.\n\n"
            "Do you approve this action?",
            QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
            QMessageBox.StandardButton.Cancel,
        )
        if confirmation != QMessageBox.StandardButton.Yes:
            self.action_status.setText("Process stop cancelled. No system setting was changed.")
            self.append_chat("AgentOS", "You cancelled the process stop. No action was taken.")
            return
        success, message = self.agent.stop_process(pid)
        self.action_status.setText(message)
        self.append_chat("AgentOS", message)
        if success:
            self.tray.showMessage("AgentOS action completed", message, QSystemTrayIcon.MessageIcon.Information, 3500)
        self.refresh_snapshot()

    def protect_selected_process(self) -> None:
        selected = self.selected_process()
        if selected is None:
            self.action_status.setText("Select an app to protect it from CPU Agent automatic stopping.")
            return
        _pid, name = selected
        if self.agent.cpu_agent.protect_app(name):
            message = f"{name} is protected from CPU Agent automatic stopping. Manual stop remains available."
            self.action_status.setText(message)
            self.append_chat("CPU Agent", message)

    @staticmethod
    def open_reports_folder() -> None:
        REPORTS_DIR.mkdir(exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(REPORTS_DIR)))


def apply_style(application: QApplication) -> None:
    application.setStyleSheet("""
        QWidget { background: #ffffff; color: #111111; font-family: Segoe UI, Ubuntu, Arial; font-size: 13px; }
        #root { background: #ffffff; } #appTitle { font-size: 27px; font-weight: 700; color: #111111; } #subtitle, #metricDetail { color: #555555; }
        #localState, #kernelState { color: #333333; background: transparent; border: none; padding: 7px 4px; font-weight: 700; font-size: 10px; }
        #metricCard { background: #fafafa; border: 1px solid #e5e5e5; border-radius: 12px; } #metricLabel { color: #555555; font-size: 10px; font-weight: 700; } #metricValue { color: #111111; font-size: 22px; font-weight: 700; }
        #chatPanel { background: #ffffff; border: none; padding: 4px; } #controlPanel { background: #ffffff; border: none; border-left: 1px solid #e5e5e5; padding: 14px; }
        #chat { background: #ffffff; border: none; padding: 12px; } QLineEdit { background: #fafafa; border: 1px solid #dddddd; border-radius: 14px; padding: 12px 13px; color: #111111; }
        QLineEdit:focus { border: 1px solid #777777; }
        QPushButton { background: #111111; color: #ffffff; border: none; border-radius: 10px; padding: 10px 13px; font-weight: 700; } QPushButton:hover { background: #333333; } QPushButton:pressed { background: #555555; }
        QPushButton#suggestion, QPushButton#secondaryButton { background: #ffffff; color: #111111; border: 1px solid #dddddd; } QPushButton#suggestion:hover, QPushButton#secondaryButton:hover { background: #f2f2f2; } QPushButton#suggestion:pressed, QPushButton#secondaryButton:pressed { background: #e6e6e6; }
        QPushButton#warningButton { background: #111111; color: #ffffff; } QPushButton#dangerButton { background: #a61b1b; color: #ffffff; } QPushButton#dangerButton:hover { background: #7f1313; }
        QTableWidget { background: #ffffff; color: #111111; gridline-color: #eeeeee; border: none; selection-background-color: #eeeeee; selection-color: #111111; } QHeaderView::section { background: #ffffff; color: #555555; border: none; border-bottom: 1px solid #dddddd; padding: 8px; font-weight: 700; }
        #sectionTitle { color: #111111; font-size: 15px; font-weight: 700; } #architecture { color: #444444; background: #f7f7f7; border-radius: 9px; padding: 9px; }
        #traceView { background: #fafafa; border: none; border-radius: 9px; padding: 5px; color: #222222; } #actionStatus { color: #333333; background: #fafafa; border-left: 2px solid #111111; padding: 10px; border-radius: 4px; }
        QScrollBar:vertical { background: #ffffff; width: 8px; border: none; } QScrollBar::handle:vertical { background: #cccccc; border-radius: 4px; min-height: 25px; } QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
    """)


def main() -> int:
    if sys.platform != "linux" and os.getenv("AGENTOS_DEV_ALLOW_NON_LINUX") != "1":
        print("AgentOS is a Linux-only application. Run it on Ubuntu Desktop or another supported Linux desktop.")
        return 1
    application = QApplication(sys.argv)
    application.setQuitOnLastWindowClosed(False)
    apply_style(application)
    window = AgentOSWindow()
    window.show()
    return application.exec()


if __name__ == "__main__":
    raise SystemExit(main())
