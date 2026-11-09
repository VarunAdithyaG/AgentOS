"""Local LangGraph orchestration for AgentOS.

Each node has one clear responsibility. The graph uses no cloud model and never
passes free-form model output to the operating system.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Annotated, TYPE_CHECKING, TypedDict
import operator

from langgraph.graph import END, START, StateGraph

if TYPE_CHECKING:
    from agentos_desktop import LocalAgent


class GraphState(TypedDict, total=False):
    command: str
    intent: str
    snapshot: dict[str, Any]
    cpu_assessment: dict[str, Any]
    findings: list[str]
    recommendation: str
    summary: str
    risk: str
    execution: str
    proposed_pid: int | None
    proposed_name: str | None
    report_file: str | None
    trace: Annotated[list[dict[str, str]], operator.add]


@dataclass
class AgentResult:
    intent: str
    summary: str
    findings: list[str]
    recommendation: str
    risk: str
    execution: str
    snapshot: dict[str, Any]
    trace: list[dict[str, str]]
    proposed_pid: int | None = None
    proposed_name: str | None = None
    report_file: str | None = None


class AgentOrchestrator:
    """A small, review-friendly multi-agent system built with LangGraph."""

    def __init__(self, local_agent: LocalAgent) -> None:
        self.local_agent = local_agent
        self.graph = self._build_graph()

    @staticmethod
    def _event(agent: str, detail: str, status: str = "complete") -> dict[str, str]:
        return {"agent": agent, "detail": detail, "status": status}

    def _intent_router(self, state: GraphState) -> GraphState:
        intent = self.local_agent.classify(state["command"])
        return {"intent": intent, "trace": [self._event("Intent Router", f"Recognised request as {intent.replace('_', '')}.")]}

    def _system_observer(self, state: GraphState) -> GraphState:
        snapshot = self.local_agent.snapshot()
        kernel = snapshot["kernel"]
        detail = "Collected local CPU, memory, disk, battery, and process data."
        if kernel["available"]:
            detail += f" Verified {kernel['process_count']} processes with the read-only kernel module."
        else:
            detail += " Kernel module unavailable, so psutil fallback is active."
        return {"snapshot": snapshot, "trace": [self._event("System Observer", detail)]}

    def _cpu_agent(self, state: GraphState) -> GraphState:
        assessment = state["snapshot"]["cpu_agent"]
        if assessment.get("available"):
            detail = (
                f"Trained on {assessment['sample_count']} validated CPU samples; "
                f"live CPU is {assessment['status']} against its baseline."
            )
        else:
            detail = "Training is pending until at least 30 valid CPU samples are available."
        return {"cpu_assessment": assessment, "trace": [self._event("CPU Agent", detail)]}

    def _diagnosis_agent(self, state: GraphState) -> GraphState:
        snapshot = state["snapshot"]
        intent = state["intent"]
        processes = snapshot["processes"]
        top_cpu = processes[0] if processes else None
        cpu, memory, disk = snapshot["cpu"], snapshot["memory"], snapshot["disk"]
        proposed_pid = None
        proposed_name = None
        cpu_assessment = state.get("cpu_assessment", snapshot["cpu_agent"])

        if intent == "performance_analysis":
            findings = [f"CPU usage is {cpu}% ({self.local_agent.risk(cpu)}).", f"Memory usage is {memory}% ({self.local_agent.risk(memory)})."]
            if top_cpu:
                findings.append(f"Highest listed process is {top_cpu['name']} (PID {top_cpu['pid']}, {top_cpu['cpu']}% CPU).")
            if snapshot["kernel"]["available"]:
                findings.append(f"Read-only kernel telemetry verified {snapshot['kernel']['process_count']} processes and {snapshot['kernel']['ram_used_bytes'] / 1024**3:.2f} GB used RAM.")
            findings.append(cpu_assessment["summary"])
            recommendation = "Review the top CPU process before taking any action." if cpu_assessment.get("status") == "elevated" else ("Review unused applications and browser tabs." if max(cpu, memory) >= 65 else "Current resource use is normal. No correction is required.")
            summary = "I analysed the current performance state."
        elif intent == "disk_analysis":
            findings = [f"Disk usage is {disk}% ({self.local_agent.risk(disk)}).", f"{snapshot['disk_used']} GB of {snapshot['disk_total']} GB is in use."]
            recommendation = "Review large personal files and application caches." if disk >= 75 else "Disk capacity is currently adequate."
            summary = "I analysed local storage."
        elif intent == "memory_analysis":
            top_memory = max(processes, key=lambda item: item["memory"]) if processes else None
            findings = [f"Memory usage is {memory}% ({self.local_agent.risk(memory)})."]
            if top_memory:
                findings.append(f"Highest listed memory process is {top_memory['name']} (PID {top_memory['pid']}, {top_memory['memory']}% RAM).")
            recommendation = "Close unused applications if memory stays high."
            summary = "I analysed memory usage."
        elif intent == "process_analysis":
            findings = ["The process table is ordered by current CPU usage."]
            if top_cpu:
                findings.append(f"Top listed process is {top_cpu['name']} (PID {top_cpu['pid']}).")
            findings.append(cpu_assessment["summary"])
            recommendation = "Select a normal application only if you want to request a lower priority."
            summary = "I inspected running processes."
        elif intent == "lower_priority":
            target = self.local_agent.find_named_process(state["command"], processes)
            findings = ["A priority change can affect the selected application, so it requires your approval."]
            if target:
                proposed_pid, proposed_name = target["pid"], target["name"]
                findings.insert(0, f"Proposed process: {proposed_name} (PID {proposed_pid}).")
                recommendation = "Review the request in the approval dialog. AgentOS will not change it automatically."
            else:
                recommendation = "Select a process in the table, then choose the priority button."
            summary = "I prepared a controlled action request."
        elif intent == "generate_report":
            findings = ["AgentOS will create a text report from the current local snapshot."]
            recommendation = "The report remains on this computer."
            summary = "I prepared a local report task."
        else:
            findings = [f"CPU: {cpu}%.", f"Memory: {memory}%.", f"Disk: {disk}%.", f"Boot time: {snapshot['boot']}."]
            findings.append(cpu_assessment["summary"])
            recommendation = "Ask about performance, processes, memory, disk, or request a local report."
            summary = "Here is the current local system status."
        return {"findings": findings, "recommendation": recommendation, "summary": summary, "proposed_pid": proposed_pid, "proposed_name": proposed_name, "trace": [self._event("Diagnosis Agent", "Compared the requested goal with current local system evidence.")]}

    def _safety_guardian(self, state: GraphState) -> GraphState:
        command = state["command"].lower()
        blocked_terms = ("sudo", "rm ", "delete", "kill", "shutdown", "reboot", "format", "install package")
        if any(term in command for term in blocked_terms):
            return {"risk": "blocked", "execution": "blocked", "summary": "I blocked this request for safety.", "findings": ["This prototype does not allow raw shell commands, deletion, process killing, shutdown, package installation, or privileged actions."], "recommendation": "Use one of the approved monitoring or report tasks instead.", "trace": [self._event("Safety Guardian", "Blocked an unsafe or unsupported system request.", "blocked")]}
        if state["intent"] == "lower_priority":
            return {"risk": "approval required", "execution": "waiting for approval", "trace": [self._event("Safety Guardian", "Priority change is permitted only after explicit user confirmation.", "approval required")]}
        return {"risk": "read only", "execution": "ready", "trace": [self._event("Safety Guardian", "Approved an allowed local, read-only task.")]}

    def _execution_agent(self, state: GraphState) -> GraphState:
        if state["execution"] == "blocked":
            return {"trace": [self._event("Execution Agent", "No system task was run.", "blocked")]}
        if state["intent"] == "generate_report":
            report = self.local_agent.generate_report(state["snapshot"], state["command"])
            return {"report_file": report, "execution": "completed", "trace": [self._event("Execution Agent", f"Created local report {report}.")]}
        if state["intent"] == "lower_priority":
            return {"trace": [self._event("Execution Agent", "Paused pending the visible approval dialog.", "waiting")]}
        return {"execution": "completed", "trace": [self._event("Execution Agent", "Completed local analysis. No system setting was changed.")]}

    def _response_agent(self, state: GraphState) -> GraphState:
        self.local_agent.log(state["command"], state["intent"], state["recommendation"])
        return {"trace": [self._event("Response Agent", "Prepared an explainable result for the desktop assistant.")]}

    def _build_graph(self):
        graph = StateGraph(GraphState)
        graph.add_node("intent_router", self._intent_router)
        graph.add_node("system_observer", self._system_observer)
        graph.add_node("cpu_agent", self._cpu_agent)
        graph.add_node("diagnosis_agent", self._diagnosis_agent)
        graph.add_node("safety_guardian", self._safety_guardian)
        graph.add_node("execution_agent", self._execution_agent)
        graph.add_node("response_agent", self._response_agent)
        graph.add_edge(START, "intent_router")
        graph.add_edge("intent_router", "system_observer")
        graph.add_edge("system_observer", "cpu_agent")
        graph.add_edge("cpu_agent", "diagnosis_agent")
        graph.add_edge("diagnosis_agent", "safety_guardian")
        graph.add_edge("safety_guardian", "execution_agent")
        graph.add_edge("execution_agent", "response_agent")
        graph.add_edge("response_agent", END)
        return graph.compile()

    def run(self, command: str) -> AgentResult:
        output = self.graph.invoke({"command": command, "trace": []})
        return AgentResult(
            intent=output["intent"], summary=output["summary"], findings=output["findings"], recommendation=output["recommendation"],
            risk=output["risk"], execution=output["execution"], snapshot=output["snapshot"], trace=output["trace"],
            proposed_pid=output.get("proposed_pid"), proposed_name=output.get("proposed_name"), report_file=output.get("report_file"),
        )
