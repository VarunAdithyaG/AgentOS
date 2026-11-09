# AgentOS desktop prototype

AgentOS is a local, native desktop assistant for the **Agentic AI-Enabled Linux Operating System** project. It is designed to sit in the Linux system tray, not inside a browser.

## What the review prototype demonstrates

- AgentOS icon and right-click menu in the system tray
- Compact ChatGPT-style assistant popup when the tray icon is clicked
- One-click **Expand** control that reveals the larger system-control view
- Live CPU, RAM, disk, battery, and process information
- A chat-like interface that understands local monitoring requests
- A visible LangGraph orchestration trace for every request
- Optional read-only kernel telemetry from the included `sysmetrics` Linux kernel module
- Explainable findings and recommendations
- Local SQLite activity log and local text reports
- Controlled actions: lowering the priority of, or gracefully stopping, a selected non-critical user process only after explicit approval

## Local-only boundary

- No OpenAI, DeepSeek, cloud database, or remote telemetry
- No raw AI-generated terminal commands
- No automatic force-kill, file deletion, package removal, or privileged action
- Every state-changing task requires a visible confirmation dialog
- Reports and activity logs remain under this project directory

## LangGraph agent architecture

Every request passes through this local-only workflow, which is visible in the expanded application window:

```text
Intent Router → System Observer → CPU Agent → Diagnosis Agent → Safety Guardian → Execution Agent → Response Agent
```

- **Intent Router:** identifies the allowed task.
- **System Observer:** reads live local metrics and processes.
- **CPU Agent:** trains a robust hourly CPU baseline from valid rows in
  `system_metrics.csv`, then compares each live reading against that baseline.
  Under sustained system-wide CPU pressure it can gracefully stop an anomalous,
  non-critical user process. Use **Protect selected app** for applications you
  intentionally run at high CPU; manual stopping remains available.

### CPU Agent automatic stopping

The CPU Agent retrains its hourly total-CPU baseline whenever the metrics CSV
changes. It also learns separate normal CPU ranges for each live process and
adds repeat-use days from the CSV app list to application trust. It only
performs a graceful automatic stop when current total CPU is above *your*
learned range and the same PID remains anomalous for consecutive checks.
Critical system processes, processes owned by another user, AgentOS itself,
and protected applications are never selected. Choose **Protect selected app**
for an application you intentionally run at high CPU; it continues to be
observed but is excluded from automatic stopping. Manual stopping stays
available for protected applications.

New, untrusted processes (including browser PIDs such as Brave, Chrome, or
Firefox) that create a clearly high CPU load are stopped immediately when they
are outside your learned usage pattern. AgentOS sends that PID a graceful stop
request and force-stops it only if the graceful request times out. The browser closes at the process level;
Linux does not reliably expose a website tab as a separately stoppable process.

### Learned application trust and resource preference

Each application also receives a persistent **trust score** from 0 to 100.
Repeated use across different days, with CPU use that stays within the learned
range, increases the score. Sustained abnormal use lowers it. A score of 60 or
higher marks an app as trusted: AgentOS never automatically stops its PIDs.
The process table shows each app's score and level. This is a preference for
resource decisions, not a privileged CPU-priority override; manual process
controls remain under your control.
- **Diagnosis Agent:** converts measurements into an explanation.
- **Safety Guardian:** blocks dangerous requests and marks changes that need approval.
- **Execution Agent:** runs only an allowed task, such as report generation. It pauses controlled changes until approval.
- **Response Agent:** displays the result and stores a local log entry.


## Run for the review

Use Ubuntu Desktop for the final presentation. The current source also launches on other desktop systems for development.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python agentos_desktop.py
```

The AgentOS icon appears in the system tray. Click it to open the compact assistant. Click **Expand** to display system controls and the LangGraph agent trace. Closing the window keeps AgentOS running in the tray; use **Quit AgentOS** from the tray menu to exit.

## Suggested review flow

1. Open AgentOS from the tray icon.
2. Show live CPU, memory, disk, battery, and processes in the native window.
3. Ask: `Why is my system slow?`
4. Explain the agent's findings and recommendation.
5. Ask: `Generate local report` and show the resulting local file.
6. Select a normal user process. Click **Lower selected process priority**.
7. Show the approval dialog. Confirm it, then show the completed result in AgentOS.

The **Stop selected process** action is also available for a normal process owned
by the current user. It requires a separate approval, refuses critical and
AgentOS-session processes, sends a graceful stop request, and never force-kills.

## Local AI next step

The review build uses transparent rule-based intent routing. The next milestone can connect the same tool policy to an Ollama local model. The model must return a limited intent and approved tool name, never a raw shell command.

## Kernel telemetry integration

The included `linux-kernel-module-mychardev` source is integrated as an optional read-only source. When its `/dev/sysmetrics` device is available, AgentOS validates the module's CPU count, RAM, and process-count snapshot and marks the desktop UI as **Kernel verified**. If it is unavailable, AgentOS continues safely with `psutil` and labels the source as a fallback.

On the target Ubuntu computer, build the provided module in its nested project folder:

```bash
cd linux-kernel-module-mychardev/linux-kernel-module-mychardev
make
sudo insmod mychardev.ko
cat /dev/sysmetrics
```

The module is read-only. It rejects writes, and AgentOS never loads, unloads, or modifies the kernel module itself. Give the review user read access to `/dev/sysmetrics` through an appropriate local udev rule or group. The companion `test_user --watch 15` tool can create fresh CPU, memory, disk, GPU, and top-process history in `system_metrics.csv`; AgentOS ignores stale CSV data.

## Start automatically after Linux login

The included `systemd/agentos-desktop.service` is a template. Copy it to `~/.config/systemd/user/`, adjust the `AgentOS` path if needed, then run:

```bash
systemctl --user daemon-reload
systemctl --user enable --now agentos-desktop.service
```

Desktop environments vary in how they show tray icons. Test the target Ubuntu desktop before the review and use its supported app-indicator integration if needed.
