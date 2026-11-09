# AgentOS Linux desktop prototype

Extract the ZIP and open a terminal inside the AgentOS folder on Ubuntu Desktop.

```bash
sudo apt update
sudo apt install python3 python3-venv python3-pip
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python agentos_desktop.py
```

Internet is needed to install dependencies. The assistant itself uses local rule-based intent routing and has no cloud model configured.

Try `Show system status`, `Check memory usage`, `Check disk usage`, `Why is my system slow?`, or `Generate local report`. Click Expand for system details and the LangGraph trace. Data and report folders are created automatically on this laptop.

This is a development prototype. Application launching, Chrome tab control, voice, Ollama, and automatic RAM management are not implemented. Known process-selection issues mean priority changes should not be demonstrated until fixed. Report matching can also interpret questions about generating a report as execution requests.

Kernel integration is optional. The assistant uses psutil if `/dev/sysmetrics` is unavailable. To build the module on the destination laptop:

```bash
sudo apt install build-essential linux-headers-$(uname -r)
cd linux-kernel-module-mychardev/linux-kernel-module-mychardev
make
sudo insmod mychardev.ko
sudo cat /dev/sysmetrics
```

Kernel compatibility, Secure Boot signing, and user read access must be checked on the destination laptop. AgentOS should run as the ordinary desktop user, not with sudo. The included systemd service is an optional template whose paths and desktop-session setup require adjustment.
