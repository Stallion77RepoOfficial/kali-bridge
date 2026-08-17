# Kali Bridge

Kali Bridge is an MCP server that lets Codex securely collaborate with a Kali
Linux machine. It supports commands, background jobs, interactive terminals,
file transfers, and HTTP requests from Kali.

> Use only on systems you own or are explicitly authorized to test.

## Requirements

- Codex or Claude Code 
- A reachable Kali Linux machine with Python 3 and SSH enabled
- SSH access as a normal user or root

## Installation

Run the installer from this repository on your Mac:

```bash
python3 install.py --kali-host 192.168.1.50 --kali-user kali
```

With an SSH key:

```bash
python3 install.py \
  --kali-host 192.168.1.50 \
  --kali-user kali \
  --identity ~/.ssh/id_ed25519
```

For a root installation:

```bash
python3 install.py --kali-host 192.168.1.50 --kali-user root
```

The installer uploads Kali Bridge, creates a virtual environment, installs its
dependencies, starts the agent as a systemd service, and adds the MCP server to
Codex automatically. The agent listens only on `127.0.0.1`; Codex connects to
it through SSH.

## Verify

Restart Codex, then ask it to run:

```text
kali_status
```

If the connection works, try:

```text
kali_exec(command="id && uname -a")
```
