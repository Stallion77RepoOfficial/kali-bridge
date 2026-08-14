#!/usr/bin/env python3
"""Install kali-bridge on Kali and register it with Codex on this Mac.

The MCP server is launched through SSH by Codex. Both the agent and MCP server
therefore run on Kali and communicate over 127.0.0.1; port 4444 is never
exposed to the network.
"""

import argparse
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parent
AGENT = ROOT / "agent" / "kali_agent.py"
SERVER = ROOT / "server" / "kali_mcp.py"


def run(argv, *, input_text=None, capture=False):
    print("+", shlex.join(str(x) for x in argv))
    return subprocess.run(
        [str(x) for x in argv], input=input_text, text=True,
        check=True, capture_output=capture,
    )


def remote_script(install_dir, port, root_install):
    qdir = shlex.quote(install_dir)
    service = """[Unit]
Description=kali-bridge agent
After=network.target

[Service]
Type=simple
ExecStart={python} {agent} --listen 127.0.0.1 --port {port}
Restart=on-failure
RestartSec=2

[Install]
WantedBy={target}
"""
    python = "%s/venv/bin/python" % install_dir
    agent = "%s/agent/kali_agent.py" % install_dir
    if root_install:
        unit = "/etc/systemd/system/kali-bridge.service"
        target = "multi-user.target"
        systemctl = "systemctl"
    else:
        unit = "$HOME/.config/systemd/user/kali-bridge.service"
        target = "default.target"
        systemctl = "systemctl --user"
    content = service.format(python=python, agent=agent, port=port, target=target)
    return """set -eu
command -v python3 >/dev/null
mkdir -p {d}/agent {d}/server
mv /tmp/kali-bridge-agent.py {d}/agent/kali_agent.py
mv /tmp/kali-bridge-mcp.py {d}/server/kali_mcp.py
chmod 700 {d}/agent/kali_agent.py {d}/server/kali_mcp.py
python3 -m venv {d}/venv
{d}/venv/bin/python -m pip install --upgrade pip
{d}/venv/bin/python -m pip install 'mcp[cli]' pydantic
mkdir -p "$(dirname {unit})"
cat > {unit} <<'KALI_BRIDGE_SERVICE'
{content}KALI_BRIDGE_SERVICE
{systemctl} daemon-reload
{systemctl} enable --now kali-bridge.service
{systemctl} --no-pager --full status kali-bridge.service
""".format(d=qdir, unit=unit, content=content, systemctl=systemctl)


def toml_string(value):
    return json.dumps(str(value), ensure_ascii=False)


def update_codex_config(ssh_target, identity, install_dir, port):
    config = Path.home() / ".codex" / "config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    old = config.read_text(encoding="utf-8") if config.exists() else ""
    ssh_args = ["-T"]
    if identity:
        ssh_args += ["-i", str(Path(identity).expanduser().resolve())]
    ssh_args += [
        ssh_target,
        "%s/venv/bin/python" % install_dir,
        "%s/server/kali_mcp.py" % install_dir,
        "--host", "127.0.0.1", "--port", str(port),
    ]
    block = "\n".join([
        "[mcp_servers.kali-bridge]",
        'command = "ssh"',
        "args = [%s]" % ", ".join(toml_string(x) for x in ssh_args),
        "startup_timeout_sec = 30",
        "",
    ])
    pattern = re.compile(
        r"(?ms)^\[mcp_servers\.kali-bridge\]\s*\n.*?(?=^\[|\Z)"
    )
    if pattern.search(old):
        new = pattern.sub(block, old, count=1)
    else:
        prefix = old
        if prefix and not prefix.endswith("\n"):
            prefix += "\n"
        new = prefix + ("\n" if prefix else "") + block
    if config.exists():
        backup = config.with_suffix(".toml.kali-bridge-backup")
        backup.write_text(old, encoding="utf-8")
        print("Codex configuration backup:", backup)
    config.write_text(new, encoding="utf-8")
    print("Codex MCP configuration updated:", config)


def main():
    parser = argparse.ArgumentParser(
        description="Install kali-bridge over SSH and add it to Codex"
    )
    parser.add_argument("--kali-host", required=True, help="Kali IP or SSH hostname")
    parser.add_argument("--kali-user", default="kali", help="SSH user (or root)")
    parser.add_argument("--identity", help="SSH private key path")
    parser.add_argument("--port", type=int, default=4444)
    parser.add_argument("--install-dir", help="remote installation directory")
    args = parser.parse_args()

    for path in (AGENT, SERVER):
        if not path.is_file():
            parser.error("missing repository file: %s" % path)
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")

    root_install = args.kali_user == "root"
    install_dir = args.install_dir or (
        "/opt/kali-bridge" if root_install else "/home/%s/.local/share/kali-bridge" % args.kali_user
    )
    target = "%s@%s" % (args.kali_user, args.kali_host)
    ssh_base = ["ssh"]
    scp_base = ["scp"]
    if args.identity:
        key = str(Path(args.identity).expanduser().resolve())
        ssh_base += ["-i", key]
        scp_base += ["-i", key]

    run(scp_base + [AGENT, "%s:/tmp/kali-bridge-agent.py" % target])
    run(scp_base + [SERVER, "%s:/tmp/kali-bridge-mcp.py" % target])
    script = remote_script(install_dir, args.port, root_install)
    run(ssh_base + ["-T", target, "bash", "-s"], input_text=script)
    update_codex_config(target, args.identity, install_dir, args.port)
    print("\nInstallation complete. Restart Codex, then call kali_status.")


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        print("Installation command failed with exit code %s" % exc.returncode,
              file=sys.stderr)
        raise SystemExit(exc.returncode)
    except (OSError, RuntimeError) as exc:
        print("Installation failed: %s" % exc, file=sys.stderr)
        raise SystemExit(1)
