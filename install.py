#!/usr/bin/env python3
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys


ROOT = Path(__file__).resolve().parent
AGENT = ROOT / "agent" / "kali_agent.py"
SERVER = ROOT / "server" / "kali_mcp.py"
LAUNCHER = ROOT / "launch.sh"
CA_KEY = Path.home() / ".ssh" / "kali_bridge_ca"


def run(argv, *, input_text=None):
    print("+", shlex.join(str(x) for x in argv))
    return subprocess.run(
        [str(x) for x in argv], input=input_text, text=True, check=True,
    )


def ensure_ca():
    if CA_KEY.exists():
        print("CA exists:", CA_KEY)
    else:
        CA_KEY.parent.mkdir(parents=True, exist_ok=True)
        run(["ssh-keygen", "-t", "ed25519", "-f", str(CA_KEY),
             "-C", "kali-bridge-ca", "-N", "", "-q"])
        print("CA created:", CA_KEY)
    return (CA_KEY.with_suffix(".pub")).read_text(encoding="utf-8").strip()


def remote_script(install_dir, port, ca_pub, sudo):
    d = shlex.quote(install_dir)
    ca = shlex.quote(ca_pub)
    service = (
        "[Unit]\n"
        "Description=kali-bridge agent\n"
        "After=network.target\n\n"
        "[Service]\n"
        "Type=simple\n"
        "ExecStart=%s/venv/bin/python %s/agent/kali_agent.py "
        "--listen 127.0.0.1 --port %d\n"
        "Restart=on-failure\n"
        "RestartSec=2\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    ) % (install_dir, install_dir, port)
    return r"""set -eu
S={sudo}
command -v python3 >/dev/null

# Single install directory: agent/, server/, venv/.
$S mkdir -p {d}/agent {d}/server
$S mv /tmp/kali-bridge-agent.py {d}/agent/kali_agent.py
$S mv /tmp/kali-bridge-mcp.py   {d}/server/kali_mcp.py
$S chmod 700 {d}/agent/kali_agent.py {d}/server/kali_mcp.py
[ -x {d}/venv/bin/python ] || $S python3 -m venv {d}/venv
$S {d}/venv/bin/python -m pip install --upgrade pip
$S {d}/venv/bin/python -m pip install 'mcp[cli]' pydantic

# Agent runs as a loopback-only service.
$S tee /etc/systemd/system/kali-bridge.service >/dev/null <<'KALI_BRIDGE_SERVICE'
{service}KALI_BRIDGE_SERVICE
$S systemctl daemon-reload
$S systemctl enable --now kali-bridge.service

# Trust the kali-bridge CA for certificate logins (existing keys keep working).
printf '%s\n' {ca} | $S tee /etc/ssh/kali_bridge_ca.pub >/dev/null
$S chmod 644 /etc/ssh/kali_bridge_ca.pub
$S mkdir -p /etc/ssh/sshd_config.d
$S tee /etc/ssh/sshd_config.d/kali-bridge.conf >/dev/null <<'KALI_BRIDGE_SSHD'
TrustedUserCAKeys /etc/ssh/kali_bridge_ca.pub
PermitRootLogin prohibit-password
KALI_BRIDGE_SSHD
if $S sshd -t; then
  $S systemctl restart ssh 2>/dev/null || $S systemctl restart sshd 2>/dev/null || $S service ssh restart
else
  echo "sshd -t failed; drop-in left in place but sshd not restarted" >&2
  exit 1
fi
$S systemctl --no-pager --full status kali-bridge.service || true
""".format(d=d, ca=ca, service=service, sudo=("sudo" if sudo else ""))


def write_env(host, user, port):
    env = ROOT / "kali-bridge.env"
    env.write_text(
        "# Local runtime config for launch.sh. NOT committed (see .gitignore).\n"
        "KALI_BRIDGE_HOST=%s\n"
        "KALI_BRIDGE_USER=%s\n"
        "KALI_BRIDGE_PORT=%d\n"
        "KALI_BRIDGE_CA=$HOME/.ssh/kali_bridge_ca\n" % (host, user, port),
        encoding="utf-8",
    )
    print("Runtime config written:", env)


def register_claude(port):
    config = Path.home() / ".claude.json"
    if config.exists():
        data = json.loads(config.read_text(encoding="utf-8"))
        backup = config.with_suffix(".json.kali-bridge-backup")
        backup.write_text(config.read_text(encoding="utf-8"), encoding="utf-8")
        print("Claude config backup:", backup)
    else:
        data = {}
    servers = data.setdefault("mcpServers", {})
    servers["kali-bridge"] = {
        "type": "stdio",
        "command": str(LAUNCHER),
        "args": [],
        "env": {},
    }
    config.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print("Claude MCP server registered:", config)


def main():
    parser = argparse.ArgumentParser(description="Install kali-bridge")
    parser.add_argument("--kali-host", required=True, help="Kali IP or SSH hostname")
    parser.add_argument("--kali-user", default="root",
                        help="SSH user for this one setup run (default: root)")
    parser.add_argument("--identity", help="initial SSH private key for setup")
    parser.add_argument("--port", type=int, default=1616,
                        help="loopback port the agent listens on (default: 1616)")
    parser.add_argument("--install-dir", default="/opt/kali-bridge",
                        help="single install directory on Kali")
    args = parser.parse_args()

    for path in (AGENT, SERVER, LAUNCHER):
        if not path.is_file():
            parser.error("missing repository file: %s" % path)
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")

    LAUNCHER.chmod(0o755)
    ca_pub = ensure_ca()

    target = "%s@%s" % (args.kali_user, args.kali_host)
    ssh_base = ["ssh"]
    scp_base = ["scp"]
    if args.identity:
        key = str(Path(args.identity).expanduser().resolve())
        ssh_base += ["-i", key]
        scp_base += ["-i", key]

    run(scp_base + [str(AGENT), "%s:/tmp/kali-bridge-agent.py" % target])
    run(scp_base + [str(SERVER), "%s:/tmp/kali-bridge-mcp.py" % target])
    script = remote_script(args.install_dir, args.port, ca_pub,
                          sudo=(args.kali_user != "root"))
    run(ssh_base + ["-T", target, "bash", "-s"], input_text=script)

    write_env(args.kali_host, "root", args.port)
    register_claude(args.port)
    print("\nInstallation complete. Restart Claude, then call kali_status.")


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
