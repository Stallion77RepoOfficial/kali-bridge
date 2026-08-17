#!/usr/bin/env bash
set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "$SELF_DIR/kali-bridge.env" ] && . "$SELF_DIR/kali-bridge.env"

KALI_HOST="${KALI_BRIDGE_HOST:-kali}"
KALI_USER="${KALI_BRIDGE_USER:-root}"
AGENT_PORT="${KALI_BRIDGE_PORT:-1616}"
CA_KEY="${KALI_BRIDGE_CA:-$HOME/.ssh/kali_bridge_ca}"
CERT_TTL="${KALI_BRIDGE_CERT_TTL:-10m}"
INSTALL_DIR="${KALI_BRIDGE_INSTALL_DIR:-/opt/kali-bridge}"
REMOTE_PY="$INSTALL_DIR/venv/bin/python"
REMOTE_SERVER="$INSTALL_DIR/server/kali_mcp.py"

if [ ! -f "$CA_KEY" ]; then
  echo "kali-bridge: CA key not found at $CA_KEY" >&2
  exit 1
fi

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/kali-bridge.XXXXXX")"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT INT TERM

EPH="$WORKDIR/id"
ssh-keygen -t ed25519 -f "$EPH" -N "" -q -C "kali-bridge-ephemeral"

ssh-keygen -s "$CA_KEY" -I "kali-bridge-$(date +%s)-$$" \
  -n "$KALI_USER" -V "-1m:+$CERT_TTL" "$EPH.pub" -q

ssh -T \
  -i "$EPH" \
  -o "CertificateFile=$EPH-cert.pub" \
  -o IdentitiesOnly=yes \
  -o StrictHostKeyChecking=accept-new \
  -o PasswordAuthentication=no \
  -o KbdInteractiveAuthentication=no \
  "$KALI_USER@$KALI_HOST" \
  "$REMOTE_PY $REMOTE_SERVER --host 127.0.0.1 --port $AGENT_PORT"
