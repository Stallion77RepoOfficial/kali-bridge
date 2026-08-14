#!/usr/bin/env python3
"""kali-bridge MCP server -- runs on macOS, talks to the Kali agent over TCP.

Exposes the Kali box to MCP clients (Claude Desktop, Codex) as tools for
running commands, driving interactive shells, and reading/writing files.

Configure with env vars or CLI flags:
    KALI_BRIDGE_HOST (default 127.0.0.1)
    KALI_BRIDGE_PORT (default 4444)
"""

import argparse
import json
import os
import re
import socket
import struct
import sys
from typing import Annotated, Any

try:  # mcp >= 2.0 renamed FastMCP to MCPServer; the API we use is identical.
    from mcp.server.mcpserver import MCPServer as _Server
    from mcp.server.mcpserver.exceptions import ToolError
except ImportError:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _Server
    from mcp.server.fastmcp.exceptions import ToolError

from pydantic import Field

VERSION = "2.0.0"

MAX_HEADER = 1 * 1024 * 1024
MAX_PAYLOAD = 64 * 1024 * 1024
CONNECT_TIMEOUT = 10.0
IO_MARGIN = 30.0

HOST = os.environ.get("KALI_BRIDGE_HOST", "127.0.0.1")
PORT = int(os.environ.get("KALI_BRIDGE_PORT", "4444"))


def log(message: str) -> None:
    # stdout is the MCP transport; diagnostics must go to stderr.
    print("[kali-mcp] %s" % message, file=sys.stderr, flush=True)


# --------------------------------------------------------------------------
# transport
# --------------------------------------------------------------------------

def call(op: str, payload: bytes = b"", io_timeout: float = 60.0, **args: Any):
    """Run one request against the agent and return (header, payload)."""
    header: dict[str, Any] = {"op": op}
    for key, value in args.items():
        if value is not None:
            header[key] = value
    header_raw = json.dumps(header).encode("utf-8")

    try:
        sock = socket.create_connection((HOST, PORT), timeout=CONNECT_TIMEOUT)
    except OSError as exc:
        raise ToolError(
            "cannot reach kali agent at %s:%d (%s). Is kali_agent.py running on the "
            "Kali VM, and is the IP right? Check with kali_status." % (HOST, PORT, exc))

    try:
        sock.settimeout(io_timeout)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.sendall(struct.pack("!II", len(header_raw), len(payload)))
        sock.sendall(header_raw)
        if payload:
            sock.sendall(payload)

        prefix = _recv_exact(sock, 8)
        header_len, payload_len = struct.unpack("!II", prefix)
        if header_len == 0 or header_len > MAX_HEADER or payload_len > MAX_PAYLOAD:
            raise ToolError("agent sent a malformed frame (%d/%d bytes)"
                            % (header_len, payload_len))
        reply = json.loads(_recv_exact(sock, header_len).decode("utf-8"))
        body = _recv_exact(sock, payload_len)
    except socket.timeout:
        raise ToolError("agent timed out after %.0fs on %s" % (io_timeout, op))
    except (OSError, ValueError) as exc:
        raise ToolError("transport error on %s: %s" % (op, exc))
    finally:
        sock.close()

    if not reply.get("ok"):
        raise ToolError("%s failed [%s]: %s" % (
            op, reply.get("kind", "error"), reply.get("error", "unknown error")))
    return reply, body


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    if n == 0:
        return b""
    chunks = []
    remaining = n
    while remaining:
        chunk = sock.recv(min(remaining, 1 << 20))
        if not chunk:
            raise OSError("connection closed mid-frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


# --------------------------------------------------------------------------
# formatting
# --------------------------------------------------------------------------

ANSI_OSC = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
ANSI_CSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
ANSI_OTHER = re.compile(r"\x1b[@-Z\\-_]|[\x00\x07\x0f]")


def strip_ansi(text: str) -> str:
    """Flatten PTY output into something a model can read."""
    text = ANSI_OSC.sub("", text)
    text = ANSI_CSI.sub("", text)
    text = ANSI_OTHER.sub("", text)
    text = text.replace("\r\n", "\n")
    # Lone CRs overwrite the line on a real terminal; emulate that.
    return "\n".join(
        line.split("\r")[-1] if "\r" in line else line
        for line in text.split("\n")
    )


def section(title: str, body: str) -> str:
    body = body.rstrip("\n")
    if not body:
        return "--- %s: empty ---" % title
    return "--- %s ---\n%s" % (title, body)


def as_json(data: Any) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False, default=str)


def clean(reply: dict) -> dict:
    return {k: v for k, v in reply.items() if k not in ("ok", "op")}


# --------------------------------------------------------------------------
# server
# --------------------------------------------------------------------------

mcp = _Server(
    "kali-bridge",
    log_level=os.environ.get("KALI_BRIDGE_LOG_LEVEL", "WARNING"),
    instructions=(
        "Runs commands and manages files on a Kali Linux VM over the kali-bridge "
        "protocol. Use kali_exec for one-shot commands that finish quickly. Use "
        "kali_job_* for long scans (nmap, gobuster, hydra) so nothing blocks. Use "
        "kali_session_* only for programs that prompt interactively (msfconsole, "
        "sqlmap, an ssh login). Use the file tools instead of cat/echo heredocs "
        "when reading or writing files -- they are binary safe.\n\n"
        "Every program on the box is reachable through kali_exec; there is no "
        "per-tool wrapper to look for. For a tool that runs as a local server "
        "with a REST API (gophish, BloodHound, a ZAP daemon, msfrpcd, Neo4j), "
        "the pattern is: start it with kali_job_start, find its port with "
        "kali_services, then drive its API with kali_http. Requests leave from "
        "the Kali box, so 127.0.0.1 reaches its loopback services directly."
    ),
)


@mcp.tool()
def kali_status() -> str:
    """Check that the Kali agent is reachable and report host details.

    Run this first when anything else fails, to tell a dead agent apart from a
    failing command.
    """
    reply, _ = call("ping", io_timeout=15.0)
    info = clean(reply)
    info["mcp_version"] = VERSION
    info["endpoint"] = "%s:%d" % (HOST, PORT)
    return as_json(info)


@mcp.tool()
def kali_exec(
    command: Annotated[str, Field(description=(
        "Shell command line, run through `bash -lc`, so pipes, redirects, globs "
        "and $VARS all work."))],
    cwd: Annotated[str | None, Field(description="Working directory on Kali.")] = None,
    timeout: Annotated[float, Field(description=(
        "Seconds before the process group is killed. Raise it for slow commands, "
        "or use kali_job_start instead."), ge=1, le=3600)] = 120,
    stdin: Annotated[str | None, Field(
        description="Text piped to the command's stdin.")] = None,
    env: Annotated[dict[str, str] | None, Field(
        description="Extra environment variables.")] = None,
    merge_stderr: Annotated[bool, Field(
        description="Fold stderr into stdout in order.")] = False,
    max_output: Annotated[int, Field(description=(
        "Max bytes returned per stream; the middle is dropped when longer."),
        ge=1024, le=4194304)] = 200000,
) -> str:
    """Run a single command on Kali and return stdout, stderr and the exit code.

    Best for commands that finish in seconds: id, ls, cat, curl, a quick nmap.
    There is no PTY, so the output is clean; interactive prompts will hang until
    the timeout -- use kali_session_start for those.
    """
    reply, _ = call(
        "exec",
        payload=(stdin or "").encode("utf-8"),
        io_timeout=timeout + IO_MARGIN,
        command=command, cwd=cwd, timeout=timeout, env=env,
        merge_stderr=merge_stderr, max_output=max_output,
    )
    lines = ["exit_code: %s" % reply.get("exit_code"),
             "duration: %ss" % reply.get("duration")]
    if reply.get("timed_out"):
        lines.append("TIMED OUT -- process group was killed")
    if reply.get("truncated"):
        lines.append("output truncated (stdout %s B, stderr %s B on the host)"
                     % (reply.get("stdout_len"), reply.get("stderr_len")))
    lines.append(section("stdout", reply.get("stdout", "")))
    if reply.get("stderr"):
        lines.append(section("stderr", reply["stderr"]))
    return "\n".join(lines)


@mcp.tool()
def kali_services(
    include_udp: Annotated[bool, Field(
        description="Also list UDP listeners.")] = False,
) -> str:
    """List the ports being listened on, with the process behind each one.

    Use it to find a locally running tool before driving it: gophish, BloodHound,
    a ZAP daemon, msfrpcd, Neo4j, a target web app. Process names only show for
    sockets owned by the agent's user, so a service started by root shows the
    port but no name.
    """
    reply, _ = call("services.list", io_timeout=30.0, include_udp=include_udp)
    return as_json({"as_user": reply.get("as_user"),
                    "count": reply.get("count"),
                    "services": reply.get("services", []),
                    "errors": reply.get("errors", [])})


@mcp.tool()
def kali_http(
    url: Annotated[str, Field(description=(
        "Full URL. Requests are made from the Kali box, so 127.0.0.1 reaches "
        "services bound to its loopback with no tunnelling."))],
    method: Annotated[str, Field(
        description="HTTP method: GET, POST, PUT, DELETE, PATCH, HEAD.")] = "GET",
    headers: Annotated[dict[str, str] | None, Field(description=(
        "Request headers, e.g. an API key: {\"Authorization\": \"...\"}."))] = None,
    json_body: Annotated[dict | None, Field(description=(
        "Body sent as JSON; sets Content-Type automatically. Use this instead "
        "of hand-escaping JSON into a curl command."))] = None,
    body: Annotated[str | None, Field(
        description="Raw request body. Ignored when json_body is given.")] = None,
    timeout: Annotated[float, Field(description="Seconds to wait.",
                                    ge=1, le=600)] = 30,
    insecure: Annotated[bool, Field(description=(
        "Skip TLS verification. Needed for the self-signed certificates local "
        "admin panels normally use."))] = False,
    max_bytes: Annotated[int, Field(description="Max response bytes returned.",
                                    ge=1024, le=8388608)] = 1048576,
) -> str:
    """Make an HTTP request from the Kali box and return status, headers and body.

    This is the way to drive any tool that exposes a REST API — gophish,
    BloodHound CE, a ZAP daemon, msfrpcd, Neo4j — and to reach a target web app
    from the box's own network position. Prefer it over curl through kali_exec:
    no shell quoting, so JSON bodies and header values survive intact.

    A 4xx or 5xx response is returned as data, not raised as an error.
    """
    payload = b""
    request_headers = dict(headers or {})
    if json_body is not None:
        payload = json.dumps(json_body).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/json")
    elif body:
        payload = body.encode("utf-8")

    reply, content = call("http.request", payload=payload,
                          io_timeout=timeout + IO_MARGIN, url=url,
                          method=method.upper(), headers=request_headers,
                          timeout=timeout, insecure=insecure,
                          max_bytes=max_bytes)

    interesting = ("content-type", "content-length", "location", "server",
                   "www-authenticate", "set-cookie")
    shown = {k: v for k, v in reply.get("headers", {}).items()
             if k.lower() in interesting}
    lines = ["%s %s %s" % (reply.get("status"), reply.get("reason"),
                           reply.get("url")),
             "duration: %ss   bytes: %s%s" % (
                 reply.get("duration"), reply.get("length"),
                 "  (truncated)" if reply.get("truncated") else "")]
    if shown:
        lines.append(section("headers", as_json(shown)))
    lines.append(section("body", content.decode("utf-8", "replace")))
    return "\n".join(lines)


# ---- background jobs -----------------------------------------------------

@mcp.tool()
def kali_job_start(
    command: Annotated[str, Field(
        description="Command line, run through `bash -lc`.")],
    cwd: Annotated[str | None, Field(description="Working directory on Kali.")] = None,
    env: Annotated[dict[str, str] | None, Field(
        description="Extra environment variables.")] = None,
    merge_stderr: Annotated[bool, Field(
        description="Fold stderr into stdout in order.")] = False,
) -> str:
    """Start a long-running command in the background and return its job_id.

    Use for scans and brute force runs that take minutes: nmap -A, gobuster,
    hydra, tcpdump. Poll it with kali_job_output; the job keeps running on Kali
    even if this MCP server restarts.
    """
    reply, _ = call("job.start", io_timeout=30.0, command=command, cwd=cwd,
                    env=env, merge_stderr=merge_stderr)
    return as_json(clean(reply))


@mcp.tool()
def kali_job_output(
    job_id: Annotated[str, Field(description="Job id from kali_job_start.")],
    timeout: Annotated[float, Field(description=(
        "Seconds to wait for new output before returning. 0 returns immediately."),
        ge=0, le=600)] = 5,
    max_output: Annotated[int, Field(description="Max bytes returned per stream.",
                                     ge=1024, le=4194304)] = 200000,
) -> str:
    """Read whatever the job has produced since the last read.

    Output is consumed, so each call returns only new bytes. Check `alive` to see
    whether the job is still running and `exit_code` once it is done.
    """
    reply, _ = call("job.output", io_timeout=timeout + IO_MARGIN,
                    job_id=job_id, timeout=timeout, max_output=max_output)
    lines = ["job_id: %s" % reply.get("job_id"),
             "command: %s" % reply.get("command"),
             "alive: %s" % reply.get("alive"),
             "exit_code: %s" % reply.get("exit_code"),
             "runtime: %ss" % reply.get("runtime")]
    if reply.get("dropped"):
        lines.append("dropped %s bytes (buffer overflow or truncation)"
                     % reply["dropped"])
    lines.append(section("new stdout", reply.get("stdout", "")))
    if reply.get("stderr"):
        lines.append(section("new stderr", reply["stderr"]))
    return "\n".join(lines)


@mcp.tool()
def kali_job_list() -> str:
    """List background jobs with their state, runtime and buffered output size."""
    reply, _ = call("job.list", io_timeout=15.0)
    return as_json(reply.get("jobs", []))


@mcp.tool()
def kali_job_kill(
    job_id: Annotated[str, Field(description="Job id to signal.")],
    signal: Annotated[str, Field(description=(
        "Signal name: TERM (polite), KILL (forced), INT, HUP."))] = "TERM",
) -> str:
    """Signal a background job's whole process group, stopping it and its children."""
    reply, _ = call("job.kill", io_timeout=15.0, job_id=job_id, signal=signal)
    return as_json(clean(reply))


@mcp.tool()
def kali_job_remove(
    job_id: Annotated[str, Field(description="Job id to drop from the registry.")],
) -> str:
    """Kill a job if needed and forget it, freeing its output buffer."""
    reply, _ = call("job.remove", io_timeout=20.0, job_id=job_id)
    return as_json(clean(reply))


# ---- interactive sessions ------------------------------------------------

@mcp.tool()
def kali_session_start(
    shell: Annotated[str, Field(
        description="Program to run under the PTY.")] = "/bin/bash",
    cwd: Annotated[str | None, Field(description="Working directory on Kali.")] = None,
    env: Annotated[dict[str, str] | None, Field(
        description="Extra environment variables.")] = None,
    rows: Annotated[int, Field(description="Terminal height.", ge=10, le=200)] = 40,
    cols: Annotated[int, Field(description="Terminal width.", ge=40, le=500)] = 120,
) -> str:
    """Open a persistent PTY shell on Kali and return its session_id.

    Only needed for programs that require a real terminal or that prompt for
    input: msfconsole, sqlmap, an ssh login, sudo asking for a password, python
    REPLs. For anything else prefer kali_exec, whose output is far cleaner.
    Always close sessions with kali_session_close when finished.
    """
    reply, _ = call("session.start", io_timeout=30.0, shell=shell, cwd=cwd,
                    env=env, rows=rows, cols=cols)
    return as_json(clean(reply))


@mcp.tool()
def kali_session_send(
    session_id: Annotated[str, Field(
        description="Session id from kali_session_start.")],
    data: Annotated[str, Field(description=(
        "Text to type into the shell. For Ctrl-C and friends use "
        "kali_session_signal rather than control characters."))],
    enter: Annotated[bool, Field(
        description="Append a newline, as pressing Return.")] = True,
    consume_echo: Annotated[bool, Field(description=(
        "Discard the terminal's echo of this input so the next read returns "
        "only the command's output. Leave it on unless you specifically want to "
        "see what the terminal echoed back."))] = True,
) -> str:
    """Type input into an interactive session. Read the result with kali_session_read.

    The echo of what you type is swallowed by default, so a later `wait_for`
    matches the command's output rather than the command itself.
    """
    reply, _ = call("session.send", payload=data.encode("utf-8"), io_timeout=20.0,
                    session_id=session_id, enter=enter, consume_echo=consume_echo)
    return as_json(clean(reply))


@mcp.tool()
def kali_session_read(
    session_id: Annotated[str, Field(description="Session id to read from.")],
    timeout: Annotated[float, Field(description=(
        "Seconds to wait for output. Give slow commands more time."),
        ge=0, le=600)] = 5,
    wait_for: Annotated[str | None, Field(description=(
        "Regex to wait for, matched against the same escape-stripped text this "
        "tool returns. Returns as soon as it appears instead of burning the "
        "whole timeout. Do not anchor with $: a prompt is usually followed by "
        "escape sequences, so the stream does not end where the prompt does."))] = None,
    strip_ansi_codes: Annotated[bool, Field(description=(
        "Remove terminal escape sequences and collapse overwritten lines."))] = True,
    max_output: Annotated[int, Field(description="Max bytes returned.",
                                     ge=1024, le=4194304)] = 200000,
) -> str:
    """Read and consume output produced by an interactive session since the last read.

    Pair it with `wait_for` to sync on a prompt rather than guessing at sleeps.

    For a REPL of its own (radare2, msfconsole, a python shell), waiting on the
    prompt itself is unreliable: the program redraws its prompt before echoing
    what you typed, so the pattern matches before your command has even run. The
    technique that always works is a sentinel the program computes for you --
    send `<command>; ?vi 48383*48383` to radare2 and wait for `2340914689`. The
    value appears only in the output, never in the command, so the match cannot
    fire early.
    """
    reply, body = call("session.read", io_timeout=timeout + IO_MARGIN,
                       session_id=session_id, timeout=timeout,
                       wait_for=wait_for, max_output=max_output,
                       match_stripped=True)
    text = body.decode("utf-8", "replace")
    if strip_ansi_codes:
        text = strip_ansi(text)
    lines = ["session_id: %s" % reply.get("session_id"),
             "alive: %s" % reply.get("alive"),
             "exit_code: %s" % reply.get("exit_code")]
    if wait_for:
        lines.append("matched: %s" % reply.get("matched"))
    if reply.get("dropped"):
        lines.append("dropped %s bytes" % reply["dropped"])
    lines.append(section("output", text))
    return "\n".join(lines)


@mcp.tool()
def kali_session_signal(
    session_id: Annotated[str, Field(description="Session id to signal.")],
    signal: Annotated[str, Field(description=(
        "Signal name. INT is Ctrl-C, QUIT is Ctrl-\\, TERM ends it."))] = "INT",
) -> str:
    """Send a signal to a session's foreground process group -- the Ctrl-C equivalent."""
    reply, _ = call("session.signal", io_timeout=15.0,
                    session_id=session_id, signal=signal)
    return as_json(clean(reply))


@mcp.tool()
def kali_session_resize(
    session_id: Annotated[str, Field(description="Session id to resize.")],
    rows: Annotated[int, Field(description="Terminal height.", ge=10, le=200)] = 40,
    cols: Annotated[int, Field(description="Terminal width.", ge=40, le=500)] = 120,
) -> str:
    """Change a session's terminal size, for tools that wrap output to the width."""
    reply, _ = call("session.resize", io_timeout=15.0,
                    session_id=session_id, rows=rows, cols=cols)
    return as_json(clean(reply))


@mcp.tool()
def kali_session_list() -> str:
    """List open PTY sessions with their shell, state and buffered output size."""
    reply, _ = call("session.list", io_timeout=15.0)
    return as_json(reply.get("sessions", []))


@mcp.tool()
def kali_session_close(
    session_id: Annotated[str, Field(description="Session id to terminate.")],
) -> str:
    """Terminate an interactive session and release its PTY."""
    reply, _ = call("session.close", io_timeout=20.0, session_id=session_id)
    return as_json(clean(reply))


# ---- filesystem ----------------------------------------------------------

@mcp.tool()
def kali_read_file(
    path: Annotated[str, Field(description="Absolute path on Kali; ~ is expanded.")],
    offset: Annotated[int, Field(description="Byte offset to start at.", ge=0)] = 0,
    length: Annotated[int, Field(description=(
        "Max bytes to read; 0 means to the end of the file."), ge=0)] = 262144,
) -> str:
    """Read a file from Kali as text.

    Preferred over `cat` -- no shell quoting, no PTY noise, and it reports the
    true file size so you can page through large files with offset/length.
    Binary files come back with replacement characters; use kali_download instead.
    """
    reply, body = call("fs.read", io_timeout=120.0,
                       path=path, offset=offset, length=length)
    header = "path: %s\nsize: %s bytes\nreturned: %s bytes (offset %s)%s" % (
        reply.get("path"), reply.get("size"), reply.get("read"), reply.get("offset"),
        "" if reply.get("eof") else "\nmore data follows -- raise offset to continue")
    return header + "\n" + section("content", body.decode("utf-8", "replace"))


@mcp.tool()
def kali_write_file(
    path: Annotated[str, Field(description="Absolute path on Kali; ~ is expanded.")],
    content: Annotated[str, Field(description="Text to write, UTF-8 encoded.")],
    append: Annotated[bool, Field(description="Append instead of overwriting.")] = False,
    mode: Annotated[str | None, Field(description=(
        "Octal permissions to set afterwards, e.g. '755' for a script."))] = None,
    parents: Annotated[bool, Field(
        description="Create missing parent directories.")] = True,
) -> str:
    """Write text to a file on Kali, overwriting it unless append is set.

    Preferred over `echo >` heredocs -- no quoting or escaping problems with
    payloads, quotes, backslashes or newlines.
    """
    reply, _ = call("fs.write", payload=content.encode("utf-8"), io_timeout=120.0,
                    path=path, append=append, mode=mode, parents=parents)
    return as_json(clean(reply))


@mcp.tool()
def kali_list_dir(
    path: Annotated[str, Field(description="Directory path on Kali.")] = ".",
) -> str:
    """List a directory on Kali with each entry's type, size, mode and mtime."""
    reply, _ = call("fs.list", io_timeout=60.0, path=path)
    return as_json({"path": reply.get("path"), "count": reply.get("count"),
                    "entries": reply.get("entries", [])})


@mcp.tool()
def kali_stat(
    path: Annotated[str, Field(description="Path on Kali to inspect.")],
) -> str:
    """Show type, size, permissions, owner and mtime for one path on Kali."""
    reply, _ = call("fs.stat", io_timeout=30.0, path=path)
    return as_json(clean(reply))


@mcp.tool()
def kali_mkdir(
    path: Annotated[str, Field(description="Directory to create on Kali.")],
    mode: Annotated[str | None, Field(
        description="Octal permissions, e.g. '700'.")] = None,
) -> str:
    """Create a directory on Kali, including any missing parents."""
    reply, _ = call("fs.mkdir", io_timeout=30.0, path=path, parents=True, mode=mode)
    return as_json(clean(reply))


@mcp.tool()
def kali_delete(
    path: Annotated[str, Field(description="Path on Kali to delete.")],
    recursive: Annotated[bool, Field(description=(
        "Required to delete a non-empty directory and everything under it."))] = False,
) -> str:
    """Delete a file, or a directory when recursive is set.

    This is irreversible -- there is no trash on the Kali box. Confirm the path
    with kali_stat or kali_list_dir before deleting anything you did not create.
    """
    reply, _ = call("fs.delete", io_timeout=120.0, path=path, recursive=recursive)
    return as_json(clean(reply))


@mcp.tool()
def kali_upload(
    local_path: Annotated[str, Field(description="File on this Mac to send.")],
    remote_path: Annotated[str, Field(description="Destination path on Kali.")],
    mode: Annotated[str | None, Field(
        description="Octal permissions to set on Kali.")] = None,
) -> str:
    """Copy a file from this Mac to the Kali VM, binary safe.

    Use for wordlists, payloads, scripts and captures instead of pasting content
    through the shell.
    """
    path = os.path.abspath(os.path.expanduser(local_path))
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_PAYLOAD + 1)
    except OSError as exc:
        raise ToolError("cannot read local file %s: %s" % (path, exc))
    if len(data) > MAX_PAYLOAD:
        raise ToolError("local file exceeds the %d byte frame limit" % MAX_PAYLOAD)
    reply, _ = call("fs.write", payload=data, io_timeout=600.0,
                    path=remote_path, append=False, mode=mode, parents=True)
    return as_json({"local_path": path, "remote_path": reply.get("path"),
                    "bytes_written": reply.get("bytes_written")})


@mcp.tool()
def kali_download(
    remote_path: Annotated[str, Field(description="File on Kali to fetch.")],
    local_path: Annotated[str, Field(description="Destination path on this Mac.")],
) -> str:
    """Copy a file from the Kali VM to this Mac, binary safe.

    Use for scan results, pcaps, dumps and screenshots that you want to keep or
    analyse locally.
    """
    path = os.path.abspath(os.path.expanduser(local_path))
    reply, body = call("fs.read", io_timeout=600.0, path=remote_path,
                       offset=0, length=MAX_PAYLOAD)
    if not reply.get("eof"):
        raise ToolError("file is larger than one frame (%s bytes); fetch it in "
                        "parts with kali_read_file" % reply.get("size"))
    try:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(body)
    except OSError as exc:
        raise ToolError("cannot write local file %s: %s" % (path, exc))
    return as_json({"remote_path": reply.get("path"), "local_path": path,
                    "bytes": len(body)})


def print_config(kind: str, host: str, port: int) -> None:
    """Emit a ready-to-paste client entry with this machine's real paths.

    Absolute paths differ per machine and the clients launch the server without
    your shell PATH, so the paths are resolved here rather than left for a human
    to substitute into an example.
    """
    python = os.path.abspath(sys.executable)
    script = os.path.abspath(__file__)
    args = [script, "--host", host, "--port", str(port)]

    if kind == "codex":
        print("# append to ~/.codex/config.toml")
        print("[mcp_servers.kali-bridge]")
        print('command = "%s"' % python)
        print("args = [%s]" % ", ".join('"%s"' % a for a in args))
        print("startup_timeout_sec = 30")
    elif kind == "claude":
        print("// merge into the mcpServers object of")
        print('// ~/Library/Application Support/Claude/claude_desktop_config.json')
        print(json.dumps({"kali-bridge": {"command": python, "args": args}}, indent=2))
    else:  # plain, for GUI forms that want one field at a time
        print("command:  %s" % python)
        for i, a in enumerate(args, 1):
            print("arg %d:    %s" % (i, a))


def main() -> None:
    global HOST, PORT
    parser = argparse.ArgumentParser(description="kali-bridge MCP server")
    parser.add_argument("--host", default=HOST, help="Kali agent address")
    parser.add_argument("--port", type=int, default=PORT, help="Kali agent port")
    parser.add_argument("--print-config", choices=["codex", "claude", "fields"],
                        help="print a client configuration for this machine and exit")
    args = parser.parse_args()
    HOST, PORT = args.host, args.port

    if args.print_config:
        print_config(args.print_config, HOST, PORT)
        return
    log("v%s bridging to %s:%d" % (VERSION, HOST, PORT))
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
