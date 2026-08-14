#!/usr/bin/env python3
"""kali-bridge agent v2 -- runs on the Kali box, stdlib only.

Serves the kali-bridge wire protocol (see docs/protocol.md) over TCP:
one request/response per connection, with PTY sessions and background
jobs held in agent-side registries so the MCP server can stay stateless.

No authentication, no encryption -- keep it on the default loopback address.
"""

import argparse
import errno
import fcntl
import json
import os
import platform
import pty
import re
import signal
import socket
import socketserver
import stat as statmod
import struct
import subprocess
import sys
import termios
import threading
import time
import uuid

VERSION = "2.0.0"

MAX_HEADER = 1 * 1024 * 1024
DEFAULT_MAX_PAYLOAD = 64 * 1024 * 1024
DEFAULT_BUFFER_CAP = 8 * 1024 * 1024
DEFAULT_MAX_OUTPUT = 256 * 1024

START_TIME = time.time()


# --------------------------------------------------------------------------
# framing
# --------------------------------------------------------------------------

class ProtocolError(Exception):
    pass


class RequestError(Exception):
    def __init__(self, message, kind="bad_request"):
        super().__init__(message)
        self.kind = kind


def recv_exact(sock, n):
    if n == 0:
        return b""
    chunks = []
    remaining = n
    while remaining:
        chunk = sock.recv(min(remaining, 1 << 20))
        if not chunk:
            raise ProtocolError("connection closed mid-frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_frame(sock, max_payload):
    prefix = recv_exact(sock, 8)
    header_len, payload_len = struct.unpack("!II", prefix)
    if header_len == 0 or header_len > MAX_HEADER:
        raise ProtocolError("header length out of range: %d" % header_len)
    if payload_len > max_payload:
        raise ProtocolError("payload length out of range: %d" % payload_len)
    header_raw = recv_exact(sock, header_len)
    payload = recv_exact(sock, payload_len)
    try:
        header = json.loads(header_raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ProtocolError("malformed header JSON: %s" % exc)
    if not isinstance(header, dict):
        raise ProtocolError("header must be a JSON object")
    return header, payload


def write_frame(sock, header, payload=b""):
    header_raw = json.dumps(header, default=str).encode("utf-8")
    sock.sendall(struct.pack("!II", len(header_raw), len(payload)))
    sock.sendall(header_raw)
    if payload:
        sock.sendall(payload)


# --------------------------------------------------------------------------
# output buffering
# --------------------------------------------------------------------------

class OutputBuffer:
    """Append-only byte buffer with a hard cap and blocking reads.

    Readers drain the buffer; when the cap is exceeded the oldest bytes are
    discarded and counted in `dropped` so callers can tell output was lost.
    """

    def __init__(self, cap=DEFAULT_BUFFER_CAP):
        self.cap = cap
        self._buf = bytearray()
        self._dropped = 0
        self._closed = False
        self._cond = threading.Condition()

    def write(self, data):
        if not data:
            return
        with self._cond:
            self._buf.extend(data)
            overflow = len(self._buf) - self.cap
            if overflow > 0:
                del self._buf[:overflow]
                self._dropped += overflow
            self._cond.notify_all()

    def close(self):
        with self._cond:
            self._closed = True
            self._cond.notify_all()

    def pending(self):
        with self._cond:
            return len(self._buf)

    def drain(self, timeout=0.0, wait_for=None, match_stripped=True):
        """Consume buffered bytes.

        With `wait_for` (a regex) the call blocks until the pattern shows up or
        the timeout expires. The pattern is matched against the escape-stripped
        text by default, so it cannot match digits hiding inside an escape
        sequence that the caller will never be shown -- a resize to 200 columns
        makes the terminal emit "200" inside a cursor-movement code, which would
        otherwise satisfy a `wait_for` of "200".

        Returns (data, dropped, matched).
        """
        pattern = re.compile(wait_for.encode("utf-8")) if wait_for else None

        def hit(raw):
            if not pattern:
                return False
            return bool(pattern.search(strip_ansi_bytes(raw) if match_stripped else raw))

        deadline = time.monotonic() + max(0.0, timeout)
        with self._cond:
            while True:
                if hit(bytes(self._buf)):
                    break
                if not pattern and self._buf:
                    break
                if self._closed:
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._cond.wait(remaining)
            data = bytes(self._buf)
            self._buf.clear()
            dropped = self._dropped
            self._dropped = 0
            return data, dropped, hit(data)

    def consume_echo(self, sent, timeout=0.75):
        """Remove the terminal's echo of `sent` from the head of the buffer.

        A PTY echoes back whatever is typed into it, so without this the echoed
        command text looks like program output: a `wait_for` regex would happily
        match the command the caller just sent rather than its result.

        The prefix is only dropped when the whole of `sent` is matched, so a
        program that disables echo (a password prompt) loses nothing.
        """
        if not sent.strip():
            return 0
        deadline = time.monotonic() + max(0.0, timeout)
        with self._cond:
            while True:
                length = _echo_prefix_length(self._buf, sent)
                if length is not None:
                    del self._buf[:length]
                    return length
                if self._closed:
                    return 0
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return 0
                self._cond.wait(remaining)


def _echo_prefix_length(buf, sent):
    """Length of the echo of `sent` at the head of `buf`, or None.

    Tolerant of what readline adds to an echo: carriage returns and colour or
    cursor escape sequences are skipped. None means "not (yet) a full match",
    which keeps the caller from consuming a partial or unrelated prefix.
    """
    expected = sent.replace(b"\r", b"").replace(b"\n", b"")
    i = 0
    for want in expected:
        while True:
            if i >= len(buf):
                return None
            byte = buf[i]
            if byte == 0x1B:  # skip an escape sequence
                end = _escape_end(buf, i)
                if end is None:
                    return None
                i = end
                continue
            if byte in (0x0D, 0x07, 0x00):  # CR, bell, NUL are noise here
                i += 1
                continue
            break
        if buf[i] != want:
            return None
        i += 1
    # Swallow the newline the terminal echoes after the input, when it is there.
    while i < len(buf) and buf[i] in (0x0D, 0x0A):
        i += 1
    return i


def _escape_end(buf, start):
    """Index just past the escape sequence starting at `start`, or None."""
    i = start + 1
    if i >= len(buf):
        return None
    if buf[i] == 0x5B:  # CSI
        i += 1
        while i < len(buf) and 0x20 <= buf[i] <= 0x3F:
            i += 1
        if i >= len(buf):
            return None
        return i + 1
    if buf[i] == 0x5D:  # OSC, terminated by BEL or ST
        i += 1
        while i < len(buf):
            if buf[i] == 0x07:
                return i + 1
            if buf[i] == 0x1B and i + 1 < len(buf) and buf[i + 1] == 0x5C:
                return i + 2
            i += 1
        return None
    return i + 1


ANSI_OSC = re.compile(rb"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
ANSI_CSI = re.compile(rb"\x1b\[[0-9;?]*[ -/]*[@-~]")
ANSI_OTHER = re.compile(rb"\x1b[@-Z\\-_]|[\x00\x07\x0f]")


def strip_ansi_bytes(data):
    """Drop terminal escape sequences, so a match sees what a reader would."""
    data = ANSI_OSC.sub(b"", data)
    data = ANSI_CSI.sub(b"", data)
    return ANSI_OTHER.sub(b"", data)


def clamp_output(data, cap):
    """Trim to `cap` bytes keeping head and tail, which is what matters most."""
    if cap <= 0 or len(data) <= cap:
        return data, 0
    dropped = len(data) - cap
    head = max(1, cap * 6 // 10)
    tail = max(1, cap - head)
    marker = b"\n...[%d bytes truncated by kali-bridge]...\n" % dropped
    return data[:head] + marker + data[-tail:], dropped


# --------------------------------------------------------------------------
# process helpers
# --------------------------------------------------------------------------

def build_env(overrides, for_pty):
    env = os.environ.copy()
    env.setdefault("TERM", "xterm-256color" if for_pty else "dumb")
    if not for_pty:
        env["DEBIAN_FRONTEND"] = "noninteractive"
    if overrides:
        for key, value in overrides.items():
            if value is None:
                env.pop(str(key), None)
            else:
                env[str(key)] = str(value)
    return env


def resolve_cwd(cwd):
    if not cwd:
        return None
    path = os.path.abspath(os.path.expanduser(str(cwd)))
    if not os.path.isdir(path):
        raise RequestError("cwd is not a directory: %s" % path, "not_found")
    return path


def shell_argv(command, shell):
    shell = shell or "/bin/bash"
    if not os.path.exists(shell):
        raise RequestError("shell not found: %s" % shell, "not_found")
    return [shell, "-lc", command]


def resolve_signal(name, default=signal.SIGTERM):
    if name is None:
        return default
    if isinstance(name, int):
        return name
    text = str(name).upper()
    if text.isdigit():
        return int(text)
    if not text.startswith("SIG"):
        text = "SIG" + text
    try:
        return int(getattr(signal, text))
    except AttributeError:
        raise RequestError("unknown signal: %s" % name)


def kill_tree(proc, sig=signal.SIGTERM):
    """Signal the whole process group; children of a shell matter here."""
    if proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), sig)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.send_signal(sig)
        except (ProcessLookupError, OSError):
            pass


def terminate_tree(proc, grace=3.0):
    kill_tree(proc, signal.SIGTERM)
    try:
        proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        kill_tree(proc, signal.SIGKILL)
        try:
            proc.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            pass


# --------------------------------------------------------------------------
# jobs
# --------------------------------------------------------------------------

class Job:
    def __init__(self, command, cwd=None, env=None, shell=None,
                 merge_stderr=False, buffer_cap=DEFAULT_BUFFER_CAP):
        self.id = uuid.uuid4().hex[:12]
        self.command = command
        self.cwd = cwd
        self.merge_stderr = merge_stderr
        self.started = time.time()
        self.finished = None
        self.exit_code = None
        self.stdout = OutputBuffer(buffer_cap)
        self.stderr = self.stdout if merge_stderr else OutputBuffer(buffer_cap)

        self.proc = subprocess.Popen(
            shell_argv(command, shell),
            cwd=cwd,
            env=build_env(env, for_pty=False),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT if merge_stderr else subprocess.PIPE,
            start_new_session=True,
            close_fds=True,
        )

        self._pumps = [
            threading.Thread(target=self._pump, args=(self.proc.stdout, self.stdout),
                             daemon=True, name="job-%s-out" % self.id)
        ]
        if not merge_stderr and self.proc.stderr is not None:
            self._pumps.append(
                threading.Thread(target=self._pump, args=(self.proc.stderr, self.stderr),
                                 daemon=True, name="job-%s-err" % self.id))
        self._threads = list(self._pumps)
        self._threads.append(
            threading.Thread(target=self._reap, daemon=True, name="job-%s-reap" % self.id))
        for thread in self._threads:
            thread.start()

    def _pump(self, stream, buffer):
        try:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                buffer.write(chunk)
        except (OSError, ValueError):
            pass
        finally:
            try:
                stream.close()
            except OSError:
                pass

    def _reap(self):
        self.exit_code = self.proc.wait()
        # Drain first: the process can exit while its last writes are still
        # sitting in the pipe, and a caller that stops polling on alive=False
        # would otherwise lose the tail of the output.
        for pump in self._pumps:
            pump.join(timeout=30)
        self.finished = time.time()
        self.stdout.close()
        if self.stderr is not self.stdout:
            self.stderr.close()

    @property
    def alive(self):
        """True while more output may still arrive, not merely while it runs."""
        if self.proc.poll() is None:
            return True
        return any(pump.is_alive() for pump in self._pumps)

    def info(self):
        return {
            "job_id": self.id,
            "command": self.command,
            "pid": self.proc.pid,
            "cwd": self.cwd,
            "alive": self.alive,
            "exit_code": self.exit_code,
            "started": self.started,
            "runtime": round((self.finished or time.time()) - self.started, 3),
            "pending_stdout": self.stdout.pending(),
            "pending_stderr": self.stderr.pending() if self.stderr is not self.stdout else 0,
        }


# --------------------------------------------------------------------------
# interactive PTY sessions
# --------------------------------------------------------------------------

def set_winsize(fd, rows, cols):
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


class Session:
    def __init__(self, shell="/bin/bash", cwd=None, env=None, rows=40, cols=120,
                 buffer_cap=DEFAULT_BUFFER_CAP):
        self.id = uuid.uuid4().hex[:12]
        self.shell = shell or "/bin/bash"
        self.cwd = cwd
        self.rows = rows
        self.cols = cols
        self.created = time.time()
        self.finished = None
        self.exit_code = None
        self.buffer = OutputBuffer(buffer_cap)
        self._write_lock = threading.Lock()

        if not os.path.exists(self.shell):
            raise RequestError("shell not found: %s" % self.shell, "not_found")

        self.master_fd, slave_fd = pty.openpty()
        set_winsize(self.master_fd, rows, cols)

        def child_setup():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)
            # Belt and braces against an inherited SIG_IGN: subprocess only
            # restores SIGPIPE and friends, so Ctrl-C would otherwise be dead.
            for sig in (signal.SIGINT, signal.SIGQUIT, signal.SIGTSTP,
                        signal.SIGTTIN, signal.SIGTTOU):
                signal.signal(sig, signal.SIG_DFL)

        try:
            self.proc = subprocess.Popen(
                [self.shell, "-l"],
                preexec_fn=child_setup,
                cwd=cwd,
                env=build_env(env, for_pty=True),
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True,
            )
        finally:
            os.close(slave_fd)

        self._pump_thread = threading.Thread(
            target=self._pump, daemon=True, name="session-%s" % self.id)
        self._pump_thread.start()

    def _pump(self):
        while True:
            try:
                chunk = os.read(self.master_fd, 65536)
            except OSError as exc:
                if exc.errno == errno.EINTR:
                    continue
                chunk = b""
            if not chunk:
                break
            self.buffer.write(chunk)
        self.exit_code = self.proc.wait()
        self.finished = time.time()
        self.buffer.close()

    @property
    def alive(self):
        return self.proc.poll() is None

    def send(self, data):
        if not self.alive:
            raise RequestError("session %s has exited" % self.id, "not_found")
        with self._write_lock:
            total = 0
            view = memoryview(data)
            while total < len(data):
                try:
                    total += os.write(self.master_fd, view[total:])
                except OSError as exc:
                    if exc.errno == errno.EINTR:
                        continue
                    if exc.errno == errno.EAGAIN:
                        time.sleep(0.01)
                        continue
                    raise RequestError("write to session failed: %s" % exc, "os_error")
            return total

    def resize(self, rows, cols):
        self.rows, self.cols = rows, cols
        try:
            set_winsize(self.master_fd, rows, cols)
        except OSError as exc:
            raise RequestError("resize failed: %s" % exc, "os_error")

    def signal(self, sig):
        # Target the terminal's foreground process group, which is what pressing
        # Ctrl-C does. Signalling the shell's own group instead would hit an
        # interactive bash, which ignores SIGINT, and leave the running command
        # untouched -- job control puts that command in a group of its own.
        try:
            pgid = os.tcgetpgrp(self.master_fd)
        except OSError:
            pgid = os.getpgid(self.proc.pid)
        try:
            os.killpg(pgid, sig)
        except (ProcessLookupError, PermissionError, OSError) as exc:
            raise RequestError("signal failed: %s" % exc, "os_error")
        return pgid

    def close(self):
        terminate_tree(self.proc)
        try:
            os.close(self.master_fd)
        except OSError:
            pass
        self.buffer.close()

    def info(self):
        return {
            "session_id": self.id,
            "shell": self.shell,
            "pid": self.proc.pid,
            "cwd": self.cwd,
            "rows": self.rows,
            "cols": self.cols,
            "alive": self.alive,
            "exit_code": self.exit_code,
            "created": self.created,
            "age": round(time.time() - self.created, 3),
            "pending_bytes": self.buffer.pending(),
        }


# --------------------------------------------------------------------------
# registries
# --------------------------------------------------------------------------

class Registry:
    def __init__(self, label, limit):
        self.label = label
        self.limit = limit
        self._items = {}
        self._lock = threading.Lock()

    def add(self, item):
        with self._lock:
            live = sum(1 for other in self._items.values() if other.alive)
            if live >= self.limit:
                raise RequestError(
                    "too many live %ss (limit %d); close some first"
                    % (self.label, self.limit), "bad_request")
            self._items[item.id] = item
            return item

    def get(self, item_id):
        with self._lock:
            item = self._items.get(item_id)
        if item is None:
            raise RequestError("no such %s: %s" % (self.label, item_id), "not_found")
        return item

    def remove(self, item_id):
        with self._lock:
            return self._items.pop(item_id, None)

    def all(self):
        with self._lock:
            return list(self._items.values())

    def count_alive(self):
        return sum(1 for item in self.all() if item.alive)


SESSIONS = Registry("session", 32)
JOBS = Registry("job", 64)


# --------------------------------------------------------------------------
# operations
# --------------------------------------------------------------------------

def require(header, key):
    value = header.get(key)
    if value is None or (isinstance(value, str) and not value):
        raise RequestError("missing required argument: %s" % key)
    return value


def op_ping(header, payload, config):
    return {
        "version": VERSION,
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "user": _current_user(),
        "cwd": os.getcwd(),
        "uptime": round(time.time() - START_TIME, 3),
        "sessions": SESSIONS.count_alive(),
        "jobs": JOBS.count_alive(),
        "max_payload": config["max_payload"],
    }, b""


def _current_user():
    try:
        import pwd
        return "%s(uid=%d)" % (pwd.getpwuid(os.geteuid()).pw_name, os.geteuid())
    except Exception:
        return "uid=%d" % os.geteuid()


def op_exec(header, payload, config):
    command = require(header, "command")
    cwd = resolve_cwd(header.get("cwd"))
    timeout = float(header.get("timeout") or 120)
    merge = bool(header.get("merge_stderr"))
    cap = int(header.get("max_output") or DEFAULT_MAX_OUTPUT)
    stdin_data = payload or b""

    started = time.monotonic()
    proc = subprocess.Popen(
        shell_argv(command, header.get("shell")),
        cwd=cwd,
        env=build_env(header.get("env"), for_pty=False),
        stdin=subprocess.PIPE if stdin_data else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT if merge else subprocess.PIPE,
        start_new_session=True,
        close_fds=True,
    )

    timed_out = False
    try:
        out, err = proc.communicate(input=stdin_data or None, timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        terminate_tree(proc)
        try:
            out, err = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            out, err = b"", b""
    out = out or b""
    err = err or b""

    out_full, err_full = len(out), len(err)
    out, out_dropped = clamp_output(out, cap)
    err, err_dropped = clamp_output(err, cap)

    return {
        "exit_code": proc.returncode,
        "timed_out": timed_out,
        "duration": round(time.monotonic() - started, 3),
        "cwd": cwd or os.getcwd(),
        "stdout": out.decode("utf-8", "replace"),
        "stderr": err.decode("utf-8", "replace"),
        "stdout_len": out_full,
        "stderr_len": err_full,
        "truncated": bool(out_dropped or err_dropped),
    }, b""


def op_job_start(header, payload, config):
    command = require(header, "command")
    job = Job(
        command,
        cwd=resolve_cwd(header.get("cwd")),
        env=header.get("env"),
        shell=header.get("shell"),
        merge_stderr=bool(header.get("merge_stderr")),
        buffer_cap=config["buffer_cap"],
    )
    JOBS.add(job)
    return job.info(), b""


def op_job_output(header, payload, config):
    job = JOBS.get(require(header, "job_id"))
    timeout = float(header.get("timeout") or 0)
    cap = int(header.get("max_output") or DEFAULT_MAX_OUTPUT)

    out, out_dropped, _ = job.stdout.drain(timeout=timeout)
    if job.stderr is job.stdout:
        err, err_dropped = b"", 0
    else:
        err, err_dropped, _ = job.stderr.drain(timeout=0)

    out, out_clamped = clamp_output(out, cap)
    err, err_clamped = clamp_output(err, cap)

    info = job.info()
    info.update({
        "stdout": out.decode("utf-8", "replace"),
        "stderr": err.decode("utf-8", "replace"),
        "dropped": out_dropped + err_dropped + out_clamped + err_clamped,
    })
    return info, b""


def op_job_list(header, payload, config):
    return {"jobs": [job.info() for job in JOBS.all()]}, b""


def op_job_kill(header, payload, config):
    job = JOBS.get(require(header, "job_id"))
    sig = resolve_signal(header.get("signal"), signal.SIGTERM)
    kill_tree(job.proc, sig)
    return {"job_id": job.id, "signal": int(sig), "alive": job.alive}, b""


def op_job_remove(header, payload, config):
    job = JOBS.get(require(header, "job_id"))
    if job.alive:
        terminate_tree(job.proc)
    JOBS.remove(job.id)
    return {"job_id": job.id, "removed": True}, b""


def op_session_start(header, payload, config):
    session = Session(
        shell=header.get("shell") or "/bin/bash",
        cwd=resolve_cwd(header.get("cwd")),
        env=header.get("env"),
        rows=int(header.get("rows") or 40),
        cols=int(header.get("cols") or 120),
        buffer_cap=config["buffer_cap"],
    )
    SESSIONS.add(session)
    return session.info(), b""


def op_session_send(header, payload, config):
    session = SESSIONS.get(require(header, "session_id"))
    data = payload or b""
    if header.get("enter"):
        data += b"\n"
    written = session.send(data)
    echo = 0
    if header.get("consume_echo", True):
        echo = session.buffer.consume_echo(data)
    return {"session_id": session.id, "bytes_written": written,
            "echo_consumed": echo}, b""


def op_session_read(header, payload, config):
    session = SESSIONS.get(require(header, "session_id"))
    timeout = float(header.get("timeout") or 0)
    cap = int(header.get("max_output") or DEFAULT_MAX_OUTPUT)
    data, dropped, matched = session.buffer.drain(
        timeout=timeout, wait_for=header.get("wait_for"),
        match_stripped=header.get("match_stripped", True))
    data, clamped = clamp_output(data, cap)
    info = session.info()
    info.update({"matched": matched, "dropped": dropped + clamped})
    return info, data


def op_session_resize(header, payload, config):
    session = SESSIONS.get(require(header, "session_id"))
    session.resize(int(header.get("rows") or 40), int(header.get("cols") or 120))
    return session.info(), b""


def op_session_signal(header, payload, config):
    session = SESSIONS.get(require(header, "session_id"))
    pgid = session.signal(resolve_signal(header.get("signal"), signal.SIGINT))
    info = session.info()
    info["signalled_pgid"] = pgid
    return info, b""


def op_session_list(header, payload, config):
    return {"sessions": [session.info() for session in SESSIONS.all()]}, b""


def op_session_close(header, payload, config):
    session = SESSIONS.get(require(header, "session_id"))
    session.close()
    SESSIONS.remove(session.id)
    return {"session_id": session.id, "closed": True}, b""


# ---- filesystem ----------------------------------------------------------

def resolve_path(value):
    return os.path.abspath(os.path.expanduser(str(value)))


def op_fs_read(header, payload, config):
    path = resolve_path(require(header, "path"))
    offset = int(header.get("offset") or 0)
    length = int(header.get("length") or 0)
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as handle:
            if offset:
                handle.seek(offset)
            limit = length if length > 0 else config["max_payload"]
            data = handle.read(min(limit, config["max_payload"]))
    except IsADirectoryError:
        raise RequestError("path is a directory: %s" % path, "bad_request")
    except FileNotFoundError:
        raise RequestError("no such file: %s" % path, "not_found")
    except OSError as exc:
        raise RequestError("read failed: %s" % exc, "os_error")
    return {
        "path": path,
        "size": size,
        "offset": offset,
        "read": len(data),
        "eof": offset + len(data) >= size,
    }, data


def op_fs_write(header, payload, config):
    path = resolve_path(require(header, "path"))
    append = bool(header.get("append"))
    if header.get("parents"):
        os.makedirs(os.path.dirname(path) or "/", exist_ok=True)
    try:
        with open(path, "ab" if append else "wb") as handle:
            handle.write(payload or b"")
        if header.get("mode") is not None:
            os.chmod(path, int(str(header["mode"]), 8))
    except IsADirectoryError:
        raise RequestError("path is a directory: %s" % path, "bad_request")
    except FileNotFoundError:
        raise RequestError("parent directory missing: %s" % path, "not_found")
    except OSError as exc:
        raise RequestError("write failed: %s" % exc, "os_error")
    return {"path": path, "bytes_written": len(payload or b""), "append": append,
            "size": os.path.getsize(path)}, b""


def _entry_type(mode):
    if statmod.S_ISDIR(mode):
        return "dir"
    if statmod.S_ISLNK(mode):
        return "symlink"
    if statmod.S_ISREG(mode):
        return "file"
    if statmod.S_ISSOCK(mode):
        return "socket"
    if statmod.S_ISFIFO(mode):
        return "fifo"
    return "other"


def op_fs_list(header, payload, config):
    path = resolve_path(require(header, "path"))
    entries = []
    try:
        with os.scandir(path) as scan:
            for entry in scan:
                try:
                    info = entry.stat(follow_symlinks=False)
                    entries.append({
                        "name": entry.name,
                        "type": _entry_type(info.st_mode),
                        "size": info.st_size,
                        "mode": oct(statmod.S_IMODE(info.st_mode)),
                        "uid": info.st_uid,
                        "gid": info.st_gid,
                        "mtime": round(info.st_mtime, 3),
                    })
                except OSError as exc:
                    entries.append({"name": entry.name, "type": "unreadable",
                                    "error": str(exc)})
    except NotADirectoryError:
        raise RequestError("not a directory: %s" % path, "bad_request")
    except FileNotFoundError:
        raise RequestError("no such directory: %s" % path, "not_found")
    except OSError as exc:
        raise RequestError("list failed: %s" % exc, "os_error")
    entries.sort(key=lambda item: (item.get("type") != "dir", item["name"].lower()))
    return {"path": path, "count": len(entries), "entries": entries}, b""


def op_fs_stat(header, payload, config):
    path = resolve_path(require(header, "path"))
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        raise RequestError("no such path: %s" % path, "not_found")
    except OSError as exc:
        raise RequestError("stat failed: %s" % exc, "os_error")
    result = {
        "path": path,
        "type": _entry_type(info.st_mode),
        "size": info.st_size,
        "mode": oct(statmod.S_IMODE(info.st_mode)),
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mtime": round(info.st_mtime, 3),
        "exists": True,
    }
    if statmod.S_ISLNK(info.st_mode):
        try:
            result["target"] = os.readlink(path)
        except OSError:
            pass
    return result, b""


def op_fs_mkdir(header, payload, config):
    path = resolve_path(require(header, "path"))
    try:
        if header.get("parents", True):
            os.makedirs(path, exist_ok=True)
        else:
            os.mkdir(path)
        if header.get("mode") is not None:
            os.chmod(path, int(str(header["mode"]), 8))
    except FileExistsError:
        raise RequestError("path already exists: %s" % path, "bad_request")
    except OSError as exc:
        raise RequestError("mkdir failed: %s" % exc, "os_error")
    return {"path": path, "created": True}, b""


def op_fs_delete(header, payload, config):
    path = resolve_path(require(header, "path"))
    recursive = bool(header.get("recursive"))
    if path in ("/", os.path.expanduser("~")):
        raise RequestError("refusing to delete %s" % path, "bad_request")
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        raise RequestError("no such path: %s" % path, "not_found")
    kind = _entry_type(info.st_mode)
    try:
        if kind == "dir":
            if recursive:
                import shutil
                shutil.rmtree(path)
            else:
                os.rmdir(path)
        else:
            os.unlink(path)
    except OSError as exc:
        if isinstance(exc, OSError) and exc.errno == errno.ENOTEMPTY:
            raise RequestError(
                "directory not empty, pass recursive=true: %s" % path, "bad_request")
        raise RequestError("delete failed: %s" % exc, "os_error")
    return {"path": path, "type": kind, "deleted": True, "recursive": recursive}, b""


# ---- listening services ---------------------------------------------------

def _parse_ss(text, proto):
    """Parse `ss -lnpH` rows into service dicts."""
    services = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 5:
            continue
        local = fields[3] if proto == "tcp" else fields[4]
        # ss puts the port after the last colon; IPv6 addresses are bracketed.
        if ":" not in local:
            continue
        address, _, port = local.rpartition(":")
        if not port.isdigit():
            continue
        entry = {
            "proto": proto,
            "address": address.strip("[]") or "*",
            "port": int(port),
            "process": None,
            "pid": None,
        }
        users = line.partition("users:((")[2]
        if users:
            name, _, rest = users.partition('",')
            entry["process"] = name.strip('"')
            pid = rest.partition("pid=")[2].partition(",")[0]
            if pid.isdigit():
                entry["pid"] = int(pid)
        services.append(entry)
    return services


def op_services_list(header, payload, config):
    include_udp = bool(header.get("include_udp"))
    services = []
    errors = []

    def collect(args, proto):
        try:
            done = subprocess.run(args, capture_output=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append("%s: %s" % (" ".join(args), exc))
            return
        services.extend(_parse_ss(done.stdout.decode("utf-8", "replace"), proto))

    collect(["ss", "-ltnpH"], "tcp")
    if include_udp:
        collect(["ss", "-lunpH"], "udp")

    if not services and not errors:
        errors.append("no listening sockets found")

    # Process names are only visible for sockets this user owns.
    services.sort(key=lambda item: (item["proto"], item["port"], item["address"]))
    return {"count": len(services), "services": services,
            "as_user": _current_user(), "errors": errors}, b""


# ---- HTTP from the box ----------------------------------------------------

def op_http_request(header, payload, config):
    import ssl
    import urllib.error
    import urllib.request

    url = require(header, "url")
    method = str(header.get("method") or "GET").upper()
    timeout = float(header.get("timeout") or 30)
    max_bytes = int(header.get("max_bytes") or 1024 * 1024)
    body = payload or None

    request = urllib.request.Request(url, data=body, method=method)
    for key, value in (header.get("headers") or {}).items():
        request.add_header(str(key), str(value))

    context = None
    if url.lower().startswith("https"):
        context = ssl.create_default_context()
        if header.get("insecure"):
            # Local admin panels are routinely self-signed; opt in explicitly.
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

    opener_args = {"timeout": timeout}
    if context is not None:
        opener_args["context"] = context

    started = time.monotonic()
    try:
        response = urllib.request.urlopen(request, **opener_args)
        status, reason = response.status, response.reason
    except urllib.error.HTTPError as exc:
        # A 4xx/5xx is data the caller wants, not a transport failure.
        response, status, reason = exc, exc.code, exc.reason
    except urllib.error.URLError as exc:
        raise RequestError("request to %s failed: %s" % (url, exc.reason), "os_error")
    except (ValueError, OSError) as exc:
        raise RequestError("request to %s failed: %s" % (url, exc), "bad_request")

    try:
        content = response.read(max_bytes + 1)
    finally:
        try:
            response.close()
        except Exception:
            pass

    truncated = len(content) > max_bytes
    if truncated:
        content = content[:max_bytes]

    headers = {}
    try:
        for key, value in response.headers.items():
            headers[key] = value
    except Exception:
        pass

    return {
        "url": getattr(response, "url", url),
        "status": status,
        "reason": str(reason),
        "method": method,
        "headers": headers,
        "length": len(content),
        "truncated": truncated,
        "duration": round(time.monotonic() - started, 3),
    }, content


OPS = {
    "ping": op_ping,
    "exec": op_exec,
    "services.list": op_services_list,
    "http.request": op_http_request,
    "job.start": op_job_start,
    "job.output": op_job_output,
    "job.list": op_job_list,
    "job.kill": op_job_kill,
    "job.remove": op_job_remove,
    "session.start": op_session_start,
    "session.send": op_session_send,
    "session.read": op_session_read,
    "session.resize": op_session_resize,
    "session.signal": op_session_signal,
    "session.list": op_session_list,
    "session.close": op_session_close,
    "fs.read": op_fs_read,
    "fs.write": op_fs_write,
    "fs.list": op_fs_list,
    "fs.stat": op_fs_stat,
    "fs.mkdir": op_fs_mkdir,
    "fs.delete": op_fs_delete,
}


# --------------------------------------------------------------------------
# server
# --------------------------------------------------------------------------

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        config = self.server.config
        sock = self.request
        sock.settimeout(config["io_timeout"])
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass

        try:
            header, payload = read_frame(sock, config["max_payload"])
        except ProtocolError as exc:
            # Answer with a real frame so the caller sees why, not a bare reset.
            log(config, "frame error from %s: %s" % (self.client_address[0], exc))
            self._fail(sock, str(exc), "bad_request")
            return
        except (socket.timeout, OSError) as exc:
            log(config, "read error from %s: %s" % (self.client_address[0], exc))
            return

        op_name = header.get("op")
        handler = OPS.get(op_name)
        if handler is None:
            self._fail(sock, "unknown op: %r" % op_name, "bad_request")
            return

        log(config, "%s <- %s" % (op_name, self.client_address[0]), verbose=True)
        try:
            result, out_payload = handler(header, payload, config)
        except RequestError as exc:
            self._fail(sock, str(exc), exc.kind)
            return
        except Exception as exc:  # noqa: BLE001 -- never let one request kill the agent
            log(config, "internal error in %s: %r" % (op_name, exc))
            self._fail(sock, "%s: %s" % (type(exc).__name__, exc), "internal")
            return

        result = dict(result)
        result["ok"] = True
        result.setdefault("op", op_name)
        try:
            write_frame(sock, result, out_payload)
        except OSError as exc:
            log(config, "reply failed for %s: %s" % (op_name, exc))

    def _fail(self, sock, message, kind):
        try:
            write_frame(sock, {"ok": False, "error": message, "kind": kind})
        except OSError:
            pass

    def handle_error(self, request, client_address):
        log(self.server.config, "handler crash from %s" % (client_address,))


class BridgeServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 64


class BridgeServer6(BridgeServer):
    address_family = socket.AF_INET6


def log(config, message, verbose=False):
    if verbose and not config.get("verbose"):
        return
    print("[kali-agent] %s" % message, file=sys.stderr, flush=True)


def restore_inherited_signals(config):
    """Undo SIG_IGN dispositions inherited from whatever started the agent.

    A shell without job control sets SIGINT and SIGQUIT to SIG_IGN in the
    background jobs it starts, and unlike a handler, SIG_IGN survives exec. So
    an agent launched with `setsid agent &` would hand that deafness down to
    every shell and every command it spawns, and Ctrl-C in a session would do
    nothing at all.

    SIGINT is put back to Python's own handler rather than SIG_DFL so that the
    agent still shuts down cleanly on Ctrl-C; children get SIG_DFL regardless,
    because exec resets handled signals to their default.
    """
    restored = []
    wanted = [
        (signal.SIGINT, signal.default_int_handler),
        (signal.SIGQUIT, signal.SIG_DFL),
        (signal.SIGTSTP, signal.SIG_DFL),
        (signal.SIGTTIN, signal.SIG_DFL),
        (signal.SIGTTOU, signal.SIG_DFL),
    ]
    for sig, disposition in wanted:
        try:
            if signal.getsignal(sig) == signal.SIG_IGN:
                signal.signal(sig, disposition)
                restored.append(signal.Signals(sig).name)
        except (OSError, ValueError, AttributeError):
            pass
    if restored:
        log(config, "restored inherited SIG_IGN on %s" % ", ".join(restored))


def main():
    parser = argparse.ArgumentParser(description="kali-bridge agent v2")
    parser.add_argument("--listen", default="127.0.0.1",
                        help="bind address (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=4444)
    parser.add_argument("--max-payload", type=int, default=DEFAULT_MAX_PAYLOAD,
                        help="max bytes per frame payload")
    parser.add_argument("--buffer-cap", type=int, default=DEFAULT_BUFFER_CAP,
                        help="per session/job output buffer cap in bytes")
    parser.add_argument("--io-timeout", type=float, default=600.0,
                        help="socket timeout for a single request in seconds")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    config = {
        "max_payload": args.max_payload,
        "buffer_cap": args.buffer_cap,
        "io_timeout": args.io_timeout,
        "verbose": args.verbose,
    }

    signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    restore_inherited_signals(config)

    server_class = BridgeServer6 if ":" in args.listen else BridgeServer
    server = server_class((args.listen, args.port), Handler)
    server.config = config

    log(config, "v%s listening on %s:%d (no auth, no TLS)"
        % (VERSION, args.listen, args.port))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log(config, "shutting down")
    finally:
        for session in SESSIONS.all():
            try:
                session.close()
            except Exception:
                pass
        for job in JOBS.all():
            if job.alive:
                try:
                    terminate_tree(job.proc)
                except Exception:
                    pass
        server.server_close()


if __name__ == "__main__":
    main()
