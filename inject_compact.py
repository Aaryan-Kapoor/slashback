#!/usr/bin/env python3
"""Self-compact injector for a live Claude Code session.

Types a slash command (default /compact) at the session's own idle prompt by
duplicating the ssh pty master fd out of sshd with pidfd_getfd and writing the
keystrokes to it. Must run detached and under sudo: pidfd_getfd needs
PTRACE_MODE_ATTACH on the sshd process. Root is dropped back to the invoking
user as soon as the master fd is held; everything after that (transcript
parsing, locking, logging) runs unprivileged.

Usage (from the arming wrapper in SKILL.md):
  sudo -n python3 inject_compact.py --pid <claude_pid> --session <session_id>
        [--command /compact] [--log FILE] [--transcript PATH] [--timeout 90] [--dry-run]

Exit status: 0 delivered, 2 gave up (no idle window, or a pre-write check failed),
1 setup error. Every outcome is written to --log when given.
"""
import argparse
import array
import ctypes
import errno
import fcntl
import json
import os
import pwd
import re
import select
import sys
import time

SYS_pidfd_open = 434
SYS_pidfd_getfd = 438
TIOCGPTN = 0x80045430

libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.syscall.restype = ctypes.c_long

# stop_reasons that mean the assistant handed the turn back and the prompt is idle.
# max_tokens / stop_sequence describe generation, not TUI readiness, so they are
# deliberately excluded: an unrecognised end of turn fails closed (no injection).
TERMINAL_STOP = {"end_turn", "refusal"}

# Transcript entry types that are bookkeeping written around a turn and say nothing
# about whether the prompt is idle. Anything not listed here, and not one of the
# state-bearing types (assistant / user / attachment), blocks injection.
METADATA_TYPES = {
    "system", "file-history-snapshot", "file-history-delta", "last-prompt",
    "cost-state", "ai-title", "custom-title", "agent-name", "agent-setting",
    "mode", "permission-mode", "atis-latch", "queue-operation", "bridge-session",
    "pr-link", "frame-link", "artifact-comment-monitor", "artifact-autoreact-ledger",
    "summary",
}

COMMAND_RE = re.compile(r"^/[A-Za-z0-9][A-Za-z0-9 _:./=\-]{0,199}$")
QUIET_SECONDS = 1.0        # transcript must be untouched this long after a finished turn
WRITE_TIMEOUT = 2.0        # per keystroke write, on a possibly non-blocking master
TAIL_WINDOW = 65536        # initial tail read; doubled up to TAIL_MAX for large records
TAIL_MAX = 16 * 1024 * 1024


def syscall(n, *args):
    r = libc.syscall(ctypes.c_long(n), *[ctypes.c_long(a) for a in args])
    if r < 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))
    return r


class Log:
    def __init__(self, path):
        self.path = path

    def __call__(self, msg):
        line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} [{os.getpid()}] {msg}"
        if self.path:
            try:
                with open(self.path, "a") as f:
                    f.write(line + "\n")
                return
            except OSError:
                pass
        print(line, file=sys.stderr)


# ---------------------------------------------------------------- process introspection

def comm(pid):
    try:
        with open(f"/proc/{pid}/comm") as f:
            return f.read().strip()
    except OSError:
        return ""


def ppid(pid):
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("PPid:"):
                    return int(line.split()[1])
    except OSError:
        pass
    return 0


def ancestors(pid):
    out = []
    while pid and pid != 1:
        out.append(pid)
        pid = ppid(pid)
    return out


def parse_stat(text):
    """Return (pgrp, tty_nr, tpgid) from /proc/<pid>/stat text. comm may contain ')'."""
    fields = text[text.rindex(")") + 2:].split()
    return int(fields[2]), int(fields[4]), int(fields[5])


def in_foreground(pid):
    """True if the process is alive and its process group owns its controlling tty."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            pgrp, tty_nr, tpgid = parse_stat(f.read())
    except (OSError, ValueError):
        return False
    return tty_nr != 0 and tpgid == pgrp


def process_environ(pid):
    try:
        with open(f"/proc/{pid}/environ", "rb") as f:
            raw = f.read()
    except OSError:
        return {}
    env = {}
    for item in raw.split(b"\0"):
        if b"=" in item:
            k, v = item.split(b"=", 1)
            env[k.decode(errors="replace")] = v.decode(errors="replace")
    return env


def invoking_uid():
    """The real user this was armed for: the sudo caller, or ourselves if not under sudo."""
    return int(os.environ.get("SUDO_UID", os.getuid()))


def validate_target(pid):
    if comm(pid) != "claude":
        raise SystemExit(f"pid {pid} is not a claude process (comm={comm(pid)!r})")
    try:
        owner = os.stat(f"/proc/{pid}").st_uid
    except OSError as e:
        raise SystemExit(f"cannot stat /proc/{pid}: {e}")
    if owner != invoking_uid():
        raise SystemExit(f"pid {pid} is owned by uid {owner}, not the invoking uid {invoking_uid()}")
    return pid


def pts_of(pid):
    for fd in (0, 1, 2):
        try:
            t = os.readlink(f"/proc/{pid}/fd/{fd}")
        except OSError:
            continue
        if "/pts/" in t:
            return int(t.rsplit("/", 1)[1])
    raise SystemExit("controlling pts not found")


def pidfd_of(pid):
    return syscall(SYS_pidfd_open, pid, 0)


def pid_alive(pidfd):
    """A pidfd becomes readable when its process exits."""
    r, _, _ = select.select([pidfd], [], [], 0)
    return not r


# ---------------------------------------------------------------- pty master

def steal_master(claude_pid, ptsnum):
    """Duplicate the sshd fd that is the master for /dev/pts/<ptsnum> and return it."""
    candidates = [p for p in ancestors(claude_pid) if "sshd" in comm(p)]
    if not candidates:
        raise SystemExit("no sshd ancestor: session is not reached over ssh")
    for sshd in candidates:
        try:
            pidfd = pidfd_of(sshd)
        except OSError as e:
            if e.errno == errno.ESRCH:
                continue  # ancestor exited between listing and open
            raise SystemExit(f"pidfd_open({sshd}) failed: {e}")
        try:
            try:
                entries = os.listdir(f"/proc/{sshd}/fd")
            except OSError:
                continue
            for entry in entries:
                try:
                    stolen = syscall(SYS_pidfd_getfd, pidfd, int(entry), 0)
                except OSError as e:
                    if e.errno in (errno.EPERM, errno.EACCES):
                        raise SystemExit(f"pidfd_getfd on sshd {sshd} denied: {e} (run under sudo)")
                    if e.errno == errno.ENOSYS:
                        raise SystemExit("pidfd_getfd unsupported by this kernel (needs Linux >= 5.6)")
                    continue  # EBADF: fd closed in the meantime
                try:
                    buf = array.array("i", [0])
                    fcntl.ioctl(stolen, TIOCGPTN, buf, True)
                    if buf[0] == ptsnum:
                        return stolen
                except OSError:
                    pass  # not a pty master
                os.close(stolen)
        finally:
            os.close(pidfd)
    raise SystemExit(f"no sshd master fd for pts {ptsnum}")


def write_all(fd, data, timeout=WRITE_TIMEOUT):
    """Write every byte, tolerating short and would-block writes, within timeout."""
    deadline = time.monotonic() + timeout
    view = memoryview(data)
    while view:
        try:
            n = os.write(fd, view)
        except BlockingIOError:
            n = 0
        if n:
            view = view[n:]
            continue
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"pty write stalled with {len(view)} bytes pending")
        select.select([], [fd], [], remaining)


def drop_privileges():
    if os.geteuid() != 0 or "SUDO_UID" not in os.environ:
        return
    uid = int(os.environ["SUDO_UID"])
    gid = int(os.environ.get("SUDO_GID", pwd.getpwuid(uid).pw_gid))
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)


# ---------------------------------------------------------------- transcript

def slug(path):
    """Claude Code's project directory name for a cwd: every non-alphanumeric -> '-'."""
    return re.sub(r"[^a-zA-Z0-9]", "-", path)


def project_dir(cwd, env, home):
    """Resolve <config>/projects/<name> the way Claude Code does at startup.

    CLAUDE_CONFIG_DIR overrides ~/.claude; CLAUDE_CODE_PROJECT_DIR_NAME replaces the
    cwd-derived slug but is honoured only when CLAUDE_CONFIG_DIR is also set.
    """
    config = env.get("CLAUDE_CONFIG_DIR") or os.path.join(home, ".claude")
    name = env.get("CLAUDE_CODE_PROJECT_DIR_NAME") if env.get("CLAUDE_CONFIG_DIR") else None
    if not name or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name):
        name = slug(cwd)
    return os.path.join(config, "projects", name)


def find_transcript(pid, session_id):
    """Exact transcript path for this claude process and session id."""
    try:
        cwd = os.readlink(f"/proc/{pid}/cwd")
        home = pwd.getpwuid(os.stat(f"/proc/{pid}").st_uid).pw_dir
    except (OSError, KeyError) as e:
        raise SystemExit(f"cannot resolve cwd/home of pid {pid}: {e}")
    return os.path.join(project_dir(cwd, process_environ(pid), home), f"{session_id}.jsonl")


def tail_records(path):
    """Newest-first complete JSON records from the file tail, or None if unusable.

    Grows the window until at least one complete line is available or the whole file
    is read. A trailing fragment (an append in progress) makes the tail unusable.
    """
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            window = TAIL_WINDOW
            while True:
                start = max(0, size - window)
                f.seek(start)
                chunk = f.read(size - start)
                if not chunk.endswith(b"\n"):
                    return None  # partial last line: writer mid-append
                lines = chunk.split(b"\n")
                if start > 0:
                    lines = lines[1:]  # first piece is the truncated head of a record
                lines = [l for l in lines if l.strip()]
                if lines or start == 0:
                    break
                if window >= TAIL_MAX:
                    return None
                window *= 2
    except OSError:
        return None
    out = []
    for raw in reversed(lines):
        try:
            out.append(json.loads(raw))
        except ValueError:
            return None  # corrupt record anywhere in the tail: refuse to guess
    return out


def turn_complete(path):
    """True when the transcript's newest state-bearing entry is a finished assistant turn.

    During a turn the tail is tool_use / tool_result / attachment entries; a completed
    turn ends with an assistant message whose stop_reason is terminal, followed only by
    known bookkeeping entries. Anything unrecognised fails closed.
    """
    records = tail_records(path)
    if not records:
        return False
    for o in records:
        if not isinstance(o, dict):
            return False
        t = o.get("type")
        if t == "assistant":
            msg = o.get("message")
            return isinstance(msg, dict) and msg.get("stop_reason") in TERMINAL_STOP
        if t in ("user", "attachment"):
            return False  # a prompt, a tool result, or its attachment: mid-turn
        if t not in METADATA_TYPES:
            return False
    return False


def transcript_quiet(path, seconds=QUIET_SECONDS):
    try:
        return time.time() - os.path.getmtime(path) >= seconds
    except OSError:
        return False


def compaction_observed(path, previous_size):
    """True if a compact_boundary or compact summary was appended after previous_size."""
    try:
        with open(path, "rb") as f:
            f.seek(previous_size)
            new = f.read()
    except OSError:
        return False
    for raw in new.split(b"\n"):
        try:
            o = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(o, dict):
            continue
        if o.get("type") == "system" and o.get("subtype") == "compact_boundary":
            return True
        if o.get("isCompactSummary"):
            return True
    return False


# ---------------------------------------------------------------- main

def validate_command(command):
    if not COMMAND_RE.fullmatch(command):
        raise SystemExit(f"refusing command {command!r}: must be a single-line slash command")
    return command


def acquire_lock(transcript, session_id):
    """One injector per session. Returns the held fd, or None if another holds it."""
    path = os.path.join(os.path.dirname(transcript), f".self-compact-{session_id}.lock")
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return None
    return fd


def parse_args(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pid", type=int, required=True, help="pid of the claude TUI process ($CLAUDE_PID)")
    ap.add_argument("--session", required=True, help="session id ($CLAUDE_CODE_SESSION_ID)")
    ap.add_argument("--command", default="/compact", help="slash command to type (default /compact)")
    ap.add_argument("--log", default=None, help="append progress and outcome to this file")
    ap.add_argument("--transcript", default=None, help="override the derived transcript path")
    ap.add_argument("--timeout", type=float, default=90.0, help="seconds to wait for an idle prompt")
    ap.add_argument("--dry-run", action="store_true", help="do everything except write keystrokes")
    a = ap.parse_args(argv)
    if a.pid <= 0:
        ap.error("--pid must be a positive integer")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", a.session):
        ap.error("--session must be a session id")
    return a


def main(argv=None):
    a = parse_args(sys.argv[1:] if argv is None else argv)
    log = Log(a.log)
    try:
        return run(a, log)
    except SystemExit as e:
        if not isinstance(e.code, str):
            raise
        # The arming wrapper discards stderr, so a setup error that is only printed
        # leaves no trace. Record it, unprivileged so the log stays user-owned.
        drop_privileges()
        log(f"setup error: {e.code}")
        return 1


def run(a, log):
    command = validate_command(a.command)

    # Privileged phase: identify the target and hold its pty master, nothing else.
    validate_target(a.pid)
    ptsnum = pts_of(a.pid)
    master = steal_master(a.pid, ptsnum)
    claude_fd = pidfd_of(a.pid)
    drop_privileges()
    log(f"armed: claude={a.pid} pts={ptsnum} session={a.session} command={command!r} uid={os.getuid()}")

    try:
        transcript = a.transcript or find_transcript(a.pid, a.session)
        if not os.path.isfile(transcript):
            log(f"gave up: transcript not found at {transcript}")
            return 2
        lock = acquire_lock(transcript, a.session)
        if lock is None:
            log("gave up: another injector is already armed for this session")
            return 2
        log(f"gating on {transcript}")

        def ready():
            if not pid_alive(claude_fd):
                return "claude exited"
            if not in_foreground(a.pid):
                return "claude is not the foreground process on its tty"
            if not turn_complete(transcript):
                return "turn not complete"
            if not transcript_quiet(transcript):
                return "transcript still being written"
            return None

        deadline = time.monotonic() + a.timeout
        time.sleep(1)  # let the arming turn settle before sampling
        while True:
            why = ready()
            if why is None:
                break
            if why == "claude exited":
                log(f"gave up: {why}")
                return 2
            if time.monotonic() >= deadline:
                log(f"gave up: no idle window within {a.timeout:.0f}s (last reason: {why})")
                return 2
            time.sleep(0.5)

        # Deliver, re-validating before each write so a prompt that stops being idle
        # mid-sequence gets at most a cleared line, never a submitted command.
        size_before = os.path.getsize(transcript)
        for label, data, pause in (("clear line", b"\x15", 0.15),
                                   ("command", command.encode(), 0.4),
                                   ("enter", b"\r", 0)):
            why = ready()
            if why is not None:
                log(f"aborted before {label}: {why}")
                return 2
            if a.dry_run:
                log(f"dry-run: would write {data!r} ({label})")
            else:
                write_all(master, data)
            time.sleep(pause)
        log(f"delivered {command!r}" + (" (dry-run, nothing written)" if a.dry_run else ""))

        if command.split()[0] == "/compact" and not a.dry_run:
            until = time.monotonic() + 60
            while time.monotonic() < until:
                if compaction_observed(transcript, size_before):
                    log("compaction observed in transcript")
                    return 0
                time.sleep(1)
            log("compaction not observed within 60s of delivery")
        return 0
    finally:
        os.close(master)
        os.close(claude_fd)


if __name__ == "__main__":
    sys.exit(main())
