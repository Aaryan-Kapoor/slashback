#!/usr/bin/env python3
"""Unit tests for inject_compact.py.

Run: python3 test_inject_compact.py   (exits non-zero on failure)
 or: pytest test_inject_compact.py
Synthetic transcripts and fds only; no live session or sudo needed.
"""
import importlib.util
import json
import os
import sys
import tempfile

_spec = importlib.util.spec_from_file_location(
    "ic", os.path.join(os.path.dirname(os.path.abspath(__file__)), "inject_compact.py")
)
ic = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ic)


def _write(entries, trailing=b""):
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    os.close(fd)
    with open(path, "wb") as f:
        for o in entries:
            f.write((o if isinstance(o, str) else json.dumps(o)).encode() + b"\n")
        f.write(trailing)
    return path


def _turn_complete(entries, trailing=b""):
    path = _write(entries, trailing)
    try:
        return ic.turn_complete(path)
    finally:
        os.unlink(path)


A_END = {"type": "assistant", "message": {"stop_reason": "end_turn", "content": [{"type": "text"}]}}
A_REFUSAL = {"type": "assistant", "message": {"stop_reason": "refusal"}}
A_MAX = {"type": "assistant", "message": {"stop_reason": "max_tokens"}}
A_THINK = {"type": "assistant", "message": {"stop_reason": None, "content": [{"type": "thinking"}]}}
A_TOOL = {"type": "assistant", "message": {"stop_reason": "tool_use", "content": [{"type": "tool_use"}]}}
U_RES = {"type": "user", "message": {"content": [{"type": "tool_result"}]}}
U_PROMPT = {"type": "user", "message": {"role": "user", "content": "next question"}}
ATTACH = {"type": "attachment"}
# What Claude Code 2.1.26x actually writes after a finished turn.
REAL_TAIL = [
    {"type": "system", "subtype": "stop_hook_summary"},
    {"type": "system", "subtype": "turn_duration"},
    {"type": "file-history-snapshot"},
    {"type": "last-prompt"},
    {"type": "cost-state"},
]


# ---------------------------------------------------------------- turn_complete

def test_completed_turn():
    assert _turn_complete([A_TOOL, U_RES, A_END]) is True


def test_refusal_is_terminal():
    assert _turn_complete([A_TOOL, U_RES, A_REFUSAL]) is True


def test_max_tokens_is_not_readiness():
    assert _turn_complete([A_TOOL, U_RES, A_MAX]) is False


def test_realistic_bookkeeping_after_end_turn():
    assert _turn_complete([A_TOOL, U_RES, A_END] + REAL_TAIL) is True


def test_mid_tool_call():
    assert _turn_complete([A_END, A_TOOL]) is False


def test_tool_result_pending():
    assert _turn_complete([A_TOOL, U_RES]) is False


def test_attachment_after_tool_result():
    assert _turn_complete([A_TOOL, U_RES, ATTACH]) is False


def test_attachment_newer_than_end_turn():
    assert _turn_complete([A_END, ATTACH]) is False


def test_new_human_prompt_after_end_turn():
    assert _turn_complete([A_END] + REAL_TAIL + [U_PROMPT]) is False


def test_streaming_thinking_block():
    assert _turn_complete([A_END, U_PROMPT, A_THINK]) is False


def test_empty_transcript():
    assert _turn_complete([]) is False


def test_partial_trailing_line_blocks():
    # An append in progress must not expose the older completed turn.
    assert _turn_complete([A_END], trailing=b'{"type":"user","message":') is False


def test_corrupt_record_blocks():
    assert _turn_complete([A_END, "not json"]) is False


def test_unknown_type_fails_closed():
    assert _turn_complete([A_END, {"type": "brand-new-thing"}]) is False


def test_malformed_message_shapes_do_not_raise():
    assert _turn_complete([{"type": "assistant", "message": None}]) is False
    assert _turn_complete([{"type": "assistant", "message": [1, 2]}]) is False
    assert _turn_complete(["null"]) is False
    assert _turn_complete(["[1,2,3]"]) is False


def test_large_final_record_beyond_initial_window():
    big = dict(A_END, message={"stop_reason": "end_turn", "content": [{"type": "text", "text": "x" * 70000}]})
    assert _turn_complete([A_TOOL, U_RES, big]) is True


def test_large_bookkeeping_record_hides_nothing():
    snap = {"type": "file-history-snapshot", "blob": "y" * 70000}
    assert _turn_complete([A_END, snap]) is True


def test_huge_tail_gives_up():
    old_max = ic.TAIL_MAX
    ic.TAIL_MAX = 4096
    try:
        assert _turn_complete([{"type": "cost-state", "blob": "z" * 10000}]) is False
    finally:
        ic.TAIL_MAX = old_max


# ---------------------------------------------------------------- transcript location

def test_slug_replaces_every_non_alphanumeric():
    assert ic.slug("/home/u/.claude") == "-home-u--claude"
    assert ic.slug("/home/u/writing/agents_book") == "-home-u-writing-agents-book"
    assert ic.slug("/srv/llama.cpp") == "-srv-llama-cpp"


def test_project_dir_default():
    assert ic.project_dir("/home/u/proj", {}, "/home/u") == "/home/u/.claude/projects/-home-u-proj"


def test_project_dir_config_override():
    env = {"CLAUDE_CONFIG_DIR": "/srv/tenant"}
    assert ic.project_dir("/home/u/proj", env, "/home/u") == "/srv/tenant/projects/-home-u-proj"


def test_project_dir_name_override_requires_config_dir():
    env = {"CLAUDE_CONFIG_DIR": "/srv/tenant", "CLAUDE_CODE_PROJECT_DIR_NAME": "work"}
    assert ic.project_dir("/home/u/proj", env, "/home/u") == "/srv/tenant/projects/work"
    env = {"CLAUDE_CODE_PROJECT_DIR_NAME": "work"}
    assert ic.project_dir("/home/u/proj", env, "/home/u") == "/home/u/.claude/projects/-home-u-proj"


def test_project_dir_name_override_validated():
    env = {"CLAUDE_CONFIG_DIR": "/srv/tenant", "CLAUDE_CODE_PROJECT_DIR_NAME": "../etc"}
    assert ic.project_dir("/home/u/proj", env, "/home/u") == "/srv/tenant/projects/-home-u-proj"


def test_compaction_observed():
    path = _write([A_END])
    try:
        size = os.path.getsize(path)
        assert ic.compaction_observed(path, size) is False
        with open(path, "ab") as f:
            f.write(json.dumps({"type": "system", "subtype": "compact_boundary"}).encode() + b"\n")
        assert ic.compaction_observed(path, size) is True
    finally:
        os.unlink(path)


# ---------------------------------------------------------------- guards

def test_command_validation():
    assert ic.validate_command("/compact") == "/compact"
    assert ic.validate_command("/compact focus on the parser") == "/compact focus on the parser"
    for bad in ("compact", "/compact\rls", "/a\nb", "/x\x1b[A", "", "/" + "a" * 300):
        try:
            ic.validate_command(bad)
        except SystemExit:
            continue
        raise AssertionError(f"accepted {bad!r}")


def test_parse_stat_with_parens_in_comm():
    pgrp, tty, tpgid = ic.parse_stat("42 (cl(a)ude) S 1 42 40 34817 42 4194560 1 2 3")
    assert (pgrp, tty, tpgid) == (42, 34817, 42)


def test_in_foreground_self():
    # The test runner may or may not own a tty; either way this must not raise.
    assert ic.in_foreground(os.getpid()) in (True, False)
    assert ic.in_foreground(2 ** 22 + 12345) is False


def test_lock_is_exclusive():
    path = _write([])
    try:
        held = ic.acquire_lock(path, "sess")
        assert held is not None
        assert ic.acquire_lock(path, "sess") is None
        os.close(held)
        again = ic.acquire_lock(path, "sess")
        assert again is not None
        os.close(again)
    finally:
        os.unlink(path)
        lock = os.path.join(os.path.dirname(path), ".self-compact-sess.lock")
        if os.path.exists(lock):
            os.unlink(lock)


def test_write_all_handles_short_and_blocked_writes():
    r, w = os.pipe()
    os.set_blocking(w, False)
    real_write = ic.os.write
    calls = []

    def one_byte(fd, data):
        calls.append(len(data))
        if len(calls) == 2:
            raise BlockingIOError()
        return real_write(fd, bytes(data[:1]))

    ic.os.write = one_byte
    try:
        ic.write_all(w, b"/compact\r", timeout=2)
    finally:
        ic.os.write = real_write
    assert os.read(r, 100) == b"/compact\r"
    assert len(calls) >= 10
    os.close(r)
    os.close(w)


def test_write_all_times_out_when_stalled():
    r, w = os.pipe()
    os.set_blocking(w, False)
    # Fill the pipe so further writes block.
    try:
        while True:
            os.write(w, b"x" * 65536)
    except BlockingIOError:
        pass
    try:
        ic.write_all(w, b"/compact\r", timeout=0.2)
    except TimeoutError:
        pass
    else:
        raise AssertionError("expected TimeoutError")
    finally:
        os.close(r)
        os.close(w)


def test_pidfd_alive_and_exit():
    pid = os.fork()
    if pid == 0:
        os._exit(0)
    fd = ic.pidfd_of(pid)
    try:
        os.waitpid(pid, 0)
        assert ic.pid_alive(fd) is False
        me = ic.pidfd_of(os.getpid())
        assert ic.pid_alive(me) is True
        os.close(me)
    finally:
        os.close(fd)


def test_args_require_positive_pid_and_session():
    import contextlib
    import io
    for argv in (["--pid", "0", "--session", "s"], ["--pid", "12", "--session", ""], ["--session", "s"]):
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                ic.parse_args(argv)
        except SystemExit:
            continue
        raise AssertionError(f"accepted {argv}")
    a = ic.parse_args(["--pid", "12", "--session", "abc-123"])
    assert (a.pid, a.session, a.command, a.timeout) == (12, "abc-123", "/compact", 90.0)


def test_setup_error_is_logged():
    # The arming wrapper sends stderr to /dev/null, so a setup error must reach --log.
    fd, log = tempfile.mkstemp(suffix=".log")
    os.close(fd)
    try:
        rc = ic.main(["--pid", str(os.getpid()), "--session", "abc", "--log", log])
        with open(log) as f:
            text = f.read()
        assert rc == 1
        assert "setup error: pid" in text and "is not a claude process" in text
    finally:
        os.unlink(log)


def main():
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failures = 0
    for name, fn in tests:
        try:
            fn()
            print(f"[PASS] {name}")
        except Exception as e:  # noqa: BLE001
            failures += 1
            print(f"[FAIL] {name}: {type(e).__name__}: {e}")
    print("OK" if not failures else f"{failures} FAILED")
    raise SystemExit(1 if failures else 0)


if __name__ == "__main__":
    main()
