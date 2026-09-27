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
    good = ("/compact", "/compact focus on the parser, keep the test names", "/recap", "/context",
            "/reload-skills", "/rename parser rewrite", "/btw is the lock per session?", "/usage",
            "/status", "/plan", "/theme dark", "/theme", "/tui fullscreen", "/model fable",
            "/model claude-opus-5-5[1m]", "/effort xhigh", "/scroll-speed 2.5")
    for command in good:
        assert ic.validate_command(command) == command, command
    bad = (
        "compact", "", "/compact\rls", "/a\nb", "/x\x1b[A", "/compact " + "a" * 301,
        # not on the allowlist, including aliases of allowed commands
        "/logout", "/login", "/permissions", "/hooks", "/config", "/add-dir /", "/mcp",
        "/plugin", "/clear", "/reset", "/rewind", "/exit", "/resume", "/fork", "/goal done",
        "/teleport", "/feedback hi", "/export", "/heapdump", "/fast", "/batch", "/cost",
        # arguments the command does not take, or text that would not submit as typed
        "/context full", "/rename", "/btw", "/model gpt-5", "/model", "/effort turbo",
        "/tui classic", "/compact see @secrets.txt", "/compact line\\", "/compact  two  spaces",
        "/compact ", " /compact", "/compact\ttab",
    )
    for command in bad:
        try:
            ic.validate_command(command)
        except SystemExit:
            continue
        raise AssertionError(f"accepted {command!r}")


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


# ---------------------------------------------------------------- T3 Code transport

def _t3_thread(status="ready", active=None, messages=None, activities=None):
    if messages is None:
        messages = [{"id": "u1", "role": "user", "streaming": False, "updatedAt": "t1"},
                    {"id": "a1", "role": "assistant", "streaming": False, "updatedAt": "t2"}]
    return {"id": "th", "runtimeMode": "full-access", "interactionMode": "default",
            "modelSelection": {"instanceId": "claudeAgent", "model": "m"},
            "session": {"status": status, "activeTurnId": active, "updatedAt": "s1"},
            "messages": messages, "activities": activities or []}


def test_t3_idle_after_finished_reply():
    assert ic.t3_not_idle(_t3_thread()) is None


def test_t3_not_idle_while_running_or_stopped():
    assert ic.t3_not_idle(_t3_thread(status="running", active="turn")) == "session running"
    assert ic.t3_not_idle(_t3_thread(status="ready", active="turn")) == "turn active"
    for status in ("starting", "interrupted", "stopped", "error"):
        assert ic.t3_not_idle(_t3_thread(status=status)) is not None


def test_t3_not_idle_when_someone_else_sent_a_message():
    msgs = [{"id": "a1", "role": "assistant", "streaming": False},
            {"id": "u2", "role": "user", "streaming": False}]
    assert ic.t3_not_idle(_t3_thread(messages=msgs)) is not None
    # ...unless that newest message is our own /compact, which gets no reply.
    assert ic.t3_not_idle(_t3_thread(messages=msgs), own_message="u2") is None


def test_t3_not_idle_while_streaming_or_empty():
    streaming = [{"id": "a1", "role": "assistant", "streaming": True}]
    assert ic.t3_not_idle(_t3_thread(messages=streaming)) is not None
    assert ic.t3_not_idle(_t3_thread(messages=[])) == "no messages"
    assert ic.t3_not_idle({"messages": []}) == "no provider session"


def test_t3_turn_start_mirrors_thread():
    cmd = ic.t3_turn_start(_t3_thread(), "/compact")
    assert cmd["type"] == "thread.turn.start" and cmd["threadId"] == "th"
    assert cmd["message"]["text"] == "/compact" and cmd["message"]["role"] == "user"
    assert cmd["message"]["attachments"] == []
    assert (cmd["runtimeMode"], cmd["interactionMode"]) == ("full-access", "default")
    assert cmd["modelSelection"]["instanceId"] == "claudeAgent"
    assert cmd["createdAt"].endswith("Z")
    assert cmd["commandId"] != cmd["message"]["messageId"]


def test_t3_compaction_outcome_matches_request_id():
    ok = {"kind": "context-compaction", "summary": "Compacted context 900k to 40k tokens",
          "payload": {"state": "compacted", "requestId": "m1"}}
    other = {"kind": "context-compaction", "summary": "auto", "payload": {"requestId": "m0"}}
    failed = {"kind": "provider.turn.start.failed", "summary": "Context compaction failed",
              "payload": {"detail": "unavailable while a provider turn is running", "requestId": "m1"}}
    assert ic.t3_compaction_outcome(_t3_thread(activities=[other]), "m1") is None
    assert ic.t3_compaction_outcome(_t3_thread(activities=[other, ok]), "m1")[0] == "ok"
    assert ic.t3_compaction_outcome(_t3_thread(activities=[failed]), "m1") == \
        ("failed", "unavailable while a provider turn is running")
    assert ic.t3_compaction_outcome(_t3_thread(activities=["junk", {"payload": None}]), "m1") is None


def test_t3_wait_idle_requires_two_equal_samples():
    samples = [_t3_thread(status="running", active="t"), _t3_thread(), _t3_thread()]

    class Api:
        calls = 0

        def thread(self, _):
            Api.calls += 1
            return samples[min(Api.calls, len(samples)) - 1]

    real_poll, ic.T3_POLL = ic.T3_POLL, 0
    try:
        thread, why = ic.t3_wait_idle(Api(), "th", timeout=5)
    finally:
        ic.T3_POLL = real_poll
    assert why is None and thread["session"]["status"] == "ready" and Api.calls == 3


def test_t3_wait_idle_times_out():
    class Api:
        def thread(self, _):
            raise ic.T3Error("connection refused")

    real_poll, ic.T3_POLL = ic.T3_POLL, 0.01
    try:
        thread, why = ic.t3_wait_idle(Api(), "th", timeout=0.05)
    finally:
        ic.T3_POLL = real_poll
    assert thread is None and "connection refused" in why


def test_t3_thread_for_session():
    import sqlite3
    d = tempfile.mkdtemp()
    os.mkdir(os.path.join(d, "userdata"))
    con = sqlite3.connect(os.path.join(d, "userdata", "state.sqlite"))
    con.execute("create table provider_session_runtime (thread_id text, resume_cursor_json text)")
    con.execute("insert into provider_session_runtime values ('th-1', ?)", (json.dumps({"resume": "sess-a"}),))
    con.execute("insert into provider_session_runtime values ('th-2', ?)", (json.dumps({"resume": "sess-b"}),))
    con.commit()
    con.close()
    assert ic.t3_thread_for_session(d, "sess-b") == "th-2"
    try:
        ic.t3_thread_for_session(d, "sess-missing")
    except SystemExit:
        pass
    else:
        raise AssertionError("resolved a session with no thread")


def test_t3_base_dir_from_cmdline():
    import subprocess
    p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(5)", "serve", "--base-dir", "/srv/t3"])
    try:
        for _ in range(50):
            with open(f"/proc/{p.pid}/cmdline", "rb") as f:
                if b"--base-dir" in f.read():
                    break
            import time
            time.sleep(0.02)
        assert ic.t3_base_dir(p.pid) == "/srv/t3"
    finally:
        p.kill()
        p.wait()


def test_t3_api_sends_bearer_and_ignores_proxy_env():
    import http.server
    import threading
    seen = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            seen["auth"] = self.headers.get("Authorization")
            seen["body"] = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            out = b'{"sequence": 7}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.handle_request, daemon=True).start()
    old = os.environ.get("http_proxy")
    os.environ["http_proxy"] = "http://127.0.0.1:9"  # would swallow the token if honoured
    try:
        api = ic.T3Api(f"http://127.0.0.1:{server.server_port}", "tok")
        assert api.dispatch({"type": "x"}) == {"sequence": 7}
    finally:
        if old is None:
            del os.environ["http_proxy"]
        else:
            os.environ["http_proxy"] = old
        server.server_close()
    assert seen == {"auth": "Bearer tok", "body": {"type": "x"}}


def test_t3_refuses_commands_it_does_not_handle():
    server = ic.T3Server(1, "/nonexistent", "http://127.0.0.1:1", "/bin/false")
    a = ic.parse_args(["--pid", "12", "--session", "abc", "--command", "/logout"])
    for command in ("/logout", "/clear", "/compact keep the tests"):
        a.command = command
        try:
            ic.run_t3(a, lambda _: None, server)
        except SystemExit as e:
            assert "only" in str(e.code)
        else:
            raise AssertionError(f"accepted {command!r}")


def test_t3_refuses_non_loopback_origin():
    server = ic.T3Server(1, "/nonexistent", "http://100.64.0.9:3774", "/bin/false")
    a = ic.parse_args(["--pid", "12", "--session", "abc"])
    try:
        ic.run_t3(a, lambda _: None, server)
    except SystemExit as e:
        assert "not loopback" in str(e.code)
    else:
        raise AssertionError("sent a token to a non-loopback origin")


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
