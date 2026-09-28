---
name: slashback
description: Make the current Claude Code session run /compact (or another allowlisted slash command) on itself from within a tool call, either in a T3 Code thread or in a bare SSH login with no tmux, and restart work afterwards in T3. Use when you need the live session to compact itself.
---

# slashback

Runs `/compact` against the current Claude Code session exactly as if the user had sent it, without anyone touching the keyboard. The injector picks one of two supported paths on its own.

- **T3 Code.** When the session was launched by a T3 Code server, the injector sends `/compact` as a message through T3's own orchestration API (`POST /api/orchestration/dispatch`), which is the same operation T3's composer performs. T3 recognises that message as a compaction request, refuses it while a turn is running, and reports the result as a thread activity. The injector authenticates with a short-lived bearer session minted by the `t3` CLI, the same way `t3 project add` talks to a running server, and revokes that session when it exits. No root is involved. Once compaction has finished, it sends one fixed follow-up message, `[slashback] Context compacted. Continue where you left off.`, so that the session starts working again.
- **SSH terminal.** When the session is a TUI reached over SSH, the injector duplicates the ssh pty master file descriptor out of `sshd` with `pidfd_getfd` and types the keystrokes into it, so the TUI parses the command as real typed input. For this path the injector re-executes itself under `sudo -n` and drops root again as soon as it holds the descriptor.

## Requirements

For T3 Code you need a T3 server on a loopback origin (the default `127.0.0.1`) whose `t3` binary provides `auth session issue`, and nobody else sending a message in the thread at the moment of compaction.

For an SSH terminal you need an `sshd` process holding the pty master (tmux is neither needed nor used), passwordless `sudo`, Linux 5.6 or newer, glibc, `python3`, and nobody typing in the session, because the injector clears the input line before typing and an unsubmitted draft would be lost.

## How to run it

Arm the injector detached, passing this session's own pid and session id from the environment Claude Code exports to every tool shell, then end the turn immediately and say nothing further:

```bash
LOG="${CLAUDE_CONFIG_DIR:-$HOME/.claude}/slashback.log"
setsid python3 ~/.claude/skills/slashback/slashback.py \
  --pid "$CLAUDE_PID" --session "$CLAUDE_CODE_SESSION_ID" --log "$LOG" >/dev/null 2>&1 &
disown
```

Do not wrap it in `sudo` yourself. The SSH path elevates on its own, and the T3 path must not run as root.

The T3 path only accepts the exact message `/compact`, because that is the only slash command T3 handles natively. Anything else, including `/compact` with instructions, is refused. On the SSH path `--command` can send any command on the injector's allowlist, for example `--command "/compact keep the parser notes"` or `--command "/model fable"`. The allowlist covers context upkeep (`/compact`, `/recap`, `/context`, `/reload-skills`, `/pause-memory`, `/rename`, `/btw`, `/list-agents`), read-only information (`/usage`, `/status`, `/version`, `/help`, `/skills`, `/skill-doctor`, `/doctor`, `/release-notes`, `/diff`), display and mode (`/plan`, `/brief`, `/focus`, `/theme`, `/color`, `/tui`, `/scroll-speed`), and `/model` and `/effort` with fixed argument sets. Aliases, free text containing `@` or `\`, and every other command are refused. `--no-resume` skips the T3 follow-up message, `--timeout` changes the 90 second wait for an idle prompt, `--transport pty|t3` overrides detection, and `--dry-run` does everything except send, which is the way to test the setup.

## Why it must be detached and idle-gated

A command that arrives while the session is busy does not run as a command. On the SSH path the keystrokes get queued behind the tool call, and on the T3 path T3 rejects compaction while a turn is running. The wrapper detaches the injector with `setsid` so that it outlives the arming turn, and the injector fires only once the prompt is genuinely idle.

- **T3 Code.** The thread's provider session must be `ready` with no active turn, and its newest message must be a finished assistant reply. Both conditions have to hold on two consecutive polls a second apart, and a newer user message from anyone else counts as busy.
- **SSH terminal.** The session's own transcript must end in an assistant message with `stop_reason` `end_turn` or `refusal`, followed only by known bookkeeping entries, and the file must then have been quiet for about a second. The claude process must also be alive and in the foreground on its terminal. These checks are repeated before each of the three writes (clear line, command, Enter).

Anything unexpected fails closed, and a per-session lock stops two injectors from overlapping. The injector gives up after the timeout and never repeats, so it cannot spam the session.

Because the command lands at the idle prompt, end your turn right after arming. If you keep working, the injector will time out waiting for you.

## Verifying it fired

Read the log file. It records `armed` with the chosen transport, then either `delivered '/compact'` or a line saying why it stopped (`gave up`, `aborted before`, or `setup error`). On the T3 path it continues with `compaction observed in T3: <summary>` or `compaction failed in T3: <detail>`, then `resume sent`, and ends with `revoked T3 auth session`. On the SSH path it logs `compaction observed in transcript` once a `compact_boundary` entry appears. The exit status is 0 on success, 2 when the injector gave up or the compaction failed, and 1 on a setup error. The detached wrapper discards that status, which is why the log exists.
