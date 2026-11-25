"""`storekeeper with-key`: hand Apple's tools (xcodebuild, altool, notarytool),
which take only a key file, the App Store Connect key for one command.

    storekeeper with-key [--json] <command> [args...]
        run <command>; every @ASC_KEY@ in its arguments becomes the key file's path
    storekeeper with-key [--json] --check
        the same as `storekeeper key check`

The work is done by with-key.sh beside this file: it writes AuthKey_<ASC_KEY_ID>.p8
into a fresh folder (mode 700, the file 600), runs the command, and deletes the
folder when the command ends, also on INT, TERM, HUP and QUIT. A hard kill
(SIGKILL) or a power loss cannot be caught: the next run deletes this user's key
folders older than 6 hours whose run (the PID in the name) is gone.

Without --json the wrapper replaces this process and the command's exit code is
storekeeper's. With --json the key is checked first (nothing runs if it is not
there), the command's stdout goes to stderr, its stdin is closed (it can never
wait for input), and storekeeper prints one JSON object: exit 0, or 1 with the
error code command_failed and the command's own exit code in the result.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
from pathlib import Path

from . import key
from .output import Outcome, emit, failure, help_outcome

WRAPPER = Path(__file__).with_name("with-key.sh")
BASH = "/bin/bash"
FORWARDED = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT)
USAGE_FIX = "storekeeper with-key [--json] --check | <command> [args...] (@ASC_KEY@ = the key path)"


def _env() -> dict:
    """The wrapper's environment: no BASH_ENV or ENV, which bash would source first."""
    env = {k: v for k, v in os.environ.items() if k not in ("BASH_ENV", "ENV")}
    return {**env, "STOREKEEPER_PYTHON": sys.executable}


def _run_wrapped(argv: list[str]) -> int:
    """The wrapper as a child, its output on stderr, signals passed on to it so it
    can delete the key folder before it ends."""
    proc = subprocess.Popen(
        [BASH, str(WRAPPER), *argv], stdin=subprocess.DEVNULL, stdout=2, env=_env()
    )
    old = {s: signal.signal(s, lambda sig, _frame: proc.send_signal(sig)) for s in FORWARDED}
    try:
        return proc.wait()
    finally:
        for s, handler in old.items():
            signal.signal(s, handler)


def _options(argv: list[str]) -> tuple[set, list[str]]:
    """storekeeper's own options come first; the command and its arguments are
    passed on untouched (an Apple tool's --json is its own)."""
    opts = set()
    while argv and argv[0] in ("--json", "--check", "--", "-h", "--help"):
        word = argv.pop(0)
        if word == "--":
            break
        opts.add(word)
    return opts, argv


def main(argv) -> int:
    opts, command = _options(list(argv))
    as_json = "--json" in opts
    if opts & {"-h", "--help"}:
        text = "usage: " + USAGE_FIX + "\n\n" + __doc__
        if as_json:
            return emit("with-key", help_outcome(text), True)
        print(text)
        return 0
    if "--check" in opts:
        if command:
            return emit(
                "with-key", failure("usage", "--check takes no command", USAGE_FIX), as_json
            )
        return emit("with-key", key.check_outcome(), as_json)
    if not command:
        return emit("with-key", failure("usage", "no command to run", USAGE_FIX), as_json)
    if not as_json:
        os.execve(BASH, [BASH, str(WRAPPER), *command], _env())
    ready = key.check_outcome()
    if ready.exit != 0:
        ready.lines = []
        return emit("with-key", ready, True)
    code = _run_wrapped(command)
    result = {"command": os.path.basename(command[0]), "command_exit": code}
    if code == 0:
        return emit("with-key", Outcome(result=result), True)
    fix = "read the command's own output on stderr; the key folder is gone"
    message = f"{result['command']} exited {code}"
    return emit("with-key", failure("command_failed", message, fix, result), True)
