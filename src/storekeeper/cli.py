"""The `storekeeper` command.

    storekeeper --version
    storekeeper key where | check | status [keychain]
    storekeeper with-key --check | <command> [args...]     (@ASC_KEY@ = the key file)
    storekeeper check-icon <App.app> [--icon-name NAME] | --store-page URL
    storekeeper api METHOD PATH [--query NAME=VALUE ...] [--body FILE|-] [--all]
                    [--private-env NAME ...] [--live]

Every command takes --json: one JSON object on stdout, nothing else there.
Exit codes: 0 ok, 1 finding or refusal, 2 usage, 3 keychain locked, 4 cannot tell.
Nothing prompts or waits for input.
"""

from __future__ import annotations

import sys
import traceback
from pathlib import Path

from . import __version__, api, icon, key, withkey
from .output import Outcome, emit, failure, help_outcome

COMMANDS = {"key": key.main, "with-key": withkey.main, "api": api.main}
USAGE = "\n\n".join(__doc__.split("\n\n")[1:3])


def _utf8() -> None:
    """Text in any locale: never a UnicodeEncodeError on the way out."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")


def _internal(err: Exception, command: str, as_json: bool) -> int:
    """A bug: one JSON object, exit 4. Only the exception's type and place are
    shown, never its text or a traceback, which could hold a value."""
    frames = traceback.extract_tb(err.__traceback__)
    where = f" at {Path(frames[-1].filename).name}:{frames[-1].lineno}" if frames else ""
    message = f"internal error: {type(err).__name__}{where}"
    fix = "this is a bug in storekeeper: report the command line (never the key) and this line"
    return emit(command, failure("internal", message, fix), as_json)


def main(argv=None, **inject) -> int:
    """`inject` is for tests: check-icon's run_tool and fetch."""
    _utf8()
    argv = sys.argv[1:] if argv is None else list(argv)
    words = [a for a in argv if a != "--json"]
    try:
        return _dispatch(argv, words, inject)
    except Exception as err:  # the contract: one JSON object, even for a bug
        return _internal(err, words[0] if words else "storekeeper", "--json" in argv)


def _dispatch(argv: list, words: list, inject: dict) -> int:
    as_json = "--json" in argv
    if words[:1] in (["-h"], ["--help"]):
        if as_json:
            return emit("help", help_outcome("usage:\n" + USAGE), True)
        print("usage:\n" + USAGE)
        return 0
    if words == ["--version"]:
        outcome = Outcome(result={"version": __version__}, lines=[f"storekeeper {__version__}"])
        return emit("version", outcome, as_json)
    if not words:
        outcome = failure(
            "usage", "no command", "run `storekeeper --help`", lines=["usage:", USAGE]
        )
        return emit("storekeeper", outcome, as_json, stdout=sys.stderr if not as_json else None)
    i = argv.index(words[0])
    command, rest = words[0], ["--json"] * ("--json" in argv[:i]) + argv[i + 1 :]
    if command == "check-icon":
        return icon.main(rest, **inject)
    if command not in COMMANDS:
        fix = "run `storekeeper --help`"
        return emit(command, failure("usage", f"unknown command {command!r}", fix), as_json)
    return COMMANDS[command](rest)
