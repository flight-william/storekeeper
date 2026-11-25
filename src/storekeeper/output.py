"""What a command reports, and the one place it is printed: as text for a person,
or with --json as one JSON object on stdout for an agent.

The JSON object (schema_version 1, README "JSON output"):

    {"schema_version": 1, "command": "key check", "ok": false, "exit": 1,
     "result": {...}, "error": {"code": "key_absent", "message": "...", "fix": "..."}}

`ok` is exit == 0. `error` is null when there is none. With --json nothing else is
written to stdout; the text report goes to stderr. Every string is masked.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field

from .errors import EXIT_FOR, OK, ASCError
from .mask import Masker

SCHEMA_VERSION = 1


@dataclass
class Outcome:
    exit: int = OK
    result: dict = field(default_factory=dict)
    error: dict | None = None
    lines: list[str] = field(default_factory=list)  # the text report


def failure(code: str, message: str, fix: str, result: dict | None = None, lines=()) -> Outcome:
    error = {"code": code, "message": message, "fix": fix}
    return Outcome(EXIT_FOR[code], result or {}, error, list(lines))


def from_error(err: ASCError, result: dict | None = None) -> Outcome:
    outcome = failure(err.code, str(err), err.fix, result)
    if err.status is not None:
        outcome.error["status"] = err.status
    return outcome


def document(command: str, outcome: Outcome) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "command": command,
        "ok": outcome.exit == OK,
        "exit": outcome.exit,
        "result": outcome.result,
        "error": outcome.error,
    }


def emit(
    command: str, outcome: Outcome, as_json: bool, masker: Masker | None = None,
    stdout=None, stderr=None,
) -> int:  # fmt: skip
    """Print the outcome; return its exit code."""
    masker = masker or Masker()
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    report = stderr if as_json else stdout
    for line in outcome.lines:
        print(masker.text(line), file=report)
    if outcome.error:
        who = "storekeeper" if command == "storekeeper" else f"storekeeper {command}"
        print(masker.text(f"{who}: {outcome.error['message']}"), file=stderr)
        if outcome.error["fix"]:
            print(masker.text(f"fix: {outcome.error['fix']}"), file=stderr)
    if as_json:
        # ASCII only (\\u escapes): one line any locale can print.
        print(json.dumps(masker.obj(document(command, outcome))), file=stdout)
    return outcome.exit


def help_outcome(text: str) -> Outcome:
    return Outcome(result={"help": text})


class UsageError(Exception):
    """A wrong command line: exit 2, reported like any other error."""


class Parser(argparse.ArgumentParser):
    """argparse that raises UsageError instead of printing and exiting, so a usage
    error is reported through emit() (as JSON with --json) like any other."""

    def error(self, message):
        raise UsageError(f"{message} (usage: {self.format_usage().strip()[7:]})")

    def exit(self, status=0, message=None):  # --help, after printing
        raise SystemExit(status)


def with_json(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    parser.add_argument(
        "--json", action="store_true", help="print one JSON object on stdout (schema 1)"
    )
    return parser


def run(command: str, parser: Parser, argv, body, masker: Masker | None = None) -> int:
    """Parse argv, call body(args) -> Outcome, and emit it. A usage error is exit 2,
    in JSON too when --json is anywhere in argv."""
    if "--json" in argv and ("-h" in argv or "--help" in argv):
        return emit(command, help_outcome(parser.format_help()), True, masker)
    try:
        args = parser.parse_args(argv)
    except UsageError as err:
        fix = f"run `storekeeper {command} --help`"
        return emit(command, failure("usage", str(err), fix), "--json" in argv, masker)
    return emit(command, body(args), args.json, masker)
