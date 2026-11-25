"""`storekeeper api`: one App Store Connect request from the command line.

    storekeeper api METHOD PATH [--query NAME=VALUE ...] [--body FILE|-] [--all]
                    [--private-env NAME ...] [--live] [--json]

A dry run unless --live: it reads no key, opens no socket, and reports the
planned request (method, path, query, body), with every personal value masked,
so it can be shown before it is sent. Writes (POST, PATCH, DELETE) are checked
against the default write fences, in a dry run too. --private-env names
environment variables whose values are personal: they are masked everywhere.
--body - reads the body from stdin; nothing else ever reads stdin.
"""

from __future__ import annotations

import json
import os
import sys

from . import client as client_mod
from .errors import ASCError
from .mask import Masker
from .output import Outcome, Parser, UsageError, failure, from_error, run, with_json

METHODS = ("GET", "POST", "PATCH", "DELETE")


def parser() -> Parser:
    p = Parser(prog="storekeeper api", description="One App Store Connect API request.")
    p.add_argument("method", type=str.upper, choices=METHODS)
    p.add_argument("path", help="the API path, e.g. /v1/apps")
    p.add_argument("--query", action="append", default=[], metavar="NAME=VALUE")
    p.add_argument("--body", metavar="FILE", help="a JSON body; - reads stdin")
    p.add_argument("--all", action="store_true", help="GET: follow every page")
    p.add_argument("--private-env", action="append", default=[], metavar="NAME")
    p.add_argument("--live", action="store_true", help="send it (default: dry run)")
    return with_json(p)


def _query(pairs: list[str]) -> dict:
    query = {}
    for pair in pairs:
        name, sep, value = pair.partition("=")
        if not sep or not name:
            raise UsageError(f"--query {pair} is not NAME=VALUE")
        query[name] = value
    return query


def _body(source: str | None):
    if source is None:
        return None
    try:
        if source == "-":
            text = sys.stdin.read()
        else:
            with open(source, encoding="utf-8") as fh:
                text = fh.read()
        body = json.loads(text)
    except (OSError, ValueError) as err:
        raise UsageError(f"--body {source}: not a readable JSON file ({err})") from None
    if not isinstance(body, dict):
        raise UsageError(f"--body {source}: the body must be a JSON object")
    return body


def _send(c: client_mod.Client, args, query: dict, body):
    if args.method == "GET":
        return c.get_all(args.path, query) if args.all else c.get(args.path, query)
    if query:
        raise UsageError(f"{args.method} takes no --query")
    if args.method == "DELETE":
        return c.delete(args.path)
    if body is None:
        # The fence speaks first: a refused write is refused, with or without a body.
        check = c.fences.check_post if args.method == "POST" else c.fences.check_patch
        check(args.path, *(() if args.method == "POST" else (None,)))
        raise UsageError(f"{args.method} needs --body")
    return c.post(args.path, body) if args.method == "POST" else c.patch(args.path, body)


def _say(line: str) -> None:
    print(line, file=sys.stderr)  # the client's text log: never stdout


def request(args, masker: Masker) -> Outcome:
    masker.add(*((os.environ.get(n) or "").strip() or None for n in args.private_env))
    result = {"live": args.live, "plan": []}
    try:
        client_mod.check_path(args.path)  # before any setting is read or any key touched
        query, body = _query(args.query), _body(args.body)
        creds = client_mod.credentials_from_env() if args.live else None
        c = client_mod.Client(args.live, creds, out=_say, masker=masker)
        result["plan"] = c.plan
        answer = _send(c, args, query, body)
    except UsageError as err:
        return failure("usage", str(err), "run `storekeeper api --help`", result)
    except ASCError as err:
        return from_error(err, result)
    if args.live:
        result["response"] = answer
    return Outcome(result=result)


def main(argv) -> int:
    masker = Masker()
    return run("api", parser(), list(argv), lambda args: request(args, masker), masker)
