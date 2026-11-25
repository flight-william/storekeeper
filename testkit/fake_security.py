"""A stand-in for macOS `security`, for tests: the fake secret store.

Named by SECURITY_BIN (storekeeper.key honours it), so a test never reads or
writes a keychain of the machine it runs on. The key module refuses it for a
keychain in the real home's Library/Keychains, and names it on stderr when used
(storekeeper.stand_ins). A keychain here is a JSON file at the path the real one
would have; the verbs the tool uses act on it with the real tool's exit codes.
Every call is appended to FAKE_SECURITY_LOG (one JSON line: the argv, and what a
`-i` line ran), so a test can see what was asked.

The real tool's two traps are refusals here, never copies: a read or write on a
locked keychain (the real one opens a password dialog and hangs) exits LOCKED and
logs "prompt"; a keychain path that does not exist (the real one quietly uses the
login keychain) exits NO_SUCH_KEYCHAIN and logs "login-fallback". A test asserts
neither appears.

One verb has no real twin: `keychain-status <path>` prints unlocked, locked or
absent. storekeeper.key.keychain_locked reads a real keychain's state from
Security.framework, which knows nothing of these files, and asks a stand-in this.

Stdlib only. Run as a program: python3 -I fake_security.py <security's arguments>.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

NOT_FOUND = 44  # the real tool's exit for an item that is not there
DUPLICATE = 45
NO_SUCH_KEYCHAIN = 50
WRONG_PASSPHRASE = 51
LOCKED = 36  # the real tool would prompt: refused
USAGE = 2


def security_words(line: str) -> list[str]:
    """How `security -i` splits one command line, as probed on macOS with
    show-keychain-info on a nonexistent path: whitespace separates words,
    double quotes group, and inside them a backslash takes the next character."""
    words, word, quoted, i, started = [], "", False, 0, False
    line = line.rstrip("\n")
    while i < len(line):
        ch = line[i]
        if quoted and ch == "\\" and i + 1 < len(line):
            word, i = word + line[i + 1], i + 2
            continue
        if ch == '"':
            quoted, started = not quoted, True
        elif ch.isspace() and not quoted:
            if started:
                words.append(word)
            word, started = "", False
        else:
            word, started = word + ch, True
        i += 1
    if started:
        words.append(word)
    return words


def log(entry: dict) -> None:
    path = os.environ.get("FAKE_SECURITY_LOG")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")


def options(args: list[str], flags: str, valued: str) -> tuple[dict, list[str]]:
    """getopt for one verb: single-letter flags, then the operands."""
    opts: dict = {}
    i = 0
    while i < len(args) and args[i].startswith("-") and len(args[i]) == 2:
        letter = args[i][1]
        if letter in valued:
            opts[letter] = args[i + 1]
            i += 2
        elif letter in flags:
            opts[letter] = True
            i += 1
        else:
            raise ValueError(f"unknown option {args[i]}")
    return opts, args[i:]


def load(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def save(path: str, kc: dict) -> None:
    Path(path).write_text(json.dumps(kc), encoding="utf-8")


def named(path: str | None) -> int | None:
    """None when the keychain file is there; else the refusal, logged."""
    if path and Path(path).is_file():
        return None
    log({"login-fallback": path})
    print(f"security: no keychain at {path} (the real tool would use login)", file=sys.stderr)
    return NO_SUCH_KEYCHAIN


def open_unlocked(path: str | None) -> tuple[dict | None, int]:
    refused = named(path)
    if refused is not None:
        return None, refused
    kc = load(path)
    if kc["locked"]:
        log({"prompt": path})
        print(f"security: {path} is locked (the real tool would prompt)", file=sys.stderr)
        return None, LOCKED
    return kc, 0


def create_keychain(args: list[str]) -> int:
    opts, rest = options(args, "", "p")
    path = rest[0]
    if Path(path).exists():
        return 48  # a keychain with the same name already exists
    save(path, {"passphrase": opts["p"], "locked": False, "lock_on_sleep": False,
                "timeout": 300, "items": []})  # fmt: skip
    return 0


def unlock_keychain(args: list[str]) -> int:
    opts, rest = options(args, "", "p")
    refused = named(rest[0])
    if refused is not None:
        return refused
    kc = load(rest[0])
    if opts.get("p") != kc["passphrase"]:
        print("security: The user name or passphrase you entered is not correct.", file=sys.stderr)
        return WRONG_PASSPHRASE
    kc["locked"] = False
    save(rest[0], kc)
    return 0


def lock_keychain(args: list[str]) -> int:
    refused = named(args[0])
    if refused is not None:
        return refused
    kc = load(args[0])
    kc["locked"] = True
    save(args[0], kc)
    return 0


def set_keychain_settings(args: list[str]) -> int:
    opts, rest = options(args, "lu", "t")
    kc, code = open_unlocked(rest[0])
    if kc is None:
        return code
    kc["lock_on_sleep"] = bool(opts.get("l"))
    kc["timeout"] = int(opts.get("t", 300)) if opts.get("u") else None
    save(rest[0], kc)
    return 0


def show_keychain_info(args: list[str]) -> int:
    refused = named(args[0])
    if refused is not None:
        return refused
    kc = load(args[0])
    info = f'Keychain "{args[0]}"'
    info += " lock-on-sleep" if kc["lock_on_sleep"] else ""
    info += f" timeout={kc['timeout']}s" if kc["timeout"] is not None else " no-timeout"
    print(info, file=sys.stderr)  # the real tool prints it on stderr
    return 0


def add_generic_password(args: list[str]) -> int:
    opts, rest = options(args, "U", "aslw")
    kc, code = open_unlocked(rest[0] if rest else None)
    if kc is None:
        return code
    same = [it for it in kc["items"] if (it["a"], it["s"]) == (opts["a"], opts["s"])]
    if same and not opts.get("U"):
        return DUPLICATE
    kc["items"] = [it for it in kc["items"] if it not in same]
    kc["items"].append({"a": opts["a"], "s": opts["s"], "l": opts.get("l", ""), "w": opts["w"]})
    save(rest[0], kc)
    return 0


def find_generic_password(args: list[str]) -> int:
    opts, rest = options(args, "w", "as")
    kc, code = open_unlocked(rest[0] if rest else None)
    if kc is None:
        return code
    for it in kc["items"]:
        if it["a"] == opts.get("a", it["a"]) and it["s"] == opts.get("s", it["s"]):
            print(it["w"] if opts.get("w") else f'keychain: "{rest[0]}"\nclass: "genp"')
            return 0
    print("security: The specified item could not be found in the keychain.", file=sys.stderr)
    return NOT_FOUND


def delete_keychain(args: list[str]) -> int:
    refused = named(args[0])
    if refused is not None:
        return refused
    Path(args[0]).unlink()
    return 0


def list_keychains(args: list[str]) -> int:
    return 0  # no search list: the fake never adds a keychain to one


def keychain_status(args: list[str]) -> int:
    if not Path(args[0]).is_file():
        print("absent")
        return 1
    locked = load(args[0])["locked"]
    print("locked" if locked else "unlocked")
    return 3 if locked else 0


VERBS = {
    "create-keychain": create_keychain,
    "unlock-keychain": unlock_keychain,
    "lock-keychain": lock_keychain,
    "set-keychain-settings": set_keychain_settings,
    "show-keychain-info": show_keychain_info,
    "add-generic-password": add_generic_password,
    "find-generic-password": find_generic_password,
    "delete-keychain": delete_keychain,
    "list-keychains": list_keychains,
    "keychain-status": keychain_status,
}


def run(words: list[str]) -> int:
    verb = VERBS.get(words[0]) if words else None
    if verb is None:
        print(f"security: unknown command {words[:1]}", file=sys.stderr)
        return USAGE
    try:
        return verb(words[1:])
    except (ValueError, IndexError, KeyError) as err:
        print(f"security: {words[0]}: {err.__class__.__name__}", file=sys.stderr)
        return USAGE


def main(argv: list[str]) -> int:
    log({"argv": argv})
    if argv != ["-i"]:
        return run(argv)
    code = 0
    for line in sys.stdin.read().splitlines():
        words = security_words(line)
        if words:
            log({"stdin": words[0]})
            code = run(words)
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
