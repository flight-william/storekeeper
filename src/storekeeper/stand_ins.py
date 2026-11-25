"""A test's stand-in for macOS `security`, held to tests.

SECURITY_BIN names a program that replaces `security` (the fake secret store in
testkit/fake_security.py). It is honoured only when STOREKEEPER_TEST_STAND_IN=1
is set too, and `key check`/`key status` report it in JSON (`stand_in`). The key
module asks this rule before every call.

The rule: a stand-in is refused for a keychain in the real home's
Library/Keychains, the home taken from the user database, not $HOME. A bare
keychain name is one of that folder (`security` reads it so). "In" is judged by
device and inode too, so another spelling of the same folder, or a hard link to a
file in it, is refused as well. Tests keep their keychains in temp folders; a
stand-in in front of the user's keychains would be handed every secret. A
stand-in that is used says so on stderr, once per process for each path.
"""

from __future__ import annotations

import os
import pwd
import sys

NAME = "SECURITY_BIN"
FLAG = "STOREKEEPER_TEST_STAND_IN"  # must be "1" for NAME to be honoured at all
_said: set = set()


class Refused(Exception):
    """A stand-in set for a real keychain: the run must stop before anything runs."""


def real_home() -> str:
    """The user's home from the user database: $HOME is the caller's to change."""
    return pwd.getpwuid(os.getuid()).pw_dir


def keychains_folder(home: str | None = None) -> str:
    return os.path.realpath(os.path.join(home or real_home(), "Library", "Keychains"))


def _real_keychain(keychain: str, home: str | None) -> bool:
    folder = keychains_folder(home)
    if keychain.startswith("~"):
        keychain = (home or real_home()) + keychain[1:]
    target = os.path.realpath(os.path.join(folder, keychain))  # an absolute path stays itself
    if target == folder or target.startswith(folder + os.sep):
        return True
    return _same_file_inside(target, folder)


def _same_file_inside(target: str, folder: str) -> bool:
    """By which file it is, not how it is spelled: a case-insensitive disk takes
    upper and lower case for the same file, /System/Volumes/Data/... is the same
    folder as /..., and a hard link is the same file kept elsewhere. Any part of the
    path that is the Keychains folder by device and inode, or a file with a second
    link, is a real keychain."""
    try:
        folder_stat = os.stat(folder)
    except OSError:
        return False  # no such folder: nothing in it to stand in front of
    try:
        if os.stat(target).st_nlink > 1 and os.path.isfile(target):
            return True
    except OSError:
        pass
    path = target
    while True:
        try:
            if os.path.samestat(os.stat(path), folder_stat):
                return True
        except OSError:
            pass  # not there (yet): its parent decides
        parent = os.path.dirname(path)
        if parent == path:
            return False
        path = parent


def active(env=None) -> bool:
    """True when a stand-in answers for `security` (README: the JSON says so)."""
    env = os.environ if env is None else env
    return bool(env.get(NAME)) and env.get(FLAG) == "1"


def stand_in(keychain: str, env=None, home: str | None = None) -> str | None:
    """The stand-in's path, or None for the real `security`. Honoured only when the
    test flag is set too; raises Refused when one is set and `keychain` is a real
    one; says on stderr which one is used, or that one was ignored."""
    env = os.environ if env is None else env
    path = env.get(NAME)
    if not path:
        return None
    if env.get(FLAG) != "1":
        if ("ignored", path) not in _said:
            _said.add(("ignored", path))
            print(f"{NAME} is set but ignored: it is honoured only with {FLAG}=1", file=sys.stderr)
        return None
    if _real_keychain(keychain, home):
        raise Refused(
            f"{NAME} is set ({path}) and {keychain} is a real keychain: refused. "
            f"A stand-in is for tests; unset {NAME}."
        )
    if path not in _said:
        _said.add(path)
        print(f"{NAME} is set: using {path}, not the macOS Keychain", file=sys.stderr)
    return path
