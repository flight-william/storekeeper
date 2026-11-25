"""The secret store the keychain tests run against: the fake by default, real
throwaway macOS keychains on opt-in.

    python3 -I tests/test_key.py                        the fake store
    STOREKEEPER_REAL_KEYCHAIN=1 python3 -I tests/test_key.py
                                                        real throwaway keychains

The same goes for tests/test_with_key.py: one set of tests, two stores. A default
run never touches a keychain of the machine it runs on. The fake
(fake_security.py, named to the tool by SECURITY_BIN) copies the real tool's
verbs and refuses its two traps; only the real run proves the tool against
securityd itself. Run it after changing storekeeper/key.py or with-key.sh.

The real store lives here, not in a test file, because it calls `security`. It
makes each keychain inside the test's temp folder, with a name of its own (never
"login" or "asc": securityd may take a keychain for another of the same file
name), unlocked, never on the search list, deleted afterwards.
"""

from __future__ import annotations

import importlib
import json
import os
import subprocess
import sys
import unittest
import uuid
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
FAKE = HERE / "fake_security.py"
PASSPHRASE = "throwaway-test-passphrase"
REAL = os.environ.get("STOREKEEPER_REAL_KEYCHAIN") == "1"
# The verbs that open a password dialog on a keychain that is not unlocked.
PROMPTS_WHEN_LOCKED = ("find-generic-password", "add-generic-password", "-i")


def _locked(kc: str) -> bool:
    # The caller has put src/ on sys.path.
    return importlib.import_module("storekeeper.key").keychain_locked(kc)


class Store:
    """What a keychain test asks of the store. `env` goes to every tool run."""

    real = False

    def __init__(self, case: unittest.TestCase, folder: Path):
        self.case, self.folder, self.env = case, folder, {}

    def bin(self) -> str:
        return "security"

    def mine(self, kc: str) -> bool:
        folder = os.path.realpath(self.folder)
        return os.path.realpath(kc).startswith(folder + os.sep)

    def only_mine(self, verb: str, named: list[str]) -> None:
        """Real keychains only of this test's folder: a command naming none searches
        the login keychain, and one naming a keychain that is not there quietly uses
        login. A new one is made in the folder."""
        if verb == "list-keychains":
            return
        assert named, f"{verb} names no keychain: the real tool would use login"
        for kc in named:
            there = verb == "create-keychain" or Path(kc).is_file()
            assert self.mine(kc) and there, f"{verb} {kc}: not a keychain of {self.folder}"

    def run(self, *args: str, data: bytes | None = None) -> subprocess.CompletedProcess:
        """One `security` command, refused on a keychain that is not unlocked."""
        named = [a for a in args if a.endswith(".keychain-db")]
        named += [w for w in (data or b"").decode().split('"') if w.endswith(".keychain-db")]
        if self.real:
            self.only_mine(args[0], named)
        if args[0] in PROMPTS_WHEN_LOCKED:
            for kc in named:
                assert Path(kc).is_file() and not _locked(kc), f"{kc} would prompt"
        return subprocess.run(
            [self.bin(), *args], input=data, capture_output=True, timeout=30,
            env={**os.environ, **self.env},
        )  # fmt: skip

    def must(self, *args: str, data: bytes | None = None) -> None:
        done = self.run(*args, data=data)
        assert done.returncode == 0, f"{args[0]}: exit {done.returncode} {done.stderr!r}"

    def make_keychain(self, folder: Path | None = None) -> str:
        """A keychain of its own name in `folder` (the store's by default):
        unlocked, no auto-lock, deleted afterwards."""
        kc = (folder or self.folder) / f"throwaway-{uuid.uuid4().hex[:12]}.keychain-db"
        self.must("create-keychain", "-p", PASSPHRASE, str(kc))
        assert kc.is_file(), "the throwaway keychain was not created"
        self.case.addCleanup(self.delete_if_there, kc)
        self.unlock(str(kc))
        self.must("set-keychain-settings", str(kc))
        assert not _locked(str(kc))
        return str(kc)

    def delete_if_there(self, kc: Path) -> None:
        """Never name a keychain that does not exist to `security`."""
        if kc.exists():
            self.run("delete-keychain", str(kc))

    def lock(self, kc: str) -> None:
        self.must("lock-keychain", kc)

    def unlock(self, kc: str) -> None:
        self.must("unlock-keychain", "-p", PASSPHRASE, kc)

    def store_item(self, kc: str, account: str, service: str, value: str) -> None:
        """`value` as a generic password, over stdin (`security -i`), never on argv."""
        assert Path(kc).is_file()
        line = f'add-generic-password -U -a "{account}" -s "{service}" -w "{value}" "{kc}"\n'
        self.must("-i", data=line.encode())

    def read_item(self, kc: str, account: str, service: str) -> str:
        done = self.run("find-generic-password", "-a", account, "-s", service, "-w", kc)
        assert done.returncode == 0, f"no item {service}/{account} in {kc}"
        return done.stdout.decode().rstrip("\n")

    def calls(self) -> list[dict]:
        """What the tool asked the store, where it can tell (the fake's log)."""
        return []


class FakeStore(Store):
    """fake_security.py behind SECURITY_BIN; its log is the store's own."""

    def __init__(self, case: unittest.TestCase, folder: Path):
        super().__init__(case, folder)
        stand_in = folder / "fake-security" / "security"
        stand_in.parent.mkdir()
        stand_in.write_text(f'#!/bin/sh\nexec "{sys.executable}" -I "{FAKE}" "$@"\n')
        stand_in.chmod(0o755)
        self.log = folder / "fake-security" / "calls"
        self.env = {
            "SECURITY_BIN": str(stand_in),
            "STOREKEEPER_TEST_STAND_IN": "1",  # a stand-in is honoured only with this
            "FAKE_SECURITY_LOG": str(self.log),
        }
        patch = mock.patch.dict(os.environ, self.env)  # the key module in this process too
        patch.start()
        case.addCleanup(patch.stop)
        case.addCleanup(self.no_traps)

    def no_traps(self) -> None:
        """The real tool would have prompted, or used the login keychain."""
        traps = [c for c in self.calls() if "prompt" in c or "login-fallback" in c]
        self.case.assertEqual(traps, [], "the tool fell into a trap of the real `security`")

    def bin(self) -> str:
        return self.env["SECURITY_BIN"]

    def calls(self) -> list[dict]:
        if not self.log.exists():
            return []
        return [json.loads(x) for x in self.log.read_text().splitlines()]


class RealStore(Store):
    real = True

    def __init__(self, case: unittest.TestCase, folder: Path):
        # A stand-in set in the shell would answer the key module's lock check about
        # a real keychain while this store calls the real tool.
        assert not os.environ.get("SECURITY_BIN"), "unset SECURITY_BIN for a real run"
        super().__init__(case, folder)


def store_for(case: unittest.TestCase, folder: Path) -> Store:
    """The fake, unless STOREKEEPER_REAL_KEYCHAIN=1 asks for real throwaway keychains."""
    return (RealStore if REAL else FakeStore)(case, folder)
