"""Tests for the key in the Keychain (storekeeper.key) and the client reading it.

python3 -I tests/test_key.py

Every test makes its own throwaway EC key and, where it needs one, its own
keychain inside the test's temp folder, in the fake secret store;
STOREKEEPER_REAL_KEYCHAIN=1 runs the same tests on real throwaway keychains
(keychain_stores.py). No test reads the login keychain or a real key; `security`
is stubbed on PATH where a test must see that it is not called.
"""

from __future__ import annotations

import base64
import contextlib
import importlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent / "src"), str(HERE), str(HERE.parent / "testkit")]
# By name: these load from the folders the line above puts on sys.path (-I leaves them off).
asc_client = importlib.import_module("storekeeper.client")
asc_key = importlib.import_module("storekeeper.key")
stand_ins = importlib.import_module("storekeeper.stand_ins")
stores = importlib.import_module("keychain_stores")
PROMPTS_WHEN_LOCKED, store_for = stores.PROMPTS_WHEN_LOCKED, stores.store_for
raw_to_der = importlib.import_module("storekeeper.jwt").raw_to_der

# Every openssl here: macOS's LibreSSL always, Homebrew's OpenSSL where installed.
OPENSSLS = [p for p in ("/usr/bin/openssl", "/opt/homebrew/bin/openssl") if Path(p).exists()]


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def make_ec_key(folder: Path) -> tuple[bytes, Path]:
    """A throwaway P-256 key: (its PKCS#8 PEM, the public key's PEM file)."""
    key, pub = folder / "throwaway.p8", folder / "pub.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
         "-pkeyopt", "ec_param_enc:named_curve", "-out", str(key)],  # named, as Apple's are
        check=True, capture_output=True,
    )  # fmt: skip
    subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(pub)], check=True)
    pem = key.read_bytes()
    key.unlink()  # the tests hold the key in memory, the way the client does
    return pem, pub


def verifies(pub: Path, data: bytes, raw_sig: bytes, folder: Path) -> bool:
    sig = folder / "sig.der"
    sig.write_bytes(raw_to_der(raw_sig))
    done = subprocess.run(
        ["openssl", "dgst", "-sha256", "-verify", str(pub), "-signature", str(sig)],
        input=data,
        capture_output=True,
    )
    return done.returncode == 0


def body_line(pem: bytes) -> str:
    """The item's format (plan, Design): the PEM's body as one base64 line."""
    return "".join(x for x in pem.decode().splitlines() if not x.startswith("-----"))


def capture_token(client: asc_client.Client) -> str:
    """The bearer token the client sends on one GET (urlopen replaced, no network)."""
    seen = []

    class Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b"{}"

    def fake_urlopen(req, timeout):
        seen.append(req.get_header("Authorization"))
        return Resp()

    with mock.patch.object(asc_client, "_urlopen", fake_urlopen):
        client.get("/v1/apps")
    return seen[0].removeprefix("Bearer ")


class TempCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)


class KeychainClientTests(TempCase):
    def setUp(self):
        super().setUp()
        self.pem, self.pub = make_ec_key(self.dir)
        self.store = store_for(self, self.dir)
        self.kc = self.store.make_keychain()
        self.env = {
            "ASC_KEY_ID": "TESTKEY001",
            "ASC_ISSUER": "iss-test",
            "STOREKEEPER_KEYCHAIN": self.kc,
        }

    def test_2_a_live_client_signs_with_the_keychain_copy(self):
        self.store_item(body_line(self.pem))
        creds = asc_client.credentials_from_env(self.env)
        token = capture_token(asc_client.Client(True, creds, out=lambda s: None))
        head, body, sig = token.split(".")
        self.assertEqual(json.loads(_b64d(head))["kid"], "TESTKEY001")
        self.assertEqual(json.loads(_b64d(body))["iss"], "iss-test")
        self.assertTrue(verifies(self.pub, f"{head}.{body}".encode(), _b64d(sig), self.dir))

    def store_item(self, value: str) -> None:
        self.store.store_item(self.kc, "TESTKEY001", asc_key.SERVICE, value)

    def token_error(self):
        creds = asc_client.credentials_from_env(self.env)
        with self.assertRaises(asc_client.ASCError) as err:
            capture_token(asc_client.Client(True, creds, out=lambda s: None))
        return err.exception

    def test_4_errors_name_the_fix_and_never_the_value(self):
        line = body_line(self.pem)
        # Read at token time: locked after the credentials were made, the token stops.
        self.store_item(line)
        creds = asc_client.credentials_from_env(self.env)
        self.store.lock(self.kc)
        seen = len(self.store.calls())
        bin_dir, log = stub_security(self.dir)  # nothing may reach the real one now
        # By path, as the key module runs it (review 1, M3): nothing may reach the real one.
        with mock.patch.object(asc_key, "SECURITY", str(bin_dir / "security")):
            with self.assertRaises(asc_client.ASCError) as err:
                capture_token(asc_client.Client(True, creds, out=lambda s: None))
            self.assertIn("is locked", str(err.exception))
            self.assertEqual(err.exception.code, "keychain_locked")
            self.assertEqual(err.exception.fix, f"security unlock-keychain {self.kc}")
            with self.assertRaises(asc_client.ASCError) as err:
                asc_client.credentials_from_env(self.env)
            self.assertIn("is locked", str(err.exception))
        self.assertFalse(log.exists(), "a locked keychain reached security")
        reads = [
            c for c in self.store.calls()[seen:]
            if c.get("stdin") or c.get("argv", [""])[0] in PROMPTS_WHEN_LOCKED
        ]  # fmt: skip
        self.assertEqual(reads, [], "a locked keychain reached the store")
        self.store.unlock(self.kc)
        # Not one base64 line: refused, and the stored text is not repeated.
        self.store_item("not-base64 " + line[:40])
        err = self.token_error()
        self.assertIn("not one base64 line", str(err))
        self.assertEqual(err.code, "key_invalid")
        self.assertIn("Keychain setup", err.fix)
        self.assertNotIn(line[:40], str(err) + err.fix)
        # No item for this ID: the credentials say so, and how to fix it.
        with self.assertRaises(asc_client.ASCError) as caught:
            asc_client.credentials_from_env({**self.env, "ASC_KEY_ID": "OTHERKEY01"})
        self.assertIn("holds no App Store Connect key OTHERKEY01", str(caught.exception))
        self.assertIn("Keychain setup", caught.exception.fix)


class SigningTests(TempCase):
    def test_1_openssl_signs_from_dev_fd_under_libressl_and_homebrew(self):
        # The key goes to openssl through /dev/fd/N, never a file.
        self.assertTrue(OPENSSLS, "no openssl: macOS has /usr/bin/openssl")
        pem, pub = make_ec_key(self.dir)
        for openssl in OPENSSLS:
            with self.subTest(openssl=openssl):
                raw = asc_key.sign_openssl(b"head.body", pem, openssl=openssl)
                self.assertEqual(len(raw), 64)
                self.assertTrue(verifies(pub, b"head.body", raw, self.dir))
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), ["pub.pem", "sig.der"])


def stub_security(folder: Path) -> tuple[Path, Path]:
    """A `security` on PATH that only records that it was called: (bin, log)."""
    bin_dir, log = folder / "bin", folder / "security-calls"
    bin_dir.mkdir()
    (bin_dir / "security").write_text(f'#!/bin/sh\necho "$1" >> "{log}"\nexit 44\n')
    (bin_dir / "security").chmod(0o755)
    return bin_dir, log


class CommandLineTests(TempCase):
    def test_4_check_and_status_that_cannot_tell_exit_4_not_absent(self):
        # 1 means "not there"; a failure must not look like that.
        env = {"ASC_KEY_ID": "TESTKEY001", "STOREKEEPER_KEYCHAIN": str(self.dir / "x.keychain-db")}
        for command, broken in (("check", "key_state"), ("status", "keychain_locked")):
            with self.subTest(command=command):
                (self.dir / "x.keychain-db").write_bytes(b"")
                err = io.StringIO()
                boom = mock.Mock(side_effect=asc_client.ASCError("security gave no answer"))
                with mock.patch.dict(os.environ, env), mock.patch.object(asc_key, broken, boom):
                    with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                        code = asc_key.main([command])
                self.assertEqual(code, 4)
                self.assertIn("security gave no answer", err.getvalue())


class DryRunTests(TempCase):
    def test_3_a_dry_run_never_reads_the_key(self):
        bin_dir, log = stub_security(self.dir)
        kc = self.dir / "asc.keychain-db"
        kc.write_bytes(b"")  # exists, so only the stub stands between the client and a read
        creds = asc_client.Credentials("TESTKEY001", "iss", str(kc))
        lines: list[str] = []
        path = f"{bin_dir}:{os.environ.get('PATH', '/usr/bin:/bin')}"
        with (
            mock.patch.dict(os.environ, {"PATH": path}),
            mock.patch.object(asc_key, "SECURITY", str(bin_dir / "security")),
        ):
            client = asc_client.Client(False, creds, out=lines.append)
            client.get("/v1/apps")
            client.post("/v1/betaGroups", {"data": {}})
        self.assertIn("  DRY-RUN GET /v1/apps", lines)
        self.assertFalse(log.exists(), "a dry run called security")


class StandInTests(TempCase):
    """SECURITY_BIN is a test's switch. A stand-in is refused for a keychain in the real
    home's Library/Keychains, named on stderr when used, and a broken one is "cannot
    tell" (4), never "not there" (1). The real home is a parameter or a patch here: the
    tests give a folder of their own."""

    def setUp(self):
        super().setUp()
        self.home = self.dir / "home"
        self.kcs = self.home / "Library/Keychains"
        self.kcs.mkdir(parents=True)
        self.bin, self.log = stub_security(self.dir)  # records any call, answers nothing
        # A stand-in is honoured only with the test flag (review 1, L1).
        self.env = {"SECURITY_BIN": str(self.bin / "security"), "STOREKEEPER_TEST_STAND_IN": "1"}

    def rule(self, keychain: str, env=None):
        err = io.StringIO()
        env = self.env if env is None else env
        with contextlib.redirect_stderr(err):
            got = stand_ins.stand_in(keychain, env=env, home=str(self.home))
        return got, err.getvalue()

    def test_no_stand_in_means_the_real_tool_and_no_word(self):
        self.assertEqual(self.rule(str(self.kcs / "login.keychain-db"), env={}), (None, ""))

    def test_a_stand_in_for_a_test_keychain_is_used_and_named_on_stderr(self):
        got, err = self.rule(str(self.dir / "t.keychain-db"))
        self.assertEqual(got, self.env["SECURITY_BIN"])
        self.assertIn(f"SECURITY_BIN is set: using {got}, not the macOS Keychain", err)

    def test_a_stand_in_for_a_real_keychain_is_refused_however_it_is_named(self):
        (self.dir / "link").symlink_to(self.kcs)
        names = [self.kcs / "asc.keychain-db", self.kcs / "x/../login", self.kcs]
        names += [self.dir / "link/asc.keychain-db", "login.keychain-db"]  # bare: in the folder
        # The same folder by another spelling: judged by device and inode.
        lower = Path(str(self.kcs).lower())
        data = Path("/System/Volumes/Data" + os.path.realpath(self.kcs))
        for other in (lower, data):
            self.assertTrue(os.path.samefile(other, self.kcs), f"{other} is not the folder here")
        names += [lower / "asc.keychain-db", data / "asc.keychain-db"]
        kc = self.kcs / "kept.keychain-db"
        kc.write_bytes(b"")
        os.link(kc, self.dir / "hard-link.keychain-db")  # the same file, kept elsewhere
        names += [self.dir / "hard-link.keychain-db"]
        for name in map(str, names):
            with self.subTest(keychain=name):
                with self.assertRaises(stand_ins.Refused) as err:
                    self.rule(name, env={"SECURITY_BIN": "/s", "STOREKEEPER_TEST_STAND_IN": "1"})
                self.assertIn("SECURITY_BIN is set", str(err.exception))

    def test_the_real_home_is_the_user_databases_never_home(self):
        entry = mock.Mock(pw_dir="/nonexistent/home-from-the-user-database")
        with mock.patch.object(stand_ins.pwd, "getpwuid", return_value=entry):
            with mock.patch.dict(os.environ, {"HOME": str(self.home)}):
                self.assertEqual(stand_ins.real_home(), "/nonexistent/home-from-the-user-database")

    def main(self, command: str, keychain: Path, **env: str) -> tuple[int, str]:
        err = io.StringIO()
        env = {**self.env, "ASC_KEY_ID": "TESTKEY001", "STOREKEEPER_KEYCHAIN": str(keychain), **env}
        with mock.patch.dict(os.environ, env), contextlib.redirect_stderr(err):
            with mock.patch.object(stand_ins, "real_home", lambda: str(self.home)):
                with contextlib.redirect_stdout(io.StringIO()):
                    return asc_key.main([command]), err.getvalue()

    def test_the_key_module_never_lets_a_stand_in_answer_for_a_real_keychain(self):
        kc = self.kcs / "asc.keychain-db"
        kc.write_bytes(b"")  # there, so only the rule stands between it and the stand-in
        for command, code in (("check", 4), ("status", 4), ("pem", 1)):
            with self.subTest(command=command):
                got, err = self.main(command, kc)
                self.assertEqual(got, code, err)
                self.assertIn("SECURITY_BIN is set", err)
                self.assertIn("refused", err)
        self.assertFalse(self.log.exists(), "the stand-in was asked about a real keychain")

    def test_a_stand_in_or_security_that_cannot_run_is_cannot_tell(self):
        kc = self.dir / "t.keychain-db"
        kc.write_bytes(b"")
        got, err = self.main("check", kc, SECURITY_BIN=str(self.dir / "missing"))
        self.assertEqual(got, 4, err)
        unlocked = mock.patch.object(asc_key, "keychain_locked", return_value=False)
        # `security` is run by its absolute path (review 1, M3): one that is not there.
        missing = mock.patch.object(asc_key, "SECURITY", str(self.dir / "no-security"))
        with unlocked, missing:
            got, err = self.main("check", kc, SECURITY_BIN="")
        self.assertEqual(got, 4, err)


class RealStoreGuardTests(TempCase):
    """The real store runs only what names a keychain of the test's own folder, and
    refuses to start with a stand-in already set. Nothing here reaches `security`:
    subprocess.run is replaced."""

    def test_a_real_run_refuses_a_stand_in_already_set(self):
        with mock.patch.dict(os.environ, {"SECURITY_BIN": "/s"}):
            with self.assertRaises(AssertionError):
                stores.RealStore(self, self.dir)

    def test_the_real_store_runs_nothing_that_names_no_keychain_of_its_folder(self):
        with mock.patch.dict(os.environ):
            os.environ.pop("SECURITY_BIN", None)
            store = stores.RealStore(self, self.dir)
        mine = self.dir / "mine.keychain-db"
        mine.write_bytes(b"")
        read = PROMPTS_WHEN_LOCKED[0]
        refused = [
            (read, "-s", "x"),  # no keychain: the real tool searches login
            ("lock-keychain", str(self.dir / "none.keychain-db")),  # missing: login again
            ("show-keychain-info", str(self.dir.parent / "elsewhere.keychain-db")),
            ("create-keychain", "-p", "x", str(self.dir.parent / "elsewhere.keychain-db")),
        ]
        with mock.patch.object(stores.subprocess, "run") as run:
            for args in refused:
                with self.subTest(args=args), self.assertRaises(AssertionError):
                    store.run(*args)
            with self.assertRaises(AssertionError):
                store.run("-i", data=b'unlock-keychain -p "x" "/tmp/elsewhere.keychain-db"\n')
            run.assert_not_called()
            store.run("list-keychains", "-d", "user")
            store.run("create-keychain", "-p", "x", str(self.dir / "new.keychain-db"))
            store.run("show-keychain-info", str(mine))
            self.assertEqual(run.call_count, 3)


if __name__ == "__main__":
    unittest.main()
