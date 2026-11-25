"""Tests for the command line and its JSON contract (README, "JSON output").

python3 -I tests/test_cli.py

Every command takes --json and then prints one JSON object on stdout and nothing
else; the exit code is fixed by the error's code. No test opens a socket or
touches a real keychain: keychains are in the fake store or absent.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib
import io
import json
import os
import plistlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path[:0] = [str(ROOT / "src"), str(HERE), str(ROOT / "testkit")]
storekeeper = importlib.import_module("storekeeper")
cli = importlib.import_module("storekeeper.cli")
key_mod = importlib.import_module("storekeeper.key")
errors = importlib.import_module("storekeeper.errors")
helpers = importlib.import_module("test_key")
guards = importlib.import_module("no_network")
no_network = guards.no_socket
body_line, make_ec_key, store_for = helpers.body_line, helpers.make_ec_key, helpers.store_for

RUN = ROOT / "src" / "storekeeper" / "_run.py"
TOP_KEYS = {"schema_version", "command", "ok", "exit", "result", "error"}
EMAIL = "Reviewer.Person@Example.org"


class CliCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        guards.block_network(self)

    def cli(self, *argv: str, env: dict | None = None, **inject):
        out, err = io.StringIO(), io.StringIO()
        base = {"STOREKEEPER_KEYCHAIN": str(self.dir / "absent.keychain-db"), "HOME": str(self.dir)}
        with mock.patch.dict(os.environ, {**base, **(env or {})}):
            for name in ("ASC_KEY_ID", "ASC_ISSUER", REVIEW):
                if env is None or name not in env:
                    os.environ.pop(name, None)
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = cli.main(list(argv), **inject)
        return code, out.getvalue(), err.getvalue()

    def doc(self, *argv: str, **kw) -> tuple[dict, str]:
        """Run with --json; check the one-object rule and the schema; give the object."""
        code, out, err = self.cli(*argv, "--json", **kw)
        lines = out.splitlines()
        self.assertEqual(len(lines), 1, f"stdout is not one line: {out!r}")
        doc = json.loads(lines[0])
        self.assert_schema(doc, code)
        return doc, err

    def assert_schema(self, doc: dict, code: int) -> None:
        self.assertEqual(set(doc), TOP_KEYS)
        self.assertEqual(doc["schema_version"], 1)
        self.assertEqual(doc["exit"], code)
        self.assertEqual(doc["ok"], code == 0)
        self.assertIsInstance(doc["result"], dict)
        if doc["error"] is None:
            self.assertEqual(code, 0)
            return
        self.assertLessEqual({"code", "message", "fix"}, set(doc["error"]))
        self.assertLessEqual(set(doc["error"]), {"code", "message", "fix", "status"})
        self.assertIn(doc["error"]["code"], errors.EXIT_FOR)
        self.assertEqual(errors.EXIT_FOR[doc["error"]["code"]], code)
        self.assertTrue(doc["error"]["fix"], "an error with no fix")


REVIEW = "REVIEW_EMAIL"


class TopLevelTests(CliCase):
    def test_version(self):
        doc, _ = self.doc("--version")
        self.assertEqual(doc["result"], {"version": storekeeper.__version__})
        self.assertEqual(doc["command"], "version")

    def test_an_unknown_command_is_usage_in_json_too(self):
        doc, err = self.doc("nope")
        self.assertEqual((doc["exit"], doc["error"]["code"]), (2, "usage"))
        self.assertIn("nope", err)

    def test_no_command_is_usage(self):
        code, out, err = self.cli()
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("usage", err)


class KeyCommandTests(CliCase):
    def keychain(self, with_key: bool = True) -> str:
        store = store_for(self, self.dir)
        kc = store.make_keychain()
        if with_key:
            pem, _ = make_ec_key(self.dir)
            store.store_item(kc, "TESTKEY001", key_mod.SERVICE, body_line(pem))
        self.store = store
        return kc

    def test_where(self):
        doc, _ = self.doc("key", "where")
        self.assertEqual(
            doc["result"],
            {"keychain": str(self.dir / "absent.keychain-db"), "service": key_mod.SERVICE},
        )

    def test_check_present_absent_locked_and_unset(self):
        kc = self.keychain()
        env = {"ASC_KEY_ID": "TESTKEY001", "STOREKEEPER_KEYCHAIN": kc}
        doc, _ = self.doc("key", "check", env=env)
        self.assertEqual(doc["result"]["state"], "present")
        self.assertEqual(doc["command"], "key check")
        self.assertEqual(doc["result"]["keychain"], kc)
        doc, _ = self.doc("key", "check", env={**env, "ASC_KEY_ID": "OTHERKEY01"})
        self.assertEqual((doc["exit"], doc["error"]["code"]), (1, "key_absent"))
        self.assertIn("Keychain setup", doc["error"]["fix"])
        self.store.lock(kc)
        doc, _ = self.doc("key", "check", env=env)
        self.assertEqual((doc["exit"], doc["error"]["code"]), (3, "keychain_locked"))
        self.assertEqual(doc["error"]["fix"], f"security unlock-keychain {kc}")
        doc, _ = self.doc("key", "check", env={"STOREKEEPER_KEYCHAIN": kc})
        self.assertEqual((doc["exit"], doc["error"]["code"]), (2, "env_missing"))

    def test_the_command_is_named_wherever_json_stands(self):
        code, out, _ = self.cli("--json", "key", "where")
        self.assertEqual(json.loads(out)["command"], "key where")
        code, out, _ = self.cli("key", "--json", "where")
        self.assertEqual(json.loads(out)["command"], "key where")

    def test_check_that_cannot_tell_is_4(self):
        boom = mock.Mock(side_effect=storekeeper.ASCError("no answer", code="cannot_tell"))
        with mock.patch.object(key_mod, "key_state", boom):
            doc, _ = self.doc("key", "check", env={"ASC_KEY_ID": "TESTKEY001"})
        self.assertEqual((doc["exit"], doc["error"]["code"]), (4, "cannot_tell"))

    def test_status(self):
        kc = self.keychain(with_key=False)
        doc, _ = self.doc("key", "status", kc)
        self.assertEqual(doc["result"], {"keychain": kc, "state": "unlocked", "stand_in": True})
        doc, _ = self.doc("key", "status")
        self.assertEqual((doc["exit"], doc["result"]["state"]), (1, "absent"))

    def test_pem_has_no_json_form(self):
        doc, _ = self.doc("key", "pem", env={"ASC_KEY_ID": "TESTKEY001"})
        self.assertEqual((doc["exit"], doc["error"]["code"]), (2, "usage"))

    def test_text_mode_says_the_state_on_stdout(self):
        kc = self.keychain()
        code, out, _ = self.cli(
            "key", "check", env={"ASC_KEY_ID": "TESTKEY001", "STOREKEEPER_KEYCHAIN": kc}
        )
        self.assertEqual((code, out), (0, "present\n"))

    def test_with_key_check_is_key_check(self):
        kc = self.keychain()
        doc, _ = self.doc(
            "with-key", "--check", env={"ASC_KEY_ID": "TESTKEY001", "STOREKEEPER_KEYCHAIN": kc}
        )
        self.assertEqual(doc["command"], "with-key")
        self.assertEqual(doc["result"]["state"], "present")


class ApiTests(CliCase):
    def setUp(self):
        super().setUp()
        for name in ("_security", "keychain_locked"):  # a dry run reads no key
            guard = mock.patch.object(key_mod, name, no_network)
            guard.start()
            self.addCleanup(guard.stop)

    def body_file(self, body: dict) -> str:
        path = self.dir / "body.json"
        path.write_text(json.dumps(body))
        return str(path)

    def test_a_dry_run_prints_the_plan_with_personal_values_masked(self):
        body = {"data": {"type": "appStoreReviewDetails", "attributes": {"contactEmail": EMAIL}}}
        doc, err = self.doc(
            "api", "POST", "/v1/appStoreReviewDetails", "--body", self.body_file(body),
            "--private-env", REVIEW, env={REVIEW: EMAIL},
        )  # fmt: skip
        self.assertEqual(doc["exit"], 0)
        self.assertEqual(doc["command"], "api")
        self.assertFalse(doc["result"]["live"])
        (step,) = doc["result"]["plan"]
        self.assertEqual((step["method"], step["path"]), ("POST", "/v1/appStoreReviewDetails"))
        self.assertEqual(step["body"]["data"]["attributes"]["contactEmail"], storekeeper.PRIVATE)
        self.assertEqual(step["query"], {})
        self.assertNotIn(EMAIL.lower(), (json.dumps(doc) + err).lower())
        self.assertIn("DRY-RUN POST", err)

    def test_a_query_is_planned_and_masked_too(self):
        doc, _ = self.doc(
            "api", "GET", "/v1/betaTesters", "--query", f"filter[email]={EMAIL}",
            "--query", "limit=5", "--private-env", REVIEW, env={REVIEW: EMAIL},
        )  # fmt: skip
        (step,) = doc["result"]["plan"]
        self.assertEqual(step["query"], {"filter[email]": storekeeper.PRIVATE, "limit": "5"})
        self.assertIsNone(step["body"])

    def test_a_write_outside_the_fences_is_refused_and_masked(self):
        doc, err = self.doc(
            "api", "POST", f"/v1/betaTesters/{EMAIL}", "--private-env", REVIEW, env={REVIEW: EMAIL}
        )
        # Not even an API path (review 1, H1): refused before the fences are asked.
        self.assertEqual((doc["exit"], doc["error"]["code"]), (1, "path_refused"))
        self.assertEqual(doc["result"]["plan"], [])
        refused, _ = self.doc("api", "POST", "/v1/apps", "--body", self.body_file({"data": {}}))
        self.assertEqual((refused["exit"], refused["error"]["code"]), (1, "write_refused"))
        self.assertIn(storekeeper.PRIVATE, doc["error"]["message"])
        self.assertNotIn(EMAIL, json.dumps(doc) + err)

    def test_live_without_settings_is_env_missing(self):
        doc, _ = self.doc("api", "GET", "/v1/apps", "--live")
        self.assertEqual((doc["exit"], doc["error"]["code"]), (2, "env_missing"))

    def test_a_body_that_is_not_json_is_usage(self):
        bad = self.dir / "bad.json"
        bad.write_text("{not json")
        doc, _ = self.doc("api", "PATCH", "/v1/appStoreVersions/1", "--body", str(bad))
        self.assertEqual((doc["exit"], doc["error"]["code"]), (2, "usage"))

    def test_a_bad_method_or_query_is_usage(self):
        for argv in (("api", "PUT", "/v1/apps"), ("api", "GET", "/v1/apps", "--query", "x")):
            with self.subTest(argv=argv):
                doc, _ = self.doc(*argv)
                self.assertEqual(doc["error"]["code"], "usage")

    def test_the_live_response_is_returned_and_masked(self):
        creds = storekeeper.Credentials("K", "I", "/x.keychain-db")
        answer = {"data": [{"attributes": {"email": EMAIL.lower()}}]}
        client_mod = importlib.import_module("storekeeper.client")
        with mock.patch.object(client_mod, "credentials_from_env", return_value=creds):
            with mock.patch.object(client_mod.Client, "_request", return_value=answer):
                doc, err = self.doc(
                    "api", "GET", "/v1/betaTesters", "--live", "--private-env", REVIEW,
                    env={REVIEW: EMAIL},
                )  # fmt: skip
        self.assertTrue(doc["result"]["live"])
        self.assertEqual(doc["result"]["response"]["data"][0]["attributes"]["email"], "<private>")


class CheckIconTests(CliCase):
    def app(self) -> Path:
        app = self.dir / "Test.app"
        (app / "Contents" / "Resources").mkdir(parents=True)
        (app / "Contents" / "Resources" / "Assets.car").write_bytes(b"")
        (app / "Contents" / "Info.plist").write_bytes(plistlib.dumps({}))
        return app

    def test_pass_and_missing(self):
        app = self.app()
        fixture = (HERE / "fixtures" / "assetutil-mac-with-icon.json").read_text()
        doc, _ = self.doc("check-icon", str(app), run_tool=lambda argv: fixture)
        self.assertEqual(doc["result"]["icon_found"], True)
        self.assertEqual(doc["result"]["mode"], "app")
        self.assertEqual(doc["result"]["icon_name"], "AppIcon")
        doc, err = self.doc("check-icon", str(app), run_tool=lambda argv: "[]")
        self.assertEqual((doc["exit"], doc["error"]["code"]), (1, "icon_missing"))
        self.assertIn("ASSETCATALOG_COMPILER_APPICON_NAME", doc["error"]["fix"])

    def test_store_page_placeholder(self):
        url = "https://apps.apple.com/app/id0000000000"
        image = "https://is1-ssl.mzstatic.com/x/Placeholder.mill/1200x630wa.jpg"
        grid = b"\xff\xd8 a synthetic grey grid \xff\xd9"
        known = ((hashlib.sha256(grid).hexdigest(), len(grid)),)
        pages = {url: f'<meta property="og:image" content="{image}">'.encode(), image: grid}
        with mock.patch.object(importlib.import_module("storekeeper.icon"), "PLACEHOLDERS", known):
            doc, _ = self.doc("check-icon", "--store-page", url, fetch=pages.__getitem__)
        self.assertEqual((doc["exit"], doc["error"]["code"]), (1, "icon_placeholder"))
        self.assertEqual(doc["result"]["share_image"], image)
        self.assertIs(doc["result"]["placeholder"], True)

    def test_neither_app_nor_page_is_usage(self):
        doc, _ = self.doc("check-icon")
        self.assertEqual((doc["exit"], doc["error"]["code"]), (2, "usage"))


class OnlyJsonOnStdoutTests(unittest.TestCase):
    """As a separate process: stdout holds the one JSON object and nothing else."""

    def test_every_command_prints_only_its_json_object(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {
                "PATH": "/usr/bin:/bin",
                "HOME": tmp,
                "STOREKEEPER_KEYCHAIN": str(Path(tmp, "absent.keychain-db")),
                "ASC_KEY_ID": "TESTKEY001",
            }
            runs = [
                ["--version"], ["key", "where"], ["key", "check"], ["key", "status"],
                ["with-key", "--check"], ["check-icon", str(Path(tmp, "Missing.app"))],
                ["api", "GET", "/v1/apps", "--query", "limit=1"],
                ["api", "DELETE", "/v1/apps/1"], ["nope"], ["key"],
            ]  # fmt: skip
            for argv in runs:
                with self.subTest(argv=argv):
                    done = subprocess.run(
                        [sys.executable, "-I", str(RUN), *argv, "--json"],
                        capture_output=True, text=True, env=env, timeout=60,
                        stdin=subprocess.DEVNULL,
                    )  # fmt: skip
                    lines = done.stdout.splitlines()
                    self.assertEqual(len(lines), 1, done.stdout + done.stderr)
                    doc = json.loads(lines[0])
                    self.assertEqual(set(doc), TOP_KEYS)
                    self.assertEqual(doc["exit"], done.returncode)


if __name__ == "__main__":
    unittest.main()
