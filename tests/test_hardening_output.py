"""Tests for review 1's output fixes: what masking covers (M4), the JSON
contract under bad input (M5), the stand-in flag (L1), the unlock hint (L2), the
key ID (L7), the keychain defaults, the placeholder (P2) and the README's fence
list (L4).

python3 -I tests/test_hardening_output.py

No socket is opened and no real keychain is touched.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import urllib.parse
import urllib.request
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path[:0] = [str(ROOT / "src"), str(HERE), str(ROOT / "testkit")]
storekeeper = importlib.import_module("storekeeper")
client_mod = importlib.import_module("storekeeper.client")
cli = importlib.import_module("storekeeper.cli")
fences = importlib.import_module("storekeeper.fences")
icon = importlib.import_module("storekeeper.icon")
key_mod = importlib.import_module("storekeeper.key")
mask = importlib.import_module("storekeeper.mask")
stand_ins = importlib.import_module("storekeeper.stand_ins")
helpers = importlib.import_module("test_key")
guards = importlib.import_module("no_network")

RUN = ROOT / "src" / "storekeeper" / "_run.py"


class M4MaskingTests(unittest.TestCase):
    def masked(self, values, text):
        m = mask.Masker()
        m.add(*values)
        return m.text(text)

    def test_any_letter_case(self):
        self.assertEqual(
            self.masked(["jane.roe@example.org"], "to Jane.Roe@Example.org"), "to <private>"
        )

    def test_a_phone_grouped_another_way(self):
        typed = "+1 (555) 010-9999"
        for shown in ("+1 555 010 9999", "555-010-9999", "15550109999", "(555) 0109999"):
            with self.subTest(shown=shown):
                self.assertEqual(self.masked([typed], f"call {shown} now"), "call <private> now")

    def test_json_unicode_escapes_and_lower_case_percent_hex(self):
        name = "Zoë Example"
        self.assertNotIn("Zo", self.masked([name], json.dumps({"n": name})))
        email = "a+b@example.org"
        encoded = urllib.parse.quote(email, safe="").lower()
        self.assertEqual(self.masked([email], f"q={encoded}"), "q=<private>")

    def test_no_over_masking_of_numbers_ids_or_words(self):
        self.assertEqual(
            self.masked(["tester404@example.org"], "HTTP 404 /v1/betaGroups/1404"),
            "HTTP 404 /v1/betaGroups/1404",
        )
        self.assertEqual(self.masked(["Li"], "Lisbon Li"), "Lisbon Li")
        self.assertEqual(
            self.masked(["Ann"], "planned Annual, Ann Example"), "planned Annual, <private> Example"
        )

    def test_a_plans_method_and_path_are_never_masked(self):
        m = mask.Masker()
        m.add("apps")
        got = m.obj({"plan": [{"method": "GET", "path": "/v1/apps", "body": {"x": "apps"}}]})
        self.assertEqual(got["plan"][0]["path"], "/v1/apps")
        self.assertEqual(got["plan"][0]["body"]["x"], "<private>")


class N1EscapedTextTests(unittest.TestCase):
    """Re-review N1: a value right after an escape (the n of \\n, the D of %3D)."""

    def masked(self, values, text):
        m = mask.Masker()
        m.add(*values)
        return m.text(text)

    def test_values_after_an_escape_are_masked(self):
        values = ["Jane Roe", "555-010-9999", "jane.roe@example.org", "Roe"]
        text = '"Contact:\\nJane Roe\\n555-010-9999\\njane.roe@example.org\\tRoe"'
        got = self.masked(values, text)
        for clear in ("Jane", "Roe", "0109999", "010-9999", "jane.roe"):
            self.assertNotIn(clear, got)
        self.assertEqual(self.masked(["Jane Roe"], "name%3DJane%20Roe&x=1"), "name%3D<private>&x=1")
        self.assertEqual(self.masked(["Roe"], "a\\u00e9Roe"), "a\\u00e9<private>")

    def test_a_single_word_still_keeps_its_boundaries(self):
        self.assertEqual(self.masked(["Ann"], "Annual planned\\nAnn"), "Annual planned\\n<private>")


class CliCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        guards.block_network(self)

    def run_cli(self, *argv, env=None):
        out, err = io.StringIO(), io.StringIO()
        base = {"STOREKEEPER_KEYCHAIN": str(self.dir / "absent.keychain-db"), "HOME": str(self.dir)}
        with mock.patch.dict(os.environ, {**base, **(env or {})}):
            for name in ("ASC_KEY_ID", "ASC_ISSUER", "SECURITY_BIN", "STOREKEEPER_TEST_STAND_IN"):
                if not env or name not in env:
                    os.environ.pop(name, None)
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = cli.main(list(argv))
        lines = out.getvalue().splitlines()
        self.assertEqual(len(lines), 1, f"not one JSON line: {out.getvalue()!r}")
        doc = json.loads(lines[0])
        self.assertEqual(doc["exit"], code)
        return doc, err.getvalue()


class M5OneObjectTests(CliCase):
    def test_bodies_that_are_not_json_objects(self):
        for text in ("[1, 2]", '"str"', "3", "null"):
            with self.subTest(body=text):
                path = self.dir / "b.json"
                path.write_text(text)
                doc, _ = self.run_cli("api", "PATCH", "/v1/apps/123", "--body", str(path), "--json")
                self.assertEqual((doc["exit"], doc["error"]["code"]), (2, "usage"))
        path.write_text('{"data": [1]}')
        doc, _ = self.run_cli("api", "PATCH", "/v1/apps/123", "--body", str(path), "--json")
        self.assertEqual(doc["error"]["code"], "write_refused")

    def test_bad_paths_are_refused_before_any_setting_is_read(self):
        for path in ("/v1/apps x", "/v1/äpps", ".evil.example/v1/apps"):
            with self.subTest(path=path):
                doc, _ = self.run_cli("api", "GET", path, "--live", "--json")
                self.assertEqual((doc["exit"], doc["error"]["code"]), (1, "path_refused"))

    def test_help_with_json_is_one_object(self):
        for argv in (["--help"], ["api", "--help"], ["key", "-h"], ["check-icon", "--help"],
                     ["with-key", "--help"]):  # fmt: skip
            with self.subTest(argv=argv):
                doc, _ = self.run_cli(*argv, "--json")
                self.assertEqual(doc["exit"], 0)
                self.assertIn("usage", doc["result"]["help"])

    def test_an_internal_error_is_one_object_with_no_secret_and_exit_4(self):
        boom = mock.Mock(side_effect=RuntimeError("secret-value-xyz"))
        with mock.patch.dict(cli.COMMANDS, {"key": boom}):
            doc, err = self.run_cli("key", "check", "--json")
        self.assertEqual((doc["exit"], doc["error"]["code"]), (4, "internal"))
        self.assertNotIn("secret-value-xyz", json.dumps(doc) + err)
        self.assertNotIn("Traceback", json.dumps(doc))
        self.assertIn("RuntimeError", doc["error"]["message"])

    def test_a_query_that_is_not_a_pair_is_masked_in_the_error(self):
        value = "o'neil@example.org"
        doc, err = self.run_cli(
            "api", "GET", "/v1/betaTesters", "--query", value, "--private-env", "TESTER",
            "--json", env={"TESTER": value},
        )  # fmt: skip
        self.assertEqual(doc["error"]["code"], "usage")
        self.assertNotIn("neil", json.dumps(doc) + err)

    def test_an_odd_locale_still_gives_one_object(self):
        with tempfile.TemporaryDirectory() as tmp:
            latin1 = "en_US.ISO8859-1"
            env = {"PATH": "/usr/bin:/bin", "HOME": tmp, "LC_ALL": latin1, "LANG": latin1}
            env["STOREKEEPER_KEYCHAIN"] = str(Path(tmp, "k"))
            argv = ["api", "GET", "/v1/apps", "--query", "name=Zoë Ωmega 名前", "--json"]
            for py in (sys.executable, "/usr/bin/python3"):
                with self.subTest(python=py):
                    done = subprocess.run(
                        [py, "-I", str(RUN), *argv], capture_output=True, env=env, timeout=60
                    )
                    lines = done.stdout.splitlines()
                    self.assertEqual(len(lines), 1, done.stdout + done.stderr)
                    doc = json.loads(lines[0])
                    self.assertEqual((done.returncode, doc["exit"]), (0, 0))
                    self.assertEqual(doc["result"]["plan"][0]["query"]["name"], "Zoë Ωmega 名前")


class N1DryRunReportTests(CliCase):
    def test_a_multi_line_notes_field_is_masked_on_stdout_and_stderr(self):
        notes = "Contact:\nJane Roe\n555-010-9999\njane.roe@example.org"
        body = {"data": {"attributes": {"contactEmail": "jane.roe@example.org", "notes": notes}}}
        path = self.dir / "review.json"
        path.write_text(json.dumps(body))
        env = {"R_NAME": "Jane Roe", "R_PHONE": "555-010-9999", "R_EMAIL": "jane.roe@example.org"}
        doc, err = self.run_cli(
            "api", "POST", "/v1/appStoreReviewDetails", "--body", str(path), "--json",
            "--private-env", "R_NAME", "--private-env", "R_PHONE", "--private-env", "R_EMAIL",
            env=env,
        )  # fmt: skip
        self.assertEqual(doc["exit"], 0)
        self.assertIn("DRY-RUN POST", err)
        for clear in ("Jane", "Roe", "010-9999", "0109999", "jane.roe"):
            with self.subTest(clear=clear):
                self.assertNotIn(clear, json.dumps(doc))
                self.assertNotIn(clear, err)


class LowTests(CliCase):
    def test_l1_a_stand_in_needs_the_test_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            kc = str(Path(tmp, "t.keychain-db"))
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertIsNone(
                    stand_ins.stand_in(kc, env={"SECURITY_BIN": "/s"}, home=tmp + "/h")
                )
            self.assertIn("ignored", err.getvalue())
            env = {"SECURITY_BIN": "/s", "STOREKEEPER_TEST_STAND_IN": "1"}
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(stand_ins.stand_in(kc, env=env, home=tmp + "/h"), "/s")

    def test_l1_json_says_when_a_stand_in_answered(self):
        store = helpers.store_for(self, self.dir)
        kc = store.make_keychain()
        env = {"ASC_KEY_ID": "TESTKEY001", "STOREKEEPER_KEYCHAIN": kc, **store.env}
        doc, _ = self.run_cli("key", "check", "--json", env=env)
        self.assertIs(doc["result"]["stand_in"], True)
        doc, _ = self.run_cli("key", "status", "--json")
        self.assertIs(doc["result"]["stand_in"], False)

    def test_l2_the_unlock_hint_is_quoted(self):
        path = "/tmp/kc; echo INJECTED #/a b.keychain-db"
        self.assertEqual(
            key_mod.unlock_hint(path),
            "security unlock-keychain '/tmp/kc; echo INJECTED #/a b.keychain-db'",
        )
        self.assertEqual(
            key_mod.unlock_hint("/tmp/plain.keychain-db"),
            "security unlock-keychain /tmp/plain.keychain-db",
        )

    def test_l7_a_key_id_that_is_not_one_is_refused_in_python(self):
        for bad in ("BAD\nID", "abc", "K/../x", "K Y"):
            with self.subTest(key_id=bad):
                with self.assertRaises(storekeeper.ASCError) as err:
                    storekeeper.credentials_from_env(
                        {
                            "ASC_KEY_ID": bad,
                            "ASC_ISSUER": "I",
                            "STOREKEEPER_KEYCHAIN": str(self.dir / "k"),
                        }
                    )
                self.assertEqual(err.exception.code, "env_missing")
                self.assertNotIn("\n", str(err.exception))
                doc, _ = self.run_cli("key", "check", "--json", env={"ASC_KEY_ID": bad})
                self.assertEqual(doc["error"]["code"], "env_missing")


class DefaultsTests(unittest.TestCase):
    def test_the_keychain_and_service_names_and_their_overrides(self):
        self.assertEqual(
            key_mod.keychain_path({"HOME": "/h"}), "/h/Library/Keychains/storekeeper.keychain-db"
        )
        self.assertEqual(key_mod.keychain_path({"HOME": "/h", "STOREKEEPER_KEYCHAIN": "/k"}), "/k")
        self.assertEqual(key_mod.keychain_path({"HOME": "/h", "ASC_KEYCHAIN": "/k"}),
                         "/h/Library/Keychains/storekeeper.keychain-db")  # fmt: skip
        self.assertEqual(key_mod.service_name({}), "storekeeper")
        self.assertEqual(key_mod.service_name({"STOREKEEPER_SERVICE": "other"}), "other")


class P2PlaceholderTests(unittest.TestCase):
    def test_only_the_hash_and_size_ship(self):
        self.assertEqual(list((HERE / "fixtures").glob("*.jpg")), [])
        for digest, size in icon.PLACEHOLDERS:
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
            self.assertIsInstance(size, int)

    def test_a_synthetic_image_with_a_known_hash_is_found(self):
        image = b"\xff\xd8 synthetic grey grid \xff\xd9"
        known = ((hashlib.sha256(image).hexdigest(), len(image)),)
        with mock.patch.object(icon, "PLACEHOLDERS", known):
            self.assertTrue(icon.is_placeholder(image))
            self.assertFalse(icon.is_placeholder(image + b"x"))


class L4ReadmeFenceListTests(unittest.TestCase):
    def test_the_readme_lists_exactly_the_default_fences(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        start, end = "<!-- fences:start -->\n", "<!-- fences:end -->"
        self.assertIn(start, readme)
        listed = readme.split(start, 1)[1].split(end, 1)[0]
        self.assertEqual(listed, fences.markdown(fences.DEFAULT_FENCES))


if __name__ == "__main__":
    unittest.main()
