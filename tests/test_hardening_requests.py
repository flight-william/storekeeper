"""Tests for review 1's request fixes: where a request may go (H1), what the
fences let through (H2), redirects (M1), which tools are run (M3), and the
network edges (L5).

python3 -I tests/test_hardening_requests.py

No socket is opened and no real keychain is touched.
"""

from __future__ import annotations

import importlib
import io
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

BAD_PATHS = (
    ".evil.example/v1/apps", ".localhost:8443/v1/apps", "@evil.example/x", "//evil.example/v1/apps",
    "v1/apps", "/x1/apps", "/v1", "/v1/", "/v1/apps x", "/v1/äpps", "/v1/apps\n", "/v1/apps\t",
    "/v1/apps/%2e%2e/users", "/v1/apps/../users", "/v1/apps/./x", "/v1//apps", "/v1/apps;x",
    "/v1/apps\\x", "/v1/apps?x=1", "/v1/apps#x",
)  # fmt: skip


class Quiet(unittest.TestCase):
    def setUp(self):
        guards.block_network(self)

    def refused(self, call, code="path_refused"):
        with self.assertRaises(storekeeper.ASCError) as err:
            call()
        self.assertEqual(err.exception.code, code, str(err.exception))
        self.assertTrue(err.exception.fix)
        return err.exception


class H1RequestTargetTests(Quiet):
    def test_a_path_that_is_not_an_api_path_is_refused_for_every_method_in_a_dry_run(self):
        c = storekeeper.Client(False, out=lambda s: None)
        for path in BAD_PATHS:
            senders = (c.get, lambda p: c.post(p, {}), lambda p: c.patch(p, {}), c.delete)
            for send in senders:
                with self.subTest(path=path):
                    with self.assertRaises(storekeeper.ASCError) as err:
                        send(path)
                    self.assertIn(err.exception.code, ("path_refused", "write_refused"))
        self.assertEqual(c.plan, [])

    def test_a_get_is_refused_with_path_refused(self):
        c = storekeeper.Client(False, out=lambda s: None)
        self.refused(lambda: c.get(".evil.example/v1/apps"))

    def test_a_live_get_never_sends_a_refused_path(self):
        creds = storekeeper.Credentials("K", "I", "/x.keychain-db")
        c = storekeeper.Client(True, creds, out=lambda s: None)
        with mock.patch.object(client_mod, "make_token", return_value="T"):
            for path in (".evil.example/v1/apps", "/v1/apps x", "/v1/äpps"):
                with self.subTest(path=path):
                    self.refused(lambda p=path: c.get(p))

    def test_the_url_is_built_on_apples_host_only(self):
        url = client_mod.api_url("/v1/apps", {"filter[bundleId]": "com.example.app"})
        parts = urllib.parse.urlsplit(url)
        self.assertEqual((parts.scheme, parts.netloc), ("https", "api.appstoreconnect.apple.com"))
        self.assertFalse(
            client_mod.same_origin("https://api.appstoreconnect.apple.com.evil.example/v1")
        )
        self.assertFalse(client_mod.same_origin("http://api.appstoreconnect.apple.com/v1/apps"))
        self.assertTrue(client_mod.same_origin("https://api.appstoreconnect.apple.com/v1/apps"))

    def test_a_next_link_to_another_host_is_not_followed(self):
        creds = storekeeper.Credentials("K", "I", "/x.keychain-db")
        c = storekeeper.Client(True, creds, out=lambda s: None)
        page = {"data": [], "links": {"next": "https://evil.example/v1/apps?cursor=x"}}
        with mock.patch.object(storekeeper.Client, "_send", return_value=page):
            self.refused(lambda: c.get_all("/v1/apps"))


class H2FenceSegmentTests(Quiet):
    def test_the_reviews_paths_and_their_kin_are_refused(self):
        c = storekeeper.Client(False, out=lambda s: None)
        attrs = {"data": {"attributes": {"contentRightsDeclaration": "X"}}}
        writes = [
            ("PATCH", "/v1/appStoreVersions/%2e%2e/apps/123"),
            ("PATCH", "/v1/appStoreVersions/.%2e/users/abc"),
            ("PATCH", "/v1/apps/%2e%2e%2fusers%2fabc"),
            ("DELETE", "/v1/appScreenshotSets/%2e%2e/betaGroups/1"),
            ("POST", "/v1/betaGroups/%2e%2e%2fusers/relationships/builds"),
            ("PATCH", "/v1/appStoreVersions/./x"),
            ("PATCH", "/v1/appStoreVersions//v1/apps/1"),
            ("PATCH", "/v1/appStoreVersions/a;b"),
            ("PATCH", "/v1/appStoreVersions/a\\b"),
            ("DELETE", "/v1/appScreenshotSets/"),
            ("PATCH", "/v1/apps/"),
        ]
        for method, path in writes:
            with self.subTest(method=method, path=path):
                send = {
                    "PATCH": lambda p: c.patch(p, attrs),
                    "DELETE": c.delete,
                    "POST": lambda p: c.post(p, {"data": []}),
                }[method]
                with self.assertRaises(storekeeper.ASCError) as err:
                    send(path)
                self.assertIn(err.exception.code, ("path_refused", "write_refused"))
        self.assertEqual(c.plan, [])

    def test_the_fence_checks_refuse_them_on_their_own_too(self):
        f = fences.DEFAULT_FENCES
        for check, path in (
            (lambda p: f.check_patch(p, {"data": {}}), "/v1/appStoreVersions/%2e%2e/apps/1"),
            (f.check_delete, "/v1/appScreenshotSets/%2e%2e/betaGroups/1"),
            (f.check_post, "/v1/betaGroups/%2e%2e%2fusers/relationships/builds"),
        ):
            with self.subTest(path=path):
                self.refused(lambda f=check, p=path: f(p), code="write_refused")

    def test_a_delete_reaches_one_set_and_nothing_below_it(self):
        c = storekeeper.Client(False, out=lambda s: None)
        c.delete("/v1/appScreenshotSets/abc-123_X")
        path = "/v1/appScreenshotSets/1/relationships/appScreenshots"
        self.refused(lambda: c.delete(path), code="write_refused")

    def test_an_attribute_rule_also_refuses_included_and_a_data_list(self):
        c = storekeeper.Client(False, out=lambda s: None)
        body = {"data": {"attributes": {"contentRightsDeclaration": "X"}}, "included": [{}]}
        self.refused(lambda: c.patch("/v1/apps/1", body), code="write_refused")
        self.refused(lambda: c.patch("/v1/apps/1", {"data": [1]}), code="write_refused")

    def test_ordinary_ids_still_pass(self):
        c = storekeeper.Client(False, out=lambda s: None)
        c.patch("/v1/appStoreVersions/0a1b2c3d-4e5f-6789-abcd-ef0123456789", {"data": {}})
        c.patch("/v1/appStoreVersions/123/relationships/build", {"data": {}})
        c.post("/v1/betaGroups/G_1-x/relationships/builds", {"data": []})
        self.assertEqual(len(c.plan), 3)


class M1RedirectTests(unittest.TestCase):
    def test_the_api_opener_refuses_every_redirect(self):
        handlers = [
            h for h in client_mod._OPENER.handlers
            if isinstance(h, urllib.request.HTTPRedirectHandler)
        ]  # fmt: skip
        self.assertTrue(handlers)
        req = urllib.request.Request("https://api.appstoreconnect.apple.com/v1/apps")
        for h in handlers:
            for newurl in (
                "https://elsewhere.example/x",
                "https://api.appstoreconnect.apple.com/v1/x",
            ):
                with self.subTest(newurl=newurl), self.assertRaises(storekeeper.ASCError) as err:
                    h.redirect_request(req, io.BytesIO(), 302, "Found", {}, newurl)
                self.assertIn("redirect", err.exception.fix)

    def test_check_icon_follows_redirects_only_to_apples_two_hosts(self):
        handlers = [
            h for h in icon._OPENER.handlers if isinstance(h, urllib.request.HTTPRedirectHandler)
        ]
        self.assertTrue(handlers)
        req = urllib.request.Request("https://apps.apple.com/app/id0")
        for h in handlers:
            for bad in ("https://evil.example/x", "http://apps.apple.com/x"):
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    h.redirect_request(req, io.BytesIO(), 302, "Found", {}, bad)
            ok = h.redirect_request(
                req, io.BytesIO(), 302, "Found", {}, "https://is1.mzstatic.com/a"
            )
            self.assertEqual(ok.full_url, "https://is1.mzstatic.com/a")


class M3ToolPathTests(unittest.TestCase):
    def test_security_and_openssl_are_macos_own_by_absolute_path(self):
        self.assertEqual(key_mod.SECURITY, "/usr/bin/security")
        self.assertEqual(key_mod.OPENSSL, "/usr/bin/openssl")

    def test_security_is_run_by_its_path_whatever_path_says(self):
        seen = []
        done = subprocess.CompletedProcess([], 44, b"", b"")
        env = {"PATH": "/nonexistent", "SECURITY_BIN": "", "STOREKEEPER_TEST_STAND_IN": ""}
        with mock.patch.dict(os.environ, env), mock.patch.object(
            key_mod, "_run", lambda argv, **kw: seen.append(argv) or done
        ):  # fmt: skip
            with tempfile.TemporaryDirectory() as tmp:
                key_mod._security(
                    "show-keychain-info", keychain=str(Path(tmp, "t.keychain-db")), capture=False
                )
        self.assertEqual(seen[0][0], "/usr/bin/security")

    def test_a_lookalike_openssl_on_path_never_gets_the_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            pem, pub = helpers.make_ec_key(folder)
            fake = folder / "bin" / "openssl"
            fake.parent.mkdir()
            fake.write_text(f'#!/bin/sh\ntouch "{folder}/fake-ran"\nexit 1\n')
            fake.chmod(0o755)
            with mock.patch.dict(os.environ, {"PATH": f"{fake.parent}:/usr/bin:/bin"}):
                name, signer = key_mod.pick_signer()
                raw = signer(b"head.body", pem)
            self.assertEqual(name, "openssl")
            self.assertFalse((folder / "fake-ran").exists(), "the PATH openssl was run")
            self.assertTrue(helpers.verifies(pub, b"head.body", raw, folder))


class L5NetworkEdgeTests(Quiet):
    def test_l5_an_upload_url_must_be_https_and_retry_after_is_capped(self):
        creds = storekeeper.Credentials("K", "I", "/x.keychain-db")
        c = storekeeper.Client(True, creds, out=lambda s: None)
        with self.assertRaises(storekeeper.ASCError) as err:
            c.upload_part({"url": "http://upload.example/x"}, b"data", "part 1")
        self.assertEqual(err.exception.code, "path_refused")
        sleeps = []
        c = storekeeper.Client(True, creds, out=lambda s: None, sleep=sleeps.append)
        calls = []

        def fake(req, timeout):
            calls.append(req)
            if len(calls) == 1:
                raise urllib.error.HTTPError(
                    req.full_url, 429, "x", {"Retry-After": "100000"}, io.BytesIO(b"{}")
                )
            return io.BytesIO(b"{}")

        class Resp(io.BytesIO):
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake_open(req, timeout):
            out = fake(req, timeout)
            return Resp(out.getvalue())

        with mock.patch.object(client_mod, "_urlopen", fake_open), mock.patch.object(
            client_mod, "make_token", return_value="T"
        ):  # fmt: skip
            c.get("/v1/apps")
        self.assertLessEqual(sleeps[0], client_mod.MAX_WAIT)
        self.assertLessEqual(client_mod.MAX_WAIT, 60)


if __name__ == "__main__":
    unittest.main()
