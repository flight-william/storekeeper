"""Tests for the App Store Connect client (stdlib unittest; no network, no real key).

python3 -I tests/test_client.py
"""

from __future__ import annotations

import base64
import importlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent / "src"), str(HERE), str(HERE.parent / "testkit")]
# By name: these load from the folders the line above puts on sys.path (-I leaves them off).
storekeeper = importlib.import_module("storekeeper")
client_mod = importlib.import_module("storekeeper.client")
key_mod = importlib.import_module("storekeeper.key")

# No test here may see the Keychain of whoever runs it: a locked real keychain
# would turn the credential tests red. Every credential test names, through
# STOREKEEPER_KEYCHAIN, a keychain in this module's temp folder that is never created;
# setUpModule makes any other path, and any call to `security` or
# Security.framework, fail the test loudly. test_key.py covers keychains, each
# one a throwaway in the fake store.
_TEMP: tempfile.TemporaryDirectory | None = None
_GUARDS: list = []


def _no_keychain() -> str:
    assert _TEMP is not None, "setUpModule has not run"
    return str(Path(_TEMP.name, "absent.keychain-db"))


def _env(**values: str) -> dict[str, str]:
    """An environment for credentials_from_env whose keychain does not exist."""
    return {"STOREKEEPER_KEYCHAIN": _no_keychain(), **values}


def _keychain_reached(*_args, **_kwargs):
    raise AssertionError("a test reached a keychain (security or Security.framework)")


def setUpModule():
    global _TEMP
    _TEMP = tempfile.TemporaryDirectory(prefix="storekeeper-test-")
    real_path = key_mod.keychain_path

    def test_keychains_only(env=None):
        path = real_path(env)
        if Path(path).parent != Path(_TEMP.name):
            raise AssertionError("a test asked for a keychain outside its temp folder: use _env()")
        return path

    _GUARDS[:] = [
        mock.patch.object(key_mod, "keychain_path", test_keychains_only),
        mock.patch.object(key_mod, "_security", _keychain_reached),
        mock.patch.object(key_mod, "keychain_locked", _keychain_reached),
    ]
    for guard in _GUARDS:
        guard.start()


def tearDownModule():
    for guard in reversed(_GUARDS):
        guard.stop()
    if _TEMP is not None:
        _TEMP.cleanup()


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _creds() -> object:
    return storekeeper.Credentials("K", "ISS", _no_keychain())


class JWTTests(unittest.TestCase):
    def test_claims_and_header_shape(self):
        self.assertEqual(
            storekeeper.jwt_claims("iss-x", 1000),
            {"iss": "iss-x", "iat": 1000, "exp": 2200, "aud": "appstoreconnect-v1"},
        )
        self.assertEqual(
            storekeeper.jwt_header("KID"), {"alg": "ES256", "kid": "KID", "typ": "JWT"}
        )

    def test_der_raw_round_trip_keeps_high_bit_and_short_integers(self):
        raw = bytes([0x80] + [1] * 31) + bytes([0] * 31 + [5])
        der = storekeeper.raw_to_der(raw)
        self.assertEqual(storekeeper.der_to_raw(der), raw)

    def test_token_signed_with_a_throwaway_key_verifies(self):
        with tempfile.TemporaryDirectory() as tmp:
            key, pub = Path(tmp, "throwaway.p8"), Path(tmp, "pub.pem")
            subprocess.run(
                ["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt",
                 "ec_paramgen_curve:P-256", "-out", str(key)],
                check=True, capture_output=True,
            )  # fmt: skip
            subprocess.run(
                ["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(pub)],
                check=True,
                capture_output=True,
            )
            pem = key.read_bytes()
            token = storekeeper.sign_token("KID123", "issuer-id", pem, now=1_700_000_000)
            head, body, sig = token.split(".")
            self.assertEqual(json.loads(_b64d(head)), storekeeper.jwt_header("KID123"))
            claims = json.loads(_b64d(body))
            self.assertEqual(claims["aud"], "appstoreconnect-v1")
            self.assertEqual(claims["exp"] - claims["iat"], 20 * 60)
            self.assertEqual(claims["iss"], "issuer-id")
            raw = _b64d(sig)
            self.assertEqual(len(raw), 64)
            sig_file = Path(tmp, "sig.der")
            sig_file.write_bytes(storekeeper.raw_to_der(raw))
            ok = subprocess.run(
                ["openssl", "dgst", "-sha256", "-verify", str(pub), "-signature", str(sig_file)],
                input=f"{head}.{body}".encode(),
                capture_output=True,
            )
            self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)

    def test_no_signer_names_the_missing_pieces(self):
        with mock.patch.dict(sys.modules, {"cryptography": None}):
            with mock.patch.object(key_mod, "OPENSSL", "/nonexistent/openssl"):
                with self.assertRaises(storekeeper.ASCError) as err:
                    storekeeper.pick_signer()
        self.assertIn("cryptography", str(err.exception))
        self.assertIn("openssl", str(err.exception))
        self.assertEqual(err.exception.code, "no_signer")


class CredentialTests(unittest.TestCase):
    def test_missing_variables_are_named_and_values_never_shown(self):
        with self.assertRaises(storekeeper.ASCError) as err:
            storekeeper.credentials_from_env(_env(ASC_KEY_ID="K"))
        self.assertIn("missing: ASC_ISSUER", str(err.exception))
        self.assertEqual((err.exception.code, err.exception.exit_code), ("env_missing", 2))
        self.assertIn("ASC_ISSUER", err.exception.fix)
        creds = storekeeper.Credentials("K", "secret-issuer", "/x.keychain-db")
        self.assertNotIn("secret-issuer", repr(creds))

    def test_two_settings_and_the_key_only_in_the_keychain(self):
        self.assertEqual(storekeeper.ENV_NAMES, ("ASC_KEY_ID", "ASC_ISSUER"))
        with self.assertRaises(storekeeper.ASCError) as err:
            storekeeper.credentials_from_env(_env(ASC_KEY_ID="K", ASC_ISSUER="I"))
        self.assertEqual(err.exception.code, "key_absent")
        self.assertIn("Keychain setup", err.exception.fix)

    def test_a_key_file_setting_is_not_read(self):
        # No file fallback: a path in ASC_KEY changes nothing.
        with tempfile.NamedTemporaryFile(suffix=".p8") as key:
            env = _env(ASC_KEY=key.name, ASC_KEY_ID="K", ASC_ISSUER="I")
            with self.assertRaises(storekeeper.ASCError) as err:
                storekeeper.credentials_from_env(env)
        self.assertEqual(err.exception.code, "key_absent")
        self.assertNotIn(key.name, str(err.exception))


class PublicSurfaceTests(unittest.TestCase):
    """What a library user imports from `storekeeper`."""

    def test_every_documented_name_is_on_the_package(self):
        missing = [n for n in storekeeper.__all__ if not hasattr(storekeeper, n)]
        self.assertEqual(missing, [])
        for name in ("Client", "Credentials", "credentials_from_env", "personal_env", "ASCError"):
            self.assertIn(name, storekeeper.__all__)


class _Resp(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class TransportTests(unittest.TestCase):
    def test_429_is_retried_and_the_log_is_method_path_status_only(self):
        calls = []

        def fake_urlopen(req, timeout):
            calls.append(req)
            if len(calls) == 1:
                raise urllib.error.HTTPError(
                    req.full_url, 429, "Too Many", {"Retry-After": "3"}, io.BytesIO(b"{}")
                )
            return _Resp(b'{"data": []}')

        lines: list[str] = []
        sleeps: list[float] = []
        c = storekeeper.Client(True, _creds(), out=lines.append, sleep=sleeps.append)
        with mock.patch.object(client_mod, "_urlopen", fake_urlopen):
            with mock.patch.object(client_mod, "make_token", return_value="TOKEN-SECRET"):
                got = c.get("/v1/apps", {"filter[bundleId]": "com.example.app"})
        self.assertEqual(got, {"data": []})
        self.assertEqual(sleeps, [3.0])
        self.assertEqual(lines, ["  GET /v1/apps -> 429", "  GET /v1/apps -> 200"])
        self.assertEqual(calls[1].get_header("Authorization"), "Bearer TOKEN-SECRET")

    def _client(self, responses, sleeps=None):
        """A live client whose urlopen plays `responses` (an HTTP status or a body)."""
        calls: list = []

        def fake_urlopen(req, timeout):
            calls.append(req)
            item = responses[len(calls) - 1]
            if isinstance(item, BaseException):
                raise item
            if isinstance(item, int):
                raise urllib.error.HTTPError(req.full_url, item, "x", {}, io.BytesIO(b"{}"))
            return _Resp(item)

        c = storekeeper.Client(
            True,
            _creds(),
            out=lambda s: None,
            sleep=(sleeps if sleeps is not None else []).append,
        )
        patches = (
            mock.patch.object(client_mod, "_urlopen", fake_urlopen),
            mock.patch.object(client_mod, "make_token", return_value="T"),
        )
        return c, calls, patches

    def test_a_post_answered_503_is_not_retried(self):
        c, calls, (p1, p2) = self._client([503, b'{"data": {}}'])
        with p1, p2, self.assertRaises(storekeeper.ASCError) as err:
            c.post("/v1/betaGroups", {"data": {}})
        self.assertEqual(len(calls), 1)
        self.assertEqual(err.exception.status, 503)
        self.assertEqual((err.exception.code, err.exception.exit_code), ("unsure", 4))
        self.assertIn("read the resource back", err.exception.fix)

    def test_a_post_answered_429_is_retried_and_a_get_503_too(self):
        c, calls, (p1, p2) = self._client([429, b'{"data": {}}', 503, b'{"data": []}'])
        with p1, p2:
            c.post("/v1/betaGroups", {"data": {}})
            c.get("/v1/apps")
        self.assertEqual(len(calls), 4)

    def test_no_response_becomes_an_asc_error(self):
        lost = urllib.error.URLError("timed out")
        c, calls, (p1, p2) = self._client([lost, TimeoutError()])
        with p1, p2:
            with self.assertRaises(storekeeper.ASCError) as err:
                c.get("/v1/apps")
            self.assertIn("no response", str(err.exception))
            self.assertEqual(err.exception.code, "no_response")
            with self.assertRaises(storekeeper.ASCError) as err:
                c.post("/v1/betaGroups", {"data": {}})
            self.assertEqual(err.exception.code, "unsure")

    def test_403_stops_with_apples_error_text(self):
        def fake_urlopen(req, timeout):
            body = b'{"errors":[{"code":"FORBIDDEN_ERROR","title":"not allowed","detail":"role"}]}'
            raise urllib.error.HTTPError(req.full_url, 403, "Forbidden", {}, io.BytesIO(body))

        c = storekeeper.Client(True, _creds(), out=lambda s: None)
        with mock.patch.object(client_mod, "_urlopen", fake_urlopen):
            with mock.patch.object(client_mod, "make_token", return_value="T"):
                with self.assertRaises(storekeeper.ASCError) as err:
                    c.post("/v1/profiles", {"data": {}})
        self.assertEqual(err.exception.status, 403)
        self.assertIn("FORBIDDEN_ERROR", str(err.exception))
        self.assertEqual((err.exception.code, err.exception.exit_code), ("api_error", 1))


class MaskingTests(unittest.TestCase):
    def test_a_personal_value_never_reaches_an_output_line(self):
        lines: list[str] = []
        c = storekeeper.Client(False, out=lines.append)
        values = storekeeper.personal_env(
            c, ("REVIEW_EMAIL", "REVIEW_PHONE"),
            {"REVIEW_EMAIL": "Someone@Example.com", "REVIEW_PHONE": "+1 555 0100"},
        )  # fmt: skip
        self.assertEqual(storekeeper.env_report(values), "REVIEW_EMAIL set, REVIEW_PHONE set")
        c.post(
            "/v1/appStoreReviewDetails",
            {"data": {"attributes": {"contactEmail": "someone@example.com", "phone": "15550100"}}},
        )
        c.get("/v1/betaTesters", {"filter[email]": "Someone@Example.com"})
        text = "\n".join(lines)
        self.assertNotIn("example.com", text.lower())
        self.assertNotIn("5550100", text)
        self.assertIn(storekeeper.PRIVATE, text)


if __name__ == "__main__":
    unittest.main()
