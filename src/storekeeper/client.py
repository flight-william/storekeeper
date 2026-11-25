"""The App Store Connect API client: GET, POST, PATCH, DELETE and upload PUT,
with retry, a dry run by default, write fences, and masking of personal values.

Credentials come from the environment only:

    ASC_KEY_ID    the key's ID
    ASC_ISSUER    the issuer ID (App Store Connect: Users and Access, Integrations,
                  App Store Connect API)
    ASC_KEYCHAIN  optional: the keychain that holds the key (storekeeper.key)

The key itself lives in the Keychain (storekeeper.key). Credentials only check that
the item is there; the key is read when a token is signed.

The token is an ES256 JWT, 20 minutes, audience appstoreconnect-v1 (storekeeper.jwt).
Signing uses the `cryptography` module when it is installed, else the `openssl`
command, which gets the key through a pipe (/dev/fd/N), never a file.

A dry run makes no network call and reads no key: each request is printed
(method, path, JSON body; the body never carries a secret). A live call logs
method, path (no query) and HTTP status only; an upload PUT logs Apple's host
only (its URL is pre-signed). Writes are fenced by the lists in storekeeper.fences.
Personal values (a review contact, a tester) are read from the environment at
run time with personal_env(); every line the client prints has each of them
replaced by <private>, as typed or URL-encoded.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass

from . import key as asc_key
from .errors import ASCError
from .fences import API_PATH, DEFAULT_FENCES, Fences, shown
from .jsonapi import describe_error
from .jwt import b64url, jwt_claims, jwt_header
from .mask import PRIVATE as PRIVATE
from .mask import QUERY_SAFE, Masker

API_HOST = "api.appstoreconnect.apple.com"
API_ROOT = "https://" + API_HOST
MAX_WAIT = 60  # seconds: a Retry-After above this is cut to it (nothing waits long)
TOKEN_REFRESH_AFTER = 15 * 60
ENV_NAMES = ("ASC_KEY_ID", "ASC_ISSUER")
RETRY_STATUSES = (429, 500, 502, 503, 504)  # GET, PATCH and upload PUT; POST and DELETE on 429 only
UNSURE = "Apple may have saved it anyway: read the resource back before sending it again"
MAX_ATTEMPTS = 4


def sign_token(
    key_id: str,
    issuer: str,
    pem: bytes,
    now: int | None = None,
    signer: Callable[[bytes, bytes], bytes] | None = None,
) -> str:
    """The signed token from a PEM held in memory."""
    now = int(time.time()) if now is None else now
    if signer is None:
        _, signer = asc_key.pick_signer()
    head = b64url(json.dumps(jwt_header(key_id), separators=(",", ":")).encode())
    body = b64url(json.dumps(jwt_claims(issuer, now), separators=(",", ":")).encode())
    signing_input = f"{head}.{body}".encode("ascii")
    return f"{head}.{body}.{b64url(signer(signing_input, pem))}"


def make_token(key_id: str, issuer: str, keychain: str, now: int | None = None) -> str:
    """The signed token, the key read from `keychain` now and held only in memory."""
    return sign_token(key_id, issuer, asc_key.read_pem(key_id, keychain), now)


# --- credentials ---------------------------------------------------------


@dataclass(frozen=True)
class Credentials:
    key_id: str
    issuer: str
    keychain: str

    def __repr__(self) -> str:  # never print the issuer
        return "Credentials(<from environment>)"


def env_status(env: dict | None = None) -> dict[str, bool]:
    env = os.environ if env is None else env
    return {name: bool(env.get(name)) for name in ENV_NAMES}


def credentials_from_env(env: dict | None = None) -> Credentials:
    """The key ID, the issuer and the keychain that holds the key. The key is not read here."""
    env = os.environ if env is None else env
    missing = [n for n in ENV_NAMES if not env.get(n)]
    if missing:
        raise ASCError(
            "a live run needs ASC_KEY_ID and ASC_ISSUER; missing: " + ", ".join(missing),
            code="env_missing", fix="export " + " and ".join(missing) + " (README, Settings)",
        )  # fmt: skip
    asc_key.check_key_id(env["ASC_KEY_ID"])
    keychain = asc_key.keychain_path(env)
    state = asc_key.key_state(env["ASC_KEY_ID"], keychain)
    if state == "locked":
        raise asc_key.locked_error(keychain)
    if state == "absent":
        raise ASCError(
            f"{keychain} holds no App Store Connect key {env['ASC_KEY_ID']}",
            code="key_absent", fix=f"store the key: {asc_key.STORE_HINT}",
        )  # fmt: skip
    return Credentials(env["ASC_KEY_ID"], env["ASC_ISSUER"], keychain)


# --- the client ----------------------------------------------------------


def _query(params: dict | None) -> str:
    if not params:
        return ""
    return "?" + urllib.parse.urlencode(params, safe=QUERY_SAFE)


def check_path(path) -> None:
    """Refuse anything but an API path (storekeeper.fences.API_PATH), for every
    method, dry run or live: a path that does not start with /v<N>/ would put the
    bearer token on another host once it is appended to API_ROOT."""
    if not isinstance(path, str) or not API_PATH.fullmatch(path):
        raise ASCError(
            f"{shown(path)} is not an App Store Connect API path",
            code="path_refused",
            fix="give a path like /v1/apps: /v<N>/ and segments of letters, digits, _ and -",
        )


def same_origin(url: str) -> bool:
    parts = urllib.parse.urlsplit(url)
    return parts.scheme == "https" and parts.netloc == API_HOST


def api_url(path: str, params: dict | None = None) -> str:
    """The request's URL, on Apple's API host and nowhere else."""
    check_path(path)
    url = API_ROOT + path + _query(params)
    if not same_origin(url):
        raise ASCError(
            f"{shown(path)} leaves {API_HOST}", code="path_refused", fix="check the path"
        )
    return url


class _RefuseRedirect(urllib.request.HTTPRedirectHandler):
    """The API is never followed through a redirect: urllib would send the token on."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        where = urllib.parse.urlsplit(req.full_url).path
        raise ASCError(
            f"{req.get_method()} {where}: HTTP {code} redirect refused",
            code,
            "api_error",
            "the API answered with a redirect, which is never followed (the token would "
            "go with it); check the path, nothing more was sent",
        )


_OPENER = urllib.request.build_opener(_RefuseRedirect)


def _urlopen(req: urllib.request.Request, timeout: float):
    """Every request the client sends goes through here: no redirect is followed."""
    return _OPENER.open(req, timeout=timeout)


def _http_error(method: str, path: str, err: urllib.error.HTTPError) -> ASCError:
    message = describe_error(method, path, err)
    if method == "POST" and err.code >= 500:
        return ASCError(message, err.code, "unsure", UNSURE)
    fix = "read Apple's error text; change the request, not the retry"
    return ASCError(message, err.code, "api_error", fix)


def _lost(method: str, path: str, err: Exception) -> ASCError:
    reason = getattr(err, "reason", None) or type(err).__name__
    message = f"{method} {path}: no response ({reason})"
    if method == "POST":
        return ASCError(message, None, "unsure", UNSURE)
    return ASCError(message, None, "no_response", "check the network, then run it again")


class Client:
    """GET, POST, PATCH and DELETE against the API, plus the PUT of a reserved
    upload part. `live=False` prints and sends nothing.

    Every write is fenced (storekeeper.fences): `fences` defaults to the full list,
    and a caller narrows it to what its steps write. Every path, any method, must be
    an API path (check_path), and the URL must be on API_HOST."""

    def __init__(
        self,
        live: bool,
        creds: Credentials | None = None,
        out: Callable[[str], None] = print,
        sleep: Callable[[float], None] = time.sleep,
        fences: Fences = DEFAULT_FENCES,
        masker: Masker | None = None,
    ):
        if live and creds is None:
            raise ASCError(
                "a live client needs credentials", code="usage", fix="pass credentials_from_env()"
            )
        self.live = live
        self.fences = fences
        self.creds = creds
        self._raw_out = out
        self.masker = masker or Masker()
        self.sleep = sleep
        self._token: str | None = None
        self._token_at = 0.0
        self.last_included: list = []
        self.plan: list[dict] = []  # a dry run's requests, in order

    def out(self, line: str) -> None:
        """Every line this client prints, with each private value replaced."""
        self._raw_out(self.masker.text(line))

    def keep_private(self, *values: str | None) -> None:
        """Never print these values (storekeeper.mask says how they are found)."""
        self.masker.add(*values)

    def _bearer(self) -> str:
        assert self.creds is not None
        if self._token is None or time.time() - self._token_at > TOKEN_REFRESH_AFTER:
            self._token_at = time.time()
            c = self.creds
            self._token = make_token(c.key_id, c.issuer, c.keychain)
        return self._token

    def _request(
        self,
        method: str,
        path: str,
        params: dict | None = None,
        body: dict | None = None,
        allow_404: bool = False,
    ) -> dict | None:
        check_path(path)
        if not self.live:
            return self._dry_run(method, path, params, body)
        data = None if body is None else json.dumps(body).encode()
        # A 5xx or a lost answer to a POST may follow a save, so only the calls
        # that are safe to repeat (GET, PATCH) are retried on those; POST and
        # DELETE are retried only on 429 (refused, not done).
        retryable = RETRY_STATUSES if method in ("GET", "PATCH") else (429,)  # POST, DELETE
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                return self._send(method, path, params, data)
            except urllib.error.HTTPError as err:
                self.out(f"  {method} {path} -> {err.code}")
                if err.code == 404 and allow_404:
                    return {"data": None}
                if err.code in retryable and attempt < MAX_ATTEMPTS:
                    wait = err.headers.get("Retry-After") if err.headers else None
                    err.close()
                    pause = float(wait) if wait and wait.isdigit() else 2.0**attempt
                    self.sleep(min(pause, MAX_WAIT))
                    continue
                raise _http_error(method, path, err) from None
            except (urllib.error.URLError, TimeoutError, ConnectionError) as err:
                self.out(f"  {method} {path} -> no response")
                raise _lost(method, path, err) from None
        fix = "Apple is busy: wait, then run it again"
        message = f"{method} {path}: gave up after {MAX_ATTEMPTS} attempts"
        raise ASCError(message, None, "no_response", fix)

    def _dry_run(self, method: str, path: str, params: dict | None, body: dict | None) -> None:
        """Print the request and add it to `plan`; mask the plan before showing it."""
        query = {str(k): str(v) for k, v in (params or {}).items()}
        self.plan.append({"method": method, "path": path, "query": query, "body": body})
        self.out(f"  DRY-RUN {method} {path + _query(params)}")
        if body is not None:
            # Masked before it is encoded: an encoded value can sit right after an
            # escape (the n of \\n), where a line-by-line mask would miss it.
            shown_body = self.masker.obj(body)
            for line in json.dumps(shown_body, ensure_ascii=False, indent=2).splitlines():
                self.out(f"      {line}")
        return None

    def _send(self, method: str, path: str, params: dict | None, data: bytes | None) -> dict:
        req = urllib.request.Request(api_url(path, params), data=data, method=method)
        req.add_header("Authorization", "Bearer " + self._bearer())
        req.add_header("Accept", "application/json")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        with _urlopen(req, timeout=60) as resp:
            self.out(f"  {method} {path} -> {resp.status}")
            raw = resp.read()
            return json.loads(raw) if raw else {}

    def get(self, path: str, params: dict | None = None, allow_404: bool = False):
        return self._request("GET", path, params, allow_404=allow_404)

    def get_all(self, path: str, params: dict | None = None) -> list | None:
        """Every item of a paged list, following links.next. None in a dry run."""
        page = self.get(path, params)
        if page is None:
            return None
        items = list(page.get("data") or [])
        included = list(page.get("included") or [])
        nxt = (page.get("links") or {}).get("next")
        while nxt:
            if not same_origin(nxt):
                fix = "a next link must stay on the API host; nothing more was sent"
                raise ASCError(f"links.next leaves {API_HOST}", code="path_refused", fix=fix)
            parsed = urllib.parse.urlsplit(nxt)
            page = self.get(parsed.path, dict(urllib.parse.parse_qsl(parsed.query)))
            items += page.get("data") or []
            included += page.get("included") or []
            nxt = (page.get("links") or {}).get("next")
        self.last_included = included
        return items

    def post(self, path: str, body: dict):
        """POST, only where the fences allow; anything else is refused unsent."""
        self.fences.check_post(path)
        return self._request("POST", path, body=body)

    def patch(self, path: str, body: dict):
        """PATCH, only where the fences allow; anything else is refused unsent."""
        self.fences.check_patch(path, body)
        return self._request("PATCH", path, body=body)

    def delete(self, path: str):
        """DELETE, only where the fences allow; anything else is refused unsent."""
        self.fences.check_delete(path)
        return self._request("DELETE", path)

    def upload_part(self, operation: dict | None, data: bytes, label: str) -> None:
        """PUT one reserved part to Apple's upload URL. The URL is pre-signed, so
        only its host is ever logged; no bearer token goes with it."""
        if not self.live or operation is None:
            path = "<upload url from the reservation>"
            step = {"method": "PUT", "path": path, "query": {}, "body": None}
            self.plan.append({**step, "label": label, "bytes": len(data)})
            self.out(f"  DRY-RUN PUT <upload url from the reservation> {label} ({len(data)} bytes)")
            return
        url = operation["url"]
        parts = urllib.parse.urlsplit(url)
        host = parts.netloc
        if parts.scheme != "https" or not parts.hostname:
            fix = "use the upload operation Apple returned; it is always https"
            raise ASCError(f"upload {label}: not an https URL", code="path_refused", fix=fix)
        for attempt in range(1, MAX_ATTEMPTS + 1):
            req = urllib.request.Request(url, data=data, method=operation.get("method", "PUT"))
            for h in operation.get("requestHeaders") or []:
                req.add_header(h["name"], h["value"])
            try:
                with _urlopen(req, timeout=300) as resp:
                    self.out(f"  PUT {host} {label} -> {resp.status}")
                    return
            except urllib.error.HTTPError as err:
                self.out(f"  PUT {host} {label} -> {err.code}")
                if err.code in RETRY_STATUSES and attempt < MAX_ATTEMPTS:
                    err.close()
                    self.sleep(min(2.0**attempt, MAX_WAIT))
                    continue
                fix = "reserve the upload again; the URL may have expired"
                raise ASCError(
                    f"PUT {host} {label} -> HTTP {err.code}", err.code, "api_error", fix
                ) from None
            except (urllib.error.URLError, TimeoutError, ConnectionError) as err:
                reason = getattr(err, "reason", None) or type(err).__name__
                fix = "check the network, then reserve and upload the part again"
                raise ASCError(
                    f"PUT {host} {label}: no response ({reason})", None, "no_response", fix
                ) from None


def personal_env(client: Client, names: tuple[str, ...], env: dict | None = None) -> dict:
    """name -> value (None when unset) for personal values read at run time; each
    value is registered with the client so no output line can carry it."""
    env = os.environ if env is None else env
    values = {n: (env.get(n) or "").strip() or None for n in names}
    client.keep_private(*values.values())
    return values


def env_report(values: dict) -> str:
    """'NAME set, NAME unset': the only way a personal value is ever mentioned."""
    return ", ".join(f"{k} {'set' if v else 'unset'}" for k, v in values.items())
