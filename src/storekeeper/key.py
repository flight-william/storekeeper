"""The App Store Connect key: where it lives, how it is read, how it signs.

The key is a generic password (service "storekeeper" unless STOREKEEPER_SERVICE
names another; account = the key ID) in its own keychain,
~/Library/Keychains/storekeeper.keychain-db unless STOREKEEPER_KEYCHAIN names another.
`security` and `openssl` are macOS's own, by absolute path, never found on PATH.
The item holds the PEM's body as one base64 line. It is read when a token is
signed and handed to openssl through a pipe (/dev/fd/N), so it never touches the
disk; the one exception is `storekeeper with-key`, for Apple's tools that take
only a file.

This module is the one definition of where the key lives: the with-key wrapper
asks it (`key where`, `key check`, `key pem`) instead of restating it. The key's
PEM is never printed to a terminal, logged or put in an error message.

    storekeeper key where     the keychain's path and the item's service
    storekeeper key check     exit 0 when the keychain holds ASC_KEY_ID's key,
                              1 when not, 3 locked, 4 cannot tell (callers
                              stop on 4); attributes only: the key is not read
    storekeeper key status [keychain]
                              unlocked, locked or absent (exit 0, 3, 1; 4 cannot
                              tell), of the key's keychain or the one named; no UI
    storekeeper key pem       the PEM on stdout, for the with-key wrapper only;
                              refused when stdout is a terminal; no JSON form

Every action but pem takes --json (storekeeper.output).
"""

from __future__ import annotations

import base64
import binascii
import importlib
import os
import re
import shlex
import subprocess
import sys
from collections.abc import Callable

from . import stand_ins
from .errors import FINDING, USAGE, ASCError
from .jwt import der_to_raw
from .output import Outcome, Parser, failure, from_error, run, with_json

SERVICE = "storekeeper"
KEYCHAIN_NAME = "storekeeper.keychain-db"
SECURITY = "/usr/bin/security"
OPENSSL = "/usr/bin/openssl"
KEY_ID = re.compile(r"[A-Z0-9]+")
STORE_HINT = "the README's 'Keychain setup' steps"
SECURITY_TIMEOUT = 20
NOT_FOUND = 44  # security's exit when the item is not there
PEM_HEAD, PEM_TAIL = b"-----BEGIN PRIVATE KEY-----\n", b"-----END PRIVATE KEY-----\n"
BASE64_LINE = re.compile(rb"[A-Za-z0-9+/]+={0,2}")


def unlock_hint(keychain: str) -> str:
    return f"security unlock-keychain {shlex.quote(keychain)}"


def check_key_id(key_id: str) -> None:
    """ASC_KEY_ID is capital letters and digits, as Apple issues them."""
    if not KEY_ID.fullmatch(key_id or ""):
        raise ASCError(
            "ASC_KEY_ID is not a key ID (capital letters and digits)",
            code="env_missing",
            fix="export ASC_KEY_ID with the key's ID from App Store Connect",
        )


def service_name(env: dict | None = None) -> str:
    env = os.environ if env is None else env
    return env.get("STOREKEEPER_SERVICE") or SERVICE


def locked_error(keychain: str) -> ASCError:
    return ASCError(f"{keychain} is locked", code="keychain_locked", fix=unlock_hint(keychain))


def keychain_path(env: dict | None = None) -> str:
    """STOREKEEPER_KEYCHAIN if set, else ~/Library/Keychains/storekeeper.keychain-db."""
    env = os.environ if env is None else env
    if env.get("STOREKEEPER_KEYCHAIN"):
        return os.path.expanduser(env["STOREKEEPER_KEYCHAIN"])
    home = env.get("HOME") or os.path.expanduser("~")
    return os.path.join(home, "Library", "Keychains", KEYCHAIN_NAME)


def _stand_in(keychain: str) -> str | None:
    """SECURITY_BIN: a stand-in for `security`, for tests. Unset, the real tool is
    used; set, it is refused for a real keychain (stand_ins) and named on stderr."""
    try:
        return stand_ins.stand_in(keychain)
    except stand_ins.Refused as err:
        raise ASCError(str(err), code="cannot_tell", fix=f"unset {stand_ins.NAME}") from None


def _run(argv: list[str], **kw) -> subprocess.CompletedProcess:
    """Never waiting more than SECURITY_TIMEOUT (a prompt it should not have raised
    ends as an error, not a hung run), and a tool that cannot run is an error too:
    never an answer, which a caller would read as "not there"."""
    try:
        return subprocess.run(argv, check=False, timeout=SECURITY_TIMEOUT, **kw)
    except subprocess.TimeoutExpired:
        raise ASCError(
            f"security {argv[1]} gave no answer in {SECURITY_TIMEOUT} s (a prompt?)",
            code="cannot_tell", fix="unlock the keychain, then run the command again",
        ) from None  # fmt: skip
    except OSError as err:
        raise ASCError(
            f"{argv[0]} could not run ({err.__class__.__name__})",
            code="cannot_tell", fix="check that `security` is on PATH (macOS only)",
        ) from None  # fmt: skip


def _security(*args: str, keychain: str, capture: bool) -> subprocess.CompletedProcess:
    """`security` (or the stand-in the rule lets stand in) on `keychain`."""
    out = subprocess.PIPE if capture else subprocess.DEVNULL
    return _run([_stand_in(keychain) or SECURITY, *args], stdout=out, stderr=subprocess.DEVNULL)


def keychain_locked(keychain: str) -> bool:
    """True unless Security.framework says the keychain is open and unlocked.

    SecKeychainGetStatus never shows UI. `security find-generic-password -w` on a
    locked keychain opens an unlock dialog and hangs an unattended run, so nothing
    here reads or writes a keychain before this says it is unlocked.

    A stand-in (SECURITY_BIN) keeps its own keychains, which Security.framework
    does not know: it is asked instead (`keychain-status`, its one extra verb)."""
    stand_in = _stand_in(keychain)
    if stand_in:
        done = _run([stand_in, "keychain-status", keychain], capture_output=True)
        return done.stdout.strip() != b"unlocked"
    import ctypes

    sec = ctypes.cdll.LoadLibrary("/System/Library/Frameworks/Security.framework/Security")
    cf = ctypes.cdll.LoadLibrary(
        "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
    )
    ref, status = ctypes.c_void_p(), ctypes.c_uint32()
    if sec.SecKeychainOpen(os.fsencode(keychain), ctypes.byref(ref)) != 0:
        return True
    try:
        if sec.SecKeychainGetStatus(ref, ctypes.byref(status)) != 0:
            return True
    finally:
        cf.CFRelease(ref)
    return not status.value & 1  # kSecUnlockStateStatus


def key_state(key_id: str, keychain: str) -> str:
    """ "present", "absent" or "locked", from the item's attributes only (no -w).

    A keychain that does not exist is never named to `security`: it would quietly
    use the login keychain instead. A locked one is not searched."""
    if not key_id or not os.path.isfile(keychain):
        return "absent"
    if keychain_locked(keychain):
        return "locked"
    done = _security(
        "find-generic-password", "-a", key_id, "-s", service_name(), keychain,
        keychain=keychain, capture=False,
    )  # fmt: skip
    return "present" if done.returncode == 0 else "absent"


def read_pem(key_id: str, keychain: str) -> bytes:
    """The key's PEM, read from the keychain now. Errors name the fix, never the value."""
    if not os.path.isfile(keychain):
        raise ASCError(
            f"no keychain at {keychain}", code="key_absent", fix=f"store the key: {STORE_HINT}"
        )
    if keychain_locked(keychain):
        raise locked_error(keychain)
    done = _security(
        "find-generic-password", "-a", key_id, "-s", service_name(), "-w", keychain,
        keychain=keychain, capture=True,
    )  # fmt: skip
    if done.returncode == NOT_FOUND:
        raise ASCError(
            f"{keychain} holds no App Store Connect key {key_id}",
            code="key_absent", fix=f"store the key: {STORE_HINT}",
        )  # fmt: skip
    if done.returncode != 0:
        raise ASCError(
            f"{keychain} did not give the App Store Connect key (exit {done.returncode})",
            code="cannot_tell", fix=unlock_hint(keychain),
        )  # fmt: skip
    return pem_from_line(done.stdout, key_id)


def pem_from_line(raw: bytes, key_id: str = "") -> bytes:
    """The stored base64 line -> a PEM openssl reads (64-column body)."""
    line = raw.strip()
    try:
        if not BASE64_LINE.fullmatch(line):
            raise ValueError
        base64.b64decode(line, validate=True)
    except (ValueError, binascii.Error):
        raise ASCError(
            f"the Keychain item for {key_id or 'the key'} is not one base64 line",
            code="key_invalid", fix=f"store the key again: {STORE_HINT}",
        ) from None  # fmt: skip
    body = b"\n".join(line[i : i + 64] for i in range(0, len(line), 64))
    return PEM_HEAD + body + b"\n" + PEM_TAIL


# --- signing -------------------------------------------------------------


def sign_cryptography(signing_input: bytes, pem: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    key = serialization.load_pem_private_key(pem, password=None)
    der = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def sign_openssl(signing_input: bytes, pem: bytes, openssl: str = OPENSSL) -> bytes:
    """ES256 over signing_input with `openssl dgst -sign /dev/fd/N`: the PEM goes
    through a pipe the child inherits, never a file. Works with macOS's LibreSSL
    and Homebrew's OpenSSL."""
    read_end, write_end = os.pipe()
    try:
        os.write(write_end, pem)  # a key is far below the pipe's buffer: never blocks
        os.close(write_end)
        write_end = -1
        done = subprocess.run(
            [openssl, "dgst", "-sha256", "-sign", f"/dev/fd/{read_end}"],
            input=signing_input, capture_output=True, pass_fds=(read_end,), check=False,
        )  # fmt: skip
    finally:
        os.close(read_end)
        if write_end != -1:
            os.close(write_end)
    if done.returncode != 0:
        # Not openssl's stderr: it is not ours to vouch for.
        raise ASCError(
            f"openssl could not sign with the App Store Connect key: exit {done.returncode}",
            code="key_invalid", fix=f"check the stored key is Apple's .p8 body: {STORE_HINT}",
        )  # fmt: skip
    return der_to_raw(done.stdout)


def pick_signer() -> tuple[str, Callable[[bytes, bytes], bytes]]:
    """macOS's /usr/bin/openssl first: a module is found through sys.path, which
    PYTHONPATH can change when the tool runs without -I (a pip install)."""
    if os.path.isfile(OPENSSL) and os.access(OPENSSL, os.X_OK):
        return "openssl", sign_openssl
    try:
        importlib.import_module("cryptography")  # installed? (sign_cryptography imports it)
        return "cryptography", sign_cryptography
    except ImportError:
        pass
    raise ASCError(
        f"no ES256 signer: there is no {OPENSSL} and the Python module 'cryptography' "
        "is not installed",
        code="no_signer",
        fix="install openssl or the cryptography module (this tool installs nothing)",
    )  # fmt: skip


# --- `storekeeper key ...` -----------------------------------------------


def _cannot_tell(err: ASCError, result: dict) -> Outcome:
    """A check that failed is "cannot tell" (4), never "not there" (1): a caller
    must stop, not carry on as if the key were absent."""
    fix = err.fix or "run it again; if it persists, check `security` and the keychain"
    return failure("cannot_tell", str(err), fix, result)


def check_outcome(env=None) -> Outcome:
    """`key check`: is ASC_KEY_ID's key in the keychain? Attributes only."""
    env = os.environ if env is None else env
    keychain, key_id = keychain_path(env), env.get("ASC_KEY_ID") or ""
    result = {"keychain": keychain, "service": service_name(env), "key_id_set": bool(key_id)}
    result.update(state=None, stand_in=stand_ins.active(env))
    if not key_id:
        return failure("env_missing", "ASC_KEY_ID is not set", "export ASC_KEY_ID", result)
    try:
        check_key_id(key_id)
    except ASCError as err:
        return from_error(err, result)
    try:
        result["state"] = key_state(key_id, keychain)
    except ASCError as err:
        return _cannot_tell(err, result)
    if result["state"] == "locked":
        return from_error(locked_error(keychain), result)
    if result["state"] == "absent":
        message = f"{keychain} holds no App Store Connect key {key_id}"
        return failure("key_absent", message, f"store the key: {STORE_HINT}", result)
    return Outcome(result=result, lines=["present"])


def status_outcome(path: str) -> Outcome:
    """`key status`: is a keychain unlocked, locked or absent? No UI."""
    result = {"keychain": path, "state": None, "stand_in": stand_ins.active()}
    try:
        if not os.path.isfile(path):
            result["state"] = "absent"
        else:
            result["state"] = "locked" if keychain_locked(path) else "unlocked"
    except ASCError as err:
        return _cannot_tell(err, result)
    lines = [result["state"]]
    if result["state"] == "absent":
        fix = f"store the key: {STORE_HINT}"
        return failure("key_absent", f"no keychain at {path}", fix, result, lines)
    if result["state"] == "locked":
        outcome = from_error(locked_error(path), result)
        outcome.lines = lines
        return outcome
    return Outcome(result=result, lines=lines)


def _pem(key_id: str, keychain: str) -> int:
    """The PEM on stdout, for the with-key wrapper only: never JSON, never a terminal.
    The terminal refusal guards against accidents; it is not a boundary: anyone who
    can run this on an unlocked keychain can read the key (README, Limits)."""
    if sys.stdout.isatty():
        print("storekeeper key: the key goes to a pipe, never to a terminal", file=sys.stderr)
        return USAGE
    if not KEY_ID.fullmatch(key_id):
        print("storekeeper key: ASC_KEY_ID is not set or not a key ID", file=sys.stderr)
        return USAGE
    try:
        pem = read_pem(key_id, keychain)
    except ASCError as err:
        print(f"storekeeper key: {err}\nfix: {err.fix}", file=sys.stderr)
        return FINDING  # any failure: the wrapper stops on non-zero, and pem is internal
    sys.stdout.buffer.write(pem)
    sys.stdout.flush()
    return 0


ACTIONS = ("where", "check", "status", "pem")


def parser() -> Parser:
    p = Parser(prog="storekeeper key", description="Where the App Store Connect key lives.")
    p.add_argument("action", choices=ACTIONS)
    p.add_argument("keychain", nargs="?", help="status only: the keychain to ask about")
    return with_json(p)


def main(argv) -> int:
    argv = list(argv)

    def body(args) -> Outcome:
        if args.keychain and args.action != "status":
            return failure("usage", f"{args.action} takes no keychain", "see --help")
        if args.action == "where":
            keychain, service = keychain_path(), service_name()
            return Outcome(
                result={"keychain": keychain, "service": service}, lines=[keychain, service]
            )
        if args.action == "check":
            return check_outcome()
        if args.action == "status":
            return status_outcome(args.keychain or keychain_path())
        fix = "pem is for the with-key wrapper only; use `key check --json`"
        return failure("usage", "pem has no JSON form", fix)

    if argv == ["pem"]:
        return _pem(os.environ.get("ASC_KEY_ID") or "", keychain_path())
    words = [a for a in argv if a != "--json"]
    name = f"key {words[0]}" if words and words[0] in ACTIONS else "key"
    return run(name, parser(), argv, body)
