"""The one error the client raises, its machine codes, and the exit code each maps to.

Exit codes are fixed and documented (README, "Exit codes"):

    0  ok
    1  a finding or a refusal: key absent, a path or a write refused, an API error,
       a missing icon, a command run by with-key --json that failed
    2  usage: a wrong command line or a setting that is not set
    3  the keychain is locked
    4  cannot tell: a tool gave no answer, no response from the API, or Apple may
       have saved a write that failed, or an internal error (a bug); stop, do not
       retry blindly
"""

from __future__ import annotations

OK, FINDING, USAGE, LOCKED, CANNOT_TELL = 0, 1, 2, 3, 4

# Every machine code an error can carry, and its exit code.
EXIT_FOR = {
    "usage": USAGE,
    "env_missing": USAGE,
    "key_absent": FINDING,
    "key_invalid": FINDING,
    "write_refused": FINDING,
    "path_refused": FINDING,
    "api_error": FINDING,
    "icon_missing": FINDING,
    "icon_placeholder": FINDING,
    "command_failed": FINDING,
    "keychain_locked": LOCKED,
    "cannot_tell": CANNOT_TELL,
    "no_signer": CANNOT_TELL,
    "no_response": CANNOT_TELL,
    "unsure": CANNOT_TELL,
    "internal": CANNOT_TELL,
}


class ASCError(Exception):
    """An API or configuration failure; the message never carries a secret.

    `code` is one of EXIT_FOR's keys; `fix` is one line saying what to do next."""

    def __init__(
        self, message: str, status: int | None = None, code: str = "api_error", fix: str = ""
    ):
        super().__init__(message)
        if code not in EXIT_FOR:
            raise ValueError(f"unknown error code {code!r}")
        self.status = status
        self.code = code
        self.fix = fix

    @property
    def exit_code(self) -> int:
        return EXIT_FOR[self.code]
