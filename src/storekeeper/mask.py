"""Personal values the caller names (a review contact, a tester) never reach
output: the one definition of how they are found and replaced, for text lines and
JSON alike.

Masking covers only the values a caller names (personal_env, --private-env). An
answer from Apple is shown as Apple sent it: a list of testers shows their emails
unless each one is named.

A named value is found:
- in any letter case;
- as typed, JSON-escaped (with or without \\uXXXX), HTML-escaped and URL-encoded;
- as a phone: when it is all digits and phone punctuation, with 7 or more digits,
  its digits with any grouping between them, and its last 10 digits alone;
- a single word (letters and digits only) only as a whole word, so "Ann" leaves
  "Annual" alone; an escape just before it (\\n, \\t, \\r, \\uXXXX, %XX)
  counts as a boundary, so "\\nAnn" is still masked;
- a phone's digits only where no other digit touches them, so "404" inside an
  id stays;
- any other value (an email, a full name) wherever it stands.

A value is matched as it is typed: a name in another order or spacing, or a phone
written with a country code the named value lacks, is not found.

Values shorter than PRIVATE_MIN are not masked at all: two letters would blank
out ordinary words. The values of `method` and `path` keys are never masked, so
a plan still shows exactly where a request goes (a path holds only ids; see
storekeeper.fences.API_PATH).
"""

from __future__ import annotations

import html
import json
import re
import urllib.parse

PRIVATE = "<private>"
PRIVATE_MIN = 3
QUERY_SAFE = "[],"  # what the client's query encoder leaves unescaped; masking matches it
PHONE = re.compile(r"[0-9\s().+-]+")
PHONE_DIGITS_MIN = 7
SEPARATORS = r"[\s().+-]*"
NEVER_MASKED = ("method", "path")


def _forms(value: str) -> set[str]:
    return {
        value,
        json.dumps(value)[1:-1],
        json.dumps(value, ensure_ascii=False)[1:-1],
        html.escape(value),
        urllib.parse.quote(value, safe=""),
        urllib.parse.quote_plus(value, safe=QUERY_SAFE),
    }


def _phone_patterns(value: str) -> list[str]:
    digits = re.sub(r"\D", "", value)
    if not PHONE.fullmatch(value) or len(digits) < PHONE_DIGITS_MIN:
        return []
    numbers = {digits, digits[-10:]} if len(digits) > 10 else {digits}
    return [r"[+(]?" + SEPARATORS.join(number) for number in numbers]


WORD = re.compile(r"[A-Za-z0-9]+")
# Before a single word: no letter or digit, unless it ends an escape.
WORD_BEFORE = r"(?:(?<![A-Za-z0-9])|(?<=\\[ntr])|(?<=%[0-9A-Fa-f]{2})|(?<=\\u[0-9A-Fa-f]{4}))"


def _either(alternatives: set[str], before: str, after: str) -> str | None:
    if not alternatives:
        return None
    # Longest first, so a value is replaced before any part of it.
    return before + "(?:" + "|".join(sorted(alternatives, key=len, reverse=True)) + ")" + after


class Masker:
    """Holds every named private value and replaces each with PRIVATE."""

    def __init__(self) -> None:
        self._words: set[str] = set()
        self._phones: set[str] = set()
        self._others: set[str] = set()
        self._regex: re.Pattern | None = None

    def add(self, *values: str | None) -> None:
        for v in values:
            if not v or len(v) < PRIVATE_MIN:
                continue
            group = self._words if WORD.fullmatch(v) else self._others
            group |= {re.escape(f) for f in _forms(v)}
            self._phones |= set(_phone_patterns(v))
        parts = [
            _either(self._others, "", ""),
            _either(self._phones, "(?<![0-9])", "(?![0-9])"),
            _either(self._words, WORD_BEFORE, "(?![A-Za-z0-9])"),
        ]
        parts = [p for p in parts if p]
        self._regex = re.compile("|".join(parts), re.IGNORECASE) if parts else None

    def text(self, line: str) -> str:
        return self._regex.sub(PRIVATE, line) if self._regex else line

    def obj(self, value, key: str | None = None):
        """A JSON-ready value with every string in it (keys too) masked, except
        the values of `method` and `path`."""
        if isinstance(value, str):
            return value if key in NEVER_MASKED else self.text(value)
        if isinstance(value, dict):
            return {self.text(str(k)): self.obj(v, str(k)) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.obj(v) for v in value]
        return value
