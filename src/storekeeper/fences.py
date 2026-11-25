"""Where the client may write: the allow-lists every POST, PATCH and DELETE is
checked against before it is sent, and the path checks that apply them.

The lists are the default: the App Store Connect resources a release workflow
writes to (listing text, screenshots and previews, review details and
submission, TestFlight groups and testers, in-app purchases, Game Center).
A caller narrows them to what its own steps write; widening is an explicit,
documented opt-in."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from types import MappingProxyType

from .errors import ASCError

# The only resources a PATCH may touch: listing text, the version record (its
# fields and its build relationship), screenshot, preview and review-attachment
# commits, screenshot and preview order, the review details and a review submission.
PATCHABLE = (
    "/v1/appInfoLocalizations/",
    "/v1/appStoreVersionLocalizations/",
    "/v1/appStoreVersions/",
    "/v1/appScreenshots/",
    "/v1/appScreenshotSets/",
    "/v1/appPreviews/",
    "/v1/appPreviewSets/",
    "/v1/appStoreReviewDetails/",
    "/v1/appStoreReviewAttachments/",
    "/v1/reviewSubmissions/",
)
# Records PATCHed as a whole and never below: the path is the prefix plus one id
# (the app's content rights, the app info's categories, the age-rating answers,
# Game Center on a version, the purchase review screenshot's commit, an
# accessibility declaration's flags and publish, an achievement image's commit).
PATCHABLE_RECORDS = (
    "/v1/apps/",
    "/v1/appInfos/",
    "/v1/ageRatingDeclarations/",
    "/v1/gameCenterAppVersions/",
    "/v1/inAppPurchaseAppStoreReviewScreenshots/",
    "/v1/accessibilityDeclarations/",
    "/v1/betaBuildLocalizations/",
    "/v1/appCustomProductPageLocalizations/",
    "/v1/gameCenterAchievementImages/",
)
# Records whose PATCH may carry only these attributes (and no relationship):
# the app record is touched for its content rights, nothing else; an accessibility
# declaration for its nine supports* flags and publish (Apple's update attributes);
# a build's beta localization for its "what to test" text.
PATCH_ONLY = {
    "/v1/apps/": ("contentRightsDeclaration",),
    "/v1/accessibilityDeclarations/": (
        "publish",
        "supportsAudioDescriptions",
        "supportsCaptions",
        "supportsDarkInterface",
        "supportsDifferentiateWithoutColorAlone",
        "supportsLargerText",
        "supportsReducedMotion",
        "supportsSufficientContrast",
        "supportsVoiceControl",
        "supportsVoiceover",
    ),
    "/v1/betaBuildLocalizations/": ("whatsNew",),
    # A custom product page localization: its promotional text, nothing else.
    "/v1/appCustomProductPageLocalizations/": ("promotionalText",),
    # An achievement image's commit: Apple's update request has `uploaded` only
    # (GameCenterAchievementImageUpdateRequest.Data.Attributes, no checksum).
    "/v1/gameCenterAchievementImages/": ("uploaded",),
}
# The only resources a DELETE may touch: a screenshot or preview set (re-made from files).
DELETABLE = ("/v1/appScreenshotSets/", "/v1/appPreviewSets/")
# The only paths a POST may create on (exact match): the ones the steps use.
POSTABLE = (
    "/v1/bundleIdCapabilities",
    "/v1/profiles",
    "/v2/inAppPurchases",
    "/v1/inAppPurchaseLocalizations",
    "/v1/gameCenterDetails",
    "/v1/gameCenterLeaderboards",
    "/v1/gameCenterLeaderboardLocalizations",
    "/v1/gameCenterAchievements",
    "/v1/gameCenterAchievementLocalizations",
    "/v1/betaGroups",
    "/v1/appInfoLocalizations",
    "/v1/appStoreVersionLocalizations",
    "/v1/appScreenshotSets",
    "/v1/appScreenshots",
    "/v1/appPreviewSets",
    "/v1/appPreviews",
    "/v1/appStoreReviewDetails",
    "/v1/appStoreReviewAttachments",
    "/v1/reviewSubmissions",
    "/v1/reviewSubmissionItems",
    "/v1/gameCenterAppVersions",
    "/v1/inAppPurchasePriceSchedules",
    "/v1/inAppPurchaseAvailabilities",
    "/v1/inAppPurchaseAppStoreReviewScreenshots",
    "/v1/betaTesters",
    "/v1/accessibilityDeclarations",
    "/v1/betaAppReviewSubmissions",
    "/v1/betaBuildLocalizations",
    "/v1/appCustomProductPages",
    "/v1/appCustomProductPageLocalizations",
    "/v1/gameCenterAchievementImages",
    "/v1/gameCenterAchievementReleases",
)
# Relationship POSTs, as (prefix, suffix) around exactly one id: a known tester
# added to the internal group, a build added to a beta group.
POSTABLE_LINKS = (
    ("/v1/betaGroups/", "/relationships/betaTesters"),
    ("/v1/betaGroups/", "/relationships/builds"),
)


REFUSED_FIX = (
    "do not send it another way: this write is outside the write fences (README, Write "
    "fences), and widening them is the owner's decision, in code"
)


# An API path: /v<N>/ then one or more segments of letters, digits, _ and -. No
# '.', '..', '%', ';', '\\', empty segment, query or fragment can pass: a server
# that decodes %2e%2e before routing never sees a path this did not judge.
API_PATH = re.compile(r"/v[0-9]+(?:/[A-Za-z0-9_-]+)+")
ID = re.compile(r"[A-Za-z0-9_-]+")


def shown(path) -> str:
    """A path as it may appear in one line of a message."""
    return str(path).encode("unicode_escape").decode("ascii")


def _one_id(path: str, prefix: str, suffix: str = "") -> bool:
    """True when path is prefix + one id (letters, digits, _ and -) + suffix."""
    if not (path.startswith(prefix) and path.endswith(suffix)):
        return False
    return bool(ID.fullmatch(path[len(prefix) : len(path) - len(suffix)]))


def _refused(message: str) -> ASCError:
    return ASCError(message, code="write_refused", fix=REFUSED_FIX)


def _plain_path(method: str, path: str) -> None:
    """Refuse a write path that is not a plain API path (API_PATH)."""
    if not isinstance(path, str) or not API_PATH.fullmatch(path):
        raise _refused(
            f"{method} {shown(path)} refused: a write path is /v<N>/ and segments of "
            "letters, digits, _ and - only"
        )


def _subset(name: str, given, current) -> tuple:
    given = tuple(tuple(g) if isinstance(g, list) else g for g in given)
    extra = [g for g in given if g not in current]
    if extra:
        raise ASCError(
            f"narrowing {name} to {extra} would add to it",
            code="usage",
            fix="narrow only to entries the fences already hold; to widen, use "
            "Fences.widen(..., i_accept_wider_writes=True)",
        )
    return given


@dataclass(frozen=True)
class Fences:
    """The allow-lists one client checks its writes against. DEFAULT_FENCES is the
    full list; narrow() returns a subset; widen() is the only way past the default,
    and needs i_accept_wider_writes=True."""

    post: tuple = POSTABLE
    post_links: tuple = POSTABLE_LINKS
    patch: tuple = PATCHABLE
    patch_records: tuple = PATCHABLE_RECORDS
    patch_only: Mapping = field(default_factory=lambda: MappingProxyType(dict(PATCH_ONLY)))
    delete: tuple = DELETABLE
    widened: bool = False

    def narrow(
        self, *, post=None, post_links=None, patch=None, patch_records=None,
        patch_only=None, delete=None,
    ) -> Fences:  # fmt: skip
        """A copy holding only the given entries of each list named; every entry must
        already be here. A record left out takes its attribute rule with it; a rule
        given replaces the record's rule with a subset of it (or adds one)."""
        changes = {}
        for name, given in (("post", post), ("post_links", post_links), ("patch", patch),
                            ("patch_records", patch_records), ("delete", delete)):  # fmt: skip
            if given is not None:
                changes[name] = _subset(name, given, getattr(self, name))
        records = changes.get("patch_records", self.patch_records)
        rules = {k: v for k, v in self.patch_only.items() if k in records}
        for record, attrs in (patch_only or {}).items():
            if record not in records:
                _subset("patch_only", [record], records)
            rules[record] = _subset(f"patch_only[{record}]", attrs, rules.get(record, attrs))
        changes["patch_only"] = MappingProxyType(rules)
        return replace(self, **changes)

    def widen(
        self, *, post=(), post_links=(), patch=(), patch_records=(), patch_only=None,
        delete=(), i_accept_wider_writes: bool = False,
    ) -> Fences:  # fmt: skip
        """A copy with the given entries added. Refused unless the caller says
        i_accept_wider_writes=True: a wider fence is a decision, never a default."""
        if i_accept_wider_writes is not True:
            raise ASCError(
                "widening the write fences needs an explicit opt-in",
                code="usage",
                fix="pass i_accept_wider_writes=True, and say why in your own code",
            )
        rules = dict(self.patch_only)
        rules.update({k: tuple(v) for k, v in (patch_only or {}).items()})
        return replace(
            self,
            post=self.post + tuple(p for p in post if p not in self.post),
            post_links=self.post_links + tuple(tuple(x) for x in post_links),
            patch=self.patch + tuple(patch),
            patch_records=self.patch_records + tuple(patch_records),
            patch_only=MappingProxyType(rules),
            delete=self.delete + tuple(delete),
            widened=True,
        )

    def as_dict(self) -> dict:
        return {
            "post": list(self.post),
            "post_links": [list(x) for x in self.post_links],
            "patch": list(self.patch),
            "patch_records": list(self.patch_records),
            "patch_only": {k: list(v) for k, v in self.patch_only.items()},
            "delete": list(self.delete),
            "widened": self.widened,
        }

    def check_post(self, path: str) -> None:
        _plain_path("POST", path)
        if path not in self.post and not any(
            _one_id(path, prefix, suffix) for prefix, suffix in self.post_links
        ):
            raise _refused(f"POST {path} refused: not one of the paths this client creates on")

    def check_patch(self, path: str, body: dict | None) -> None:
        _plain_path("PATCH", path)
        if not (self.patch and path.startswith(self.patch)) and not any(
            _one_id(path, prefix) for prefix in self.patch_records
        ):
            raise _refused(f"PATCH {path} refused: not a resource this client may change")
        for prefix, allowed in self.patch_only.items():
            if _one_id(path, prefix) and not _only_attributes(body, allowed):
                raise _refused(
                    f"PATCH {path} refused: only {', '.join(allowed)} may be changed there"
                )

    def check_delete(self, path: str) -> None:
        _plain_path("DELETE", path)
        if not any(_one_id(path, prefix) for prefix in self.delete):
            raise _refused(f"DELETE {path} refused: not a resource this client may delete")


def _only_attributes(body, allowed) -> bool:
    """A body that changes only `allowed` attributes: {"data": {..., "attributes":
    {...}}} and nothing else (no relationships, no top-level included)."""
    if not isinstance(body, dict) or set(body) != {"data"} or not isinstance(body["data"], dict):
        return False
    data = body["data"]
    keys = data.get("attributes")
    if data.get("relationships") or not isinstance(keys, dict) or not keys:
        return False
    return not set(keys) - set(allowed)


def markdown(f: Fences) -> str:
    """The fences as README lines (the README's list is this, checked by a test)."""
    rules = {k: ", ".join(f"`{a}`" for a in v) for k, v in f.patch_only.items()}
    lines = ["- POST to exactly: " + ", ".join(f"`{p}`" for p in f.post)]
    lines.append("- POST a relationship: " + ", ".join(f"`{p}<id>{s}`" for p, s in f.post_links))
    lines.append("- PATCH at or below: " + ", ".join(f"`{p}<id>`" for p in f.patch))
    lines.append(
        "- PATCH one record: "
        + ", ".join(
            f"`{p}<id>`" + (f" (only {rules[p]})" if p in rules else "") for p in f.patch_records
        )
    )
    lines.append("- DELETE one record: " + ", ".join(f"`{p}<id>`" for p in f.delete))
    return "\n".join(lines) + "\n"


DEFAULT_FENCES = Fences()
