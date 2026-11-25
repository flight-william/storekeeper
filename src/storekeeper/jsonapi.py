"""Small readers for App Store Connect's JSON:API answers: an attribute, an exact
match, which app info and versions can still be edited, and Apple's error text."""

from __future__ import annotations

import json
import urllib.error

# App Store version states in which the version page can still be edited.
EDITABLE_STATES = (
    "PREPARE_FOR_SUBMISSION",
    "DEVELOPER_REJECTED",
    "REJECTED",
    "METADATA_REJECTED",
    "INVALID_BINARY",
)


def attr(item: dict, name: str):
    """A JSON:API resource's attribute."""
    return (item.get("attributes") or {}).get(name)


def find_exact(items: list[dict], name: str, value: str) -> dict | None:
    return next((i for i in items if attr(i, name) == value), None)


def editable_app_info(infos: list[dict]) -> dict | None:
    """The app info a new version edits: not the live one, else the only one."""
    editable = [i for i in infos if attr(i, "state") != "READY_FOR_DISTRIBUTION"] or infos
    return editable[0] if editable else None


def editable_versions(versions: list[dict]) -> list[dict]:
    return [v for v in versions if attr(v, "appStoreState") in EDITABLE_STATES]


def describe_error(method: str, path: str, err: urllib.error.HTTPError) -> str:
    try:
        payload = json.loads(err.read() or b"{}")
        detail = "; ".join(
            f"{e.get('code', '')}: {e.get('title', '')} {e.get('detail', '')}".strip()
            for e in payload.get("errors", [])
        )
    except (ValueError, OSError):
        detail = ""
    return f"{method} {path} -> HTTP {err.code}" + (f" ({detail})" if detail else "")
