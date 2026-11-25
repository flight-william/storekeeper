"""Storekeeper: a safety layer over Apple's App Store Connect API.

The key stays in the macOS Keychain and is read only when a token is signed; a
client is a dry run unless it is made live; every write is checked against the
write fences; personal values are masked in all output.

    import storekeeper
    client = storekeeper.Client(live=False)
    client.get("/v1/apps", {"filter[bundleId]": "com.example.app"})
"""

from __future__ import annotations

from .client import (
    API_ROOT,
    ENV_NAMES,
    PRIVATE,
    Client,
    Credentials,
    credentials_from_env,
    env_report,
    env_status,
    make_token,
    personal_env,
    sign_token,
)
from .errors import EXIT_FOR, ASCError
from .jsonapi import EDITABLE_STATES, attr, editable_app_info, editable_versions, find_exact
from .jwt import AUDIENCE, TOKEN_LIFETIME, der_to_raw, jwt_claims, jwt_header, raw_to_der
from .key import pick_signer

__version__ = "0.1.0"

__all__ = [
    "API_ROOT",
    "AUDIENCE",
    "ASCError",
    "Client",
    "Credentials",
    "EDITABLE_STATES",
    "ENV_NAMES",
    "EXIT_FOR",
    "PRIVATE",
    "TOKEN_LIFETIME",
    "attr",
    "credentials_from_env",
    "der_to_raw",
    "editable_app_info",
    "editable_versions",
    "env_report",
    "env_status",
    "find_exact",
    "jwt_claims",
    "jwt_header",
    "make_token",
    "personal_env",
    "pick_signer",
    "raw_to_der",
    "sign_token",
]
