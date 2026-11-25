"""Release guard for an app's icon on the App Store.

Before upload, on the built app (from the archive or the export):

    storekeeper check-icon <path/to/App.app> [--icon-name NAME] [--json]

After release, on the public store page (the only mode that uses the network):

    storekeeper check-icon --store-page https://apps.apple.com/app/id<ID> [--json]

Exit 0: the icon is there (in Assets.car; or the page's share image is not Apple's
        known grey placeholder: look at it once, the pass line gives its link).
Exit 1: it is not (error code icon_missing or icon_placeholder); `fix` says what to do.
Exit 2: usage. Exit 4: the check could not run (no such app, assetutil failed,
        page not read): cannot tell, never a pass.

Why: an app whose icon ships only as Resources/AppIcon.icns, with no AppIcon set in
the asset catalog, can go live with Apple's grey placeholder as its store icon and
share image. Apps whose icon is an AppIcon set in the asset catalog render.
"""

from __future__ import annotations

import hashlib
import json
import plistlib
import subprocess
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from pathlib import Path

from .output import Outcome, Parser, failure, run, with_json

FIX = (
    "add an AppIcon set to the asset catalog and set "
    "ASSETCATALOG_COMPILER_APPICON_NAME = AppIcon on every app target; "
    "an .icns alone is not enough"
)


# --- before upload: the built app -------------------------------------------


def run_assetutil(argv: list) -> str:
    """The real runner: assetutil's JSON on stdout. Tests inject their own."""
    done = subprocess.run(argv, capture_output=True, text=True, check=False)
    if done.returncode != 0:
        raise RuntimeError(f"{' '.join(argv)} exited {done.returncode}: {done.stderr.strip()}")
    return done.stdout


def find_car(app: Path):
    """Assets.car in the Mac layout (Contents/Resources) or the iOS one (top level)."""
    for car in (app / "Contents" / "Resources" / "Assets.car", app / "Assets.car"):
        if car.is_file():
            return car
    return None


def icon_name(app: Path) -> str:
    """The icon set's name as the build recorded it. Xcode writes CFBundleIconName
    from ASSETCATALOG_COMPILER_APPICON_NAME; with that setting unset the key is
    absent and "AppIcon" is assumed."""
    for plist in (app / "Contents" / "Info.plist", app / "Info.plist"):
        if plist.is_file():
            with plist.open("rb") as f:
                name = plistlib.load(f).get("CFBundleIconName")
            if isinstance(name, str) and name:
                return name
    return "AppIcon"


def icon_entries(entries: list, name: str) -> list:
    """Entries that are an app icon: any "Icon Image" rendition, or the icon set
    itself ("MultiSized Image", or "Icon" on newer catalogs) under the app's icon
    name. Keys as real assetutil output has them (tests/fixtures/)."""
    found = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        kind = e.get("AssetType")
        if kind == "Icon Image" or (kind in ("MultiSized Image", "Icon") and e.get("Name") == name):
            found.append(e)
    return found


def check_app(app: Path, name, run_tool) -> Outcome:
    result = {"mode": "app", "app": str(app), "assets_car": None, "icon_name": None}
    result["icon_found"] = False
    if not app.is_dir():
        return failure("cannot_tell", f"{app}: not found", "give the built .app", result)
    car = find_car(app)
    if car is None:
        return failure("icon_missing", f"{app}: no Assets.car, so no app icon", FIX, result)
    result["assets_car"] = str(car)
    try:
        entries = json.loads(run_tool(["xcrun", "assetutil", "--info", str(car)]))
    except (OSError, RuntimeError, ValueError) as e:
        fix = "run it on a Mac with Xcode's command line tools"
        return failure("cannot_tell", f"{car}: could not read it: {e}", fix, result)
    if not isinstance(entries, list):
        fix = "check the Xcode command line tools"
        return failure("cannot_tell", f"{car}: assetutil did not answer a list", fix, result)
    name = name or icon_name(app)
    result["icon_name"] = name
    if not icon_entries(entries, name):
        message = f"{app}: no app icon in {car.name} (looked for an icon image or the {name} set)"
        return failure("icon_missing", message, FIX, result)
    result["icon_found"] = True
    return Outcome(result=result, lines=[f"{app}: ok, {car.name} holds the {name} icon"])


# --- after release: the public store page -----------------------------------

# Apple's grey placeholder grid as the store's share image (og:image, 1200x630),
# by SHA-256 and size; the image itself is not shipped. The URL cannot tell:
# every app's icon URL ends in ".../Placeholder.mill/1200x630wa.jpg", real icons
# included. A match proves the placeholder; no match is only "not this known
# placeholder", so the pass line says to look. Only https on apps.apple.com (the
# page) and *.mzstatic.com (its images) is fetched, redirects included.
PLACEHOLDERS = (("93d900076422daeda4abcf5d436751774a65fac287a2ee7fc874cb97d35d2831", 24948),)


def is_placeholder(data: bytes) -> bool:
    return (hashlib.sha256(data).hexdigest(), len(data)) in PLACEHOLDERS


def _allowed(url: str) -> bool:
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or ""
    return parts.scheme == "https" and (host == "apps.apple.com" or host.endswith(".mzstatic.com"))


class _AppleHostsOnly(urllib.request.HTTPRedirectHandler):
    """A redirect is followed only to the same two hosts, and only over https."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _allowed(newurl):
            raise ValueError(f"a redirect to {urllib.parse.urlsplit(newurl).netloc} was refused")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_AppleHostsOnly)


def fetch_url(url: str) -> bytes:
    """The real fetcher: one GET of a public store page or its image. Tests inject their own."""
    if not _allowed(url):
        raise ValueError("only https on apps.apple.com (page) and mzstatic.com (image)")
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Macintosh) storekeeper"})
    with _OPENER.open(req, timeout=30) as resp:
        return resp.read(8_000_000)


class _OgImage(HTMLParser):
    def __init__(self):
        super().__init__()
        self.url = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "meta" and self.url is None and a.get("property") == "og:image":
            self.url = a.get("content") or None


def og_image(html: str):
    parser = _OgImage()
    parser.feed(html)
    return parser.url


def check_store_page(url: str, fetch) -> Outcome:
    result = {"mode": "store_page", "url": url, "share_image": None, "placeholder": None}
    retry = "check the URL and the network, then run it again"
    try:
        html = fetch(url).decode("utf-8", "replace")
    except (OSError, ValueError) as e:
        return failure("cannot_tell", f"{url}: could not read the page: {e}", retry, result)
    image = og_image(html)
    if not image:
        message = f"{url}: no og:image on the page, so the icon cannot be judged"
        return failure("cannot_tell", message, "open the page and look at the icon", result)
    result["share_image"] = image
    try:
        data = fetch(image)
    except (OSError, ValueError) as e:
        return failure(
            "cannot_tell", f"{image}: could not read the share image: {e}", retry, result
        )
    result["placeholder"] = is_placeholder(data)
    if result["placeholder"]:
        message = f"{url}: the store shows Apple's grey placeholder, not the icon: {image}"
        return failure("icon_placeholder", message, FIX + "; then ship a new build", result)
    line = f"{url}: ok, not Apple's known placeholder; look at it once: {image}"
    return Outcome(result=result, lines=[line])


def parser() -> Parser:
    p = Parser(
        prog="storekeeper check-icon",
        description="Fail when an app's icon is missing from its build or its store page.",
    )
    p.add_argument("app", type=Path, nargs="?", help="the built .app (from an archive or export)")
    p.add_argument(
        "--icon-name", help="the icon set's name (default: CFBundleIconName, else AppIcon)"
    )
    p.add_argument("--store-page", metavar="URL", help="after release: check the public store page")
    return with_json(p)


def main(argv=None, run_tool=run_assetutil, fetch=fetch_url) -> int:
    p = parser()

    def body(args) -> Outcome:
        if (args.app is None) == (args.store_page is None):
            fix = "run `storekeeper check-icon --help`"
            return failure("usage", "give either the built .app or --store-page URL", fix)
        if args.store_page:
            return check_store_page(args.store_page, fetch)
        return check_app(args.app, args.icon_name, run_tool)

    return run("check-icon", p, list(argv or []), body)
