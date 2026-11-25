"""Tests for the app icon release guard (storekeeper check-icon).

python3 -I tests/test_icon.py

The fixtures in tests/fixtures/ are synthetic `xcrun assetutil --info` output
(invented names, sizes and colours) in the shape real output has: a Mac app with
no icon in its catalog, and a Mac and an iPhone app with an AppIcon set. The
placeholder image is synthetic too: the guard knows Apple's only by hash and
size. No test runs assetutil or opens a socket: the runner and the fetcher are
injected.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib
import io
import json
import plistlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent / "src"), str(HERE), str(HERE.parent / "testkit")]
icon = importlib.import_module("storekeeper.icon")

FIXTURES = HERE / "fixtures"
MAC_NO_ICON = FIXTURES / "assetutil-mac-no-icon.json"
MAC_ICON = FIXTURES / "assetutil-mac-with-icon.json"
IPHONE_ICON = FIXTURES / "assetutil-iphone-with-icon.json"


def make_app(root: Path, layout: str, plist: dict) -> Path:
    """A built .app's skeleton: an Info.plist and an (empty) Assets.car."""
    app = root / "Test.app"
    base = app / "Contents" if layout == "mac" else app
    resources = base / "Resources" if layout == "mac" else app
    resources.mkdir(parents=True)
    (resources / "Assets.car").write_bytes(b"")
    (base / "Info.plist").write_bytes(plistlib.dumps(plist))
    return app


def runner_for(fixture, calls: list):
    """A fake assetutil: a fixture file's text, or a list of entries as JSON."""
    text = fixture.read_text() if isinstance(fixture, Path) else json.dumps(fixture)

    def run(argv):
        calls.append(argv)
        return text

    return run


def catalog_without_icon_images(rename: str = "AppIcon") -> list:
    """The Mac catalog with its 'Icon Image' renditions removed, so only the
    named 'MultiSized Image' entry is left to say there is an icon."""
    entries = json.loads(MAC_ICON.read_text())
    kept = [e for e in entries if e.get("AssetType") != "Icon Image"]
    for e in kept:
        if e.get("Name") == "AppIcon":
            e["Name"] = rename
    return kept


class AppIconTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.calls: list = []

    def tearDown(self):
        self._tmp.cleanup()

    def check(self, app: Path, fixture: Path, *extra: str):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = icon.main([str(app), *extra], run_tool=runner_for(fixture, self.calls))
        return code, out.getvalue()

    def test_1_a_mac_app_with_no_icon_in_its_catalog_fails_with_a_fix_line(self):
        app = make_app(self.dir, "mac", {"CFBundleIconFile": "AppIcon"})
        code, out = self.check(app, MAC_NO_ICON)
        self.assertEqual(code, 1, out)
        self.assertIn("no app icon", out)
        self.assertIn("ASSETCATALOG_COMPILER_APPICON_NAME", out)

    def test_2_a_mac_app_with_an_appicon_set_passes(self):
        app = make_app(
            self.dir, "mac", {"CFBundleIconFile": "AppIcon", "CFBundleIconName": "AppIcon"}
        )
        code, out = self.check(app, MAC_ICON)
        self.assertEqual(code, 0, out)
        car = str(app / "Contents" / "Resources" / "Assets.car")
        self.assertEqual(self.calls, [["xcrun", "assetutil", "--info", car]])

    def test_3_the_iphone_layout_reads_assets_car_at_the_top_of_the_app(self):
        app = make_app(self.dir, "ios", {"CFBundleIconName": "AppIcon"})
        code, out = self.check(app, IPHONE_ICON)
        self.assertEqual(code, 0, out)
        self.assertEqual(self.calls, [["xcrun", "assetutil", "--info", str(app / "Assets.car")]])

    def test_4_a_multisized_image_named_after_cfbundleiconname_counts(self):
        app = make_app(self.dir, "mac", {"CFBundleIconName": "MacIcon"})
        code, out = self.check(app, catalog_without_icon_images("MacIcon"))
        self.assertEqual(code, 0, out)

    def test_5_a_multisized_image_under_another_name_does_not_count(self):
        app = make_app(self.dir, "mac", {"CFBundleIconName": "AppIcon"})
        code, out = self.check(app, catalog_without_icon_images("Logo"))
        self.assertEqual(code, 1, out)
        self.assertIn("AppIcon", out)

    def test_6_icon_name_flag_overrides_the_info_plist(self):
        app = make_app(self.dir, "mac", {})
        code, out = self.check(app, catalog_without_icon_images("Brand"), "--icon-name", "Brand")
        self.assertEqual(code, 0, out)

    def test_7_an_app_with_no_assets_car_fails_with_the_fix_line(self):
        app = make_app(self.dir, "mac", {"CFBundleIconFile": "AppIcon"})
        (app / "Contents" / "Resources" / "Assets.car").unlink()
        code, out = self.check(app, MAC_ICON)
        self.assertEqual(code, 1, out)
        self.assertIn("ASSETCATALOG_COMPILER_APPICON_NAME", out)
        self.assertEqual(self.calls, [])

    def test_8_a_path_that_is_not_an_app_cannot_be_checked(self):
        code, out = self.check(self.dir / "Missing.app", MAC_ICON)
        self.assertEqual(code, 4, out)
        self.assertIn("not found", out)

    def test_9_assetutil_failing_is_reported_not_passed(self):
        app = make_app(self.dir, "mac", {})

        def broken(argv):
            raise RuntimeError("xcrun assetutil --info … exited 1: bad car")

        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = icon.main([str(app)], run_tool=broken)
        self.assertEqual(code, 4, out.getvalue())
        self.assertIn("bad car", out.getvalue())

    def test_10_output_that_is_not_json_is_reported_not_passed(self):
        app = make_app(self.dir, "mac", {})
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = icon.main([str(app)], run_tool=lambda argv: "not json")
        self.assertEqual(code, 4, out.getvalue())


# The store page's share image (og:image). Every app's icon URL ends in
# ".../Placeholder.mill/1200x630wa.jpg", real icons included, so the URL says
# nothing; only the image does. GREY_GRID stands in for Apple's placeholder: the
# tests put its hash and size in icon.PLACEHOLDERS.
STORE_URL = "https://apps.apple.com/app/id0000000000"
PLACEHOLDER_IMAGE = (
    "https://is1-ssl.mzstatic.com/image/thumb/Example/v4/00/00/00/"
    "placeholder-example/Placeholder.mill/1200x630wa.jpg"
)
ARTWORK_IMAGE = (
    "https://is1-ssl.mzstatic.com/image/thumb/Example/v4/11/11/11/"
    "artwork-example/Placeholder.mill/1200x630wa.jpg"
)
GREY_GRID = b"\xff\xd8 a synthetic grey grid, 1200x630 \xff\xd9"
KNOWN = ((hashlib.sha256(GREY_GRID).hexdigest(), len(GREY_GRID)),)


def page(og_image) -> bytes:
    meta = f'<meta property="og:image" content="{og_image}">' if og_image else ""
    head = f'<meta property="og:title" content="Example App">{meta}'
    return f"<!DOCTYPE html><html><head>{head}</head></html>".encode()


class StorePageTests(unittest.TestCase):
    def setUp(self):
        known = mock.patch.object(icon, "PLACEHOLDERS", KNOWN)
        known.start()
        self.addCleanup(known.stop)

    def check(self, answers: dict):
        """answers: URL -> the bytes served, or an exception to raise."""
        self.fetched: list = []

        def fetch(url):
            self.fetched.append(url)
            answer = answers[url]
            if isinstance(answer, Exception):
                raise answer
            return answer

        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = icon.main(["--store-page", STORE_URL], fetch=fetch)
        return code, out.getvalue()

    def test_11_a_page_showing_the_grey_grid_fails(self):
        code, out = self.check({STORE_URL: page(PLACEHOLDER_IMAGE), PLACEHOLDER_IMAGE: GREY_GRID})
        self.assertEqual(code, 1, out)
        self.assertIn("placeholder", out)
        self.assertIn(PLACEHOLDER_IMAGE, out)
        self.assertEqual(self.fetched, [STORE_URL, PLACEHOLDER_IMAGE])

    def test_12_a_page_with_placeholder_mill_in_its_url_but_real_artwork_passes(self):
        code, out = self.check(
            {STORE_URL: page(ARTWORK_IMAGE), ARTWORK_IMAGE: b"\xff\xd8 real artwork"}
        )
        self.assertEqual(code, 0, out)
        self.assertIn(ARTWORK_IMAGE, out)

    def test_13_a_page_with_no_share_image_cannot_be_judged(self):
        code, out = self.check({STORE_URL: page(None)})
        self.assertEqual(code, 4, out)
        self.assertIn("og:image", out)

    def test_14_a_failed_page_fetch_is_reported_not_passed(self):
        code, out = self.check({STORE_URL: OSError("timed out")})
        self.assertEqual(code, 4, out)
        self.assertIn("timed out", out)

    def test_15_a_failed_image_fetch_is_reported_not_passed(self):
        code, out = self.check({STORE_URL: page(ARTWORK_IMAGE), ARTWORK_IMAGE: OSError("HTTP 404")})
        self.assertEqual(code, 4, out)
        self.assertIn("HTTP 404", out)


if __name__ == "__main__":
    unittest.main()
