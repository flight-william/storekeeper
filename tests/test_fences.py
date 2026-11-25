"""Tests for the write fences: the default lists, narrowing them, and the explicit
opt-in that is the only way to widen them.

python3 -I tests/test_fences.py
"""

from __future__ import annotations

import importlib
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent / "src"), str(HERE), str(HERE.parent / "testkit")]
storekeeper = importlib.import_module("storekeeper")
fences = importlib.import_module("storekeeper.fences")

ATTRS = {"data": {"attributes": {"contentRightsDeclaration": "DOES_NOT_USE_THIRD_PARTY_CONTENT"}}}


def dry(f=None):
    lines: list[str] = []
    if f is None:
        return storekeeper.Client(False, out=lines.append), lines
    return storekeeper.Client(False, out=lines.append, fences=f), lines


class DefaultFenceTests(unittest.TestCase):
    def test_the_default_is_the_full_list_and_every_client_starts_on_it(self):
        d = fences.DEFAULT_FENCES
        self.assertEqual(d.post, fences.POSTABLE)
        self.assertEqual(d.post_links, fences.POSTABLE_LINKS)
        self.assertEqual(d.patch, fences.PATCHABLE)
        self.assertEqual(d.patch_records, fences.PATCHABLE_RECORDS)
        self.assertEqual(dict(d.patch_only), fences.PATCH_ONLY)
        self.assertEqual(d.delete, fences.DELETABLE)
        self.assertFalse(d.widened)
        self.assertIs(dry()[0].fences, d)

    def test_the_default_allows_its_paths_and_refuses_the_rest_unsent(self):
        c, lines = dry()
        c.post("/v1/betaGroups", {"data": {}})
        c.post("/v1/betaGroups/G1/relationships/builds", {"data": []})
        c.patch("/v1/apps/123", ATTRS)
        c.patch("/v1/appStoreVersions/9", {"data": {}})
        c.delete("/v1/appScreenshotSets/5")
        refused = [
            lambda: c.post("/v1/apps", {}),
            lambda: c.post("/v1/betaGroups/G1/relationships/apps", {}),
            lambda: c.patch("/v1/apps/123", {"data": {"attributes": {"name": "x"}}}),
            lambda: c.patch("/v1/apps/123/appInfos", ATTRS),
            lambda: c.patch("/v1/users/1", {}),
            lambda: c.delete("/v1/apps/1"),
            lambda: c.delete("/v1/appScreenshotSets/../apps/1"),
            lambda: c.post("/v1/betaGroups?x=1", {}),
        ]
        sent = len(lines)
        for call in refused:
            with self.subTest(call=call), self.assertRaises(storekeeper.ASCError) as err:
                call()
            self.assertEqual((err.exception.code, err.exception.exit_code), ("write_refused", 1))
            self.assertTrue(err.exception.fix)
        self.assertEqual(len(lines), sent, "a refused write reached the dry-run log")


class NarrowTests(unittest.TestCase):
    def test_a_narrowed_post_list_refuses_a_default_path_it_left_out(self):
        c, _ = dry(fences.DEFAULT_FENCES.narrow(post=["/v1/betaGroups"]))
        c.post("/v1/betaGroups", {"data": {}})
        with self.assertRaises(storekeeper.ASCError) as err:
            c.post("/v1/profiles", {"data": {}})
        self.assertEqual(err.exception.code, "write_refused")

    def test_each_list_narrows_on_its_own_and_the_others_stay(self):
        f = fences.DEFAULT_FENCES.narrow(delete=[], post_links=[])
        self.assertEqual((f.delete, f.post_links), ((), ()))
        self.assertEqual(f.post, fences.POSTABLE)
        c, _ = dry(f)
        with self.assertRaises(storekeeper.ASCError):
            c.delete("/v1/appScreenshotSets/5")
        with self.assertRaises(storekeeper.ASCError):
            c.post("/v1/betaGroups/G1/relationships/builds", {})

    def test_narrowing_to_anything_outside_the_current_list_is_refused(self):
        tries = [
            {"post": ["/v1/apps"]},
            {"patch": ["/v1/users/"]},
            {"patch_records": ["/v1/bundleIds/"]},
            {"delete": ["/v1/apps/"]},
            {"post_links": [("/v1/apps/", "/relationships/x")]},
            {"patch_only": {"/v1/apps/": ("name",)}},
        ]
        for kw in tries:
            with self.subTest(kw=kw), self.assertRaises(storekeeper.ASCError) as err:
                fences.DEFAULT_FENCES.narrow(**kw)
            self.assertEqual(err.exception.code, "usage")
            self.assertIn("widen", err.exception.fix)

    def test_a_dropped_record_takes_its_attribute_rule_with_it(self):
        f = fences.DEFAULT_FENCES.narrow(patch_records=["/v1/apps/"])
        self.assertEqual(f.patch_records, ("/v1/apps/",))
        self.assertEqual(dict(f.patch_only), {"/v1/apps/": ("contentRightsDeclaration",)})

    def test_attribute_rules_narrow_and_a_kept_record_may_gain_one(self):
        f = fences.DEFAULT_FENCES.narrow(
            patch_only={
                "/v1/accessibilityDeclarations/": ("publish",),
                "/v1/appInfos/": ("primaryLocale",),  # had no rule: a rule is narrower
            }
        )
        c, _ = dry(f)
        c.patch("/v1/accessibilityDeclarations/1", {"data": {"attributes": {"publish": True}}})
        with self.assertRaises(storekeeper.ASCError):
            body = {"data": {"attributes": {"supportsCaptions": True}}}
            c.patch("/v1/accessibilityDeclarations/1", body)
        with self.assertRaises(storekeeper.ASCError):
            c.patch("/v1/appInfos/1", {"data": {"relationships": {"x": {}}}})
        # The rules it did not name stay as they were.
        self.assertEqual(f.patch_only["/v1/apps/"], ("contentRightsDeclaration",))

    def test_a_rule_for_a_record_not_kept_is_refused(self):
        with self.assertRaises(storekeeper.ASCError):
            fences.DEFAULT_FENCES.narrow(patch_records=[], patch_only={"/v1/apps/": ()})

    def test_narrowing_leaves_the_default_alone(self):
        fences.DEFAULT_FENCES.narrow(post=[], patch=[], patch_records=[], delete=[])
        self.assertEqual(fences.DEFAULT_FENCES.post, fences.POSTABLE)
        self.assertEqual(dict(fences.DEFAULT_FENCES.patch_only), fences.PATCH_ONLY)


class WidenTests(unittest.TestCase):
    def test_widening_without_the_opt_in_is_refused(self):
        with self.assertRaises(storekeeper.ASCError) as err:
            fences.DEFAULT_FENCES.widen(post=["/v1/apps"])
        self.assertEqual(err.exception.code, "usage")
        self.assertIn("i_accept_wider_writes=True", err.exception.fix)

    def test_widening_with_the_opt_in_allows_the_new_path_and_is_marked(self):
        f = fences.DEFAULT_FENCES.widen(post=["/v1/apps"], i_accept_wider_writes=True)
        self.assertTrue(f.widened)
        self.assertIn("/v1/apps", f.post)
        self.assertFalse(fences.DEFAULT_FENCES.widened)
        c, lines = dry(f)
        c.post("/v1/apps", {"data": {}})
        self.assertIn("  DRY-RUN POST /v1/apps", lines)
        # Narrowing a widened set keeps the mark: it was widened once.
        self.assertTrue(f.narrow(post=["/v1/apps"]).widened)

    def test_the_fences_describe_themselves_for_json(self):
        d = fences.DEFAULT_FENCES.as_dict()
        self.assertEqual(
            sorted(d),
            ["delete", "patch", "patch_only", "patch_records", "post", "post_links", "widened"],
        )
        self.assertEqual(d["post"], list(fences.POSTABLE))


if __name__ == "__main__":
    unittest.main()
