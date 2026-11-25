"""Tests for `storekeeper with-key`, the one wrapper that hands Apple's tools a key
file. Throwaway key and keychain only (test_key helpers), the keychain in the fake
secret store (STOREKEEPER_REAL_KEYCHAIN=1: a real throwaway one, keychain_stores.py).

python3 -I tests/test_with_key.py
"""

from __future__ import annotations

import importlib
import json
import os
import select
import signal
import subprocess
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path[:0] = [str(ROOT / "src"), str(HERE), str(ROOT / "testkit")]
# By name: these load from the folders the line above puts on sys.path (-I leaves them off).
helpers = importlib.import_module("test_key")
OPENSSLS, TempCase, asc_key = helpers.OPENSSLS, helpers.TempCase, helpers.asc_key
body_line, make_ec_key, store_for = helpers.body_line, helpers.make_ec_key, helpers.store_for

WRAPPER = ROOT / "src" / "storekeeper" / "with-key.sh"
RUN = ROOT / "src" / "storekeeper" / "_run.py"

# The child stands in for xcodebuild/altool: it records what it was given.
CHILD = """#!/bin/bash
key="$1"
echo "arg=$key" > "$REPORT"
stat -f 'dir=%Lp' "$(dirname "$key")" >> "$REPORT"
stat -f 'file=%Lp' "$key" >> "$REPORT"
head -1 "$key" >> "$REPORT"
echo "second=$2" >> "$REPORT"
if [ -n "$HANG" ]; then trap 'kill $!; exit 1' TERM; echo started; sleep 30 & wait; fi
exit 7
"""


def report(path: Path) -> dict:
    return dict(line.split("=", 1) for line in path.read_text().splitlines() if "=" in line)


def said_started(stream) -> bool:
    """Read lines (each within 30 seconds) until the command's `started`."""
    for _ in range(20):
        ready, _, _ = select.select([stream], [], [], 30)
        line = stream.readline() if ready else b""
        if not line:
            return False
        if line == b"started\n":
            return True
    return False


def started(proc: subprocess.Popen) -> bool:
    """Wait for the command's own word that it runs (`started` on its stdout),
    not for the clock; 30 seconds of silence is a hang."""
    ready, _, _ = select.select([proc.stdout], [], [], 30)
    return bool(ready) and proc.stdout.readline() == b"started\n"


class KeyCase(TempCase):
    """A throwaway key in a fake keychain, a child that reports, a temp folder."""

    def setUp(self):
        super().setUp()
        self.pem, _ = make_ec_key(self.dir)
        self.store = store_for(self, self.dir)
        self.kc = self.store.make_keychain()
        self.store.store_item(self.kc, "TESTKEY001", asc_key.SERVICE, body_line(self.pem))
        self.child = self.dir / "child"
        self.child.write_text(CHILD)
        self.child.chmod(0o755)
        self.report = self.dir / "report"
        self.tmp = self.dir / "tmp"
        self.tmp.mkdir()
        self.env = {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": str(self.dir),
            "TMPDIR": str(self.tmp),
            "ASC_KEY_ID": "TESTKEY001",
            "STOREKEEPER_KEYCHAIN": self.kc,
            "REPORT": str(self.report),
            "STOREKEEPER_PYTHON": sys.executable,
            **self.store.env,
        }

    def run_wrapped(self, *args: str, **env: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [str(WRAPPER), str(self.child), *args],
            env={**self.env, **env}, capture_output=True, text=True, timeout=60,
        )  # fmt: skip


class WrapperTests(KeyCase):
    def test_6_a_private_file_for_one_command_then_gone_and_the_exit_passes_through(self):
        done = self.run_wrapped("@ASC_KEY@", "--key=@ASC_KEY@")
        self.assertEqual(done.returncode, 7, done.stderr)
        seen = report(self.report)
        key = Path(seen["arg"])
        self.assertEqual(key.name, "AuthKey_TESTKEY001.p8")
        self.assertEqual(key.parent.parent, self.tmp)
        self.assertEqual((seen["dir"], seen["file"]), ("700", "600"))
        self.assertIn("-----BEGIN PRIVATE KEY-----", self.report.read_text())
        self.assertEqual(seen["second"], f"--key={key}")
        self.assertFalse(key.parent.exists(), "the key folder outlived the command")
        self.assertEqual(list(self.tmp.iterdir()), [])
        self.assertNotIn(body_line(self.pem)[:40], done.stdout + done.stderr)

    def test_6_a_path_with_ampersand_or_quote_is_passed_as_it_is(self):
        # bash 5.2 reads & in ${x//pat/rep} as the match; 3.2 keeps quotes put around it.
        odd = self.dir / 'tmp & "odd"'
        odd.mkdir()
        done = self.run_wrapped("@ASC_KEY@", "a@ASC_KEY@b@ASC_KEY@", TMPDIR=str(odd))
        self.assertEqual(done.returncode, 7, done.stderr)
        key = report(self.report)["arg"]
        self.assertEqual(Path(key).parent.parent, odd)
        self.assertEqual(report(self.report)["second"], f"a{key}b{key}")

    def test_7_term_and_int_delete_the_folder_while_the_command_runs(self):
        for sig, code in ((signal.SIGTERM, 143), (signal.SIGINT, 130), (signal.SIGQUIT, 131)):
            with self.subTest(signal=sig.name):
                proc = subprocess.Popen(
                    [str(WRAPPER), str(self.child), "@ASC_KEY@"],
                    env={**self.env, "HANG": "1"},
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                )  # fmt: skip
                self.addCleanup(proc.stdout.close)
                self.assertTrue(started(proc), "the command never started")
                key = Path(report(self.report)["arg"])
                self.assertTrue(key.exists())
                os.kill(proc.pid, sig)
                self.assertEqual(proc.wait(timeout=20), code)
                self.assertFalse(key.parent.exists(), f"the key folder outlived {sig.name}")
        self.assertEqual(list(self.tmp.iterdir()), [])

    def test_7_a_command_that_ignores_term_is_killed_and_the_folder_still_goes(self):
        stubborn = self.dir / "stubborn"
        stubborn.write_text(
            '#!/bin/bash\ntrap \'\' TERM\necho "arg=$1" > "$REPORT"\necho started\n'
            "while true; do sleep 0.2; done\n"
        )
        stubborn.chmod(0o755)
        proc = subprocess.Popen(
            [str(WRAPPER), str(stubborn), "@ASC_KEY@"], env=self.env,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )  # fmt: skip
        self.addCleanup(proc.stdout.close)
        self.addCleanup(lambda: proc.poll() is None and proc.kill())
        self.assertTrue(started(proc), "the command never started")
        key = Path(report(self.report)["arg"])
        os.kill(proc.pid, signal.SIGTERM)
        self.assertEqual(proc.wait(timeout=20), 143)
        self.assertFalse(key.parent.exists(), "the key folder outlived a stubborn command")


class SweepTests(KeyCase):
    """A hard kill (SIGKILL, a power loss) leaves the key folder behind: each run
    first deletes this user's own stale key folders, and nothing else."""

    def test_a_run_sweeps_its_own_stale_key_folders_and_nothing_else(self):
        stale = self.tmp / "storekeeper-key.999999.AAAAAAAA"  # no such PID on macOS
        stale.mkdir(mode=0o700)
        (stale / "AuthKey_TESTKEY001.p8").write_text("left by a hard kill")
        fresh = self.tmp / "storekeeper-key.999998.BBBBBBBB"
        fresh.mkdir(mode=0o700)
        other = self.tmp / "something-else.CCCCCCCC"
        other.mkdir()
        plain = self.tmp / "storekeeper-key.999997.DDDDDDDD"
        plain.write_text("a file, not a key folder")
        odd = self.tmp / "storekeeper-key.EE"
        odd.mkdir()
        for path in (stale, other, plain, odd, stale / "AuthKey_TESTKEY001.p8"):
            os.utime(path, (0, 0))  # the epoch: older than any limit
        os.utime(stale, (0, 0))
        done = self.run_wrapped("@ASC_KEY@")
        self.assertEqual(done.returncode, 7, done.stderr)
        self.assertFalse(stale.exists(), "a stale key folder was left")
        for kept in (fresh, other, plain, odd):
            self.assertTrue(kept.exists(), f"{kept.name} was swept")
        self.assertIn("removed 1 stale key folder", done.stderr)

    def test_the_key_folder_is_named_for_the_sweep(self):
        self.run_wrapped("@ASC_KEY@")
        key = Path(report(self.report)["arg"])
        self.assertRegex(key.parent.name, r"^storekeeper-key\.[0-9]+\.[A-Za-z0-9]{8}$")

    def test_a_stale_folder_of_a_run_still_alive_is_kept(self):
        # Re-review N4: the PID in the name is the run's; a live one keeps its folder.
        dead = subprocess.Popen(["/usr/bin/true"])
        dead.wait(timeout=30)  # its PID now names no live process
        gone = self.tmp / f"storekeeper-key.{dead.pid}.AAAAAAAA"
        alive = self.tmp / f"storekeeper-key.{os.getpid()}.BBBBBBBB"
        for folder in (gone, alive):
            folder.mkdir(mode=0o700)
            os.utime(folder, (0, 0))
        result = self.run_wrapped("@ASC_KEY@")
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertFalse(gone.exists(), "the folder of a dead run was kept")
        self.assertTrue(alive.exists(), "the folder of a live run was swept")

    def test_no_tool_is_found_through_path_nor_bash_env_read(self):
        # Re-review N2: a look-alike dirname early on PATH, and BASH_ENV.
        decoys = self.dir / "decoys"
        decoys.mkdir()
        marker = self.dir / "decoy-ran"
        for name in ("dirname", "mktemp", "rm", "chmod", "find", "id", "sed", "sleep"):
            tool = decoys / name
            tool.write_text(f'#!/bin/sh\necho {name} >> "{marker}"\nexit 1\n')
            tool.chmod(0o755)
        startup = self.dir / "bash-env.sh"
        startup.write_text(f'echo BASH_ENV >> "{marker}"\n')
        env = {"PATH": f"{decoys}:/usr/bin:/bin", "BASH_ENV": str(startup)}
        quiet = self.dir / "quiet-child"  # runs no tool: only the wrapper is judged
        quiet.write_text('#!/bin/bash\n[[ -s "$1" ]] && exit 7\nexit 1\n')
        quiet.chmod(0o755)
        result = subprocess.run(
            [sys.executable, "-I", str(RUN), "with-key", str(quiet), "@ASC_KEY@"],
            env={**self.env, **env}, capture_output=True, text=True, timeout=60,
        )  # fmt: skip
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertFalse(marker.exists(), marker.read_text() if marker.exists() else "")


class CommandLineTests(KeyCase):
    """The same wrapper through `storekeeper with-key`, as a separate process."""

    def storekeeper(self, *args: str, **env: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-I", str(RUN), "with-key", *args],
            env={**self.env, **env}, capture_output=True, text=True, timeout=60,
        )  # fmt: skip

    def test_text_mode_runs_the_wrapper_and_passes_the_exit_through(self):
        done = self.storekeeper(str(self.child), "@ASC_KEY@")
        self.assertEqual(done.returncode, 7, done.stderr)
        key = Path(report(self.report)["arg"])
        self.assertEqual(key.name, "AuthKey_TESTKEY001.p8")
        self.assertFalse(key.parent.exists())

    def test_json_mode_prints_only_its_object_and_the_command_output_goes_to_stderr(self):
        talker = self.dir / "talker"
        talker.write_text('#!/bin/bash\necho "the command speaks"\nhead -1 "$1"\nexit "$2"\n')
        talker.chmod(0o755)
        for code in (0, 5):
            with self.subTest(code=code):
                done = self.storekeeper("--json", str(talker), "@ASC_KEY@", str(code))
                lines = done.stdout.splitlines()
                self.assertEqual(len(lines), 1, done.stdout)
                doc = json.loads(lines[0])
                self.assertEqual(doc["result"], {"command": "talker", "command_exit": code})
                self.assertIn("the command speaks", done.stderr)
                self.assertNotIn("PRIVATE KEY", done.stdout)
                if code == 0:
                    self.assertEqual((done.returncode, doc["ok"], doc["error"]), (0, True, None))
                else:
                    self.assertEqual(done.returncode, 1)
                    self.assertEqual(doc["error"]["code"], "command_failed")
        self.assertEqual(list(self.tmp.iterdir()), [])

    def test_json_mode_runs_nothing_when_the_key_is_not_there(self):
        done = self.storekeeper("--json", str(self.child), "@ASC_KEY@", ASC_KEY_ID="OTHERKEY01")
        doc = json.loads(done.stdout)
        self.assertEqual((done.returncode, doc["error"]["code"]), (1, "key_absent"))
        self.assertFalse(self.report.exists(), "the command ran without a key")

    def test_json_mode_gives_the_command_no_stdin(self):
        reader = self.dir / "reader"
        reader.write_text("#!/bin/bash\nif read -r line; then exit 9; fi\nexit 0\n")
        reader.chmod(0o755)
        done = subprocess.run(
            [sys.executable, "-I", str(RUN), "with-key", "--json", str(reader)],
            env=self.env, input="typed\n", capture_output=True, text=True, timeout=60,
        )  # fmt: skip
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_term_to_storekeeper_still_deletes_the_key_folder(self):
        proc = subprocess.Popen(
            [sys.executable, "-I", str(RUN), "with-key", "--json", str(self.child), "@ASC_KEY@"],
            env={**self.env, "HANG": "1"}, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )  # fmt: skip
        self.addCleanup(proc.stdout.close)
        self.addCleanup(proc.stderr.close)
        self.addCleanup(lambda: proc.poll() is None and proc.kill())
        self.assertTrue(said_started(proc.stderr), "the command never started")
        key = Path(report(self.report)["arg"])
        os.kill(proc.pid, signal.SIGTERM)
        self.assertEqual(proc.wait(timeout=20), 1)
        self.assertEqual(json.loads(proc.stdout.read())["result"]["command_exit"], 143)
        self.assertFalse(key.parent.exists(), "the key folder outlived TERM")


if __name__ == "__main__":
    unittest.main()
