"""Tests for verify_anchors.py. Standard library only.

    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import base64
import copy
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import verify_anchors  # noqa: E402

ANCHORS = sorted((ROOT / "anchors").glob("*.json"))
# Its digest ends in a zero byte, which is what LibreSSL's hex dump drops.
TRAILING_ZERO = ROOT / "anchors" / "00000869_813e4bd1c7174e8f.json"
SHA256_OID = bytes.fromhex("0609608648016503040201")
SHA384_OID = bytes.fromhex("0609608648016503040202")

# Stands in for macOS's openssl: the real one, except that `ts -reply -text`
# prints its hex dumps the way LibreSSL does, with trailing zero bytes folded
# into a "<SPACES/NULS>" line.
LIBRESSL_LIKE = textwrap.dedent(
    """\
    #!{python}
    import re, subprocess, sys
    out = subprocess.run([{real!r}] + sys.argv[1:], capture_output=True, text=True)
    text = out.stdout
    if "-text" in sys.argv:
        def fold(match):
            offset, pairs = match.group(1), match.group(2)
            octets = re.split(r"[ -]", pairs)
            if octets[-1] != "00":
                return match.group(0)
            while octets and octets[-1] == "00":
                octets.pop()
            kept = " ".join(octets)
            nxt = format(int(offset, 16) + 16, "04x")
            return f"    {{offset}} - {{kept}}\\n    {{nxt}} - <SPACES/NULS>\\n"
        text = re.sub(r"^    ([0-9a-f]{{4}}) - ((?:[0-9a-f]{{2}}[ -]){{15}}[0-9a-f]{{2}}) .*\\n", fold, text, flags=re.M)
    sys.stdout.write(text)
    sys.stderr.write(out.stderr)
    sys.exit(out.returncode)
    """
)


def run_verifier(directory: Path, path_prefix: str | None = None):
    env = dict(os.environ)
    if path_prefix:
        env["PATH"] = path_prefix + os.pathsep + env.get("PATH", "")
    return subprocess.run(
        [sys.executable, str(ROOT / "verify_anchors.py"), str(directory)],
        capture_output=True, text=True, env=env, check=False,
    )


def write_anchor(directory: Path, record: dict, name: str = "00000001_test.json") -> None:
    (directory / name).write_text(json.dumps(record), encoding="utf-8")


class ImprintFromTheTokenItself(unittest.TestCase):
    def test_every_published_token_covers_its_anchor(self):
        self.assertTrue(ANCHORS, "no anchors in the repository")
        for path in ANCHORS:
            record = json.loads(path.read_text(encoding="utf-8"))
            for stamp in record["timestamps"]:
                with self.subTest(anchor=path.name, authority=stamp["authority"]):
                    token = verify_anchors.read_token(base64.b64decode(stamp["token_b64"]))
                    self.assertTrue(token.granted)
                    self.assertEqual(token.hash_algorithm, "sha256")
                    self.assertEqual(token.imprint, record["digest"])
                    self.assertRegex(token.signed_at, r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(\.\d+)? UTC$")

    def test_a_truncated_token_is_unreadable(self):
        record = json.loads(TRAILING_ZERO.read_text(encoding="utf-8"))
        token = base64.b64decode(record["timestamps"][0]["token_b64"])
        with self.assertRaises(ValueError):
            verify_anchors.read_token(token[: len(token) // 2])

    def test_an_imprint_made_with_another_hash_is_not_accepted(self):
        record = json.loads(TRAILING_ZERO.read_text(encoding="utf-8"))
        token = base64.b64decode(record["timestamps"][0]["token_b64"])
        # The signature names SHA-256 too; change only the messageImprint's
        # algorithm, the last mention before the digest itself.
        at = token.rindex(SHA256_OID, 0, token.index(bytes.fromhex(record["digest"])))
        relabelled = token[:at] + SHA384_OID + token[at + len(SHA256_OID):]
        parsed = verify_anchors.read_token(relabelled)
        self.assertEqual(parsed.hash_algorithm, "sha384")
        self.assertEqual(parsed.imprint, record["digest"])
        ok, _chain, _when, note = verify_anchors.check_token(relabelled, record["digest"], "/nonexistent")
        self.assertFalse(ok)
        self.assertIn("SHA-256", note)


@unittest.skipIf(shutil.which("openssl") is None, "openssl not installed")
class WholeRun(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)

    def test_the_zero_ending_anchor_verifies_with_a_libressl_style_openssl(self):
        bin_dir = self.tmp / "bin"
        bin_dir.mkdir()
        fake = bin_dir / "openssl"
        fake.write_text(LIBRESSL_LIKE.format(python=sys.executable, real=shutil.which("openssl")))
        fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
        dump = subprocess.run(
            [str(fake), "ts", "-reply", "-in", "/dev/stdin", "-text"],
            input=base64.b64decode(json.loads(TRAILING_ZERO.read_text())["timestamps"][0]["token_b64"]),
            capture_output=True, check=False,
        ).stdout.decode()
        self.assertIn("<SPACES/NULS>", dump, "the stand-in no longer behaves like LibreSSL")

        anchors = self.tmp / "anchors"
        anchors.mkdir()
        shutil.copy(TRAILING_ZERO, anchors)
        result = run_verifier(anchors, str(bin_dir))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("FAIL", result.stdout)

    def test_the_published_anchors_verify(self):
        result = run_verifier(ROOT / "anchors")
        self.assertEqual(result.returncode, 0, result.stdout[-2000:] + result.stderr)

    def test_a_changed_document_is_caught_even_with_a_matching_digest(self):
        record = json.loads(TRAILING_ZERO.read_text(encoding="utf-8"))
        forged = copy.deepcopy(record)
        forged["document"]["entry_count"] = record["document"]["entry_count"] + 1
        forged["digest"] = verify_anchors.digest_of(forged["document"])
        anchors = self.tmp / "anchors"
        anchors.mkdir()
        write_anchor(anchors, forged)
        result = run_verifier(anchors)
        self.assertEqual(result.returncode, 1)
        self.assertIn("does not cover this document", result.stdout)


if __name__ == "__main__":
    unittest.main()
