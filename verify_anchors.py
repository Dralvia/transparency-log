#!/usr/bin/env python3
"""Verify Dralvia transparency anchors.

Standalone on purpose. Needs Python 3 and openssl, imports nothing from Dralvia,
and makes no network requests. Read it before you run it; it is short.

    python3 verify_anchors.py anchors/

Exit status is 0 only when every anchor verifies and the chain is unbroken.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HEX64 = re.compile(r"^[0-9a-f]{64}$")
DEFAULT_CA = "/etc/ssl/certs/ca-certificates.crt"


def digest_of(document) -> str:
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def check_token(token: bytes, digest: str, ca_file: str):
    """Returns (imprint_ok, chain_ok, signed_at, note).

    imprint_ok and chain_ok are kept apart deliberately. A mismatched imprint
    means the document was changed. A failed chain usually just means the
    authority's signing certificate has expired since, which says nothing about
    whether the token was genuine when issued.
    """
    with tempfile.NamedTemporaryFile(suffix=".tsr") as handle:
        handle.write(token)
        handle.flush()

        parsed = subprocess.run(
            ["openssl", "ts", "-reply", "-in", handle.name, "-text"],
            capture_output=True, text=True, check=False,
        )
        if parsed.returncode != 0:
            return False, False, None, "token unreadable"

        imprint = None
        block = re.search(r"Message data:\s*\n((?:\s+[0-9a-f]{4}.*\n)+)", parsed.stdout)
        if block:
            pairs = re.findall(r"-\s*([0-9a-f]{2}(?:\s+[0-9a-f]{2})*)", block.group(1))
            joined = "".join(part.replace(" ", "") for part in pairs)
            if HEX64.match(joined):
                imprint = joined

        stamped = re.search(r"Time stamp:\s*(.+)", parsed.stdout)
        signed_at = stamped.group(1).strip() if stamped else None

        if imprint != digest:
            return False, False, signed_at, "message imprint does not cover this document"

        if not Path(ca_file).exists():
            return True, False, signed_at, f"no CA bundle at {ca_file}, chain not checked"

        verified = subprocess.run(
            ["openssl", "ts", "-verify", "-digest", digest, "-in", handle.name, "-CAfile", ca_file],
            capture_output=True, text=True, check=False,
        )
        output = verified.stdout + verified.stderr
        if "Verification: OK" in output:
            return True, True, signed_at, None
        last = output.strip().splitlines()[-1] if output.strip() else "unknown"
        return True, False, signed_at, f"chain not verified: {last[:120]}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", nargs="?", default="anchors")
    parser.add_argument("--ca-file", default=DEFAULT_CA)
    args = parser.parse_args()

    if shutil.which("openssl") is None:
        print("openssl not found; cannot verify timestamps")
        return 2

    paths = sorted(Path(args.directory).glob("*.json"))
    if not paths:
        print(f"no anchors found in {args.directory}")
        return 2

    records = []
    for path in paths:
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"FAIL {path.name}: unreadable ({exc})")
            return 1
        records.append((path, record))
    records.sort(key=lambda item: (item[1].get("sequence") or 0, item[0].name))

    failures = 0
    expected_previous = None

    for path, record in records:
        document = record.get("document") or {}
        computed = digest_of(document)
        claimed = (record.get("digest") or "").lower()

        print(f"\n{path.name}")
        print(f"  entries {document.get('entry_count')}  root {str(document.get('merkle_root'))[:16]}...")

        if computed != claimed:
            print(f"  FAIL document does not match its digest")
            print(f"       computed {computed}")
            print(f"       claimed  {claimed}")
            failures += 1
            continue
        print("  ok   document matches its digest")

        stated_previous = document.get("previous_anchor_digest")
        if expected_previous is None:
            print("  ok   first anchor in this set")
        elif stated_previous == expected_previous:
            print("  ok   chains to the previous anchor")
        else:
            print("  FAIL chain broken; an anchor is missing or out of order")
            print(f"       expects {stated_previous}")
            print(f"       previous {expected_previous}")
            failures += 1
        expected_previous = computed

        stamps = record.get("timestamps") or []
        if not stamps:
            print("  FAIL no timestamps; this anchor is just a file")
            failures += 1
            continue

        for stamp in stamps:
            authority = stamp.get("authority", "?")
            try:
                token = base64.b64decode(stamp.get("token_b64") or "", validate=True)
            except Exception:
                print(f"  FAIL {authority}: token unreadable")
                failures += 1
                continue
            imprint_ok, chain_ok, signed_at, note = check_token(token, computed, args.ca_file)
            if not imprint_ok:
                print(f"  FAIL {authority}: {note}")
                failures += 1
            elif chain_ok:
                print(f"  ok   {authority}: signed {signed_at}")
            else:
                print(f"  warn {authority}: covers this document, signed {signed_at} ({note})")

    print()
    if failures:
        print(f"{failures} problem(s) found across {len(records)} anchor(s)")
        return 1
    print(f"{len(records)} anchor(s) verified, chain unbroken")
    return 0


if __name__ == "__main__":
    sys.exit(main())
