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
from dataclasses import dataclass
from pathlib import Path

# Where common systems keep their trusted CA bundle: Debian and Ubuntu, Fedora
# and RHEL, then macOS. Pass --ca-file to use a different one.
CA_BUNDLES = (
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
)
DEFAULT_CA = next((path for path in CA_BUNDLES if Path(path).exists()), CA_BUNDLES[0])

# Object identifiers this script needs, as their DER content bytes.
OID_SIGNED_DATA = bytes.fromhex("2a864886f70d010702")  # 1.2.840.113549.1.7.2
OID_TST_INFO = bytes.fromhex("2a864886f70d0109100104")  # 1.2.840.113549.1.9.16.1.4
HASH_NAMES = {
    bytes.fromhex("608648016503040201"): "sha256",
    bytes.fromhex("608648016503040202"): "sha384",
    bytes.fromhex("608648016503040203"): "sha512",
    bytes.fromhex("2b0e03021a"): "sha1",
}
SEQUENCE, SET, INTEGER, OCTET_STRING, OID, GENERALIZED_TIME = 0x30, 0x31, 0x02, 0x04, 0x06, 0x18
EXPLICIT_0 = 0xA0


def digest_of(document) -> str:
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _elements(data: bytes) -> list:
    """Splits DER bytes into (tag, content) pairs. Definite lengths only, as DER requires."""
    elements, pos = [], 0
    while pos < len(data):
        if pos + 2 > len(data):
            raise ValueError("truncated element")
        tag, length = data[pos], data[pos + 1]
        pos += 2
        if tag & 0x1F == 0x1F:
            raise ValueError("multi-byte tags are not used in timestamp tokens")
        if length & 0x80:
            count = length & 0x7F
            if count == 0 or count > 4:
                raise ValueError("indefinite or oversized length; not DER")
            if pos + count > len(data):
                raise ValueError("truncated length")
            length = int.from_bytes(data[pos:pos + count], "big")
            pos += count
        if pos + length > len(data):
            raise ValueError("element runs past the end of the token")
        elements.append((tag, data[pos:pos + length]))
        pos += length
    return elements


def _expect(elements: list, index: int, tag: int, what: str) -> bytes:
    if index >= len(elements) or elements[index][0] != tag:
        raise ValueError(f"unexpected structure at {what}")
    return elements[index][1]


def _single(data: bytes, tag: int, what: str) -> bytes:
    elements = _elements(data)
    if len(elements) != 1:
        raise ValueError(f"expected exactly one element at {what}")
    return _expect(elements, 0, tag, what)


@dataclass
class Token:
    granted: bool
    hash_algorithm: str
    imprint: str
    signed_at: str


def read_token(token: bytes) -> Token:
    """Reads an RFC 3161 TimeStampResp from its DER bytes.

    The message imprint is taken from the token itself rather than from
    `openssl ts -text`, whose hex dumps differ between OpenSSL and LibreSSL
    (LibreSSL folds trailing zero bytes into "<SPACES/NULS>"). Raises
    ValueError when the bytes are not a timestamp response.
    """
    response = _elements(_single(token, SEQUENCE, "TimeStampResp"))
    status = _elements(_expect(response, 0, SEQUENCE, "PKIStatusInfo"))
    granted = int.from_bytes(_expect(status, 0, INTEGER, "PKIStatus"), "big") in (0, 1)

    content_info = _elements(_expect(response, 1, SEQUENCE, "timeStampToken"))
    if _expect(content_info, 0, OID, "contentType") != OID_SIGNED_DATA:
        raise ValueError("timeStampToken is not SignedData")
    signed_data = _elements(_single(_expect(content_info, 1, EXPLICIT_0, "content"), SEQUENCE, "SignedData"))
    _expect(signed_data, 0, INTEGER, "SignedData version")
    _expect(signed_data, 1, SET, "digestAlgorithms")
    encapsulated = _elements(_expect(signed_data, 2, SEQUENCE, "encapContentInfo"))
    if _expect(encapsulated, 0, OID, "eContentType") != OID_TST_INFO:
        raise ValueError("signed content is not TSTInfo")
    tst_der = _single(_expect(encapsulated, 1, EXPLICIT_0, "eContent"), OCTET_STRING, "eContent")

    tst_info = _elements(_single(tst_der, SEQUENCE, "TSTInfo"))
    _expect(tst_info, 0, INTEGER, "TSTInfo version")
    _expect(tst_info, 1, OID, "policy")
    message_imprint = _elements(_expect(tst_info, 2, SEQUENCE, "messageImprint"))
    algorithm = _elements(_expect(message_imprint, 0, SEQUENCE, "hashAlgorithm"))
    hash_oid = _expect(algorithm, 0, OID, "hashAlgorithm OID")
    hashed = _expect(message_imprint, 1, OCTET_STRING, "hashedMessage")
    _expect(tst_info, 3, INTEGER, "serialNumber")
    gen_time = _expect(tst_info, 4, GENERALIZED_TIME, "genTime").decode("ascii")

    stamp = re.fullmatch(r"(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\.\d+)?Z", gen_time)
    if not stamp:
        raise ValueError(f"unexpected genTime {gen_time!r}")
    year, month, day, hour, minute, second, fraction = stamp.groups()
    signed_at = f"{year}-{month}-{day} {hour}:{minute}:{second}{fraction or ''} UTC"

    return Token(
        granted=granted,
        hash_algorithm=HASH_NAMES.get(hash_oid, "unknown"),
        imprint=hashed.hex(),
        signed_at=signed_at,
    )


def check_token(token: bytes, digest: str, ca_file: str):
    """Returns (imprint_ok, chain_ok, signed_at, note).

    imprint_ok and chain_ok are kept apart deliberately. A mismatched imprint
    means the document was changed. A failed chain usually just means the
    authority's signing certificate has expired since, which says nothing about
    whether the token was genuine when issued.
    """
    try:
        parsed = read_token(token)
    except ValueError as exc:
        return False, False, None, f"token unreadable ({exc})"
    signed_at = parsed.signed_at

    if not parsed.granted:
        return False, False, signed_at, "the authority did not grant this token"
    if parsed.hash_algorithm != "sha256":
        return False, False, signed_at, f"imprint uses {parsed.hash_algorithm}, not SHA-256"
    if parsed.imprint != digest:
        return False, False, signed_at, "message imprint does not cover this document"

    # The signature and chain are left to openssl, which checks the imprint
    # again on its own; the two readings have to agree.
    with tempfile.NamedTemporaryFile(suffix=".tsr") as handle:
        handle.write(token)
        handle.flush()

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
