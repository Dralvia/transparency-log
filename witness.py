#!/usr/bin/env python3
"""An independent witness of Dralvia's transparency log.

This runs on GitHub's infrastructure, not Dralvia's. That is the entire point.

Dralvia already publishes signed checkpoints and RFC 3161 anchors, but both are
produced on Dralvia's own host by Dralvia's own jobs. A sufficiently deep
compromise there could rewrite the log and re-sign every checkpoint, and the only
records of what Dralvia previously claimed would be on the compromised machine.

This script fetches the current checkpoint from Dralvia's public endpoint,
verifies its signature against the public keys already published in this
repository, checks it against everything this repository has recorded before,
and commits what it saw. The record therefore lives somewhere Dralvia does not
control, written by a runner Dralvia does not operate, in a repository where
history cannot be rewritten without leaving a trace.

What it can prove
-----------------
* The checkpoint was signed by the published key. Dralvia cannot serve a
  checkpoint signed by anything else without it being visible here.
* The log never went backwards. If a later checkpoint reports fewer entries than
  one recorded earlier, that is a rewrite and this exits non-zero.
* A count never changed its root. If entry count N reported root R on Monday and
  root R' later, the two records sit side by side in this repository forever.

What it cannot prove
--------------------
It does **not** verify that the new log contains the old one. That needs a
consistency proof, and Dralvia's consistency endpoint requires authentication, so
an anonymous witness cannot request one. This witness detects contradiction, not
prefix inclusion. Said plainly because a witness that overstates what it checked
is worse than no witness.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

CHECKPOINT_URL = "https://dralvia.tech/api/public/transparency-log/checkpoint"

# Dralvia's edge rejects the default Python user agent with a 403, so a witness
# that did not set one would look like an outage every run.
USER_AGENT = "Dralvia-Transparency-Witness/1.0 (+https://github.com/Dralvia/transparency-log)"

ROOT = Path(__file__).resolve().parent
OBSERVATIONS = ROOT / "observations"
PUBLIC_KEYS = ROOT / "PUBLIC_KEYS.txt"

TIMEOUT_SECONDS = 30


class WitnessFailure(RuntimeError):
    """Something a reader of this repository needs to know about."""


def load_public_keys() -> dict:
    keys = {}
    for line in PUBLIC_KEYS.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            keys[parts[0]] = parts[1]
    if not keys:
        raise WitnessFailure(f"{PUBLIC_KEYS.name} lists no keys")
    return keys


def fetch_checkpoint() -> dict:
    request = urllib.request.Request(
        CHECKPOINT_URL, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            body = response.read()
    except urllib.error.HTTPError as error:
        raise WitnessFailure(f"checkpoint endpoint returned HTTP {error.code}") from error
    except urllib.error.URLError as error:
        raise WitnessFailure(f"checkpoint endpoint unreachable: {error.reason}") from error
    checkpoint = json.loads(body.decode("utf-8"))
    for field in ("entry_count", "merkle_root", "signature"):
        if field not in checkpoint:
            raise WitnessFailure(f"checkpoint is missing {field}")
    return checkpoint


def verify_signature(checkpoint: dict, keys: dict) -> str:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    signature = checkpoint.get("signature") or {}
    algorithm = signature.get("algorithm")
    key_id = signature.get("key_id")
    if algorithm != "Ed25519":
        raise WitnessFailure(f"unexpected signature algorithm {algorithm!r}")
    if key_id not in keys:
        raise WitnessFailure(
            f"checkpoint signed by unpublished key {key_id!r}; known keys: "
            f"{sorted(keys)}"
        )

    signed = {k: v for k, v in checkpoint.items() if k not in ("signature", "witness_hash")}
    message = json.dumps(signed, sort_keys=True, separators=(",", ":")).encode("utf-8")
    public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(keys[key_id]))
    try:
        public_key.verify(base64.b64decode(signature["value"]), message)
    except InvalidSignature as error:
        raise WitnessFailure("checkpoint signature does not verify") from error
    return key_id


def load_observations() -> list:
    records = []
    for path in sorted(OBSERVATIONS.glob("*.json")):
        try:
            records.append((path, json.loads(path.read_text(encoding="utf-8"))))
        except ValueError as error:
            raise WitnessFailure(f"{path.name} is not readable JSON: {error}") from error
    records.sort(key=lambda item: item[1].get("observed_at", ""))
    return records


def check_against_history(checkpoint: dict, history: list) -> None:
    count = int(checkpoint["entry_count"])
    root = str(checkpoint["merkle_root"])

    for path, record in history:
        previous = record.get("checkpoint") or {}
        previous_count = int(previous.get("entry_count", -1))
        previous_root = str(previous.get("merkle_root", ""))

        if previous_count == count and previous_root != root:
            raise WitnessFailure(
                f"CONTRADICTION: {path.name} recorded entry_count {count} with root "
                f"{previous_root}, the log now reports root {root} for the same count"
            )
        if previous_count > count:
            raise WitnessFailure(
                f"REGRESSION: {path.name} recorded {previous_count} entries, the log "
                f"now reports only {count}"
            )


def _observer() -> str:
    """Where this observation was actually made.

    Hardcoding "github-actions" would have stamped that on runs made anywhere,
    including on Dralvia's own host, which is precisely the claim this
    repository exists to make honestly.
    """
    if os.environ.get("GITHUB_ACTIONS") == "true":
        repository = os.environ.get("GITHUB_REPOSITORY", "unknown")
        return f"github-actions:{repository}"
    return "manual"


def write_observation(checkpoint: dict, key_id: str, history: list) -> Path:
    count = int(checkpoint["entry_count"])
    root = str(checkpoint["merkle_root"])
    path = OBSERVATIONS / f"{count:08d}_{root[:16]}.json"
    if path.exists():
        return path

    OBSERVATIONS.mkdir(parents=True, exist_ok=True)
    document = {
        "kind": "dralvia.transparency.witness-observation",
        "version": 1,
        "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "observed_by": _observer(),
        "source_url": CHECKPOINT_URL,
        "signature_verified": True,
        "signature_key_id": key_id,
        "previous_observation": history[-1][0].name if history else None,
        "checkpoint": checkpoint,
    }
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def main() -> int:
    try:
        keys = load_public_keys()
        checkpoint = fetch_checkpoint()
        key_id = verify_signature(checkpoint, keys)
        history = load_observations()
        check_against_history(checkpoint, history)
        path = write_observation(checkpoint, key_id, history)
    except WitnessFailure as failure:
        print(f"WITNESS FAILED: {failure}", file=sys.stderr)
        return 1

    fresh = path.name not in {p.name for p, _ in history}
    print(
        f"entry_count={checkpoint['entry_count']} "
        f"root={checkpoint['merkle_root'][:16]}... "
        f"key={key_id} "
        f"{'recorded ' + path.name if fresh else 'already recorded'}"
    )
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as handle:
            handle.write(
                f"Observed **{checkpoint['entry_count']}** entries, root "
                f"`{checkpoint['merkle_root'][:16]}...`, signature verified "
                f"against `{key_id}`.\n"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
