# Dralvia transparency anchors

This repository exists so that Dralvia cannot quietly rewrite its own history.

Dralvia keeps an append-only transparency log of EvidencePack entries. The log
lives on Dralvia infrastructure, which means Dralvia could in principle rewrite
it, re-sign it, and present the result as though it had always been that way.

Everything here is designed to make that impossible to do undetected, and to let
you check it yourself without asking Dralvia for anything.

## What an anchor is

Each file under `anchors/` records one checkpoint of the transparency log:

| Field | Meaning |
| --- | --- |
| `document.merkle_root` | The root of the log at that moment. |
| `document.entry_count` | How many entries the root covers. |
| `document.checkpoint_hash` | The exact signed checkpoint being anchored. |
| `document.previous_anchor_digest` | The digest of the previous anchor. |
| `digest` | SHA-256 of the document. This is what was timestamped. |
| `timestamps[]` | One RFC 3161 token per timestamp authority. |

The timestamp tokens are the important part. They are issued by **DigiCert** and
**Sectigo**, signed with keys Dralvia does not hold and cannot obtain. Dralvia
cannot produce a token with a date of its choosing, and neither can anyone who
compromises Dralvia.

Storage can be deleted. Time cannot be forged.

## What this does and does not prove

**Proves:** the root recorded in an anchor existed no later than the time the
authorities signed it. If Dralvia rebuilt the log tomorrow, it could not produce
anchors matching the rebuilt history at yesterday's dates.

**Proves:** the anchors form an unbroken chain. Each names the digest of the one
before it, so removing an anchor leaves the next one pointing at something nobody
can reproduce.

**Does not prove:** that this repository is complete. A force push can remove
anchors from here. It cannot forge one, and clones made before then still hold
what was removed. If you care, clone this repository regularly.

**Does not prove:** anything about the period before the first anchor.

## Verify it yourself

`verify_anchors.py` needs only Python 3 and `openssl`. It talks to nothing.

```bash
python3 verify_anchors.py anchors/
```

It checks each anchor's document against its stated digest, each timestamp token
against that digest and the system trust store, and the chain from one anchor to
the next. See `VERIFY.md` for what each failure means and how to do the same
checks by hand.

## Cross-checking against the live log

Consistency proofs from the live API let you connect an anchor here to the log
Dralvia is serving now:

```
GET /api/transparency-log/consistency?old_size={entry_count}
```

Take `entry_count` from an anchor, ask for the proof, and confirm the `old_root`
it returns matches the `merkle_root` in that anchor. If it does not, the log being
served is not an extension of the log that was anchored.
