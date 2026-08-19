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

## A note on ordering

`anchors/00000867_...` was published after `anchors/00000869_...`, so the entry
counts go backwards once. That is not a rewritten log and not a failed check.

The first scheduled run read the wrong witness directory: a host-side backup
series that runs a day behind the primary one. It anchored a real, correctly
signed, slightly older checkpoint. The scheduler now reads the primary series,
and the publisher refuses any checkpoint older than the last one anchored.

It is left in place because this repository does not rewrite its history. That
rule matters more than a tidy sequence, and removing an anchor to make the
numbers look neat is precisely the behaviour the repository exists to rule out.

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

## The independent witness

`witness.py` runs here, on GitHub's infrastructure, every six hours. It is not
run by Dralvia and Dralvia cannot produce a run record in this repository.

Each run fetches the current checkpoint from Dralvia's public endpoint, which
needs no account and no key:

```
GET https://dralvia.tech/api/public/transparency-log/checkpoint
```

It then verifies the Ed25519 signature against `PUBLIC_KEYS.txt` in this
repository, compares the result against every observation already recorded in
`observations/`, and commits what it saw.

You can run exactly the same check yourself:

```bash
pip install cryptography
python3 witness.py
```

Note that Dralvia's edge rejects the default Python user agent with a 403, so a
client must set one. `witness.py` does.

### What the observations prove

- **The signature is real.** A checkpoint signed by anything other than a key
  published here fails the run.
- **The log never went backwards.** A checkpoint reporting fewer entries than one
  already recorded fails the run.
- **A count never changed its root.** If entry count N was recorded with root R
  and later reports a different root, both records sit here side by side and the
  run fails.

Because the record is committed here, on a schedule, by a runner Dralvia does not
control, "what Dralvia said the log looked like at time T" is not something
Dralvia can revise afterwards.

### What they do not prove

The observations do **not** prove that the current log contains the earlier one.
That needs a consistency proof, and Dralvia's consistency endpoint requires
authentication, so an anonymous witness cannot request one. This witness detects
contradiction, not prefix inclusion. If you hold an account, run the consistency
check in the section above as well; the two together are much stronger than
either alone.

A red run on this repository's Actions tab is a finding. Read the log, then read
`observations/` and compare for yourself.
