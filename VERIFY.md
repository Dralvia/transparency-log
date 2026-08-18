# Verifying an anchor by hand

`verify_anchors.py` does all of this. This file is for when you would rather not
run someone else's script.

## 1. Confirm the document matches its digest

```bash
python3 - <<'PY'
import hashlib, json
record = json.load(open("anchors/00000869_813e4bd1c7174e8f.json"))
canonical = json.dumps(record["document"], sort_keys=True, separators=(",", ":")).encode()
print("computed:", hashlib.sha256(canonical).hexdigest())
print("claimed: ", record["digest"])
PY
```

They must match. If they do not, the document was edited after it was stamped.

## 2. Extract a timestamp token

```bash
python3 - <<'PY'
import base64, json
record = json.load(open("anchors/00000869_813e4bd1c7174e8f.json"))
open("token.tsr", "wb").write(base64.b64decode(record["timestamps"][0]["token_b64"]))
PY
```

## 3. Verify the token against the digest

```bash
openssl ts -verify -digest "<the digest from step 1>" -in token.tsr \
  -CAfile /etc/ssl/certs/ca-certificates.crt
```

`Verification: OK` means that authority signed that exact digest.

Two failures mean different things, and the difference matters:

- **`message imprint mismatch`** means the token does not cover this document.
  This is the one that indicates something was changed.
- **`certificate verify error`** usually means the authority's signing
  certificate has expired since the token was issued. The token may still be
  perfectly good. To inspect it without checking the chain:

```bash
openssl ts -reply -in token.tsr -text | grep -E "Status|Time stamp|TSA"
```

## 4. Read the signed time

```bash
openssl ts -reply -in token.tsr -text | grep "Time stamp"
```

That is a third party stating when the digest existed. Dralvia has no way to
influence it.

## 5. Follow the chain

Each `document.previous_anchor_digest` must equal the `digest` of the previous
anchor, in `sequence` order. A gap means an anchor is missing from this
repository. Compare against your own clone, or anyone else's.

## Independence

Do not take Dralvia's word for which authorities are trustworthy. DigiCert and
Sectigo are publicly trusted CAs present in the standard trust stores shipped by
operating systems and browsers. Your own `ca-certificates` bundle is the check,
not a file from this repository.
