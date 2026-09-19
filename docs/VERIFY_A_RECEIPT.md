# Verify a receipt yourself

Anyone you share a receipt with can check it — that an agent in your org really
did what the receipt says, that nobody has edited it since, and that it was part
of the log your org committed to. They do this without an account, without your
permission, and without installing Orrery.

Verification runs on a machine with no network connection. Once your auditor has
the bundle and your org's public identity, nothing has to reach you again.

## What your auditor needs

Current Python installations refuse to install into the system interpreter, so
create a virtual environment first. If `python3 -m venv` reports that `ensurepip`
is unavailable, install your platform's `python3-venv` package and run it again.

```bash
python3 -m venv verify-receipt
source verify-receipt/bin/activate      # Windows: verify-receipt\Scripts\activate
pip install sm-arp                      # from PyPI. Nothing from your Orrery install.
```

Run everything below from inside that activated environment.

That is the whole toolchain. `sm-arp` is a small open-source library; Orrery
itself is not required at verification time.

## Publish something to verify

Receipts are private until you choose otherwise, so your org publishes nothing by
default. Publish a bundle when you want a specific set of receipts to be checkable
by someone outside your org.

Your admin token is printed once, in the server log, the first time your org
starts. Keep it somewhere safe.

```bash
curl -X POST https://<your org>/admin/api/receipts/publish \
     -H "X-Admin-Token: $ORG_ADMIN_TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"receipt_ids": ["<receipt id>"], "publication_id": "sample"}'
```

The response carries the public URL of the bundle:
`https://<your org>/.well-known/receipt-disclosure/sample.json`. Send that URL to
your auditor. `GET /.well-known/receipt-disclosure/` lists everything you have
published.

**Today you choose receipts by id and publish by hand.** There is no scheduled or
automatic publication, and nothing is published as a side effect of any other
action — if you have not run the command above, your org's disclosure list is
empty.

## The one thing that matters

**Do not take the key from the bundle.**

A disclosure bundle names its issuer (`issuer_did`) but carries **no key
material and no link to a key document**, by design. If a bundle supplied the key
that verifies it, anyone could forge a receipt, sign it with a key of their own,
ship both together, and it would check out perfectly. The bundle would prove only
that its author owns a key.

So you resolve the issuer independently:

1. Decide which org you are auditing. Fetch **its** DID document —
   `https://<that org>/.well-known/did.json` — from the host **you** chose.
2. Build `did:key:<verificationMethod[0].publicKeyMultibase>`.
3. Require it to equal the bundle's `issuer_did`. **If it does not match, stop.**

Only then does the signature check mean anything. `did:key` is self-certifying —
the identifier *is* the public key — so once you trust the identifier, no key has
to be transported at all.

## The recipe

```python
import json, sys, hashlib, urllib.request
import sm_arp

ORG    = "https://<the org you are auditing>"
BUNDLE = f"{ORG}/.well-known/receipt-disclosure/sample.json"

def get(url):
    with urllib.request.urlopen(url, timeout=30) as r:
        return json.load(r)

bundle = get(BUNDLE)

# 1. Resolve the issuer INDEPENDENTLY, from the org's own DID document.
did_doc = get(f"{ORG}/.well-known/did.json")
org_did = "did:key:" + did_doc["verificationMethod"][0]["publicKeyMultibase"]
assert bundle["issuer_did"] == org_did, "bundle was not issued by this org"

# 2. Every disclosed receipt must carry a valid signature by that issuer.
root = bundle["checkpoint"]["payload"]["merkle_root"].removeprefix("sha256:")
tree_size = bundle["checkpoint"]["payload"]["tree_size"]

import jcs as _jcs   # RFC 8785, a dependency sm-arp already pulls in

def jcs(obj):
    return _jcs.canonicalize(obj)

for d in bundle["disclosed"]:
    receipt = d["receipt"]
    res = sm_arp.verify_signature(receipt)
    assert res.ok, f"signature failed: {res.detail}"

    # 3. And must prove membership in the tree the org signed (RFC 6962).
    # RFC 6962 §2.1.1 audit-path verification. NOT the naive `idx & 1` binary
    # fold: RFC 6962 splits at the largest power of two below the tree size, so
    # the two only agree when the tree is perfectly balanced. `tree_size` is
    # required, which is why the checkpoint carries it.
    node = hashlib.sha256(b"\x00" + jcs(receipt)).digest()
    fn, sn = d["leaf_index"], tree_size - 1
    for sib_hex in d["proof"]:
        sib = bytes.fromhex(sib_hex)
        if fn & 1 or fn == sn:
            node = hashlib.sha256(b"\x01" + sib + node).digest()
            while fn != 0 and not fn & 1:
                fn >>= 1
                sn >>= 1
        else:
            node = hashlib.sha256(b"\x01" + node + sib).digest()
        fn >>= 1
        sn >>= 1
    assert node.hex() == root and sn == 0, "inclusion proof does not fold to the signed root"

print(f"OK — {len(bundle['disclosed'])} receipt(s) verified against {org_did}")
```

## What each step rules out

| Step | Without it |
|---|---|
| `issuer_did == org_did` | A forger signs with a key of their own and every other check still passes. **This is the check the rest depends on.** |
| `verify_signature` | The receipt's contents can be edited freely. |
| Inclusion proof | A genuinely-signed receipt can be swapped for a *different* genuinely-signed receipt — the signature still verifies; only the proof binds a receipt to its place in the log. |

> **Use the RFC 6962 audit-path algorithm above, not a naive `idx & 1` fold.**
> RFC 6962 splits the tree at the largest power of two below its size, so a plain
> binary fold agrees only when the tree is perfectly balanced. It will verify a
> four-receipt log and fail a seven-receipt one.

The Merkle root is inside `checkpoint`, which the org signed. So the proof shows
your receipt was in the same log the org committed to — without the org having to
reveal the rest of it. That is what selective disclosure is for.

## Try to break it

Do these. They should all fail:

- Change one character of `action.human_summary` → signature fails.
- Change one byte of the signature → signature fails.
- Flip a byte in any `proof` element → inclusion fails.
- Swap in a different receipt from the same org → inclusion fails, signature still passes.
- Point `ORG` at a *different* org → the `issuer_did` assertion fails.

Each of those failures is covered by Orrery's test suite, including a test that
runs the recipe on this page with `sm_arp` as its only import.

## What is published, and what is not

Only bundles an operator explicitly published, and only receipts the **org**
issued about its **own** actions. `GET /api/receipts` remains authenticated —
that is a member's private history, and no member's receipts are published by
this surface. Publication is never a side effect of anything else.

`GET /.well-known/receipt-disclosure/` lists what an org has published.

## The other disclosure format

This page covers the ARP receipt bundle. An agent can also present a PARC
selective-disclosure bundle — a reputation credential plus chosen receipts with
Merkle inclusion proofs (`POST /api/local/disclose`). The issuer rule is the same,
and for the same reason: its credential's proof verifies under the `did:key`
written inside the credential, so the expected issuer has to come from somewhere
else.

    community-member disclose verify bundle.json --issuer did:key:<the org's>
    community-member disclose verify bundle.json --issuer-from https://<the org>

`--issuer-from` performs step 1 above — it builds the `did:key` from
`<org>/.well-known/did.json`. One of the two is required; there is no invocation
that reports a verdict without an expected issuer.
