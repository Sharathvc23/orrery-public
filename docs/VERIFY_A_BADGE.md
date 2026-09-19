# Check an org's conformance badge yourself

Every Orrery org publishes a conformance badge: a signed statement of which
protocol versions it implements and how its own conformance checks came out. You
can fetch that badge and confirm two things without an account, our permission,
or any of our code — and without a network connection once you have the file.

You can confirm:

- **the badge has not been altered** since it was signed, and
- **which key signed it**, so you can tell whether it came from the org you are
  evaluating or from someone else.

## What the badge tells you, and what it does not

**The badge is self-attested.** The org runs its own conformance checks and signs
its own result. Nobody witnesses that run. The badge says so itself — it carries
`org.orrery.attestation: self-attested` and `org.orrery.witness: none` — and you
should read it as a signed, tamper-evident statement of what the org says about
itself, not as an independent audit.

That makes it useful for two things and unsuitable for a third:

| You can use it to | Because |
| --- | --- |
| Confirm which protocol versions an org claims to speak | The claim is signed and cannot be edited afterwards |
| Detect a badge that has been modified or substituted | Any change breaks the signature |
| **Not** to confirm the checks actually passed | Nothing independent witnessed the run |

If you need an independently checkable statement, verify a receipt instead — a
receipt commits to work that actually happened, and the recipe is in
[`VERIFY_A_RECEIPT.md`](./VERIFY_A_RECEIPT.md).

## What you need

The verifier, in a virtual environment. Most current Python installations refuse
to install into the system interpreter, so create the environment first — this is
a step, not a precaution:

```bash
python3 -m venv verify-badge
source verify-badge/bin/activate          # Windows: verify-badge\Scripts\activate
pip install sm-conformance                # from PyPI. Nothing from this repository.
```

If `python3 -m venv` reports that `ensurepip` is unavailable, your Python is
missing its venv module — on Debian and Ubuntu install `python3-venv` and run it
again. Run everything below from inside that activated environment.

## The one thing that matters

**Do not trust a badge because it verifies. Check who signed it.**

A badge names its signer in `signed_by`, and the verifier checks the signature
against that name. That proves the badge and the name agree with each other — it
does not prove the name is the org you care about. Anyone can generate a key,
sign their own badge saying whatever they like, and it will verify perfectly.

So resolve the org's identity independently, from a host you chose:

1. Decide which org you are evaluating. Fetch **its** DID document —
   `https://<that org>/.well-known/did.json`.
2. Build `did:key:<verificationMethod[0].publicKeyMultibase>`.
3. Require it to equal the badge's `signed_by`. **If it does not match, stop.**

## The recipe

Set `ORG` to the org you are checking. **Match the scheme to how it is served** —
a hosted org is `https://`, and an org you are running locally is
`http://localhost:7000`. Pointing `https://` at a local install fails with
`SSL: WRONG_VERSION_NUMBER`, which looks like a certificate problem and is not.

```python
import json, urllib.request
from sm_conformance.badge import verify_envelope

ORG = "http://localhost:7000"        # or https://<the org you are evaluating>

def get(url):
    with urllib.request.urlopen(url, timeout=30) as r:
        return json.load(r)

badge = get(f"{ORG}/.well-known/conformance.json")

# Keep the badge. Everything below this line works on the saved file alone.
with open("badge.json", "w") as f:
    json.dump(badge, f)

# 1. Resolve the org's identity independently of the badge.
did_doc = get(f"{ORG}/.well-known/did.json")
org_did = "did:key:" + did_doc["verificationMethod"][0]["publicKeyMultibase"]
assert badge["signed_by"] == org_did, "badge was not signed by this org"

# 2. Verify the signature. Raises if the badge was altered.
payload = verify_envelope(badge)

print("protocol versions :", payload["protocol_versions"])
print("checks passed     :", payload["passed"], "failed:", payload["failed"])
print("attestation       :", payload["extensions"]["org.orrery.attestation"])
```

## Checking it offline

The step above wrote `badge.json`. Verifying that file needs no network and no
contact with the org — disconnect and run:

```python
import json
from sm_conformance.badge import verify_envelope

badge = json.load(open("badge.json"))
payload = verify_envelope(badge)                     # raises if altered
assert badge["signed_by"] == "did:key:<the org DID you resolved earlier>"
print("checks passed :", payload["passed"], "failed:", payload["failed"])
```

That is what "verifies offline" means here: the signature check is arithmetic on
bytes you already hold. **You still need the org's DID**, which you resolved over
the network the first time — so keep it alongside the badge if you plan to check
it somewhere with no connection.

## Reading the result

| Field | What it means |
| --- | --- |
| `protocol_versions` | The protocol majors this org says it speaks |
| `passed` / `failed` / `skipped` | How the org's own conformance run came out |
| `skipped_vectors` | Named checks that did **not** run — read these, a skip is not a pass |
| `suite_digest` | Which version of the check suite produced the result |
| `completed_at` | When the org last ran it |
| `extensions.org.orrery.attestation` | `self-attested` — see above |

**A badge with a low check count is not a strong badge.** Read `passed` together
with `skipped_vectors` rather than treating the presence of a badge as the
result. A fresh org publishes a badge from its boot-time self-check, which is a
small suite by design.

## If a check fails

- **Signature verification raises** — the badge was altered after signing, or you
  fetched it from somewhere other than the org. Do not use it.
- **`signed_by` does not match the org's DID** — the badge belongs to someone
  else. This is the check that matters; treat a mismatch as a stop, not a warning.
- **`failed` is above zero** — the org is publishing that its own checks did not
  all pass. That is the badge working as intended; ask the operator about it.
