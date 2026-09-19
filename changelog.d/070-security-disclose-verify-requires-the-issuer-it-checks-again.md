### Security — `disclose verify` requires the issuer it checks against

`verify_disclosure` made two checks and both took their key material from the
bundle. The credential's Ed25519 proof verifies under the `did:key` named in
`credential.issuer`, and each Merkle inclusion proof folds to the
`behavioral_merkle_root` that same credential signs. A bundle whose credential,
root and receipts were produced by one keypair satisfies both checks, for any
keypair. The function took no expected issuer, so
`community-member disclose verify` reported `Disclosure verified` and exited 0
for a bundle assembled by whoever presented it.

`verify_disclosure(bundle, *, expected_issuer)` now requires a `did:key` obtained
independently of the bundle and compares it with `credential.issuer` as a third
check. The CLI requires one of two flags: `--issuer <did:key>`, or
`--issuer-from <org-url>`, which builds the `did:key` from
`<org-url>/.well-known/did.json` as described in `docs/VERIFY_A_RECEIPT.md` and
performed by `scripts/receipt_verify_canary.py`. A mismatch reports the `did:key`
the credential carries and exits 2.

`inspect_disclosure` reports the structural checks alone — `credential_ok` and
per-receipt `included`. It returns no `ok` field, because those two checks do not
establish who issued a bundle.

No code under `server/` reads a PARC credential, so an org's own trust decisions
were unaffected. The behaviour applied to a party checking a bundle presented to
it.

`docs/PRODUCT.md` and `README.md` described the bundle as verifying fully
offline. The comparison and both proofs run offline once the verifier holds the
issuer's `did:key`; obtaining that from an org's DID document is a network fetch.
Both files now state this.

`agent/tests/test_receipt_disclosure.py` asserts that a bundle signed by an
unrelated key passes both structural checks, is refused against a different
issuer, and is accepted against the key that signed it; that calling
`verify_disclosure` without an expected issuer raises; that `""` and `None` do
not pass; and that the CLI exits 2 on a mismatch.
