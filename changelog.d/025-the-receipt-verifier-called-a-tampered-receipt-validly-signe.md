### The receipt verifier called a tampered receipt validly signed

`verify.mjs` printed, for a receipt whose signature had just failed:

```
UNCONFIRMED ?  the signature is valid, but no --issuer was given so nobody checked who signed it.
```

An `--issuer` had been given, the signature was not valid, and the exit code was
`3` — the code meaning nobody checked. The output was **byte-identical** to the
benign case of an honest receipt nobody had anchored, so the two outcomes a
person most needs to tell apart were the same bytes.

`src/arp.js` was right throughout. `verifyReceipt` returns
`provenance: "unknown"` for two unrelated outcomes — a signature that FAILED, and
a signature that passed with no expected issuer supplied — because in neither
case is there anything to say about whose key it is. The CLI branched on
`provenance` before it looked at `stage`, so the broken-signature case took the
branch written for the unchecked-issuer case. The outcome is now decided on
`stage`: only stage `provenance` means the signature itself was good.

A valid signature made by a key that is not `--issuer` is now its own outcome
too, `MISMATCH`, with its own exit code — the same three-outcome vocabulary the
browser badge uses. Reporting it as a failed signature sends an operator hunting
a corrupted file when what they have is a rotation or someone else's receipt.
Exit codes: `0` verified, `1` failed, `2` unreadable, `3` unconfirmed, `4`
mismatch.

**Two green suites could not see this, and neither was looking at the output.**
`tests/provenance.test.mjs` covers the library, which was never wrong. The e2e
script ran the CLI over a tampered receipt as `>/dev/null 2>&1 && die || ok` —
asserting the exit was non-zero and discarding every byte the operator would
read, so it was satisfied by the wrong outcome. `tests/verify-cli.test.mjs` now
runs the binary as a subprocess over all five cases and asserts the printed line
and the exit code for each, including that no two outcomes share either — the
assertion that catches this class without knowing its cause. The e2e script reads
the headline now rather than the exit code alone.
