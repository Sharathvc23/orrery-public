### Security — an approval is verified before the consent gate honours it

`gate.find_valid_approval` read a candidate row's `expires_at` and its four
match fields out of the consent ledger and checked nothing else, so anything
able to write `~/.community-member/consent.db` could append a
`consent.approved` row for any capability with any expiry and have it honoured.

Each candidate row now goes through `ledger.verify_row`, which checks two
properties: that `event_sha256` re-derives from the row's own fields, and that
its Ed25519 signature over that hash verifies against the configured key.
Recomputing a correct hash is trivial because the algorithm is public, so the
signature is what distinguishes a row `record()` wrote from one it did not. A
row failing either check is not honoured.

A row that fails verification is skipped and reported; the scan continues.
Refusing the whole ledger on one bad row would let a single appended row stop
every subsequent approval, which the same file-write access could trigger
deliberately. Skipping is also the fail-closed direction here: an unverified
row is never acted on.

`ledger.verify_chain` is not called on this path. It answers a different
question — whether the ledger is complete and in order — and it is O(chain)
where this read is O(1). Measured on a keyed ledger: the verified read is
0.16ms at 100 rows and 0.25ms at 20,000, while a full chain verification of the
same ledger is 4ms and 766ms. The ledger grows with every consent decision, so
that cost has no ceiling. No bounded or partial chain walk is performed or
claimed.

Verification is applied where a row grants authority, not where it withholds
it. `find_recent_denial` and the consumed-approval tombstones are not verified:
skipping an unverifiable denial would make the action executable, which is the
unsafe direction, while a forged denial can only suppress.

`verify_chain` now also reports `unsigned_rows`. A row carrying no signature
does not break the hash chain — a ledger that ran before a signing key was
configured has such rows legitimately — so the count is what makes them
visible.

On a ledger with no signing key there is nothing to verify authenticity
against. Row integrity is still checked; write access to the file remains
sufficient to forge an approval there.
