### Fixed — `community-member audit verify` no longer reports a ledger as verified when rows were not written by the agent

The command printed `Audit chain verified` in green with the row count and the
number of signatures checked, and discarded `unsigned_rows`. On a ledger where
some rows carry no signature — rows the agent did not write — an operator read a
green success line and would have had to subtract the two numbers themselves to
notice.

`verify_chain` now returns `authenticated` alongside `ok`, and the command
reports the three states separately:

- every row signed: `Audit chain verified and authenticated`
- some rows unsigned: `Audit chain consistent; NOT authenticated`, with the
  count and what it means — those rows were not written by the agent
- no signing key: `Audit chain consistent; authenticity NOT CHECKED`, saying
  there is no key to check against

`ok` is unchanged and still answers one question: is the chain internally
consistent — do the hashes link, is nothing reordered or dropped. It stays true
for a ledger that ran before a signing key was configured, because such a ledger
is honestly consistent. Making `ok` mean "signed" would have flipped the verdict
on every one of those to answer a question `ok` was never asking.

`authenticated` is `True` only when the ledger is keyed and every row carries a
verifying signature, and `None` — not `False` — when no key is configured. There
is nothing to verify against, and "cannot be determined" is a different answer
from "was checked and failed"; calling an honest pre-key ledger unauthenticated
would say it had been tampered with. `None` is falsy, so a caller testing
`if not report["authenticated"]` fails closed on the undetermined case while one
that needs the distinction can test for it.

The subsystem's own documentation said an attacker replacing the SQLite file
"cannot fabricate rows without also forging the signature". `sha256_of` is
public, so an appended row can carry a correct hash and leave the chain
consistent; it is the signature it cannot carry. That is now stated where it was
claimed.
