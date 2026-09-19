### A booking receipt is checked against the business's own key, not only against itself

The customer's browser verified a receipt's Ed25519 signature under the `did:key`
named in the receipt. That proves the receipt is self-consistent — whoever signed
it holds the key it names — and cannot prove it came from the business the
customer dealt with, because the key and the claim about whose key it is both come
from the same document. A receipt minted with any key, carrying any summary,
satisfied that check and was shown as "Verified offline in your browser".

Verification now has a third stage. The business's `did:key` is read from its A2A
agent card, remembered in the browser the first time the customer deals with them,
and compared against every later receipt. A receipt signed by a different key is
refused; a receipt whose issuer cannot be checked reports that rather than
passing, because unknown provenance is not verification.

The badge says which of those happened instead of showing one tick for all of
them: "Verified offline — signed by this business", "Signature valid — issuer not
confirmed", "Signed by a different key than expected", or "Verification failed".

`verify.mjs` takes the same anchor as `--issuer`; without it the receipt is
reported `UNCONFIRMED` and the command exits 3.

Remembering an identity proves continuity rather than authenticity — it tells you
this is the same party as last time, and the browser store uses the same
trust-on-first-use states as the member agent's org trust, in the same words.
