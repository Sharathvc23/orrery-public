### The key-encryption secret rotates through a previous secret instead of re-keying the org

`ORRERY_KEY_SECRET` seals the org's Ed25519 signing key and members' provider
keys at rest. Changing it made every sealed row undecryptable — the signing key
first — so a leaked key-encryption secret could only be rotated by re-keying the
org and having every federated peer re-pin its `did:key`. The deploy guide said
"never rotate it casually" and offered no procedure, because none existed: the
secret that protects the identity could not itself be replaced without
replacing the identity.

`ORRERY_KEY_SECRET_PREVIOUS` is the secret being rotated out. It is read-only:
a value that fails to open under the current secret is tried under it, and
nothing is ever sealed under it. The boot-time seal-in-place migrations that
already rewrote legacy plaintext rows now also rewrite rows sealed under the
previous secret, under the current one — the `chapter_keys` row, the offline key
file and each `agent_api_keys` row — so a rotation is: set both, restart once,
watch the boot log reseal, unset the previous secret, restart again. The key
bytes and the `did:key` never change. Those migration paths now unseal before
they reseal; sealing the stored blob as if it were plaintext would have wrapped
ciphertext in ciphertext and stranded the key, which the new test through the
real `chapter_keys` path is what caught.

A wrong current secret with no previous, or with a wrong previous, still fails
as before. Classified in the environment-read guard; the procedure is in the
configuration reference, the deploy guide and the backup guide.

Guarded, each planted and observed reddening by name, the tree clean after each
revert: `unseal` never trying the previous secret; `needs_migration` ignoring
values sealed under it (the old behaviour); the migration sealing the stored blob
instead of the plaintext; `seal` writing under the previous secret when one is
set.
