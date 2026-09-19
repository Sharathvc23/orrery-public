### The SMB host has an operations page, and a persistent volume is not enough

`smb_host/README.md` showed how to start the service on a workstation; nothing
said what running it for other businesses entails. `smb_host/OPERATIONS.md` is
that page — what a tenant home holds, the settings an operator has to decide,
the post-deploy checks, and an explicit list of what the host does not do.

Writing it surfaced a durability failure worth stating on its own. A tenant's
Ed25519 key is encrypted under a keystore backend, and the default one in a
headless container derives its passphrase from a machine fingerprint that
includes the hostname. A container gets a new hostname on redeploy, so a vault
written by the previous container cannot be opened by the next one — and because
rehydration has no per-tenant error handling, the first undecryptable home raises
out of startup and the service does not come up at all. A persistent volume is
necessary and does not by itself preserve anything. Setting
`COMMUNITY_MEMBER_KEYSTORE=passphrase` with `COMMUNITY_MEMBER_PASSPHRASE` was
driven through the same restart and keeps the identity stable, including receipts
signed after it.

The page also records what the recovery phrase does and does not buy: it is
returned once and never written to disk, and no route on this host accepts one,
so it cannot put a business back on the host it was provisioned on.
