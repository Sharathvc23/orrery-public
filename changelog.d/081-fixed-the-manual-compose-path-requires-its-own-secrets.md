### Fixed — the manual Compose path requires its own secrets

`docs/CONFIGURATION.md` described the stock install, `cp .env.example .env`, as safe
for public exposure. On the manual Compose path it was not: `POSTGRES_PASSWORD` held
a published placeholder and `ORRERY_KEY_SECRET`, which seals data at rest, was
empty. `./orrery-up` generates both; the manual path does not.

The manual path now requires fresh values for both before first start, and `.env` is
created owner-readable before secrets are written to it. LLM provider keys remain
optional and are documented separately. The `prod` profile description is scoped to
the surfaces it hardens rather than to public-deployment readiness generally. Raw
Compose (the org) and `orrery-up` (the org plus a joined local agent) are documented
as different setups.

No runtime behaviour changed; the Compose file's only edit is its header comment.
Regression tests cover the copy-and-start sequence and the public-readiness wording.
