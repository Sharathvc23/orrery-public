### The rate limiter's salt names its source, and `/health` says whether a restart restores anything

Limiter buckets are snapshotted to Postgres and restored at boot, keyed by
`HMAC-SHA256(salt, client IP)` so the table never holds an address. Restore
matches by equality of that hash, so the snapshot is worth nothing unless the
next process hashes with the same salt. The salt lived in one place: a file
under the server's `.org` directory.

**Measured on a deployed three-org mesh: the server service mounted no volume.**
Every restart minted a fresh salt file, every restored hash was an orphan no
client would ever be looked up under, and the limiter booted empty — the
behaviour persistence was added to remove — while `/health` reported
`rate_limit_persistence: true` on all three, and the boot log counted the
orphaned rows as buckets "carried across the restart". The flag attested that
the table was writable. It said nothing about whether a restart would restore
anything, and nothing else did either.

**The salt now has a named source.** `ORRERY_RATE_LIMIT_SALT` is the operator-held
source for a service with no persistent filesystem; it is a secret, at least 16
characters, and it stays outside the database — a salt beside the hashes would
let a table dump be turned back into IPs, which is the constraint the hashing
exists for, and it holds in every branch. The file remains the source for an
install whose data directory persists (stock Compose mounts it on a volume), and
it is reported durable only once it has actually been read back after a boot:
`file-new` on the boot that mints it, `file` from the next one on. A volume-less
service therefore reads `file-new` on every boot, which is the symptom, stated.
An unset variable degrades to the file by name; a too-short one is **rejected**
by name — `env-rejected`, ephemeral salt in use, boot log says so — rather than
silently used or silently replaced by the file, because the operator chose the
environment and the surface should show that choice failing. A directory that
cannot be written is `ephemeral`.

**`/health` carries two facts in two fields.** `rate_limit_persistence` is
unchanged: the table is writable. `rate_limit_salt` is
`{"source": ..., "durable": ...}`, with `durable` true only for `env` and `file`.
Not folded into the existing flag, because a single boolean is exactly what read
true while the property it named did not hold. A process whose salt is not
durable skips the restore rather than counting orphaned rows as carried.

Guarded, each planted and observed reddening by name, the tree clean after
each revert:

* **a salt that changed between boots is reported not-durable, not true** —
  planted as `file-new` counting as durable (seven tests, including the
  volume-less two-boot case and the health field), and again as `/health`
  reporting `durable` from the table flag, the original defect (two tests).
* **an unset or unusable salt source degrades by name** — planted as an
  unwritable file reported as `file`, and as a too-short operator value accepted
  silently; the health test reddens in both.
* **with a stable salt, the buckets restored after a boot match what was
  flushed** — planted three ways: the file path returning fresh bytes while
  claiming `file`; the restore gate inverted; and the wiring hashing under
  bytes other than the resolved salt. The two-boot test through the real
  resolver reddens under all three.
* **the measurement is held** — salt A flushes a full bucket, salt B restores
  it, the client's key under B is not there and the client is admitted.

`ORRERY_RATE_LIMIT_SALT` is classified in the environment-read guard as a
security-relevant value; the guard was observed failing without the entry. The
two snapshot tuning variables, previously undocumented, are in the configuration
reference beside it, and the reference no longer says limiter state "is not
persisted".
