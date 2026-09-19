# NANDA Skill schemas — `skill/0.1`

- [`skill-manifest.schema.json`](./skill-manifest.schema.json) — the skill **manifest**: metadata for a signed, executable capability package.
- [`skill-package.schema.json`](./skill-package.schema.json) — the **`.nandaskill` package**: a downloadable, portable, signed skill bundle.

## The `.nandaskill` package (v0.1)

Today an org skill is *manifest + content-reference*: the registry stores the
manifest, a `content_sha256`, and an Ed25519 publisher signature over that hash.
A `.nandaskill` file makes the same skill a **self-contained, verifiable, portable
bundle** so trust travels with the file.

A `.nandaskill` file is a **ZIP** with exactly three members:

| Member | What |
|---|---|
| `manifest.json` | The skill manifest (readable JSON; `skill-manifest.schema.json`). |
| `content.bin` | The exact **signed content bytes** — the manifest in canonical form (sorted keys, compact separators, UTF-8). `sha256(content.bin) == content_sha256`. |
| `signature.json` | JCS-canonical record binding `{content_sha256, signing_key_did, signature}` — the detached publisher Ed25519 signature. |

### Signature (reused, not re-signed)

The `signature` in `signature.json` is the **existing** publisher signature — a
detached Ed25519 over `content_sha256` (the hex string), exactly as
`/api/skills/publish` verifies it. Packing needs **no private key**: it reuses
the signature the skill was published under, so a skill published via the manifest
path packs and re-verifies **unchanged**. The signing/verify machinery is not
touched.

### Verification is FAIL-CLOSED

A reader accepts a bundle only when **all** hold; any failure rejects the whole
package (nothing is installed or registered):

1. all three members are present and well-formed;
2. `sha256(content.bin) == signature.json.content_sha256` (content integrity);
3. `canonical(manifest.json) == content.bin` (the readable manifest is bound to
   the signed content — it cannot be swapped);
4. the Ed25519 `signature` verifies over `content_sha256` by `signing_key_did`.

### Registry / API surface (additive)

- `skill_registry.pack_skill(skill_id) -> bytes` — build the bundle from a
  published skill (reuses its stored signature).
- `skill_registry.verify_package_signature(bytes) -> bool` — fail-closed check.
- `skill_registry.publish_skill_from_package(bytes) -> skill` — verify, then
  register via the existing `publish_skill` path.
- `GET  /api/skills/{id}/package` → `application/zip` (keyless; the bundle is
  self-authenticating).
- `POST /api/skills/publish/package` → accepts a bundle body, verifies + registers
  (keyless, same class as `/api/skills/publish`; fail-closed on a bad/missing/
  tampered signature or a `content_sha256` mismatch).

Existing `/api/skills/publish`, `/api/skills`, `install_skill`, and
`verify_skill_signature` are unchanged.
