### Security — the SSO configuration is scoped to this org and restricted to its leaders

`POST /api/chapter/sso` and `DELETE /api/chapter/sso/{chapter_id}` accepted any
caller holding a member signature and took the target org from the request, so a
member of one org could point another org at an identity provider of their
choosing with `enforce_sso` set, or remove that org's binding.
`GET /api/chapter/sso/{chapter_id}` required no authentication at all, so the
issuer, client id and enforcement flag of any org could be read before being
replaced.

All three now require `chapter_role` in `{leader, admin}` and operate on this
org's own id. Naming a different org is refused rather than silently redirected,
except on the write path, where the config is written to this org and the
response says so.

`chapter_sso_set` and `chapter_sso_clear` took no `Request` parameter, so a role
check was not merely missing but impossible without changing the signature —
the same shape as `chapter_audit_record` before its actor was bound.

**Scope of the exposure.** `chapter_auth.get_sso_config` has two callers: the
read endpoint and the org-security A2UI surface. No authentication path reads
it. Setting `enforce_sso` changes what that surface displays — a "required
(login blocked without)" label and a posture of "private" — and blocks no login.
The configuration is displayed and not enforced, so this was a takeover of a
setting that misreports an org's security posture rather than one that admits an
attacker. A test asserts the caller set, so a future change that begins
enforcing SSO cannot do so without noticing what is already in the table.
