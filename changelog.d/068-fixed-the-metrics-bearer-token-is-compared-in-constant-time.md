### Fixed — the /metrics bearer token is compared in constant time

The handler compared with `!=`, which stops at the first differing byte.
`admin.verify_admin_token` and `auth_verify` already used `hmac.compare_digest`
for the same job. Both sides are now encoded to bytes and compared with
`compare_digest`, so a non-ASCII token returns 401 rather than raising. The
`Bearer ` prefix is still compared plainly; the scheme name is not secret.
Recorded as C6 in `AUDIT_HARSH.md`, where the severity reasoning is unchanged and
the disposition is now fixed.
