### Security — the browser executor is bounded by a capability policy

`BrowserExecutor` had no policy field and performed no origin check, so a
navigation that cleared the consent gate could reach any URL, driving a
persistent Chromium profile that holds the agent's cookies. The four other
action executors have been policy-gated since they were written.

Grants for `browser.*` are origins — `https://*.example.com` — not hostnames.
The scheme is required and matched exactly, because a hostname grant would also
authorise the cleartext scheme for the same host and put that cookie jar on the
wire in clear. The port is optional and defaults from the scheme. The host
component uses the same wildcard as `net.http`, from a single shared
implementation so the two cannot drift.

Consent and policy are both required and neither replaces the other: the gate
authorises one action at one origin, the policy says which origins are reachable
at all. The two refusals are distinguishable — `approval_not_found_or_expired`
against `sandbox_policy_deny` — and the policy is checked before the browser is
launched, so an ungranted origin is never contacted.
