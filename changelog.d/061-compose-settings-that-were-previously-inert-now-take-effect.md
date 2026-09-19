### ⚠️ Compose settings that were previously inert now take effect

Existing Compose operators should review `.env` before recreating the server.
`LLM_PROVIDER`, `LLM_MODEL`, `LLM_BASE_URL`, the two retention controls,
`ORG_ADMIN_TOKEN`, `KLAVIYO_LIVE_SENDS`, and `KLAVIYO_API_KEY` were documented
or present as template controls but previously did not reach the container. They
now take effect: the LLM values select model egress, retention values control
deletion, an explicit admin token supersedes the persisted token, and the
Klaviyo pair can enable live delivery after the existing exact or bounded
operator authorization.

The stock Compose fallback for an absent or empty `ORRERY_PROFILE` also changes
from `dev` to `prod`. This disables wildcard CORS and `/docs`, `/redoc`, and
`/openapi.json`; operators who intentionally need the prior local behavior must
set `ORRERY_PROFILE=dev`. `orrery-up` continues to write `dev` explicitly.
