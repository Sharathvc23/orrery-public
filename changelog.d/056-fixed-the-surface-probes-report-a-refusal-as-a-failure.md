### Fixed — the surface probes report a refusal as a failure

`scripts/e2e_probes.py` called `.json()` on eight responses without checking
the status first. A non-2xx body is still valid JSON, so `.get(key, default)`
returned the default and a refused request was reported as missing data — an
authentication failure surfaced as "no Agency Log receipt available to
disclose". Those eight sites now go through `json_or_fail`, which fails on any
non-2xx status and names it.
