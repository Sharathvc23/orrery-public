# Licenses

What Orrery ships, what each part is licensed under, and where the answer was
read from. Orrery itself is MIT (`LICENSE`); `NOTICE` names the copyright
holder. This page is generated evidence, not a legal opinion: every license
below was read from the package's published metadata, the upstream
repository, or the artefact itself, and the reading is cited. "MIT-compatible"
means the license permits redistribution inside an MIT-licensed work with its
own notice retained; it says nothing about any other use.

The Python table is rendered from `scripts/license_manifest.json`, which
`scripts/license_gate.py --refresh` writes from PyPI's JSON metadata for every
pinned version, and which CI's `supply-chain-pins` job checks on every PR: a
pin the manifest has never seen, a license PyPI left blank, or a copyleft or
proprietary expression fails the build by name. Regenerate this table with
`python3 scripts/license_gate.py --table`.

## Python dependencies (every `name==version` pin)

Sources: `agent/requirements.lock` (agent image + smb_host, mcp_server,
smb_signup, smb_funnel), `server/requirements.lock` (server image),
`index/requirements.lock` (index image), `conformance/federation/requirements.txt`.
Where a package appears at two versions, the locks have drifted apart; both
are shipped and both are tabled. `agent/requirements-dev.lock` is not here by
design: it holds the test runner, linter and type checker and is installed
only where CI runs the agent's tests, never into an image (see
"Development tooling" below).

| package | version | license (PyPI) | where | verdict |
|---|---|---|---|---|
| annotated-doc | 0.0.4 | MIT | agent, server | ✅ MIT-compatible |
| annotated-doc | 0.0.5 | MIT | index | ✅ MIT-compatible |
| annotated-types | 0.7.0 | MIT | agent, server | ✅ MIT-compatible |
| annotated-types | 0.8.0 | MIT | index | ✅ MIT-compatible |
| anyio | 4.14.2 | MIT | agent, server | ✅ MIT-compatible |
| anyio | 4.15.1 | MIT | index | ✅ MIT-compatible |
| asyncpg | 0.31.0 | Apache-2.0 | server | ✅ MIT-compatible |
| attrs | 26.1.0 | MIT | agent, server | ✅ MIT-compatible |
| backports.tarfile | 1.2.0 | MIT | agent | ✅ MIT-compatible |
| base58 | 2.1.1 | MIT | agent, index, server | ✅ MIT-compatible |
| certifi | 2026.6.17 | MPL-2.0 | agent, server | ✅ MPL-2.0 file-level (kept verbatim) |
| cffi | 2.1.0 | MIT-0 | agent, server | ✅ MIT-compatible |
| cffi | 2.1.1 | MIT-0 | index | ✅ MIT-compatible |
| click | 8.4.2 | BSD-3-Clause | agent, server | ✅ MIT-compatible |
| click | 8.5.0 | BSD-3-Clause | index | ✅ MIT-compatible |
| cryptography | 50.0.0 | Apache-2.0 OR BSD-3-Clause | agent, server | ✅ MIT-compatible |
| cryptography | 50.0.1 | Apache-2.0 OR BSD-3-Clause | index | ✅ MIT-compatible |
| distro | 1.9.0 | Apache-2.0 | agent, server | ✅ MIT-compatible |
| dnspython | 2.8.0 | ISC | agent | ✅ MIT-compatible |
| fastapi | 0.139.0 | MIT | agent, server | ✅ MIT-compatible |
| fastapi | 0.141.1 | MIT | index | ✅ MIT-compatible |
| h11 | 0.16.0 | MIT | agent, index, server | ✅ MIT-compatible |
| httpcore | 1.0.9 | BSD-3-Clause | agent, server | ✅ MIT-compatible |
| httpx | 0.28.1 | BSD-3-Clause | agent, server | ✅ MIT-compatible |
| idna | 3.18 | BSD-3-Clause | agent, server | ✅ MIT-compatible |
| idna | 3.19 | BSD-3-Clause | index | ✅ MIT-compatible |
| importlib-metadata | 9.0.0 | Apache-2.0 | agent | ✅ MIT-compatible |
| jaraco.classes | 3.4.0 | MIT | agent | ✅ MIT-compatible |
| jaraco.context | 6.1.2 | MIT | agent | ✅ MIT-compatible |
| jaraco.functools | 4.5.0 | MIT | agent | ✅ MIT-compatible |
| jcs | 0.2.1 | Apache-2.0 | agent, index, server | ✅ MIT-compatible |
| jeepney | 0.9.0 | MIT | agent | ✅ MIT-compatible |
| jiter | 0.16.0 | MIT | agent, server | ✅ MIT-compatible |
| jsonschema-specifications | 2025.9.1 | MIT | agent, server | ✅ MIT-compatible |
| jsonschema | 4.26.0 | MIT | agent, server | ✅ MIT-compatible |
| keyring | 25.7.0 | MIT | agent | ✅ MIT-compatible |
| markdown-it-py | 4.2.0 | MIT | agent, server | ✅ MIT-compatible |
| mdurl | 0.1.2 | MIT | agent, server | ✅ MIT-compatible |
| mnemonic | 0.21 | MIT | agent | ✅ MIT-compatible |
| more-itertools | 11.1.0 | MIT | agent | ✅ MIT-compatible |
| openai | 2.45.0 | Apache-2.0 | agent, server | ✅ MIT-compatible |
| packaging | 26.2 | Apache-2.0 OR BSD-2-Clause | agent | ✅ MIT-compatible |
| pycparser | 3.0 | BSD-3-Clause | agent, index, server | ✅ MIT-compatible |
| pydantic-core | 2.46.4 | MIT | agent, server | ✅ MIT-compatible |
| pydantic-core | 2.46.5 | MIT | index | ✅ MIT-compatible |
| pydantic | 2.13.4 | MIT | agent, server | ✅ MIT-compatible |
| pydantic | 2.13.5 | MIT | index | ✅ MIT-compatible |
| pygments | 2.20.0 | BSD-2-Clause | agent, server | ✅ MIT-compatible |
| pynacl | 1.6.2 | Apache-2.0 | agent, server | ✅ MIT-compatible |
| python-dotenv | 1.2.2 | BSD-3-Clause | server | ✅ MIT-compatible |
| qrcode | 8.2 | BSD-3-Clause | server | ✅ MIT-compatible |
| referencing | 0.37.0 | MIT | agent, server | ✅ MIT-compatible |
| rich | 15.0.0 | MIT | agent, server | ✅ MIT-compatible |
| rpds-py | 2026.6.3 | MIT | agent, server | ✅ MIT-compatible |
| secretstorage | 3.5.0 | BSD-3-Clause | agent | ✅ MIT-compatible |
| sm-aae | 0.1.0 | MIT | agent, server | ✅ MIT-compatible |
| sm-arp | 0.3.2 | MIT | agent, server | ✅ MIT-compatible |
| sm-authority | 0.2.0 | MIT | agent | ✅ MIT-compatible |
| sm-bridge | 0.6.0 | MIT | agent, server | ✅ MIT-compatible |
| sm-conformance | 0.3.2 | MIT | agent, server | ✅ MIT-compatible |
| sm-divergence | 0.8.0 | MIT | server | ✅ MIT-compatible |
| sm-federation | 0.6.0 | MIT | conformance, server | ✅ MIT-compatible |
| sm-feed | 0.2.0 | MIT | server | ✅ MIT-compatible |
| sm-listing | 0.3.0 | MIT | server | ✅ MIT-compatible |
| sm-locp | 0.2.1 | MIT | server | ✅ MIT-compatible |
| sm-parc | 0.2.3 | MIT | agent | ✅ MIT-compatible |
| sm-resolver | 0.2.0 | MIT | server | ✅ MIT-compatible |
| sniffio | 1.3.1 | MIT OR Apache-2.0 | agent, server | ✅ MIT-compatible |
| sse-starlette | 3.4.5 | BSD-3-Clause | server | ✅ MIT-compatible |
| starlette | 1.3.1 | BSD-3-Clause | agent, server | ✅ MIT-compatible |
| starlette | 1.6.0 | BSD-3-Clause | index | ✅ MIT-compatible |
| tqdm | 4.68.4 | MPL-2.0 AND MIT | agent, server | ✅ MPL-2.0 file-level (kept verbatim) |
| typing-extensions | 4.16.0 | PSF-2.0 | agent, index, server | ✅ MIT-compatible |
| typing-inspection | 0.4.2 | MIT | agent, server | ✅ MIT-compatible |
| typing-inspection | 0.4.4 | MIT | index | ✅ MIT-compatible |
| uvicorn | 0.51.0 | BSD-3-Clause | agent, server | ✅ MIT-compatible |
| uvicorn | 0.52.4 | BSD-3-Clause | index | ✅ MIT-compatible |
| zipp | 4.1.0 | MIT | agent | ✅ MIT-compatible |

Notes on the MPL-2.0 entries — **policy, accepted by the maintainer
(2026-09-19):** MPL-2.0 is file-level copyleft. The MPL-licensed files stay
MPL and unmodified inside the package that carries them, which distribution
of the surrounding MIT work permits; nothing in this repository modifies
them. The gate therefore passes `MPL-2.0` (and `MPL-2.0 AND MIT`) and labels
it, rather than failing it. Today that is `certifi` (Mozilla's CA bundle)
and `tqdm`. Any project-level copyleft — GPL, LGPL, AGPL, SSPL, EUPL — still
fails.

`qrcode 8.2` declares `BSD` and carries two classifiers, `BSD License` and
`Other/Proprietary License`. The second is a packaging artefact of that
project; its repository's `LICENSE` (`lincolnloop/python-qrcode`) is the
BSD-3-Clause text. Accepted as BSD-3-Clause by the maintainer; the reason is
recorded on the manifest entry itself, next to the metadata it explains.

### Development tooling (not shipped)

`agent/requirements-dev.lock` pins what CI installs to test, lint and
type-check the agent: `pytest 9.1.1` (MIT), `pytest-asyncio 1.4.0`
(Apache-2.0), `pytest-cov 7.1.0` (MIT), `coverage 7.15.0` (Apache-2.0),
`pluggy 1.6.0` (MIT), `iniconfig 2.3.0` (MIT), `mypy 2.2.0` (MIT),
`mypy-extensions 1.1.0` (MIT — its PyPI JSON declares nothing; the sdist's
`PKG-INFO` says `License-Expression: MIT`), `pathspec 1.1.1` (MPL-2.0),
`librt 0.13.0` (MIT), `ast-serialize 0.6.0` (MIT), `ruff 0.15.21` (MIT).
These used to sit in `requirements.lock` and shipped into the agent image;
they were moved out so the runtime carries no test or lint tooling. The file
is audited for CVEs by the same job as the runtime locks.

### Unpinned declarations

`mcp_server/pyproject.toml` declares `mcp>=1.24.0,<2.0.0` (MIT on PyPI) and
`skill/pyproject.toml` declares `httpx`, `base58`, `cryptography` (BSD-3-Clause,
MIT, Apache-2.0 OR BSD-3-Clause) — all resolved through the pinned locks above
in every image and CI job; neither package is published on its own.

## npm

`renderer/package.json` and `smb_funnel/package.json` declare **no runtime
dependencies** (`"dependencies"` absent); both ship framework-free ES modules
served as static files. The renderer's one `devDependency`, `playwright 1.61.1`
(Apache-2.0, with `playwright-core` Apache-2.0 and the optional `fsevents` MIT,
per `renderer/package-lock.json`), drives the end-to-end tests and is not
shipped. The gate refuses any runtime npm dependency until it learns npm
license metadata, so adding one is a visible change.

## Vendored and adapted code

| path | upstream | upstream license | what was taken | NOTICE |
|---|---|---|---|---|
| `server/nanda_models.py` | [projnanda/agentfacts-format](https://github.com/projnanda/agentfacts-format) — the NANDA AgentFacts schema | MIT — stated in that repository's README ("MIT License"); the repository has no `LICENSE` file and GitHub reports no license | Pydantic models written against `agentfacts_schema.json`; field names and structure follow the schema | proposed (see NOTICE) |
| `agent/community_member/a2a_models.py`, `a2a_rpc.py`, `a2a_card.py`, `a2a_client*.py` | [Google A2A protocol](https://github.com/a2aproject/A2A) specification v0.2 + current-spec method names | Apache-2.0 (the specification repository) | Hand-written models and a JSON-RPC handler implementing the published wire format; no code copied | proposed as a specification acknowledgement |
| `agent/community_member/_arp_verify/`, `_dat/`, `_merkle/`, `_conformance_vectors/` | this repository's own `conformance/arp`, `conformance/dat`, `conformance/merkle`, `vectors/signing` | MIT (first-party); lockstep guards `test_*_lockstep.py` | Byte-for-byte copies so the pip-installed agent needs no `conformance/` on its path | none needed |
| `agent/community_member/llm_runtime.py` ⇄ `server/llm_runtime.py` | first-party, byte-identical copies | MIT | one provider table in two runtimes | none needed |
| `vectors/signing/*.json`, `vectors/rotation/` | the NANDA Chapter Protocol conformance corpus, authored by this repository's maintainer | **first-party** — the maintainer's own work, licensed MIT here under `LICENSE` (confirmed 2026-09-19) | the signing and rotation test vectors, including the published test seed | none needed |
| `CODE_OF_CONDUCT.md` | [Contributor Covenant 2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/) | CC BY 4.0 | the text, adapted; attribution line present | attribution is in the file itself |

## Container base images

Both images are pulled by digest (`docker-compose.yml`, `infra/Dockerfile.*`);
nothing here redistributes them — a self-hoster's Docker pulls them.

| image | digest | what is inside | licenses |
|---|---|---|---|
| `python:3.12-slim` | `sha256:57cd7c3a…7710de` | Debian GNU/Linux 13 (trixie) userland; CPython 3.12.13 | CPython: PSF-2.0 (`/usr/local/lib/python3.12/LICENSE.txt` in the image); Debian packages: each its own, per `/usr/share/doc/*/copyright`; the Docker Official Image's own scripts (docker-library/python): MIT |
| `pgvector/pgvector:pg15` | `sha256:a20a57d7…3cc62` | PostgreSQL 15.18 (`PG_VERSION=15.18-1.pgdg12+1`) on Debian 12; the pgvector extension | PostgreSQL: PostgreSQL License; pgvector: PostgreSQL License (`LICENSE` in `pgvector/pgvector` — "Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group"); Debian packages as above |

Neither image carries OCI license labels (`docker image inspect … .Config.Labels` → `null` for both), so the column above was read from the artefacts and upstream repositories, not from image metadata.

## Assets

No fonts are shipped or fetched: every stylesheet uses a system font stack
(`ui-monospace, "SF Mono", Menlo, Consolas, monospace`, and the sans-serif
equivalents). No icon library, no CDN reference (`server/tests/test_csp.py`
asserts the CSP refuses one). The one binary asset in the tree is
`docs/images/conformance-badge.webp`, a screenshot committed by the maintainer
with the agent-native pivot and currently referenced by no page. The project logo (`orrery.svg`)
lives in the public landing repository, not here; it is first-party, drawn
in-house, and carries that repository's MIT license (confirmed 2026-09-19).

## Third-party services a self-hoster may opt into

None is required: a stock `./orrery-up` contacts nothing beyond package and
image pulls (measured by packet capture, 2026-09-19). Each of the following is
reached only after an operator sets the variable named. Pointers only; the
terms are theirs to read.

| service | enabled by | terms |
|---|---|---|
| NANDA NEST registry (`nest.projectnanda.org`) | `REGISTRY_URL` | no terms page located; site root https://nest.projectnanda.org/ |
| NANDA Index (`api.nandaindex.org`) | `NANDA_INDEX_URL`, or an explicit `discover()` call | no terms page located; project site https://nandaindex.org/ |
| host39 card hosting (`agentcards.host39.org`) | `HOST39_BASE_URL` + credential | no terms page located; https://host39.org/ |
| Klaviyo (outbound email) | the external-send live transport flag + Klaviyo key | https://www.klaviyo.com/legal/terms-of-service |
| Anthropic | `LLM_PROVIDER=anthropic` / `AGENT_PROVIDER` + key | https://www.anthropic.com/legal/commercial-terms |
| OpenAI | `LLM_PROVIDER=openai` + key | https://openai.com/policies/terms-of-use |
| xAI | `LLM_PROVIDER=xai` + key | https://x.ai/legal/terms-of-service |
| Groq | `LLM_PROVIDER=groq` + key | https://groq.com/terms-of-use |
| Ollama (local) | `LLM_PROVIDER=ollama` | runs on the operator's machine; no service terms |
| Google (owner OIDC) | the owner wizard's OIDC step, `google` provider | https://policies.google.com/terms |
| Microsoft (owner OIDC) | the owner wizard's OIDC step, `microsoft` provider | https://www.microsoft.com/servicesagreement |
