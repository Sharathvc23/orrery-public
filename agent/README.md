# orrery-agent

The sovereign **agent** runtime an individual owns and points at an **org**. Signs
its own actions with its own `did:key`, keeps a local Agency Log, and exposes its work
as signed receipts and opt-in generative A2UI surfaces over a local API.

Each person runs their **own** agent, on **their own** machine — its identity is held
behind a passphrase only they have. It is *not* part of the org's `docker compose up`
(that's the org: server + Postgres); you run this yourself.

## Run your agent

```bash
cd agent
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install ".[ed25519]"     # the agent + its real did:key identity
community-member             # first-run wizard, then serves locally
```

The wizard (interactive) walks you through: name your agent, point it at your org's
URL, pick an LLM (Anthropic / OpenAI / xAI / Groq / **or a local Ollama** — or none),
and set a passphrase
(plus an optional *duress* passphrase). Then the agent runs **headless** — serving its
**local API** (`/api/local/*` — the consent queue, skills, Agency Log, settings) plus
its NANDA surfaces. There is no bundled web UI; drive it via the API or `community-member`.

The agent **auto-picks a free port** (preferring 7777, then the next one free if
something else already holds it) and prints the exact URL it's serving on. Set
`COMMUNITY_MEMBER_PORT` to change the preference.

Re-running `community-member` later just unlocks the existing agent. `community-member
--help` lists the other commands (`panic`, `keystore`, `audit`, `graduations`, …).

> First run with **no org yet**? The agent still runs; configure an LLM via the API or
> CLI and point it at an org later → it joins and shows up in that org's member directory.

Generative UI is opt-in: the agent emits [A2UI v0.10](../docs/specs/agui.md) surfaces
**as data** that any renderer can paint (the bundled reference renderer in
[`../renderer/`](../renderer/README.md) is one) — the agent ships the surface data.
See [`../docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md).

## Built-in skills

The agent ships a small starter pack of first-party skills (in `community_member/
builtin_skills/`) so a fresh agent can *do* things before you install anything.
They load automatically and are auto-granted their declared capabilities:

| Skill | Tools | Capability |
|---|---|---|
| `calc` | `evaluate` | _(none)_ |
| `datetime` | `now`, `today` | _(none)_ |
| `draft` | `draft` | _(none)_ |
| `files` | `read_file`, `write_file`, `list_dir` | `fs.read`, `fs.write` (sandboxed to `CONFIG_DIR/workspace`) |
| `summarize` | `summarize` | _(none)_ |
| `tasks` | `add_task`, `list_tasks`, `complete_task` | _(none)_ |
| `web_fetch` | `fetch` | `net.http` |

Skills are exposed to the LLM as `skill__<id>__<tool>` tools in the chat panel and
the legacy think loop, and dispatched through the same consent-checked
`skill_runtime.invoke_tool` path as installed third-party skills. They are **not**
advertised over A2A to remote agents — the wire surface stays protocol-only.
Each `builtin_skills/<name>/` is the canonical example of the skill contract: a
`skill.py` exporting `TOOLS = [{name, description, parameters, fn}]` plus a
`manifest.json` declaring `capabilities`.

MIT.
