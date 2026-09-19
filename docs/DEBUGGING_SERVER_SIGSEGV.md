# Intermittent SIGSEGV in the server suite

Working notes. **Status: the leak the trace implicates has been removed; the
crash itself is NOT confirmed fixed, because it could not be reproduced.** Read
that sentence literally — this document exists so the next person does not have
to re-derive what was ruled out, and does not mistake a green run for a fix.

## Victim vs culprit — answered

**`server/tests/test_registry_divergence.py:140` is the victim.** The issue
suspected as much and asked for confirmation before anyone "fixed" that file.
Confirmed, with evidence:

- Line 140 is `client = MagicMock()` inside the `_client_for` helper. Nothing
  there is unsafe; it is an allocation, and allocations are what run the
  collector.
- Instrumenting every `asyncpg` entry point across a full run recorded **zero**
  calls from `test_registry_divergence.py`. It never touches asyncpg at all.
- The crash trace's *lower* frame — `asyncpg/connection.py` inside `connect()` —
  cannot originate in that file.

Changing line 140 would have moved the crash somewhere else and looked like a
fix. It is not one.

## What was actually leaking

`pg_store.py` carries the comment *"Execution (asyncpg; exercised by the docker
e2e, not the mocked unit tests)"*. **That was false.** A full-suite trace of
`asyncpg.connect` / `asyncpg.create_pool` recorded **29 real entry-point calls
from 8 test modules**, and a socket-layer trace recorded **23 real TCP connects
to port 5432** — all aimed at `postgres://test@localhost/test`, the URL
`tests/conftest.py` sets, pointing at a database that does not exist.

| Test module | asyncpg calls | Runs before the crash file? |
|---|---:|---|
| `test_openclaw_interop.py` | 13 | yes |
| `test_digest_rate_limit.py` | 10 | yes |
| `test_cors_public_read.py` | 1 | yes |
| `test_db_reliability.py` | 1 | yes |
| `test_dsar_admin_money_authz.py` | 1 | yes |
| `test_openclaw_version_gate.py` | 1 | yes |
| `test_org_roles.py` | 1 | yes |
| `test_spec_05_advertisement.py` | 1 | no (file that change) |

Seven of the eight run *before* `test_registry_divergence.py` (collection
position that change of ~250 files), which is exactly the window the theory needs.

Every attempt failed, and `_get_pool`'s `except Exception` swallowed it — so the
suite stayed green and the drift was invisible for as long as it existed.

**Why the failures still matter.** Each attempt builds asyncpg's
C-extension-backed connection machinery on a per-test event loop that
pytest-asyncio (`asyncio_mode = "auto"`, function-scoped loops) then closes. A
coroutine still suspended when its loop closes is not finalised there — it stays
reachable and is finalised later, by the garbage collector, on a different loop,
with the C extension's state no longer valid. That is precisely the shape of the
captured trace: interpreter mid-collection, suspended `connect()` frame beneath.

This is not the suite's first brush with it. `test_spec_05_advertisement.py`'s
fixture docstring already records a segfault under coverage, attributed to
"asyncpg/cffi extension state" surviving a `chapter_agent` module re-import —
and 28 test modules do `sys.modules.pop` / `importlib.reload` of `chapter_agent`
or `admin`.

## The change

`tests/conftest.py::pytest_configure` replaces asyncpg's `connect` and
`create_pool` with an immediate `ConnectionRefusedError`, unless
`ORRERY_ALLOW_REAL_DB=1` is set (the docker e2e genuinely wants a live database).

It is **behaviour-preserving by construction**: the connection attempt was
already guaranteed to fail in this suite, and `_get_pool` already returns `None`
on any exception, so every caller sees exactly what it saw before. What changes
is that no socket is opened and no C-backed connection object is ever built.

Measured, same commit, full suite:

| | real TCP connects to :5432 | wall clock |
|---|---:|---:|
| before (`ORRERY_ALLOW_REAL_DB=1`) | 23 | 35.2s |
| after | **0** | **24.3s** |

The ~31% speedup is incidental — the suite was spending eleven seconds waiting
on refused connections.

Deliberately **not** `gc.disable()`, **not** a retry wrapper, **not** test
reordering. Those hide the signal that a connection is being leaked. This
removes the leak. `tests/test_no_real_db_connections.py` holds the line, and one
of its cases asserts the conftest's *executable code* contains none of those
techniques.

## Non-reproduction at merged main (2026-08-03)

The fix landing is not the evidence — a heisenbug is closed by failing to
reproduce it, not by a merge. So it was re-run at merged main, on **both**
interpreters, because it was observed on 3.11 while CI pins 3.12 and exercising
only CI's would leave the observed configuration untested.

| Interpreter | asyncpg | Full-suite runs | Segfaults | Any non-zero exit |
|---|---|---:|---:|---:|
| **3.11.14** — the configuration it was observed in | 0.31.0 | **40** | **0** | 0 |
| **3.12.3** — CI's | 0.31.0 | **25** | **0** | 0 |

Each run was the whole suite (2626 passed, 4 skipped), under `-X faulthandler`,
with both loops running concurrently so the box stayed under CPU contention —
the condition the original reporter noted they had also tested under.

**The runs exercise genuinely fixed code, not accidentally-still-broken code.**
Verified separately at the same commit with a socket-level tracer: **0 real TCP
connects to port 5432**, down from 23 before the fix. Without this check, clean
runs would be uninterpretable — they could just mean the leak never fired.

### How much that is worth, stated honestly

With 0 events in 40 runs the rule of three puts the 95% upper bound on the
per-run crash rate at **≤7.5%** on 3.11, and ≤4.6% across all 65 — against the
**~20%** originally observed (~4 in ~20). Under that original rate, 40 clean
runs has probability 0.8⁴⁰ ≈ **1 in 7,500**.

**But run count alone does not settle it, and it would be dishonest to present
it as if it did.** The reporter's own **32 consecutive clean runs happened
*before* any fix** — at the observed rate that had probability ~1 in 1,090, so
the rate is plainly not stationary: it depends on timing, load and allocation
patterns that vary between sessions. No number of clean runs can prove absence
for a bug like this.

The case for closing therefore rests on **two independent legs, neither
sufficient alone**:

1. the mechanism the captured trace implicated is *measurably* gone (23 → 0
   real connects), and
2. 65 clean full-suite runs across both interpreters, bounding the rate well
   below what was originally seen.

Leg 1 is what makes leg 2 mean something.

## What is still NOT established

- **This is not a proof.** See above: a non-stationary intermittent fault cannot
  be proven absent by sampling. If it recurs, that is a bigger finding than the
  original — the leading theory was wrong — and it should be reported as such
  rather than re-fixed by analogy.
- **The two interpreters were never differently exposed.** Before the fix the
  mechanism was present identically on both — same asyncpg 0.31.0 C extension,
  same pytest-asyncio function-scoped loop teardown, same 23 real connects — so
  CI's 3.12 was never safer than local 3.11; it had simply run fewer times. The
  25 clean runs on 3.12 above are a check that the fix did not *introduce*
  anything there, not evidence that 3.12 was previously immune.
- **The module re-import path is untouched.** 28 modules pop/reload
  `chapter_agent` or `admin`, and that pattern has its own documented segfault
  in this suite. It is a second, independent candidate that this change does not
  address. If the segfault investigation recurs with the DB guard in place, that is where to look next.

## If it recurs

1. **Do not just re-run.** A green re-run is this bug's expected behaviour.
   `scripts/run_server_tests.sh` prints a banner saying so on any exit ≥ 128;
   CI's `server` job runs through it.
2. Save the full log — the faulthandler trace is the evidence and is not
   reproducible on demand.
3. Re-run the instrumentation. Both plugins are small and worth rebuilding:
   an asyncpg entry-point tracer (wrap `connect`/`create_pool`, record
   `PYTEST_CURRENT_TEST` + stack) and a socket tracer (wrap
   `socket.socket.connect`, record connects to :5432). Run with
   `ORRERY_ALLOW_REAL_DB=1` to compare against pre-fix behaviour.
4. Next suspect is the re-import path, not the DB path.
