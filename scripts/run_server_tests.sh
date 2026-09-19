#!/usr/bin/env bash
#
# Run the server suite and make a FATAL-SIGNAL exit legible.
#
# The problem this solves is not the crash — it is what the crash looks like.
# When the interpreter dies on SIGSEGV, pytest never reaches its summary: the
# job just ends with exit 139 and no failing test, no traceback footer, nothing
# to read. On CI that is an unexplained red `server` job that goes green on
# re-run, which trains people to hit retry. A gate people retry past is not a
# gate — that is the actual cost of the segfault investigation, more than the crash itself.
#
# So this wrapper adds exactly one thing: a loud, unmistakable explanation when
# the exit code says "killed by a signal".
#
# It deliberately does NOT retry, does NOT swallow the failure, and does NOT
# change the exit code. The segfault investigation rules out retry wrappers, and it is right to —
# a re-run would hide the very signal this is meant to surface. The job still
# fails; it just fails *legibly*.
#
# Usage (from server/):  ../scripts/run_server_tests.sh -q --cov=. ...
# Every argument is passed straight through to pytest.

set -uo pipefail

PYTHON="${PYTHON:-python}"

# -X faulthandler makes the interpreter dump a Python traceback for every thread
# on a fatal signal. Without it the segfault is silent; with it the trace names
# the frame that was executing, which is how the segfault investigation was diagnosed at all.
PYTHONFAULTHANDLER=1 "$PYTHON" -X faulthandler -m pytest "$@"
rc=$?

if [ "$rc" -ge 128 ]; then
    sig=$((rc - 128))
    signame="$(kill -l "$sig" 2>/dev/null || echo "unknown")"
    cat >&2 <<BANNER

================================================================================
  THE TEST PROCESS WAS KILLED BY A SIGNAL — this is NOT a normal test failure
================================================================================

  exit code : $rc  (128 + signal $sig, SIG${signame})

  There is no test summary above because the interpreter died before pytest
  could print one. The last test that started is the one it died DURING — not
  necessarily the one at fault.

  If this is SIGSEGV (exit 139), it is very likely the segfault investigation: an intermittent
  segfault during garbage collection, with a suspended asyncpg connect() frame
  reachable at collection time. Known characteristics:

    * Intermittent — roughly 4 in 20 full-suite runs when first seen, then 0 in
      32 consecutive runs. A clean re-run proves NOTHING.
    * The test named in the trace is the VICTIM, not the culprit. The crash is
      triggered by whatever allocation happened to run the collector.

  DO NOT simply re-run this job. A green re-run is the expected behaviour of
  this bug, not evidence it is gone.

  What to do instead:
    1. Save this job's full log — the faulthandler trace above it is the
       evidence, and it is not reproducible on demand.
    2. Read docs/DEBUGGING_SERVER_SIGSEGV.md — it has the diagnosis so far,
       what has been ruled out, and how to re-run the instrumentation.
    3. Attach the trace to the segfault investigation.

================================================================================

BANNER
fi

exit "$rc"
