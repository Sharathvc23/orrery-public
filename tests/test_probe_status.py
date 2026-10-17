"""Guards on the difference between a card that is absent and a host that is asleep.

``catalog_canary`` asserted "every entry an org advertises resolves" by treating
every non-200 identically. On 2026-10-16, the first run after the canaries were
armed, it failed on three HTTP 502s — regentix-head-of-sales, regentix-cto and
astrocity-executive-director — each of which returned 200 when re-probed by hand
minutes later, twice, with no intervention. Idle containers waking up.

That is a FALSE RED of the same family as the false greens the canary was built
to remove: its result did not depend on the condition it claims to check. It
reported "this org advertises a URL nothing backs"; it had observed "this host
had not served a request lately".

Two properties here matter more than the rest, and they pull against each other:

``test_a_persistent_not_ready_is_still_a_failure`` — the retry must not become a
way to pass. If three 502s in a row read as OK, the false red has been traded
for a false green, which is a worse bug in the same place.

``test_the_not_ready_remedy_does_not_tell_anyone_to_publish_a_card`` — the
wrong-advice half. The original failure text said to run
``publish_host39_card.py --record-on-org``, which for a 502 points the operator
at a missing card that is not missing.

And the source guards: the canary makes THREE live calls, not one. The catalog
fetch and ``GET /agents/root`` were both outside the retry at first, and the
second is the sharper one — a cold start there returned no identifier, which
``floor_verdict`` correctly fails CLOSED on, so a sleeping container
MANUFACTURED a floor breach on a healthy org. The fix was to retry before
reaching the fail-closed path; ``test_an_unreadable_org_identifier_fails_closed``
in ``test_catalog_floor`` holds the other side of that and must keep passing.

Driven directly against ``scripts/_probe_status.py``, which is stdlib-only, and
with the retry loop living there rather than in the canary for exactly this
reason: ``doc-guards`` installs nothing but pytest, so a guard needing ``httpx``
is a guard that job cannot run. Transport failures are classified by exception
class name up the MRO for the same reason, which is why the fakes below rebuild
httpx's hierarchy by NAME instead of importing it.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_SCRIPTS = _ROOT / "scripts"


def _probe_status():
    """Import ``scripts/_probe_status.py`` by path, without a package."""
    path = _SCRIPTS / "_probe_status.py"
    spec = importlib.util.spec_from_file_location("_probe_status", path)
    assert spec and spec.loader, f"cannot load {path}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _canary_source() -> str:
    return (_SCRIPTS / "catalog_canary.py").read_text(encoding="utf-8")


class _Response:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


# httpx's hierarchy, rebuilt by NAME. ConnectError/ReadTimeout are what a cold
# start looks like when the gateway does not even answer, and the classifier has
# to recognise them without importing the library the canary job installs.
class TransportError(Exception):
    pass


class ConnectError(TransportError):
    pass


class _Recorder:
    """A fake ``get`` that replays a scripted sequence and counts its calls."""

    def __init__(self, *outcomes) -> None:
        self.outcomes = list(outcomes)
        self.calls = 0

    def __call__(self, url: str):
        self.calls += 1
        outcome = self.outcomes[min(self.calls, len(self.outcomes)) - 1]
        if isinstance(outcome, BaseException):
            raise outcome
        return _Response(outcome)


def _sleeps() -> tuple[list, object]:
    waited: list[float] = []
    return waited, waited.append


def test_a_resolvable_card_passes_on_the_first_attempt():
    probe_status = _probe_status()
    get = _Recorder(200)
    waited, sleep = _sleeps()
    result = probe_status.probe(get, "https://x/card", sleep=sleep)
    assert result.verdict == probe_status.OK
    assert (result.attempts, get.calls, waited) == (1, 1, [])
    assert not result.woke


def test_a_404_is_absent_and_is_not_retried():
    """Waiting does not make an unpublished card appear.

    Retrying it would only slow down the one outcome that was always correct —
    and would blur the measurement the whole fix rests on.
    """
    probe_status = _probe_status()
    get = _Recorder(404)
    waited, sleep = _sleeps()
    result = probe_status.probe(get, "https://x/card", sleep=sleep)
    assert result.verdict == probe_status.ABSENT
    assert (result.attempts, get.calls, waited) == (1, 1, [])


@pytest.mark.parametrize("transient", [502, 503, 504, ConnectError("connection reset")])
def test_a_cold_start_resolves_on_the_retry(transient):
    """The measured condition: 502 first, 200 moments later, no intervention."""
    probe_status = _probe_status()
    get = _Recorder(transient, 200)
    waited, sleep = _sleeps()
    result = probe_status.probe(get, "https://x/card", sleep=sleep)
    assert result.verdict == probe_status.OK
    assert (result.attempts, get.calls) == (2, 2)
    assert waited == [probe_status.BACKOFF_SECONDS[0]], "the backoff was skipped or wrong"
    # The caller has to be ABLE to say it woke — a silent retry deletes the
    # signal that a host is asleep on every single run.
    assert result.woke


def test_a_persistent_not_ready_is_still_a_failure():
    """The retry must not become a way to pass.

    If a host that 502s on every attempt reads as OK, the false red has been
    traded for a false green: a real outage absorbed by its own monitor. This is
    the property that makes the rest of the fix safe.
    """
    probe_status = _probe_status()
    get = _Recorder(502, 502, 502)
    waited, sleep = _sleeps()
    result = probe_status.probe(get, "https://x/card", sleep=sleep)
    assert result.verdict == probe_status.NOT_READY
    assert result.attempts == probe_status.ATTEMPTS
    assert not result.woke
    # No backoff after the final attempt — that would be dead time in every run.
    assert len(waited) == probe_status.ATTEMPTS - 1
    assert "all 3 attempt(s)" in result.describe(), "the report must say it kept trying"


def test_an_unexpected_exception_is_not_mistaken_for_a_cold_start():
    """A bug in our own code must not be retried three times and then blamed on a host."""
    probe_status = _probe_status()
    get = _Recorder(ValueError("bad url"))
    waited, sleep = _sleeps()
    result = probe_status.probe(get, "https://x/card", sleep=sleep)
    assert result.verdict == probe_status.OTHER
    assert (result.attempts, get.calls, waited) == (1, 1, [])
    assert "ValueError" in result.describe()


def test_an_unclassified_status_is_reported_rather_than_bucketed():
    probe_status = _probe_status()
    result = probe_status.probe(_Recorder(418), "https://x/card", sleep=lambda _s: None)
    assert result.verdict == probe_status.OTHER
    assert "418" in result.describe()


def test_the_not_ready_remedy_does_not_tell_anyone_to_publish_a_card():
    """The wrong-advice half of the incident.

    For a 502 the card EXISTS; the service is the problem. The absent remedy —
    publish the card — is advice for a condition the operator does not have.
    """
    probe_status = _probe_status()
    (not_ready,) = probe_status.remediation_for([probe_status.NOT_READY])
    assert "publish_host39_card" not in not_ready.replace("publish_host39_card.py for these", "")
    assert "ANSWERED" in not_ready
    (absent,) = probe_status.remediation_for([probe_status.ABSENT])
    assert "publish_host39_card.py --record-on-org" in absent


def test_only_the_observed_verdicts_get_a_remedy():
    """A run with nothing but cold starts must not also print the card advice."""
    probe_status = _probe_status()
    assert probe_status.remediation_for([]) == []
    both = probe_status.remediation_for([probe_status.NOT_READY, probe_status.ABSENT, probe_status.ABSENT])
    assert len(both) == 2
    # Stable order, absent first: it is the finding that needs a human sooner.
    assert "nothing backs" in both[0]


def test_the_canary_routes_every_live_call_through_the_probe():
    """Three call sites, not one — and the one that was easiest to miss was fatal.

    A bare ``client.get(`` anywhere in the canary is a call outside the retry.
    The entry loop was the visible one; the catalog fetch turned a cold start
    into "catalog unreadable", and ``GET /agents/root`` turned one into a
    manufactured FLOOR BREACH.
    """
    source = _canary_source()
    assert "from _probe_status import" in source, "the canary does not import the classifier"
    assert "client.get(" not in source, "an HTTP call bypasses probe() — it will cry wolf on a cold start"
    probed = [ln for ln in source.splitlines() if "probe(client.get" in ln]
    assert len(probed) >= 3, f"expected the catalog, each entry and /agents/root to be probed, saw {len(probed)}"
    for surface in ("/.well-known/ai-catalog.json", "/agents/root"):
        assert any(surface in ln for ln in probed), f"{surface} is fetched outside probe()"


def test_the_canary_says_when_something_had_to_be_woken():
    """A green run that needed a retry is green AND worth knowing about."""
    source = _canary_source()
    assert "woke:" in source, "a retry that leaves no trace in the log is a deleted signal"
    assert "needed a retry" in source, "the run-level summary of cold starts is gone"


def test_the_canary_reports_a_not_ready_host_separately_from_an_absent_card():
    source = _canary_source()
    assert "never became ready" in source, "the two diagnoses share one heading again"
    assert "remediation_for(" in source, "the remediation no longer branches on what was measured"
