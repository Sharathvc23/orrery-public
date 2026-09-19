"""
A2A v0.2 client — talk to *any* A2A-compliant agent (not just our chapter).

This is the outbound counterpart to community_member.server's A2A endpoints.
Our legacy A2AClient in a2a_client.py speaks the chapter's REST shape; this
module speaks Google A2A JSON-RPC.

Use case: a member's agent wants to hire another agent it discovered via
the NANDA Index or a peer referral. It fetches that agent's
/.well-known/agent.json, picks a skill that looks relevant, and invokes
it through tasks/send (or tasks/sendSubscribe for streaming).

Class naming: `GoogleA2AClient` (sync) + `AsyncGoogleA2AClient` (async)
to avoid colliding with the legacy `a2a_client.A2AClient`. The historical
alias `A2AClient` is exported for backwards-compat within this module.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import AsyncIterator, Iterator
from typing import Any

import httpx

from .a2a_models import AgentCard


class A2AClientError(Exception):
    """Raised when an A2A call returns a JSON-RPC error envelope."""

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(f"A2A error {code}: {message}")
        self.code = code
        self.message = message
        self.data = data


class ActionSucceededUnreceipted(RuntimeError):
    """The external call RETURNED — the action happened — and the receipt stage
    then failed. Carries the call's result so a caller can use it, and the
    attempt id so the owed receipt can be traced. Distinct from a failed call
    on purpose: retrying this would perform the action a second time.
    """

    def __init__(self, attempt_id: str, result: dict[str, Any], cause: BaseException) -> None:
        super().__init__(
            f"action succeeded but its receipt was not recorded (attempt {attempt_id}): {type(cause).__name__}: {cause}"
        )
        self.attempt_id = attempt_id
        self.result = result
        self.cause = cause


def classify_send_failure(exc: BaseException) -> str:
    """Whether a raised ``tasks/send`` means the action did NOT happen
    (``failed``) or its outcome is not known (``unknown``).

    The old docstring said a raised call "records nothing (a receipt attests an
    action that actually happened)" — which reads "did not happen" into every
    exception. A connection refused before the request left did not happen. A
    read timeout after the request left, or a 5xx from a counterparty that may
    already have acted, is not knowable from here; recording it as failed would
    invite a retry that performs the action twice. Anything unrecognised is
    ``unknown``, the direction that never over-claims.
    """
    if isinstance(exc, A2AClientError):
        # The counterparty answered with a JSON-RPC error: it declined the task.
        return "failed"
    if isinstance(exc, httpx.ConnectError | httpx.ConnectTimeout | httpx.UnsupportedProtocol | httpx.InvalidURL):
        return "failed"  # the request never left
    return "unknown"


# ─── Shared helpers (sync + async use these) ────────────


def _envelope(method: str, params: dict[str, Any]) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": f"req-{uuid.uuid4().hex[:8]}",
        "method": method,
        "params": params,
    }


def _build_send_params(
    tool: str,
    args: dict[str, Any],
    *,
    task_id: str | None = None,
    session_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> tuple[str, dict[str, Any]]:
    """Build the tasks/send params dict and return (task_id, params)."""
    task_id = task_id or f"task-{uuid.uuid4().hex[:12]}"
    params: dict[str, Any] = {
        "id": task_id,
        "message": {
            "role": "user",
            "parts": [{"type": "data", "data": {"tool": tool, "args": args}}],
        },
    }
    if session_id is not None:
        params["sessionId"] = session_id
    if metadata is not None:
        params["metadata"] = metadata
    return task_id, params


def _unwrap_result(envelope: dict[str, Any]) -> dict[str, Any]:
    """Raise A2AClientError on error envelope, else return the `result` dict."""
    if envelope.get("error"):
        err = envelope["error"]
        raise A2AClientError(err["code"], err["message"], err.get("data"))
    return envelope["result"]


def _signed_headers(
    body: str,
    agent_id: str | None,
    private_key: str | None,
    public_key: str | None,
    scheme: str | None = None,
) -> dict[str, str]:
    """Generate X-Agent-* headers. Same scheme auth.verify_request_headers uses.

    The earlier version of this function guessed the signature scheme from
    private-key length, but Ed25519 private keys (32-byte seeds) are the
    same 44 base64 chars as HMAC-SHA256 keys — so the heuristic silently
    picked HMAC for genuine Ed25519 credentials, breaking verification on
    the server side. Pick the scheme explicitly instead: the caller passes
    one in, or we default to Ed25519 whenever pynacl is available (same
    rule auth.init_keys() uses server-side).

    Takes the caller's key as a parameter (not module state) so one process
    can authenticate as multiple identities to different remote agents.
    """
    headers = {"Content-Type": "application/json"}
    if not (agent_id and private_key):
        return headers

    from .crypto import build_did_key, ed25519_available, ed25519_sign_message, sign_message

    if scheme is None:
        scheme = "ed25519" if ed25519_available() else "hmac-sha256"
    scheme = scheme.lower()

    ts = str(int(time.time()))
    message = f"{body}:{agent_id}:{ts}"

    if scheme == "ed25519":
        sig = ed25519_sign_message(message, private_key)
        headers.update(
            {
                "X-Agent-ID": agent_id,
                "X-Agent-Signature": sig,
                "X-Agent-Timestamp": ts,
                "X-Agent-Sig-Scheme": "ed25519",
            }
        )
        if public_key:
            try:
                headers["X-Agent-DID-Key"] = build_did_key(public_key)
            except Exception:
                pass
        return headers

    sig = sign_message(message, private_key)
    headers.update(
        {
            "X-Agent-ID": agent_id,
            "X-Agent-Signature": sig,
            "X-Agent-Timestamp": ts,
            "X-Agent-Sig-Scheme": "hmac-sha256",
        }
    )
    if public_key:
        headers["X-Agent-Public-Key"] = public_key
    return headers


def _parse_sse_stream(lines: Iterator[str]) -> Iterator[dict[str, Any]]:
    """Parse SSE lines into JSON-RPC response dicts.

    Consumes only `data:` lines (event:, id:, retry: are accepted but
    ignored — our server doesn't emit them). Empty line terminates one
    event block. Malformed JSON is skipped rather than raised so a single
    bad frame doesn't take down the stream.
    """
    buf: list[str] = []
    for raw in lines:
        line = raw.rstrip("\r")
        if line == "":
            if buf:
                payload = "\n".join(buf)
                buf.clear()
                try:
                    yield json.loads(payload)
                except json.JSONDecodeError:
                    continue
            continue
        if line.startswith("data:"):
            buf.append(line[len("data:") :].strip())
    # Flush trailing event if stream ended without a blank line.
    if buf:
        try:
            yield json.loads("\n".join(buf))
        except json.JSONDecodeError:
            pass


async def _parse_sse_stream_async(
    lines: AsyncIterator[str],
) -> AsyncIterator[dict[str, Any]]:
    """Async twin of _parse_sse_stream — same semantics."""
    buf: list[str] = []
    async for raw in lines:
        line = raw.rstrip("\r")
        if line == "":
            if buf:
                payload = "\n".join(buf)
                buf.clear()
                try:
                    yield json.loads(payload)
                except json.JSONDecodeError:
                    continue
            continue
        if line.startswith("data:"):
            buf.append(line[len("data:") :].strip())
    if buf:
        try:
            yield json.loads("\n".join(buf))
        except json.JSONDecodeError:
            pass


# ─── Sync client ────────────────────────────────────────


class GoogleA2AClient:
    """Synchronous A2A client — call other agents over HTTP JSON-RPC."""

    def __init__(
        self,
        base_url: str,
        *,
        agent_id: str | None = None,
        private_key: str | None = None,
        public_key: str | None = None,
        sig_scheme: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.agent_id = agent_id
        self.private_key = private_key
        self.public_key = public_key
        self.sig_scheme = sig_scheme
        self._client = httpx.Client(timeout=timeout)

    def close(self) -> None:
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # Discovery
    def fetch_agent_card(self) -> AgentCard:
        resp = self._client.get(f"{self.base_url}/.well-known/agent.json")
        resp.raise_for_status()
        return AgentCard.model_validate(resp.json())

    # tasks/*
    def send_task(
        self,
        tool: str,
        args: dict[str, Any],
        *,
        task_id: str | None = None,
        session_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        _, params = _build_send_params(tool, args, task_id=task_id, session_id=session_id, metadata=metadata)
        return self._rpc("tasks/send", params)

    def send_task_recorded(
        self,
        tool: str,
        args: dict[str, Any],
        *,
        counterparty_did: str,
        counterparty_label: str,
        sk_bytes: bytes,
        agency_log: Any,
        category: str = "message_sent",
        chapter_url: str | None = None,
        push: bool = False,
        cosign: bool = True,
        task_id: str | None = None,
        session_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """``send_task`` that auto-emits a signed ARP receipt on success —
        with the attempt written to the Agency Log BEFORE the call.

        The receipt names the counterparty by DID, so the interaction graph
        populates itself from real A2A calls. A receipt is recorded ONLY for an
        observed success; a call that raised produces no receipt. That is not
        the same as recording nothing: this method used to run the call and
        THEN build/sign/persist the receipt, so a kill between the two, a raise
        in the receipt stage, or a timeout after the counterparty had already
        acted left an action that happened with no trace, and the docstring's
        "a failed/raised call records nothing" read "did not happen" into every
        exception.

        Now, in order: ``agency_log.begin_action`` (durable, ``pending``) →
        ``send_task`` → the attempt is finalized ``failed`` (request never left
        / counterparty declined), ``unknown`` (timeout or transport error after
        the request left, non-2xx — see :func:`classify_send_failure`) or
        ``succeeded`` with the receipt id. A process that dies in between leaves
        the ``pending`` row, which ``AgencyLog.reconcile_orphans`` marks
        ``unknown`` at the next start; it is never retried by the runtime.

        ``task_id`` doubles as the attempt's ``action_ref``: a retry with the
        same id after a success or an unknown outcome is refused before it is
        sent (:class:`~community_member.arp.DuplicateActionError`), so one
        action cannot yield two receipts or run twice. Pass one whenever a
        retry is possible; without it every call is a distinct action.

        If the call returned and the receipt stage then raised, the attempt is
        finalized ``succeeded`` with no receipt id (a receipt is owed; listed by
        ``unresolved_actions``) and :class:`ActionSucceededUnreceipted` is
        raised carrying the result — a caller that catches it must not retry.

        With ``cosign=True`` (default), the counterparty is asked to co-sign the
        receipt over the same A2A connection (``nanda/cosignReceipt``) before it
        is finalized, making it **corroborated** — the form that builds reputation
        under ``nanda-rep/0.2`` (spec/arp/0.2/cosign-companion.md §1). A
        counterparty that declines or cannot co-sign yields a valid, uncorroborated
        receipt; the call never fails for lack of a witness (§3).
        """
        from .arp import did_from_private_key
        from .interactions import record_interaction

        summary = f"Called {counterparty_label} ({tool})."
        attempt_id = agency_log.begin_action(
            issuer_did=did_from_private_key(sk_bytes),
            category=category,
            summary=summary,
            counterparty_did=counterparty_did,
            counterparty_label=counterparty_label,
            action_ref=task_id,
            detail={"tool": tool, "base_url": self.base_url},
        )
        try:
            result = self.send_task(tool, args, task_id=task_id, session_id=session_id, metadata=metadata)
        except BaseException as e:
            agency_log.finalize_action(
                attempt_id, classify_send_failure(e), detail={"error": f"{type(e).__name__}: {e}"}
            )
            raise
        # From here on the action HAPPENED. Nothing below may lose that fact.
        try:
            receipt = record_interaction(
                sk_bytes=sk_bytes,
                agency_log=agency_log,
                counterparty_did=counterparty_did,
                counterparty_label=counterparty_label,
                summary=summary,
                category=category,
                chapter_url=chapter_url,
                push=push,
                witness_fetcher=self._cosign_fetcher() if cosign else None,
            )
        except BaseException as e:
            agency_log.finalize_action(
                attempt_id, "succeeded", receipt_id=None, detail={"receipt_error": f"{type(e).__name__}: {e}"}
            )
            raise ActionSucceededUnreceipted(attempt_id, result, e) from e
        agency_log.finalize_action(attempt_id, "succeeded", receipt_id=receipt["receipt_id"])
        return result

    def _cosign_fetcher(self):
        """A ``WitnessFetcher`` that asks the connected counterparty to co-sign an
        unsigned receipt over this A2A connection. Returns the witness entry, or
        ``None`` on decline / any transport error (treated as uncorroborated)."""

        def fetch(unsigned_receipt: dict[str, Any]) -> dict[str, Any] | None:
            try:
                result = self._rpc("nanda/cosignReceipt", {"receipt": unsigned_receipt})
            except Exception:
                return None
            entry = result.get("witness") if isinstance(result, dict) else None
            return entry if isinstance(entry, dict) else None

        return fetch

    def get_task(self, task_id: str) -> dict[str, Any]:
        return self._rpc("tasks/get", {"id": task_id})

    def cancel_task(self, task_id: str) -> dict[str, Any]:
        return self._rpc("tasks/cancel", {"id": task_id})

    def stream_task(
        self,
        tool: str,
        args: dict[str, Any],
        *,
        task_id: str | None = None,
        session_id: str | None = None,
    ) -> Iterator[dict[str, Any]]:
        _, params = _build_send_params(tool, args, task_id=task_id, session_id=session_id)
        yield from self._rpc_stream("tasks/sendSubscribe", params)

    def resubscribe(self, task_id: str) -> Iterator[dict[str, Any]]:
        yield from self._rpc_stream("tasks/resubscribe", {"id": task_id})

    def legacy_task_census(self) -> dict[str, Any]:
        """How many creatorless tasks the peer holds, and what it cannot say.

        Signed like any other gated call — the peer refuses an anonymous caller.
        The reply separates ``measurement`` (records that exist; survives the
        peer's restart) from ``observation`` (what the peer's current process
        has seen; does not). Sum ``measurement.creatorless_tasks_present`` across
        agents for the fleet figure; no agent can answer for another.
        """
        return self._rpc("nanda/legacyTaskCensus", {})

    # Internals
    def _rpc(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        body = _envelope(method, params)
        body_text = json.dumps(body)
        resp = self._client.post(
            self.base_url + "/",
            content=body_text.encode(),
            headers=_signed_headers(body_text, self.agent_id, self.private_key, self.public_key, self.sig_scheme),
        )
        resp.raise_for_status()
        return _unwrap_result(resp.json())

    def _rpc_stream(self, method: str, params: dict[str, Any]) -> Iterator[dict[str, Any]]:
        body = _envelope(method, params)
        body_text = json.dumps(body)
        with self._client.stream(
            "POST",
            self.base_url + "/",
            content=body_text.encode(),
            headers={
                **_signed_headers(body_text, self.agent_id, self.private_key, self.public_key, self.sig_scheme),
                "Accept": "text/event-stream",
            },
        ) as resp:
            resp.raise_for_status()
            yield from _parse_sse_stream(resp.iter_lines())


# ─── Async client ───────────────────────────────────────


class AsyncGoogleA2AClient:
    """Asynchronous A2A client. Same surface as GoogleA2AClient."""

    def __init__(
        self,
        base_url: str,
        *,
        agent_id: str | None = None,
        private_key: str | None = None,
        public_key: str | None = None,
        sig_scheme: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.agent_id = agent_id
        self.private_key = private_key
        self.public_key = public_key
        self.sig_scheme = sig_scheme
        self._client = httpx.AsyncClient(timeout=timeout)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.aclose()

    async def fetch_agent_card(self) -> AgentCard:
        resp = await self._client.get(f"{self.base_url}/.well-known/agent.json")
        resp.raise_for_status()
        return AgentCard.model_validate(resp.json())

    async def send_task(
        self,
        tool: str,
        args: dict[str, Any],
        *,
        task_id: str | None = None,
        session_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        _, params = _build_send_params(tool, args, task_id=task_id, session_id=session_id, metadata=metadata)
        return await self._rpc("tasks/send", params)

    async def send_task_recorded(
        self,
        tool: str,
        args: dict[str, Any],
        *,
        counterparty_did: str,
        counterparty_label: str,
        sk_bytes: bytes,
        agency_log: Any,
        category: str = "message_sent",
        chapter_url: str | None = None,
        push: bool = False,
        cosign: bool = True,
        task_id: str | None = None,
        session_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Async twin of :meth:`GoogleA2AClient.send_task_recorded` — same
        write-ahead ordering, same states, same refusal of a duplicate
        ``task_id``; read that docstring for the contract.

        With ``cosign=True`` (default), the counterparty co-signs the receipt over
        this A2A connection (``nanda/cosignReceipt``) before it is finalized,
        making it corroborated under ``nanda-rep/0.2`` (cosign-companion.md §1).
        Build → await co-sign → sign mirrors the sync client; a declining or
        unreachable counterparty just yields an uncorroborated receipt (§3).
        """
        from .arp import did_from_private_key
        from .cosign import attach_entry
        from .interactions import build_interaction_receipt, finalize_interaction

        summary = f"Called {counterparty_label} ({tool})."
        attempt_id = agency_log.begin_action(
            issuer_did=did_from_private_key(sk_bytes),
            category=category,
            summary=summary,
            counterparty_did=counterparty_did,
            counterparty_label=counterparty_label,
            action_ref=task_id,
            detail={"tool": tool, "base_url": self.base_url},
        )
        try:
            result = await self.send_task(tool, args, task_id=task_id, session_id=session_id, metadata=metadata)
        except BaseException as e:
            agency_log.finalize_action(
                attempt_id, classify_send_failure(e), detail={"error": f"{type(e).__name__}: {e}"}
            )
            raise
        # From here on the action HAPPENED. Nothing below may lose that fact.
        try:
            receipt = build_interaction_receipt(
                sk_bytes=sk_bytes,
                counterparty_did=counterparty_did,
                counterparty_label=counterparty_label,
                summary=summary,
                agency_log=agency_log,
                category=category,
            )
            if cosign:
                entry: dict[str, Any] | None = None
                try:
                    res = await self._rpc("nanda/cosignReceipt", {"receipt": receipt})
                    entry = res.get("witness") if isinstance(res, dict) else None
                except Exception:
                    entry = None
                attach_entry(receipt, entry if isinstance(entry, dict) else None)
            finalize_interaction(
                receipt,
                sk_bytes=sk_bytes,
                agency_log=agency_log,
                chapter_url=chapter_url,
                push=push,
            )
        except BaseException as e:
            agency_log.finalize_action(
                attempt_id, "succeeded", receipt_id=None, detail={"receipt_error": f"{type(e).__name__}: {e}"}
            )
            raise ActionSucceededUnreceipted(attempt_id, result, e) from e
        agency_log.finalize_action(attempt_id, "succeeded", receipt_id=receipt["receipt_id"])
        return result

    async def get_task(self, task_id: str) -> dict[str, Any]:
        return await self._rpc("tasks/get", {"id": task_id})

    async def cancel_task(self, task_id: str) -> dict[str, Any]:
        return await self._rpc("tasks/cancel", {"id": task_id})

    async def stream_task(
        self,
        tool: str,
        args: dict[str, Any],
        *,
        task_id: str | None = None,
        session_id: str | None = None,
    ) -> AsyncIterator[dict[str, Any]]:
        _, params = _build_send_params(tool, args, task_id=task_id, session_id=session_id)
        async for event in self._rpc_stream("tasks/sendSubscribe", params):
            yield event

    async def resubscribe(self, task_id: str) -> AsyncIterator[dict[str, Any]]:
        async for event in self._rpc_stream("tasks/resubscribe", {"id": task_id}):
            yield event

    async def legacy_task_census(self) -> dict[str, Any]:
        """Async twin of :meth:`GoogleA2AClient.legacy_task_census`."""
        return await self._rpc("nanda/legacyTaskCensus", {})

    async def _rpc(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        body = _envelope(method, params)
        body_text = json.dumps(body)
        resp = await self._client.post(
            self.base_url + "/",
            content=body_text.encode(),
            headers=_signed_headers(body_text, self.agent_id, self.private_key, self.public_key, self.sig_scheme),
        )
        resp.raise_for_status()
        return _unwrap_result(resp.json())

    async def _rpc_stream(self, method: str, params: dict[str, Any]) -> AsyncIterator[dict[str, Any]]:
        body = _envelope(method, params)
        body_text = json.dumps(body)
        async with self._client.stream(
            "POST",
            self.base_url + "/",
            content=body_text.encode(),
            headers={
                **_signed_headers(body_text, self.agent_id, self.private_key, self.public_key, self.sig_scheme),
                "Accept": "text/event-stream",
            },
        ) as resp:
            resp.raise_for_status()
            async for event in _parse_sse_stream_async(resp.aiter_lines()):
                yield event


# Historical aliases. The class was originally exposed as A2AClient inside
# this module but the name collides with community_member.a2a_client.A2AClient
# (the legacy server REST client), so prefer the Google-prefixed names.
A2AClient = GoogleA2AClient
AsyncA2AClient = AsyncGoogleA2AClient
