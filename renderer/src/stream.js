/**
 * AG-UI SSE client for /api/surfaces/{page}/stream.
 *
 * Implements the hardened client rules from docs/specs/agui.md
 * (§AG-UI streaming — normative client behavior):
 *
 *   - Snapshot-replay backfill: every (re)connect starts a fresh run; the
 *     client discards held state at RunStarted and rebuilds from the next
 *     StateSnapshot. There is no Last-Event-ID resume — the snapshot IS the
 *     backfill.
 *   - Malformed deltas are rejected atomically (patch.js) and force a
 *     RESYNC (drop state, reconnect for a fresh snapshot). A delta is never
 *     partially applied, and a delta arriving before any snapshot is a
 *     protocol violation → resync.
 *   - Every snapshot and every patched document is re-validated as a full
 *     envelope before it is handed to the renderer; a delta that mutates
 *     the surface into an invalid envelope is treated as malformed.
 *   - Unknown event types are ignored (forward compatibility).
 *   - Reconnects use exponential backoff with jitter (1s base, 30s cap),
 *     reset after a healthy snapshot.
 *
 * Transport is fetch + ReadableStream rather than EventSource so the same
 * code runs in the browser, in `node --test`, and in the compose e2e probe.
 */

import { normalizeEnvelope } from "./envelope.js";
import { applyDelta } from "./patch.js";

const MAX_EVENT_BYTES = 2_000_000;
const MAX_GARBAGE_EVENTS = 20;

/** Incremental SSE frame parser: feed text chunks, get `data:` payloads. */
export class SseParser {
  constructor() {
    this.buffer = "";
  }

  /** @returns {string[]} complete event data payloads */
  feed(chunk) {
    this.buffer += chunk;
    if (this.buffer.length > MAX_EVENT_BYTES * 2) {
      // Hostile/broken upstream never terminating a frame — drop the buffer.
      this.buffer = "";
      return [];
    }
    const out = [];
    let idx;
    while ((idx = this.buffer.search(/\n\n|\r\n\r\n/)) !== -1) {
      const rawFrame = this.buffer.slice(0, idx);
      this.buffer = this.buffer.slice(idx + (this.buffer[idx] === "\r" ? 4 : 2));
      const dataLines = [];
      for (const line of rawFrame.split(/\r?\n/)) {
        if (line.startsWith("data:")) dataLines.push(line.slice(5).replace(/^ /, ""));
      }
      if (dataLines.length) out.push(dataLines.join("\n"));
    }
    return out;
  }
}

/**
 * Pure protocol state machine — transport-free so tests can drive it with
 * raw chunks. Emits via callbacks:
 *   onSurface(normalizedEnvelope, rawDoc)  — render this
 *   onStatus(state, detail)                — "run-started" | "resync" | "error" | "finished"
 */
export class AgUiSession {
  constructor({ onSurface, onStatus } = {}) {
    this.onSurface = onSurface || (() => {});
    this.onStatus = onStatus || (() => {});
    this.parser = new SseParser();
    this.rawDoc = null; // last VALID surface document (as sent on the wire)
    this.garbage = 0;
    this.needsResync = false;
  }

  /** Feed a transport chunk. Returns false once the session wants a resync. */
  feed(chunk) {
    for (const payload of this.parser.feed(chunk)) {
      if (this.needsResync) break;
      this.handlePayload(payload);
    }
    return !this.needsResync;
  }

  resync(detail) {
    this.needsResync = true;
    this.rawDoc = null;
    this.onStatus("resync", detail);
  }

  handlePayload(payload) {
    if (payload.length > MAX_EVENT_BYTES) {
      this.countGarbage("oversized event");
      return;
    }
    let event;
    try {
      event = JSON.parse(payload);
    } catch {
      this.countGarbage("unparseable event JSON");
      return;
    }
    if (event === null || typeof event !== "object" || typeof event.type !== "string") {
      this.countGarbage("event without a type");
      return;
    }

    switch (event.type) {
      case "RunStarted":
        // Fresh run boundary: anything we held belongs to the previous run.
        this.rawDoc = null;
        this.onStatus("run-started", typeof event.runId === "string" ? event.runId : "");
        return;
      case "StateSnapshot": {
        const normalized = normalizeEnvelope(event.snapshot);
        if (!normalized.ok) {
          this.resync(`snapshot rejected: ${normalized.reason}`);
          return;
        }
        this.rawDoc = event.snapshot;
        this.garbage = 0;
        this.onSurface(normalized, this.rawDoc);
        return;
      }
      case "StateDelta": {
        if (this.rawDoc === null) {
          this.resync("delta before snapshot");
          return;
        }
        const patched = applyDelta(this.rawDoc, event.delta);
        if (!patched.ok) {
          this.resync(`malformed delta: ${patched.detail}`);
          return;
        }
        const normalized = normalizeEnvelope(patched.doc);
        if (!normalized.ok) {
          this.resync(`delta produced an invalid envelope: ${normalized.reason}`);
          return;
        }
        this.rawDoc = patched.doc;
        this.onSurface(normalized, this.rawDoc);
        return;
      }
      case "RunError":
        this.onStatus("error", typeof event.message === "string" ? event.message.slice(0, 500) : "run error");
        return;
      case "RunFinished":
        this.onStatus("finished", "");
        return;
      default:
        // Unknown AG-UI event types (TextMessage*, ToolCall*, future
        // additions) are not for us — ignore, never resync.
        return;
    }
  }

  countGarbage(detail) {
    this.garbage += 1;
    if (this.garbage > MAX_GARBAGE_EVENTS) this.resync(`too many malformed events (${detail})`);
  }
}

/**
 * Transport wrapper: connects, feeds an AgUiSession, reconnects with
 * backoff. Backoff resets after any successful snapshot.
 */
export class SurfaceStream {
  constructor(url, { onSurface, onStatus, fetchImpl, minDelayMs = 1000, maxDelayMs = 30000 } = {}) {
    this.url = url;
    this.onSurface = onSurface || (() => {});
    this.onStatus = onStatus || (() => {});
    this.fetchImpl = fetchImpl || ((...args) => globalThis.fetch(...args));
    this.minDelayMs = minDelayMs;
    this.maxDelayMs = maxDelayMs;
    this.attempt = 0;
    this.stopped = false;
    this.abort = null;
  }

  nextDelay() {
    const exp = Math.min(this.maxDelayMs, this.minDelayMs * 2 ** Math.min(this.attempt, 10));
    return exp / 2 + Math.random() * (exp / 2); // jitter in [exp/2, exp)
  }

  stop() {
    this.stopped = true;
    if (this.abort) this.abort.abort();
  }

  async run() {
    while (!this.stopped) {
      const session = new AgUiSession({
        onSurface: (normalized, raw) => {
          this.attempt = 0; // healthy snapshot/delta → reset backoff
          this.onSurface(normalized, raw);
        },
        onStatus: this.onStatus,
      });
      try {
        this.abort = typeof AbortController === "function" ? new AbortController() : null;
        const resp = await this.fetchImpl(this.url, {
          headers: { accept: "text/event-stream" },
          signal: this.abort ? this.abort.signal : undefined,
        });
        if (!resp.ok || !resp.body) {
          this.onStatus("error", `stream HTTP ${resp.status}`);
        } else {
          const reader = resp.body.getReader();
          const decoder = new TextDecoder();
          for (;;) {
            const { done, value } = await reader.read();
            if (done || this.stopped) break;
            if (!session.feed(decoder.decode(value, { stream: true }))) {
              // Session demanded a resync — drop this connection and refetch
              // a fresh snapshot (the backfill path).
              this.abort?.abort();
              break;
            }
          }
        }
      } catch (e) {
        if (!this.stopped) this.onStatus("error", e instanceof Error ? e.message : "stream failed");
      }
      if (this.stopped) return;
      this.attempt += 1;
      this.onStatus("reconnecting", `attempt ${this.attempt}`);
      await new Promise((res) => setTimeout(res, this.nextDelay()));
    }
  }
}
