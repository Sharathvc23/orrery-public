import assert from "node:assert/strict";
import test from "node:test";

import { AgUiSession, SseParser } from "../src/stream.js";

const SURFACE = {
  createSurface: { surfaceId: "digest" },
  updateComponents: {
    surfaceId: "digest",
    root: "root",
    components: [
      { id: "root", component: "Column", children: ["t"] },
      { id: "t", component: "Text", text: "v1" },
    ],
  },
  version: "0.9",
};

const sse = (event) => `data: ${JSON.stringify(event)}\n\n`;

function makeSession() {
  const surfaces = [];
  const statuses = [];
  const session = new AgUiSession({
    onSurface: (n) => surfaces.push(n),
    onStatus: (state, detail) => statuses.push({ state, detail }),
  });
  return { session, surfaces, statuses };
}

test("SSE parser handles frames split across arbitrary chunk boundaries", () => {
  const parser = new SseParser();
  const wire = sse({ a: 1 }) + sse({ b: 2 });
  let events = [];
  for (const ch of wire) events = events.concat(parser.feed(ch)); // 1-byte chunks
  assert.deepEqual(events.map((e) => JSON.parse(e)), [{ a: 1 }, { b: 2 }]);
});

test("SSE parser handles CRLF frames and multi-line data", () => {
  const parser = new SseParser();
  const events = parser.feed('data: {"x":\r\ndata: 1}\r\n\r\n');
  assert.deepEqual(JSON.parse(events[0]), { x: 1 });
});

test("happy path: RunStarted → snapshot → delta paints twice", () => {
  const { session, surfaces } = makeSession();
  session.feed(sse({ type: "RunStarted", runId: "r1", threadId: "t" }));
  session.feed(sse({ type: "StateSnapshot", snapshot: SURFACE }));
  const next = structuredClone(SURFACE);
  next.updateComponents.components[1].text = "v2";
  session.feed(sse({ type: "StateDelta", delta: [{ op: "replace", path: "", value: next }] }));
  assert.equal(surfaces.length, 2);
  assert.equal(surfaces[1].components.get("t").text, "v2");
  assert.equal(session.needsResync, false);
});

test("targeted delta ops patch the held document", () => {
  const { session, surfaces } = makeSession();
  session.feed(sse({ type: "StateSnapshot", snapshot: SURFACE }));
  session.feed(
    sse({ type: "StateDelta", delta: [{ op: "replace", path: "/updateComponents/components/1/text", value: "patched" }] }),
  );
  assert.equal(surfaces[1].components.get("t").text, "patched");
});

test("delta before any snapshot is a protocol violation → resync", () => {
  const { session, statuses } = makeSession();
  const alive = session.feed(sse({ type: "StateDelta", delta: [{ op: "replace", path: "", value: SURFACE }] }));
  assert.equal(alive, false);
  assert.equal(statuses[0].state, "resync");
  assert.match(statuses[0].detail, /delta before snapshot/);
});

test("malformed delta → rejected atomically, resync, no partial render", () => {
  const { session, surfaces, statuses } = makeSession();
  session.feed(sse({ type: "StateSnapshot", snapshot: SURFACE }));
  const alive = session.feed(
    sse({
      type: "StateDelta",
      delta: [
        { op: "replace", path: "/updateComponents/components/1/text", value: "half" },
        { op: "explode", path: "/x" },
      ],
    }),
  );
  assert.equal(alive, false);
  assert.equal(surfaces.length, 1, "a partially-valid delta must not paint");
  assert.equal(surfaces[0].components.get("t").text, "v1");
  assert.ok(statuses.some((s) => s.state === "resync" && /malformed delta/.test(s.detail)));
});

test("a delta that mutates the surface into an invalid envelope → resync", () => {
  const { session, surfaces, statuses } = makeSession();
  session.feed(sse({ type: "StateSnapshot", snapshot: SURFACE }));
  const alive = session.feed(sse({ type: "StateDelta", delta: [{ op: "remove", path: "/updateComponents" }] }));
  assert.equal(alive, false);
  assert.equal(surfaces.length, 1);
  assert.ok(statuses.some((s) => s.state === "resync" && /invalid envelope/.test(s.detail)));
});

test("invalid snapshot → resync, nothing painted", () => {
  const { session, surfaces, statuses } = makeSession();
  const alive = session.feed(sse({ type: "StateSnapshot", snapshot: { version: "9.9" } }));
  assert.equal(alive, false);
  assert.equal(surfaces.length, 0);
  assert.ok(statuses.some((s) => s.state === "resync" && /snapshot rejected/.test(s.detail)));
});

test("RunStarted resets held state — a delta right after it must resync", () => {
  const { session } = makeSession();
  session.feed(sse({ type: "StateSnapshot", snapshot: SURFACE }));
  session.feed(sse({ type: "RunStarted", runId: "r2", threadId: "t" }));
  const alive = session.feed(sse({ type: "StateDelta", delta: [{ op: "replace", path: "", value: SURFACE }] }));
  assert.equal(alive, false, "state from a previous run must not accept the new run's deltas");
});

test("unknown event types and garbage lines are ignored without resync", () => {
  const { session, surfaces } = makeSession();
  session.feed(sse({ type: "StateSnapshot", snapshot: SURFACE }));
  session.feed(sse({ type: "TextMessageContent", messageId: "m", delta: "hi" }));
  session.feed("data: this is not json\n\n");
  session.feed(sse({ type: 42 }));
  assert.equal(session.needsResync, false);
  assert.equal(surfaces.length, 1);
});

test("sustained garbage eventually forces a resync (flood guard)", () => {
  const { session } = makeSession();
  session.feed(sse({ type: "StateSnapshot", snapshot: SURFACE }));
  for (let i = 0; i < 25 && !session.needsResync; i++) session.feed("data: garbage\n\n");
  assert.equal(session.needsResync, true);
});

test("RunError / RunFinished surface as statuses, not crashes", () => {
  const { session, statuses } = makeSession();
  session.feed(sse({ type: "RunError", runId: "r", message: "upstream died" }));
  session.feed(sse({ type: "RunFinished", runId: "r" }));
  assert.deepEqual(statuses.map((s) => s.state), ["error", "finished"]);
});
