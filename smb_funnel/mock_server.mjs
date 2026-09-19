#!/usr/bin/env node
// smb_funnel — standalone MOCK host (zero dependencies).
//
// A real HTTP server implementing the FROZEN smb_host contract, backed by the
// same src/mock_core.js the in-page mock uses. Two purposes:
//   1. Headless smoke: `node mock_server.mjs & curl …` proves the contract.
//   2. "Point the funnel at a real URL" demo without the real host yet:
//        node mock_server.mjs                       # serves API on :8788
//        (funnel) ?api=http://localhost:8788
//
// The in-page mock (API_BASE="mock") needs none of this — it's purely for when
// you want a real network hop. CORS is wide-open because this is a dev stub.

import { createServer } from "node:http";
import { route } from "./src/mock_core.js";

const PORT = Number(process.env.PORT || 8788);

function send(res, status, json) {
  const body = JSON.stringify(json);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Accept",
    "Content-Length": Buffer.byteLength(body),
  });
  res.end(body);
}

const server = createServer((req, res) => {
  if (req.method === "OPTIONS") {
    res.writeHead(204, {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Accept",
    });
    return res.end();
  }

  const url = new URL(req.url, `http://${req.headers.host}`);
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", async () => {
    let body;
    if (chunks.length) {
      try {
        body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      } catch {
        return send(res, 400, { error: "invalid JSON body" });
      }
    }
    try {
      const result = await route(req.method, url.pathname, body);
      send(res, result.status, result.json);
    } catch (e) {
      send(res, 500, { error: `mock host error: ${e.message}` });
    }
  });
});

server.listen(PORT, () => {
  process.stdout.write(`smb_funnel mock host listening on http://localhost:${PORT}\n`);
});
