# Product chart — folded

This page used to carry the at-a-glance product chart: the three pieces, the
NANDA surfaces, the accountability features, the UI layers, the `sm-*` table
and the naming rule. Each of those now lives on the page that owns it, so that
one statement has one home:

| Former section | Now |
|---|---|
| The pieces you install | [`ARCHITECTURE.md` § The five deployables](./ARCHITECTURE.md#the-five-deployables) |
| NANDA-ready surfaces | [`ARCHITECTURE.md` § The surfaces each deployable serves](./ARCHITECTURE.md#the-surfaces-each-deployable-serves) |
| Accountability and trust features, with their status | [`CLAIMS.md`](./CLAIMS.md), where each carries its evidence |
| Protocols and integrations, with tested versions and a supported / experimental / unfinished label | [`COMPATIBILITY.md`](./COMPATIBILITY.md) |
| UI layers | [`ARCHITECTURE.md` § Three layers](./ARCHITECTURE.md#three-layers) |
| The `sm-*` stack | [`../README.md`](../README.md#built-on-the-sm--stack) and [`COMPATIBILITY.md` § The sm-* pins](./COMPATIBILITY.md#the-sm--pins) |
| What is planned | [`ROADMAP.md`](./ROADMAP.md) |

## 6. Naming

- **User-facing:** an **org** hosts **agents**. The word "chapter" is **never** user-facing.
  It is the protocol noun, and it stays on every surface other software depends on —
  `chapter_id`, `/api/chapter/*`, the `X-Chapter-*` headers, event topics, the tables, the
  main module — as listed in [`ARCHITECTURE.md` § Two nouns](./ARCHITECTURE.md#two-nouns-for-one-thing-protocol-and-product).
- **Packages:** `orrery-server`, `orrery-agent`, `orrery-skill`, `orrery-lean-index`,
  `orrery-smb-host`, `orrery-mcp-server`.
