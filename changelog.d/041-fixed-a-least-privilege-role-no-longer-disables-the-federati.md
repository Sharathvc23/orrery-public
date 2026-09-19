### Fixed — a least-privilege role no longer disables the federation feed

`federation_feed.ensure_schema` treated a refused `CREATE TABLE IF NOT EXISTS` as
grounds to degrade to sm-federation §2-only. Postgres refuses that statement for
want of `CREATE` on the schema **even when the table already exists**, so a role
without DDL rights was refused on every boot regardless of whether the ensure had
anything to do, and the feed was disabled although its log was present and
readable. The refusal now leads to a presence check; only an absent log degrades.
