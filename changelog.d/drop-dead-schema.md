### The schema no longer creates forty-five tables nothing reads

`infra/init.sql` created 112 tables. Forty-five of them — pitches, polls,
sponsors, speakers, research teams, committees, role permissions, notification
preferences, invitations and the rest of a startup-community product —
were referenced by no non-test source anywhere in the repository: not the
server, the agent, the SMB host, the index, the MCP server or a script; not a
migration, the seed, the agent export format, the DSAR export or the backup
guide. The last code that wrote to any of them left with the agent-native pivot,
before the first public release. Every self-hoster has been creating them on
first boot, and the application role has been granted on them, for nothing.

`init.sql` no longer creates them, nor the twenty-two indexes, sixty-eight
constraints and nineteen triggers on them, nor the one foreign key from a live
table (`chapters.template_id`), the two triggers on `chapters` that populated
them, the eight functions that served only them, or the two enum types only they
used. Loaded fresh, the schema has 67 tables; a database migrated from the old
schema and one created from the new one are column-for-column and
constraint-for-constraint identical.

Migration `0009` carries this to existing databases and **drops only what is
empty**: it counts every table first, and if any holds a row it raises naming
each such table with its count and drops nothing — a table with data in a live
org is a finding for the operator, not something a migration deletes. A guard
test parses every `CREATE TABLE` out of `init.sql` and fails, naming the table,
for any that no non-test source references, so the schema cannot silently
regrow. Six tables the word match counts as referenced — `chapters`,
`chapter_members`, `comments`, `connections`, `group_members`, `groups` — have
no table-shaped use anywhere and match only an ordinary identifier or a JSON
key; they are declared in the guard as exactly that, with a test that holds the
declaration accurate in both directions, and are candidates for a second pass
once the live row counts are in. The foreign key from `chapters` to
`chapter_templates` was not treated as a reference: the rule that a live
table's foreign key keeps its target alive exists to protect the live table's
integrity, and `chapters` itself is only word-referenced, so a strict reading
would have kept a dead constraint alive by a word match.

Guarded, each planted and observed reddening by name, the tree clean after each
revert: a dead table's `CREATE TABLE` re-added to `init.sql` (the guard names
it); one row planted in a to-be-dropped table on a real Postgres (`0009` refuses
naming the table and the count, and all 112 tables remain; with the row gone it
drops the forty-five and a re-run is a no-op). The full server suite and the
installer's unattended first run on a fresh volume are green with the tables
gone — nothing had been depending on one by accident.
