### Added — an example grants file, and a warning for grants that permit more than they name

`shell.exec` constrains which binary runs and nothing about its arguments. A
grant for a binary that takes a path or a URL therefore permits whatever that
binary does to any path or any URL, and the `fs.*` or `net.http` patterns
elsewhere in the file do not bound it. An argument naming an existing file is
now refused against those grants, and everything else is not: `awk '{print}'
/etc/shadow` is refused and `awk 'BEGIN{getline < "/etc/shadow"}'` runs, the same
binary and grants with opposite outcomes.

The agent now prints a warning at startup for each such grant, naming what it
permits and the narrower grant it is wider than. It is a warning and not a
refusal: the operator may mean it. The binaries it covers are listed in
`SUBSUMING_BINARIES` in `agent/community_member/sandbox/policy.py`, with the
reason attached to each, so the warning and the documentation come from one
place.

That list is not exhaustive and cannot be — `shell.exec` does not constrain
arguments at all, so the property holds for almost any binary that takes a path,
a host or a command. The absence of a warning is therefore not a safety claim,
and both the lint's documentation and `docs/CONFIGURATION.md` say so, with the
shapes that escape the list: an unlisted interpreter, a binary installed under a
different name or a local script (matching is on the basename), and a tool whose
subsuming behaviour is a flag rather than its purpose, as `tar --to-command` is.

`agent/grants.policy.example` is a commented starting point for
`~/.community-member/grants.policy`. It activates nothing: every line is a
comment, and copying it into the agent's home grants no capability. An install
with no grants file continues to refuse every file, shell, network, browser and
desktop action. Its shell section suggests no binary: `shell.exec` does not
constrain arguments, so there is no narrow choice to recommend, and anything
named there would be read as a vetted default. `git` illustrates why — it is
about repositories rather than arbitrary paths, and runs any command through a
config alias, `core.pager`, `core.sshCommand` or a repository hook.

`docs/CONFIGURATION.md` carries the pattern language for each capability and
the composition property, which previously lived only in a module docstring.
That docstring's example granted `tail`, `grep` and `jq` — the first thing a
reader copies — and now grants `git`.
