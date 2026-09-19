### Security — shell arguments are narrowed against the file grants, and the child no longer inherits the agent's environment

A `shell.exec` grant names a binary and cannot constrain what that binary does,
so `shell.exec:grep` beside `fs.read:~/Downloads/**` read any file on the disk.
That specific case is now refused; the general property is not closed, as below.
An argument naming an existing file the `fs.*` grants do not cover is now
refused before the command runs, and the refusal names the argument and the
grant that would permit it.

**This is a narrowing, not a bound, and is documented as one.** It reaches one
shape — a path written as an argument. A path inside a program string escapes
it: `awk '{print} /secret'` is refused and
`awk 'BEGIN{getline < "/secret"}'` is not, the same binary and grant with
opposite outcomes. So does anything taking a program as an argument (`python -c`,
`sh -c`, `find -exec`), any host (`curl` takes a URL, not a path), and any file
that does not exist yet. Coverage is per-invocation rather than per-binary, so
there is no rule that says which commands are narrowed. Closing the property
requires containing the child process rather than reading its arguments;
`docs/CONFIGURATION.md` records what that would take.

It also refuses some harmless commands: an argument that happens to name an
existing path is refused even when the binary would never open it.

The child process now runs in `~/.community-member/shell-workdir` instead of
inheriting the agent's working directory, so a relative argument has one
meaning. Its environment is reduced to `PATH`, `HOME`, `LANG`, `LC_ALL`, `TZ`
and `TERM`. The agent's own environment holds its provider API key, and a
granted binary that prints or forwards its environment carried that key out —
`shell.exec:printenv` returned it, with no grant mentioning it and the binary
allowlist not bounding it.

`SUBSUMING_BINARIES` and the load-time warning are unchanged and still needed:
they cover the cases this narrowing cannot reach.
