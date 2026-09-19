### Changelog entries are fragments, and `[Unreleased]` is no longer hand-edited

Every pull request prepended its entry at the same spot under `## [Unreleased]`,
so any two open PRs conflicted there. Resolving those conflicts by merging
`main` into a branch left merge commits whose trees held stale versions of
files the PR never meant to touch, and on a squash-merge repository that is a
silent reversal: one such merge undid four landed PRs in a day.

A change now records itself as `changelog.d/<slug>.md` — a file only it touches
— whose first line is the `### ` heading and whose body is the entry as it
will read. `scripts/changelog_assemble.py --preview` renders the pending
entries; `--release X.Y.Z` writes the release section under `[Unreleased]`
(newest first, by the commit that first added each fragment) and removes them.
No dependency. The eighty entries that were under `[Unreleased]` are converted
to numbered fragments in the order they stood, and `[Unreleased]` now holds one
pointer line. `tests/test_changelog_fragments.py` fails, naming the entry, if
anything is written there by hand, and names a malformed fragment; the script's
self-test proves both, plus the release assembly, on a scratch changelog.
