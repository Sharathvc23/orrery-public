### Stale pins are now watched, and pull requests have an owner

This repository pins hard — Actions by commit SHA, base images by digest,
Python by lockfile — and `supply-chain-pins` holds that discipline. What it
cannot check is whether a pin is still the right one: a SHA pin is a correct pin
forever, including after the tag it came from has moved and the runtime it uses
has been deprecated.

`.github/dependabot.yml` closes that half for the two ecosystems where it can.
Actions updates arrive grouped, so five bumps are one review. Base-image digests
are watched because a digest never moves, which is the point and also the
problem: it keeps serving the image it named, security fixes and all, until
someone repins it.

Python is deliberately not listed, and the file says why: Dependabot's pip
ecosystem does not recognise the `requirements.lock` filename, so an entry
pointed at one resolves no dependency files and fails quietly. Those pins are
already covered by `dependency CVE scan`, which runs `pip-audit` over every pin
file with the set derived rather than listed, against an empty ignore file.

`.github/CODEOWNERS` requests review rather than enforcing it — branch
protection here requires the `ci gate` check, not an approval — so that an
outside contribution cannot arrive with nobody named on it.
