### An image bump now covers every file that pins the image

`.github/dependabot.yml` watched the base images in `infra/`, which is only half
of where they are pinned. The `docker` ecosystem reads Dockerfiles and Kubernetes
manifests and **does not read Compose files**, so `docker-compose.yml` — which
pins `pgvector/pgvector:pg15` by digest in three places and `python:3.12-slim` in
one — was outside the watch.

The very first bumps proved it. One moved `python:3.12-slim` to `3.14-slim` in
three Dockerfiles while Compose kept the 3.12 digest; another repinned
`pgvector/pgvector:pg15` in `Dockerfile.db` while Compose kept the old digest, so
the `e2e` job booted the image the change had not touched and reported green on a
pin it never exercised. Half-applied bumps leave the same image pinned two ways,
which is precisely the drift digest pinning exists to prevent.

A `docker-compose` entry closes it. Groups cannot span ecosystems, so an image
bump now arrives as **two pull requests that must land together** — the config
says so where someone deciding whether to merge one will read it.
