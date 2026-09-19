# vectors/rotation/v06 — mirrored, not authored

`peer-rotation-cases.json` is a **byte-for-byte copy** of the canonical corpus in
the NANDA Chapter Protocol umbrella:

    <umbrella>@60cc22d:vectors/rotation/v06/peer-rotation-cases.json
    sha256 2b71d9e35364dede15efcd2047399dad92239f7a37646c54fd8451975a4de272

**Never edit it here.** Change it in the umbrella, then re-copy and update the
digest pinned in `server/tests/test_h9_rotation_attestation.py`.

## Why a mirror rather than local fixtures

Two runtimes agreeing on a wire format by each passing the *same shipped vectors*
is conformance. Two runtimes agreeing because one copied the other's code — or
because each wrote fixtures that happen to match its own implementation — is
drift that has not surfaced yet. §8.5 was specified before either runtime
implemented it precisely so this file could be the arbiter.

The pinned digest is the drift guard: if the umbrella corpus changes, Orrery's
tests fail until someone re-syncs deliberately, rather than silently continuing
to attest against a corpus the spec no longer blesses.
