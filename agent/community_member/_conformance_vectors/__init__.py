"""Byte-for-byte mirror of the canonical ``vectors/signing/`` corpus.

Embedded so an installed agent can run the client signing-conformance checks
in-process at boot without the repo checkout. Locked to the canonical
corpus by ``agent/tests/test_conformance_boot.py::
test_embedded_vectors_lockstep_with_canonical`` (there is no
``test_conformance_vectors_lockstep.py``, which this docstring used to name)
— never edit these files here; change ``vectors/signing/`` and re-copy.
"""
