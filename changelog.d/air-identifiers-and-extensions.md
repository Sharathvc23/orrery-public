### Listings resolve again after the Index changed how it names things

The NANDA Index moved to ARD identifiers — `urn:air:<publisher-FQDN>:<namespace…>:<short-name>`,
anchored to the domain whose ownership it verified — and `resolve` now hands the
next hop the **short-name alone** rather than the whole locator. Orrery registers
as its own registry, so its entry is `urn:air:<domain>:catalog:root` and every
org-level resolve arrives as `root`. This registry did not answer to `root`, and
the live four-hop died there: the Index resolved `urn:air:regentix.ai:catalog:root`
and `GET /agents/root` returned a 404. The org's primary agent now answers to it,
alongside the agent_id, org_id and domain aliases the NEST path still sends.

Two more places spoke the old vocabulary. The tenant registrar sent an
`urn:ai:domain:…` identifier, which the Index refuses outright, and it carried the
`org.projectnanda.*` convention as flat keys under `catalog_metadata`, a field
that no longer exists — so the write returned 201 with every key, the owner
attestation included, silently dropped. The record now sends no identifier at all
(the Index derives the same string from the domain it verified), sends the
convention nested under `extensions`, and sends `hosting_path: "smb"`, which is
how the Index now derives the `resolutionRole` / `preferredDiscovery` values this
record used to assert by hand. The attestation reader follows: one key name on
both sides, so the `catalog_metadata` → `metadata` inference and the two-name
lookup it forced are gone.

A resolve that returns 200 is no longer proof the answer is about the agent that
was asked for. When no entry holds the locator, the Index answers with the
publisher's own catalog entry and says so in a new `match` field. Walking a
catalog with the short-name is the right thing to do with that; fetching an agent
card is not — the card belongs to one specific agent, so the hop would return a
stranger's agent for the one requested. `fetch_card` refuses that case by name,
and the post-registration check reports a publisher match as "no entry holds our
identifier" rather than leaving it to the did comparison to catch by accident.

Guarded: the `root` alias has its own regression test, planted and observed
reddening against the live failure; a publisher match on a card record is
asserted refused; and the retired flat `org.projectnanda.ownerAttestation` key is
asserted *not* honoured, so reading it cannot creep back.
