### Fixed — authority grant expiry is compared as an instant, not as a string

The ARP authority gate evaluated expiry with
`receipt["issued_at"] > grant_expires_at`, a string comparison. That is correct only
when both values are UTC (`Z`) at identical precision. RFC 3339 also permits a
numeric offset, so one instant written two legal ways produced two verdicts:
`2026-08-13T20:00:00Z` was refused and `2026-08-14T01:00:00+05:00`, the same moment,
was accepted. A live grant written with a negative offset was wrongly refused.

`grant_expires_at = "never"` was accepted, because a string beginning with a letter
sorts after one beginning with a digit.

The schema did not constrain it: `grant_expires_at` carries `"format": "date-time"`
and the validator is constructed without a `format_checker`, so that keyword is an
annotation and asserts nothing. Other timestamps in `schema/arp/0.2` are pinned by
an explicit regex.

Both values are now parsed to timezone-aware datetimes and compared as instants. An
expiry that cannot be parsed is refused rather than ignored. Naive timestamps are
treated as unparseable rather than assumed UTC. The boundary is unchanged: an action
at the exact expiry instant is authorised, and an absent `grant_expires_at` still
means no expiry.

The change is in the verifier rather than the schema, because an offset timestamp is
valid RFC 3339 and narrowing the schema would reject conforming emitters.

`conformance/arp` is the canonical verifier and is mirrored verbatim into
`server/_arp_verify` and `agent/community_member/_arp_verify`; all three are
re-synced. The three-way drift guards were checked against a deliberately introduced
one-line desync before being relied on.
