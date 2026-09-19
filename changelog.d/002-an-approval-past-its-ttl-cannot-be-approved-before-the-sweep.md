### An approval past its TTL cannot be approved before the sweeper runs

`governance.approve` and `reject` matched the pending row on its status alone.
The sweeper that marks items `expired` runs on the think cycle, so between an
item's `expires_at` and the next sweep it still read `pending`, and a leader
could approve it — while the approve endpoint's own docstring said "TTL still
applies — expired items stay expired". Both decisions now also require
`expires_at` to be in the future, so an expired item matches nothing, exactly as
an already-decided one does. Rejecting an expired item is refused for the same
reason: `rejected` would attribute to a person an outcome the clock made.

Guarded, each planted and observed reddening by name, the tree clean after each
revert: the approve filter on status alone (the shipped behaviour); the reject
filter on status alone.
