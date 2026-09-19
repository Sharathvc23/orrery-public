### A booking cannot outlive its receipt, and concurrent bookings are not lost

Three faults in the booking store, all found by driving the SMB host over HTTP
and none visible in its responses, which were correct while the files on disk
disagreed.

A booking was written before its receipt was attempted, with nothing to undo the
write. When the Agency Log could not be written the store gained a booking while
the receipt count stayed where it was, and the caller was told the request had
failed — so a durable booking existed that nothing accounted for, and a retry
added another. The receipt is now persisted first, so a booking that exists has
one. The remaining failure leaves an extra receipt rather than an unaccountable
booking. An agent with no signing key is unaffected: it has no receipt to persist
and still books, saying so.

The store is a read-modify-write over a single JSON file and the host serves
bookings from a thread pool, so requests for one tenant interleaved. Twenty
concurrent bookings returned success twenty times, wrote twenty receipts, and
left seven bookings on disk; three at once was enough to lose one. Two writers
truncating and filling the same file also interleaved into invalid JSON. Writes
are now serialized per store and the file is replaced atomically.

A store that existed but did not parse was reported as an empty one. That is what
turned a lost write into lost data: the agent read back no bookings while
customers held valid signed receipts, the next identifier restarted at 1 and
collided across receipts, and the next successful write replaced the damaged file
along with whatever it still held. An unreadable store now raises instead, the
file is left untouched so its contents can be recovered, and the error names it.
A store that is absent is still empty. Where this reaches an HTTP caller it is
reported separately from a transient write failure, because retrying a damaged
store cannot succeed.

The lock is per process. Two processes sharing one home can still lose an update,
though the file stays parseable.
