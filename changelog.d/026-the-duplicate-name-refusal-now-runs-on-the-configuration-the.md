### The duplicate-name refusal now runs on the configuration the host actually runs

`POST /provision` refused a repeated business name with `409` and a name of only
punctuation with `400`, but both checks lived on the cold mint path.
`SMB_HOST_POOL_SIZE` defaults to 3, and a claim from the warm pool took a
pre-minted `smb-pool-…` id without consulting the name, so on the default
configuration neither check executed. Measured on a real host with nothing set
but `HOST_PUBLIC_URL`: the identical name three times returned 201 three times —
three `did:key`s and three cards all reading the same name — and `!!!`
provisioned rather than being refused. `test_duplicate_business_name_conflicts`
asserted the 409 while setting `SMB_HOST_POOL_SIZE=0`, so the suite covered a
path nobody ran.

Both checks now come from one shared function called by both paths, so the
refusal is decided by the business name rather than by which path served the
request. On the pool path the check and the claim are taken under a single lock
acquisition, and the queue is not read until the name has passed — a refused
duplicate used to be able to strand a pre-minted tenant that no later request
could claim. The answer is derived from the tenant table rather than a second
index, so it survives a restart, which `_rehydrate` rebuilds from disk.

The refusal no longer names the existing tenant's id. On the cold path that id
was only the slug of the name the caller had just sent, but on the pool path it
belongs to somebody else's live tenant and `/t/<id>` is that tenant's endpoint,
card and booking route — so on the loopback shape, where provisioning is open, a
duplicate-name probe would have enumerated every business on the host.

The scope is unchanged and stated where it is claimed: the refusal is
exact-slug. `CORNER BAKERY`, `Corner-Bakery` and `Corner Bakery.` collide with
`Corner Bakery`; `Corner Bakery Ltd` and `Corner Bakery NYC` do not, and still
provision with their own keys. Refusing a repeat is not deciding who is entitled
to a name.
