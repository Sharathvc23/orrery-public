### The demo backend was softer than the host it stood in for

`smb_funnel/README.md` said the funnel "speaks the real host contract either
way", and that claim is what made a demo on the in-page mock evidence of
anything. It was false on every refusal, measured at `origin/main` 9c925bb:

| `POST /provision` body | real host | mock |
| --- | --- | --- |
| `{}` | `422`, `detail` an **array** | `400`, `{error: …}` |
| `business_name: ""` | `422`, `detail` an **array** | `400`, `{error: …}` |
| `business_name: "!!!"` | `400` | **`201` — it provisioned** |
| `business_name: 5` | `422` | **`201` — it provisioned** |

The shapes were the smaller half. **The mock was not differently-worded, it was
more permissive**: a punctuation-only name and a non-string name each returned a
tenant id, an endpoint, a `did:key` and a 24-word recovery phrase for input the
product refuses outright. The cause was a default — `slugify` ended `|| "agent"`,
so a name with no alphanumerics did not slug to nothing, it silently became the
tenant id `agent`. A default that fires where the input was unusable does not
rescue the request; it invents a different one and answers that.

`smoke.mjs` asserted `missing business_name → 400` — the mock's answer — in the
suite whose stated job is proving the funnel speaks the real contract. A parity
check that reads its expectation off one of the two things it compares cannot
fail.

The refusals are now stated once, in `smb_funnel/tests/host_contract.json`, and
asserted from **both** sides: `smb_host/test_main.py` drives the real host
against it and `smb_funnel/tests/contract-parity.test.mjs` drives the mock. Change
the host's wording and its test reddens; update the file and the mock's test
reddens until the mock follows. A one-sided pin is what let them diverge.
