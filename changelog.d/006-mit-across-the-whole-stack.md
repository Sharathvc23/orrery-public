### MIT across the whole stack

Orrery was Apache-2.0 while the `sm-*` primitives and the NANDA spec were MIT, and
the README argued that split as deliberate: a spec takes the most permissive license
so it is frictionless to re-implement, and the product takes Apache-2.0 for its
explicit patent grant.

The product is now **MIT** as well — `LICENSE`, `NOTICE`, and the `license` field of
all six Python distributions (`server`, `agent`, `skill`, `index`, `smb_host`,
`mcp_server`). `renderer` and `smb_funnel` already declared MIT in their
`package.json`, so every license declaration in the tree now agrees; that
disagreement is closed rather than argued.

The README's license section is rewritten rather than word-swapped. Its reasoning
turned entirely on Apache-2.0's patent grant, which MIT does not have, so keeping
the prose and changing the name would have left an argument for a product-vs-spec
boundary that no longer exists. There is now one license across the stack and no
boundary to reason about. `NOTICE` is kept for attribution — it is an Apache-2.0
artifact with no role under MIT, but it carries the copyright line and the `sm-*`
attribution, and both are still worth stating.

Copyright is Stellarminds.ai.
