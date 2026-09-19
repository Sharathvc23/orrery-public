### The A2UI renderer bounds the total number of components a surface can paint

The reference renderer bounded reference walks with a cycle guard and a depth cap.
Neither bounds expansion. The cycle guard is per path, so it refuses a component
only when it appears on its own ancestor chain, and a directed acyclic graph
contains no such repeat. A chain of components, each referencing the next one twice,
is acyclic, stays under the depth cap, declares two children per node, and doubles
the painted node count at every level. Twenty components — 1.2 KB on the wire —
painted 1,048,575 nodes in 4.8 seconds, and twenty-one exhausted a 2 GB heap, with
the existing caps (5000 components, 1000 children, depth 64) satisfied throughout.
The surface may come from any A2UI endpoint the renderer is pointed at, including a
remote org's.

A third bound now caps how many component instances one surface may paint. The same
envelopes are flat at every depth up to the maximum: about 20,000 elements in under
60 ms. Overflow truncates with a visible placeholder and a warning rather than
dropping content silently, and the budget resets per render, so one large surface
does not truncate the next.

The budget caps instances, not the size of any single component; a `Table` remains
bounded by its own 1000-row by 50-cell limit, and so on for the other per-component
caps. `docs/specs/agui.md` rule 5 required only the cycle guard and the depth cap and
has been updated to require all three.
