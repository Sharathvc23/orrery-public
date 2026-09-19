### Fixed — a capability grant that cannot match is refused when it is read

Every matcher in the policy DSL guards on a capability prefix and returns false
for anything else, so a grant naming a capability with no matcher parsed, was
stored, and matched nothing. `browser.navigate:example.com` was accepted and
permitted no navigation. Three capabilities were affected.

`browser.*` grants now have a matcher, and one written as a bare hostname is
rejected when the file is read rather than stored. A test derives the capability
list from the executor and fails if any of them can be granted in a form no
matcher accepts, or if a capability declared exempt has since become matchable.
