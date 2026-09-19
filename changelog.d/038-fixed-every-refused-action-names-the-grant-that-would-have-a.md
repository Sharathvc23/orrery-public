### Fixed — every refused action names the grant that would have allowed it

A fresh install grants nothing, so file, shell, network and browser actions are
refused until a grants file exists. Only the browser refusal said what to do
about it; the other three reported `sandbox_policy_deny` and nothing else,
leaving an operator to work out the grant syntax and the file to put it in.

All four now carry the grant line and the file path, from one helper, so they
cannot phrase it four different ways:

```
outcome  denied
reason   sandbox_policy_deny
remedy   add fs.read:/etc/hostname to ~/.community-member/grants.policy
```

`agent/tests/actions/test_refusal_names_its_remedy.py` derives the surfaces from
the runner map rather than listing them, drives each one against an install with
no grants, and fails if any policy refusal arrives without a remedy — so a fifth
policy-gated capability is covered when it is added. It also writes the grant the
refusal names and asserts the action then succeeds, so the remedy is checked to
be correct rather than merely present.
