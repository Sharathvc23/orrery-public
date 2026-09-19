### Added — environment variables are classified, and security gates go through env_flags

`env_flags.security_flag(name, *, default)` records at the call site which way a
security flag fails when nobody set it. Nothing asserted that a security-gating
variable used it: `test_env_flags.py` tests the function, not its use, and 5 of
68 environment names went through it.

`server/tests/test_env_flags_convention.py` walks the AST of every module and
resolves names held in module-level constants, so an indirectly written read
cannot hide from it. Every name it finds must be declared in exactly one of four
classes, each entry carrying a reason: a boolean security gate that must use
`security_flag`; a boolean security gate that deviates, with why routing it would
change behaviour; a security-relevant value that is not boolean, where
`security_flag` does not apply; or not security-relevant. A name that is read and
not classified fails the suite, so a variable added later must be classified
before it can land.

The set of reads is derived and the classification is declared, because no rule
over names decides the second: `ORG_HOST39_CARD_BASE` contains no security token
and gates nothing, `ORG_ADMIN_TOKEN` is a credential rather than a flag, and
`PUBLIC_URL` matches a keyword scan while deciding no access. Names a keyword
scan would flag are declared not-security-relevant with a reason, so the
classifier does not look stricter than it is.

`FEDERATION_AUTODISCOVER` now reads through `security_flag` with `default=False`,
matching its previous default. It additionally accepts `on` as true, which the
previous parse did not.

Declared as deviations rather than changed: `AUTO_REGISTER`, because
`security_flag` would make an unrecognised spelling mean publish where the inline
parse means do not publish; and the four retention sweep variables, because they
are alias pairs read in precedence order, which `security_flag` cannot express,
and because they treat an empty value as off where `security_flag` treats it as
undecided — on a sweeper that deletes, that difference matters.
