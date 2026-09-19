### Fixed — two federation comments described behaviour that had changed

`auth_verify.OPEN_POST_PATHS` said server-to-server signing had yet to land and
that the entry should move once it did. Signing has landed; the entry is open at
that gate because the caller is a peer org holding no member key, so the member
signature this gate checks is the wrong credential. The broadcast inbox handler
said enforcement defaults off during a warn-then-enforce cutover; that cutover
closed and `FEDERATION_ENFORCE_SIGNED_BROADCASTS` defaults on.
