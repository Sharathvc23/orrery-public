### Fixed — a semicolon in a grants-file comment no longer breaks the file

`parse_policy` split on `;` before stripping `#` comments, so a comment
containing a semicolon had its tail parsed as a grant. The file then failed to
parse, and because a malformed grants file is never partially applied, every
action on the install was refused. Comments are now stripped first.
