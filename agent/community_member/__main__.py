"""Enable ``python -m community_member <command>`` as an alias for the
``community-member`` console script — handy in containers where the entry
point may not be on PATH."""

from community_member.cli import main

if __name__ == "__main__":
    main()
