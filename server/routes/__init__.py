"""Route adapters extracted from chapter_agent.py (the org server monolith).

`ca` is a live proxy to the chapter_agent module: tests pop + reimport
chapter_agent (importlib) to apply fresh env, which would orphan a bound
`import chapter_agent as ca`. Resolving from sys.modules on each access means a
mounted router always reads the CURRENT module's globals (members, PUBLIC_URL…).
"""

import sys


class _ChapterAgentProxy:
    def __getattr__(self, name):
        return getattr(sys.modules["chapter_agent"], name)


ca = _ChapterAgentProxy()
