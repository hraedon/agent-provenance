#!/usr/bin/env python3
"""Thin shim — delegates to the packaged cairn._claude_hook module.

This file exists for backward compatibility with projects that reference
``integrations/claude-code/cairn_hook.py`` directly.  New installs should use
the ``cairn-claude-hook`` console script instead (what ``cairn install-harness``
wires): its shebang pins cairn's own interpreter, so the hook cannot resolve to
a python that has no cairn on its import path (WI-033).
"""

from cairn._claude_hook import main

if __name__ == "__main__":
    main()
