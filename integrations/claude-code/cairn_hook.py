#!/usr/bin/env python3
"""Thin shim — delegates to the packaged cairn._claude_hook module.

This file exists for backward compatibility with projects that reference
``integrations/claude-code/cairn_hook.py`` directly.  New installs should use
``python3 -m cairn._claude_hook`` instead (what ``cairn install-harness`` wires).
"""

from cairn._claude_hook import main

if __name__ == "__main__":
    main()
