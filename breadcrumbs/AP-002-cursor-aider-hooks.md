# AP-002: Cursor / Aider harness hooks

**Kind:** gap  
**Status:** open  
**Severity:** medium  
**Component:** integrations  
**Depends on:** AP-003

## Description

The project positions as "CloudTrail for agent actions" but only supports
Claude Code and OpenCode. Cursor has a hook/extension API. Aider has a hooks
system. Each additional harness increases the "catches everything" claim.

Pattern: same bridge approach as OpenCode (thin plugin → python bridge →
substrate).
