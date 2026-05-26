# AP-008: cairn diff command for comparing bundles

**Kind:** gap  
**Status:** resolved  
**Severity:** low  
**Component:** cli

## Description

Given two bundles, show what changed: new events, new files touched, scope
attestation changes. Useful for "what happened between audit period A and B."

Could be implemented as a new CLI command that loads two bundles and diffs
their event lists, file provenance, and scope attestations.
