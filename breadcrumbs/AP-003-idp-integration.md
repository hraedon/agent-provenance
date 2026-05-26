# AP-003: IdP integration for principal_id

**Kind:** gap  
**Status:** open  
**Severity:** medium  
**Component:** adapter  
**Blocked on:** substrate BC-197

## Description

Currently `principal_id` is stubbed from `os.getlogin()` or `PRINCIPAL_ID`
env var. Real OIDC/SAML integration would make the delegation chain (BC-197)
actually meaningful — without it, the "on behalf of" claim is self-attested.

Blocks: Cursor/Aider hooks (they should authenticate the user), auditor trust
in the delegation chain.
