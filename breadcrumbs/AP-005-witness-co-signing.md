# AP-005: Witness co-signing

**Kind:** gap  
**Status:** open  
**Severity:** low  
**Component:** verifier  
**Blocked on:** AP-004, substrate BC-196

## Description

The README describes layer 5 (witness federation) as a future goal. Even a
minimal implementation — where a second key co-signs each event batch — would
dramatically strengthen the "operator can't forge" claim beyond what HMAC
alone provides.

Depends on: RFC 3161 timestamping (AP-004), asymmetric signing (substrate
BC-196).
