# AP-004: RFC 3161 timestamp token support

**Kind:** gap  
**Status:** open  
**Severity:** medium  
**Component:** cli  
**Blocked on:** substrate Plan 012

## Description

Even before full transparency-log integration, adding a `cairn timestamp`
command that takes a bundle and fetches a TSA token would add a layer of
non-repudiation that's auditor-recognized today.

TSA selection: DigiCert/GlobalSign as commercial default, Sigstore TSA as
self-hosted option, FreeTSA for dev only.

Blocks: witness co-signing (timestamp tokens are a prerequisite for
meaningful witness claims).
