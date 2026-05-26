# AP-006: Web-based verification report (self-contained HTML)

**Kind:** gap  
**Status:** resolved  
**Severity:** low  
**Component:** cli

## Description

The CLI report is fine for technical auditors, but compliance officers are
non-technical. A self-contained HTML report (all assets inlined, no CDN
dependencies) that an auditor can open in a browser — showing scope
attestations, file provenance, and signature status with color-coded
pass/fail — would be a significant adoption accelerator.

Could reuse the JSON report format (now implemented via `--format json`) as
the data source.
