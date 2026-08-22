# FIM-Class Positioning for Agent Audit Logs

**A Technical Report on Auditor Acceptance of Cryptographically Signed
Agent-Action Event Logs**

*Version 1.0 — May 2026*

---

## Executive Summary

agent-provenance produces cryptographically signed, append-only event logs
of AI agent tool calls. The signing model uses per-deployment keys with
no commercial-CA chain — the same pattern used by file integrity monitoring
(FIM) tools like Tripwire, Wazuh, and OSSEC.

This report examines whether an external IT auditor will treat these
signed bundles as acceptable audit evidence. Our working hypothesis:
**yes, under the same conditions that FIM tools are accepted** — namely,
that the key management control is documented, configured, and operating.

This is a *working hypothesis*, not a settled answer. It has not been
validated by presenting a sample bundle to a practicing IT auditor.
Until that validation occurs, deployers should position this to their
compliance teams as "plausible, modeled on Tripwire/Wazuh acceptance,"
not as "confirmed."

---

## 1. Background: The Audit Problem

Agent tools (Claude Code, OpenCode, Cursor, etc.) are increasingly used
in regulated environments. Operators need to answer: *what did the agent
do, on whose authority, and when?*

Existing approaches fall short for external audit:

- **LLM observability platforms** (Langfuse, LangSmith, Helicone, Arize,
  AgentOps, Datadog LLM Obs): mutable databases, no signatures, no
  offline verification.
- **AI gateways** (Portkey, Credal, LiteLLM): policy and redaction at
  the prompt boundary, not action provenance.
- **Vendor-native logging** (Anthropic OTel hooks, Bedrock invocation
  logging, Azure OpenAI diagnostics): vendor-controlled, untrusted from
  an auditor's perspective, no independent integrity proof.

The closest structural analog is **AWS CloudTrail with log-file integrity
validation** — but that applies to cloud API calls, not agent tool calls.

agent-provenance fills this gap: "CloudTrail for agent actions,
vendor-independent, verifiable offline by a third-party auditor."

---

## 2. The Signing Model

Each tool-call event is signed with HMAC-SHA256 over RFC 8785 canonical
JSON. The signing key is:

- Generated locally during first-run initialization
- Stored on the host with OS-level access restrictions (mode `0600`,
  owned by the service account)
- Never transmitted off-host
- Recorded by a self-signed `key_declaration` event in the log

Key rotation is performed by signing a `key_rotation` event with the
predecessor key, preserving identity continuity across rotations.

**Limitation (partial):** HMAC-SHA256 is symmetric — the party holding the
key can forge events. This is the same limitation that applies to FIM tools
using symmetric signing. Ed25519 asymmetric signing is now available and
provides operator-forgery resistance for events signed with the Ed25519 scheme.
HMAC-signed events retain the symmetric limitation.

---

## 3. FIM Precedent in Compliance Frameworks

File integrity monitoring tools (Tripwire, Wazuh, OSSEC, AIDE) are
widely accepted in IT audits despite using internally-managed signing
keys with no commercial-CA chain. The auditor evaluates:

1. Is the control configured?
2. Do signatures verify?
3. Is the key management procedure documented and operated?

The auditor does *not* require the signing key to chain to a commercial
CA. This precedent directly applies to agent-provenance's signing model.

### 3.1 Framework-by-Framework Analysis

#### SOX ITGC (Sarbanes-Oxley IT General Controls)

- **Governing guidance:** PCAOB AS 1105 (Audit Evidence) and AS 2201
  (Internal Control Over Financial Reporting)
- **Relevance:** Controls are tested on design and operating
  effectiveness, not on key provenance. A FIM tool with internally-managed
  keys is routinely accepted as evidence of ITGC compliance.
- **agent-provenance fit:** The signed event log serves the same
  function as a FIM log — it provides tamper-evident evidence of
  actions taken on financial-reporting-relevant systems.

#### PCI DSS (Payment Card Industry Data Security Standard)

- **Requirement 10.3.4:** FIM on audit logs, required as of March 2025.
- **Requirement 11.5:** FIM on critical files.
- **Relevance:** PCI DSS explicitly requires file integrity monitoring
  and accepts tools with internally-managed signing keys.
- **agent-provenance fit:** The signed bundle satisfies the "integrity
  monitoring of audit logs" requirement. The per-file digests in each
  event provide the file-level integrity evidence.

#### FFIEC IT Examination Handbook

- **Source:** Information Security Booklet, p. 79
- **Relevance:** Prescriptive on log integrity controls without mandating
  external attestation. Examiners evaluate whether the control exists and
  operates, not whether it uses commercial-CA-signed keys.
- **agent-provenance fit:** The control description (§4) maps directly
  to FFIEC expectations for log integrity.

#### SOC 2 Type II

- **Criteria:** Trust Services Criteria CC4.1 (Monitoring Controls) and
  CC7.2 (System Monitoring)
- **Relevance:** SOC 2 is criteria-based; the auditor evaluates the
  control description in the system description. FIM tools with
  internally-managed keys are routinely included in SOC 2 system
  descriptions.
- **agent-provenance fit:** The control description template (§4) is
  designed to be copied into a SOC 2 system description.

#### HIPAA

- **§164.312(b):** Audit controls — "Implement hardware, software,
  and/or procedural mechanisms that record and examine activity in
  information systems that contain or use electronic protected health
  information."
- **Relevance:** Tamper-evident signed logs exceed the minimum
  requirement. No specific key-management standard is mandated.
- **agent-provenance fit:** The signed event log satisfies the audit
  control requirement with a stronger integrity guarantee than
  plain-text logs.

#### Internal IT Audit (IIA GTAG 3)

- **Source:** Global Technology Audit Guide 3 (GTAG 3) — Auditing
  IT Governance
- **Relevance:** Lowest acceptance bar. Internal auditors accept any
  reasonable log integrity mechanism.
- **agent-provenance fit:** Fully satisfied.

---

## 4. Key Management Control Description (Template)

Deploying organizations can adapt the following for their SOX system
description, SOC 2 system description, or internal control narrative.

> **Control:** Audit log integrity via cryptographically signed
> append-only event log.
>
> **Description:** Tool-call events emitted by configured agent
> harnesses are written to an append-only event log. Each event is
> signed using a signing key generated during system initialization
> and stored on the host with OS-level access restrictions (mode
> `0600`, owned by the service account). Keys may be HMAC-SHA256
> (default) or Ed25519 (where supported). Signatures cover the
> canonicalized JSON event payload per RFC 8785.
>
> **Key generation:** Signing keys are generated locally during
> first-run initialization, recorded by a self-signed `key_declaration`
> event in the log, and never transmitted off-host.
>
> **Key storage:** Private key material is stored at
> `<deployment-specific path>` with `0600` permissions. Access is
> restricted to the service account. HSM-backed storage is supported
> where the deployment requires it.
>
> **Key rotation:** Rotation is performed by signing a `key_rotation`
> event with the predecessor key. The principal identifier
> (`principal_id`) remains stable across rotation; the chain of
> `key_rotation` events preserves identity continuity.
>
> **Key revocation:** Revocation is recorded as a signed
> `key_revocation` event with a `revoked_at` timestamp. Events
> signed by the revoked key with `event.timestamp < revoked_at`
> remain verifiable.
>
> **Verification:** Auditors verify signatures independently using
> the `cairn verify` tool against a signed bundle. The tool requires
> no network access to verify signatures and key lifecycle; network
> access is optional for RFC 3161 timestamp anchor validation against
> the TSA's CA.
>
> **Tamper evidence:** Bundles include a `manifest.json` with
> per-file integrity hashes and a `previous_bundle_hash` pointer to
> the immediately preceding bundle, forming a hash chain across
> retention boundaries (CloudTrail-style). Gaps are detectable at
> verification time.

Substitute deployment-specific values for `<deployment-specific path>`
and any HSM/KMS specifics.

---

## 5. Limitations and Honest Caveats

### 5.1 Symmetric Key Limitation

HMAC-SHA256 signing means the party holding the key can forge events.
This is the same limitation that applies to FIM tools using symmetric
signing. It is mitigated by:

- Key access restricted to the service account (mode `0600`)
- Key rotation events creating an auditable chain
- Ed25519 asymmetric signing available for operator-forgery resistance
- No trusted-time guarantee: RFC 3161 timestamping was removed with regista
  0.6+ (the batch Merkle construction witnessed no content)

### 5.2 Missing Events

No cryptographic primitive defends against "the operator chose not to
record." The defense is structural: instrument at a layer the operator
cannot easily disable, and make the absence of regular heartbeats
itself a detectable anomaly.

### 5.3 Unvalidated Hypothesis

This positioning has **not been validated** by presenting a sample
bundle to a practicing IT auditor. The FIM precedent and the absence
of contrary published guidance both support the hypothesis, but
confirmation requires putting a real bundle in front of a Big Four
IT audit senior and recording the reaction.

Until that happens, deployers should present this to their compliance
teams as:

> "We use a FIM-class control for agent audit logs, modeled on the
> same signing pattern accepted in SOX ITGC, PCI DSS, and SOC 2
> audits. The tool produces signed bundles that can be verified
> offline. Our key management procedure is documented [link to §4
> template]."

---

## 6. What This Is Not

- **Not a legal opinion.** This is a technical analysis based on
  published guidance and established practice. Consult your compliance
  team and external auditors.
- **Not a substitute for endpoint management, DLP, MDM, or identity
  brokering.** This is an audit log layer, not an enforcement layer.
- **Not yet validated by an auditor.** See §5.3.

---

## 7. References

| Reference | Relevance |
|-----------|-----------|
| PCAOB AS 1105 — Audit Evidence | SOX ITGC audit evidence standards |
| PCAOB AS 2201 — Internal Control Over Financial Reporting | SOX ITGC control testing |
| PCI DSS v4.0 — Requirement 10.3.4 | FIM on audit logs (required March 2025) |
| PCI DSS v4.0 — Requirement 11.5 | FIM on critical files |
| FFIEC IT Examination Handbook — Information Security Booklet, p. 79 | Log integrity controls |
| SOC 2 Trust Services Criteria CC4.1, CC7.2 | Monitoring controls |
| HIPAA §164.312(b) | Audit controls |
| IIA GTAG 3 — Auditing IT Governance | Internal IT audit standards |
| RFC 8785 — JSON Canonicalization Scheme | Canonical JSON for signatures |
| RFC 3161 — Internet X.509 PKI Time-Stamp Protocol | Timestamp tokens (roadmap) |
| Tripwire / Wazuh / OSSEC | FIM tools accepted with internally-managed keys |
| AWS CloudTrail log-file integrity validation | Structural analog for hash-chained logs |

---

## Appendix: Status Tracking

| Item | Status |
|------|--------|
| FIM-class positioning analysis | Complete (this document) |
| Control description template | Complete (§4) |
| Auditor validation | **Open** — highest-leverage research item |
| Asymmetric signing (Ed25519) | **Landed** (regista BC-196, Plan 011) |
| RFC 3161 timestamping | **Removed** — regista deleted the subsystem in 0.6.0 (the Merkle construction witnessed no content) |
| Witness federation | Roadmap |

---

*This document is part of the agent-provenance project. Source:
`docs/fim-class-positioning.md`. For the full architecture and trust
model, see the project README.*
