# agent-provenance *(working name — not final)*

Cryptographic provenance for agentic workflows. Built on [substrate](../substrate).

> **Status:** Skeleton implemented.  Adapter (`CairnAdapter`), verifier
> (`cairn verify` / `cairn export`), and the substrate workflow are in place.
> Scope attestation (README §2) is implemented as a signed first-class event.
> OpenCode plugin + Python bridge end-to-end functional; Claude Code hooks
> remain open (Plan 004).

## 1. Motivation

Agent tools (Claude Code, OpenCode, Cursor, etc.) are unusable today in many
regulated environments because operators cannot reliably audit what actions the
agent took, what files it touched, on whose authority, and at what time — in a
form an external auditor will accept. The closest analogs are:

- **LLM observability** (Langfuse, LangSmith, Helicone, Arize, AgentOps,
  Datadog LLM Obs): mutable databases, no signatures, no offline verification.
- **AI gateways** (Portkey, Credal, LiteLLM): policy + redaction at the prompt
  boundary, not action provenance.
- **Vendor-native logging** (Anthropic OTel hooks, Bedrock invocation logging,
  Azure OpenAI diagnostics): vendor-controlled, untrusted from an auditor's
  perspective, no independent integrity proof.

The closest *structural* analog is AWS CloudTrail with log-file integrity
validation — but that's for cloud API calls, not agent tool calls, and the
mental model has not been ported to the agent space.

The unoccupied position is: **"CloudTrail for agent actions, vendor-independent,
verifiable offline by a third-party auditor."**

## 2. Honest scope statement (load-bearing)

This is an **audit layer**, not an **enforcement layer**. Substrate signs and
records the events that reach it. It does not, and will not in v1, prevent a
user from running an unsanctioned agent harness or routing model calls around
the audit path. That gap is real, and we name it explicitly:

- **In scope:** tamper-evident, externally verifiable record of every tool call
  emitted by *configured* agent harnesses, bound to an authenticated human
  principal, with offline verification by a third-party auditor.
- **Out of scope:** preventing or detecting agent activity that does not flow
  through a configured harness. That's an endpoint-management, network-egress,
  and identity-broker problem. We integrate with those layers; we do not
  replace them.

To make the scope statement defensible rather than hand-wavy, the *scope itself
must be a signed first-class artifact in the event log* — an attestation that
declares "this substrate instance captures events from configured harnesses A,
B, C; other sources are out of scope." An auditor reading the log can verify
the scope and reason precisely about completeness. This is non-negotiable for
v1 credibility. Implemented: `CairnAdapter.attest_scope()` records the attestation as substrate
work-item transitions, and `Verifier` surfaces attestations in its report.

## 3. Foundation: what substrate already gives us

- Append-only event log with HMAC-SHA256 over RFC 8785 canonical JSON.
- Role-gated, validated state transitions.
- Replay-verifiable projection (drift detectable in O(events)).
- Typed links between work items (e.g., parent action → child action).
- Schema-per-project isolation in shared Postgres.

What substrate **does not yet** give us, tracked as breadcrumbs against
substrate:

- **BC-196** — HMAC is symmetric; no external/adversarial verifiability.
  The org holding the key can still forge events. v1 needs pluggable signing
  (Ed25519 minimum), v2 needs witness/transparency-log anchoring.
- **BC-197** — No delegation chain. Substrate today records "agent A did X"
  but not "agent A did X on behalf of human H, under session S, authenticated
  at time T." Critical for the regulated-buyer accountability question.
- **BC-198** — Defense against the operator-forgery problem at the
  substrate layer: RFC 3161 trusted timestamping → Merkle-tree event chain
  with witness co-signatures → optional OpenTimestamps anchoring for public
  immutability without running a private blockchain.

These are substrate-level concerns; this project consumes substrate's
guarantees and shouldn't reimplement them. As they land, this project's
guarantees strengthen automatically.

## 4. Trust model (target end-state, not v1)

Layered, ordered cheapest-to-most-defensible. v1 ships the first two; v2+
adds the rest as substrate's primitives land.

1. **Canonical-JSON HMAC signature** on every tool-call event (substrate's
   existing primitive).
2. **Delegation chain** in the event payload: `principal_id`, `session_id`,
   `authenticated_at`, `scope`. Signed as part of canonical JSON.
3. **RFC 3161 trusted-timestamp tokens** on event batches. Cheap defense
   against the operator backdating events with their own key.
4. **Asymmetric signing** (Ed25519) so auditors verify with a public key
   instead of holding the signing secret.
5. **Witness federation**: periodic Merkle-root co-signatures by N
   independent parties (auditor, customer, third party). Operator cannot
   rewrite history without compromising the witnesses.
6. **Optional OpenTimestamps anchoring**: piggyback Bitcoin's economic
   security without running a private blockchain. Off by default; on for
   customers who want maximum independence.

The honest residual problem at every layer: **missing events.** No
cryptographic primitive defends against "the operator chose not to record."
That defense is structural — instrument at a layer the operator can't easily
disable, and make the absence of regular heartbeats itself a detectable
anomaly. See §2 scope statement.

### 4.1 Auditor positioning: FIM-class control (working hypothesis)

The peer model produces bundles signed by per-deployment keys with no
commercial-CA chain. The acceptance question — *will an external auditor
treat this as evidence?* — is answered, conditionally, by the file
integrity monitoring (FIM) precedent: tools like Tripwire, Wazuh, and
OSSEC are accepted in SOX ITGC, PCI DSS, and SOC 2 audits with
internally-managed signing keys, provided the **key management control**
is documented (generation, storage, rotation, revocation).

agent-provenance positions as a **FIM-class control for audit logs**.
The auditor evaluates whether the control is configured, whether
signatures verify, and whether the key management procedure is
documented and operated — not whether the signing key chains to a
commercial CA.

Regimes where this positioning is supported by published guidance or
established practice:

- **SOX ITGC** (PCAOB AS 1105 / AS 2201) — controls tested on design
  and operating effectiveness, not on key provenance.
- **PCI DSS** Requirement 10.3.4 (FIM on audit logs, required as of
  March 2025) and Requirement 11.5 (FIM on critical files).
- **FFIEC IT Examination Handbook** (Information Security Booklet,
  p. 79) — prescriptive on log integrity controls without mandating
  external attestation.
- **SOC 2 Type II** (Trust Services Criteria CC4.1, CC7.2) —
  criteria-based; control description in the system description.
- **HIPAA §164.312(b)** audit controls — exceeded by tamper-evident
  signed logs.
- **Internal IT audit** (IIA GTAG 3) — lowest acceptance bar, fully
  satisfied.

**Status:** this is a *working hypothesis*, not a settled answer. The
FIM precedent and the absence of contrary published guidance both
support it, but it has not been validated by putting a sample bundle
in front of a practicing IT auditor. That validation is the highest-
leverage outstanding research item. See §13 (Open questions) and
[`design/research-findings.md`](../agent-wake/design/research-findings.md)
+ [`research-findings-round2.md`](../agent-wake/design/research-findings-round2.md)
for the supporting analysis.

### 4.2 Key management control description (template)

Deploying organizations can copy the following into their SOX system
description, SOC 2 system description, or internal control narrative.
It documents the control an auditor will test.

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
> event with the predecessor key. The principal identifier (`principal_id`)
> remains stable across rotation; the chain of `key_rotation` events
> preserves identity continuity.
>
> **Key revocation:** Revocation is recorded as a signed
> `key_revocation` event with a `revoked_at` timestamp. Events signed
> by the revoked key with `event.timestamp < revoked_at` remain
> verifiable.
>
> **Verification:** Auditors verify signatures independently using the
> `agent-provenance verify` tool against a signed bundle (see §6).
> The tool requires no network access to verify signatures and key
> lifecycle; network access is optional for RFC 3161 timestamp anchor
> validation against the TSA's CA.
>
> **Tamper evidence:** Bundles include a `manifest.json` with per-file
> integrity hashes and a `previous_bundle_hash` pointer to the
> immediately preceding bundle, forming a hash chain across retention
> boundaries (CloudTrail-style). Gaps are detectable at verification
> time.

Substitute deployment-specific values for `<deployment-specific path>`
and any HSM/KMS specifics. The control description is the auditor's
artifact; the bundle and verifier are the evidence.

### 4.3 Considered and rejected

Decisions taken during design with concrete rationale, recorded here
so reviewers do not re-litigate them. Full analysis in
`design/research-findings.md`.

- **Sigstore bundle format** (protobuf v0.3, Fulcio + Rekor). Bundles
  are artifact-centric ("one signing event, one artifact") and assume
  a hosted CA + transparency-log trust root. agent-provenance's data
  model is an append-only log with key rotation chains, scope
  attestations, and auditor co-signatures — none of which fit the
  Sigstore bundle's structure. Adoption would require a hosted Rekor
  equivalent, which contradicts the peer model. Revisit only if a
  hosted transparency-log variant becomes part of the roadmap.
- **DID terminology for rotation** (did:plc, did:web, did:key). The
  `key_rotation` event chain is *materially equivalent* to did:plc's
  signed operation chain (stable principal, predecessor-signed
  rotation, recovery key). Adopting DID terminology adds a
  resolution-layer concept and spec debt without interop benefit:
  auditor tooling does not understand DIDs in the context of offline
  audit bundles. Direct terminology stays.
- **OpenTelemetry signed traces.** No stable published extension for
  cryptographically signing OTel span exports exists as of 2026-05.
  Trace-shaped data with parent-child spans is also a poor fit for
  the append-only audit-log model. Not pursued.
- **Blockchain-anchored timestamping as v1 default** (OpenTimestamps,
  Ethereum notarization). RFC 3161 is still the auditor-accepted
  standard. OpenTimestamps remains a v2 optional hardening layer
  (§4 layer 6), not a v1 default.

## 5. Positioning trade-off, accepted

The scoped-audit-layer posture costs us:

- **The deepest-regulated tier of buyers** (FedRAMP High, certain DoD/IC,
  some HIPAA evaluators) who grade on completeness, not just integrity.
  Acceptable: we can be a log source for those buyers, not the spine.
- **The strategic choke point.** AI gateways will add provenance eventually;
  we become their audit module rather than the platform. Acceptable: this is
  a single-person OSS project, not a venture-scale platform play.
- **Some cross-sell** (API-key vaulting, identity-bound model access,
  harness-config distribution). Acceptable: someone else can build those and
  integrate with us.

The posture is *correct for v1* and the right v1 is the one that the project
owner can deploy at their own workplace under their own compliance team's
sign-off. See §8.

## 6. Architecture sketch (v1)

```
┌──────────────────────────────────────────────────────────────┐
│  Agent harness (Claude Code, OpenCode, Cursor, …)            │
│  ─ PreToolUse  → adapter  → substrate event (action_begin)   │
│  ─ PostToolUse → adapter  → substrate event (action_end,     │
│                                              result_digest)  │
└──────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────┐
│  agent-provenance adapter (this project)                     │
│  ─ Normalizes tool calls into canonical event schema         │
│  ─ Computes file digests (before/after for Edit/Write)       │
│  ─ Hashes tool arguments (canonical form)                    │
│  ─ Resolves delegation chain (principal_id, session_id)      │
│  ─ Threads parent-action link via substrate typed links      │
└──────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────┐
│  substrate (append-only, signed, replay-verifiable)          │
└──────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────┐
│  Verifier (offline tool, this project)                       │
│  ─ Replays substrate events                                  │
│  ─ Verifies signatures, delegation chain, timestamps         │
│  ─ Re-derives file-content provenance for any action         │
│  ─ Emits auditor-ready report                                │
└──────────────────────────────────────────────────────────────┘
```

Initial harness targets: **Claude Code** and **OpenCode**. Claude Code
exposes `PreToolUse` / `PostToolUse` hooks; OpenCode exposes a skill/hook
system. Both are Python-based agent tools with hook interception points, and
the adapter will normalize both into the same canonical event schema. These
two ship first because (a) the project owner uses both daily, and (b) it
dogfoods on itself when the project is being developed.

## 7. Event schema (v1 sketch, not final)

Per-tool-call event:

```yaml
type: tool_call
tool: Edit | Write | Read | Bash | …
tool_args_hash: sha256(canonical_json(args))
tool_args_redacted: { … redacted form for human review … }
files:
  - path: /projects/foo/bar.py
    pre_digest: sha256(…)    # null if file did not exist
    post_digest: sha256(…)   # null if read-only
result_summary: { exit_code, stdout_digest, stderr_digest, … }
on_behalf_of:                # delegation chain (BC-197 dependency)
  principal_id: human:plm
  session_id: claude-code-session-…
  authenticated_at: 2026-05-22T14:32:00Z
  scope: [edit, read, bash:safe-subset]
parent_action_event_id: …    # substrate typed link to parent
harness:
  name: claude-code | opencode
  version: 0.x.y
  config_digest: sha256(settings.json)
```

The `config_digest` is load-bearing for §2: an auditor can verify which
hooks were configured at action time, and therefore what was in scope of
capture for that session.

## 8. Strategic posture

Single-person OSS project. **Not a startup, not a fundraising target, not a
sales motion.** Motivation: the project owner wants to use AI agents at work
in a regulated context and currently cannot, because nobody has built this.

Therefore:

- **Open source from day one.** MIT, same as substrate.
- **Dogfood at the owner's workplace** as the primary validation. One real
  regulated deployment, with internal compliance sign-off documentation,
  is worth more than any number of design partners.
- **Don't pre-optimize for a commercial pivot.** Architectural choices to
  "leave the door open for SaaS" drag the project. If commercialization
  later makes sense, the door is wide enough; designing for it now isn't
  necessary.
- **Build to the owner's compliance team's actual standards**, not imagined
  buyers' standards. They are the rare gift of a real auditor available
  for questions.

Practical first step (non-technical): **check employer IP/moonlighting
policy.** This conversation should happen before the project exists, not
after it's deployed and useful.

## 9. Open questions / decisions deferred

- **Name.** `agent-provenance` is descriptive but bland. Candidates under
  consideration: `cairn`, `stele`, `vellum`, `auspex`, `receipts`,
  `provenant`. See §11.
- **Harness target priority.** Claude Code and OpenCode first is decided.
  Order for v2 (Cursor? Aider? a vendor-neutral SDK wrapper?) — open.
- **Verification UX.** CLI-only for v1? A small web report for the auditor's
  laptop? — open.
- **Delegation chain origination.** v1 can stub `principal_id` from
  environment / OS user. Real IdP integration (OIDC, SAML) is a v2 question.
- **TSA selection.** Free TSAs exist (FreeTSA, DigiCert public) but
  procurement-blessed TSAs vary by industry. v1 picks one and documents
  the swap path. Research recommendation: DigiCert (or GlobalSign) as
  the commercial default; Sigstore Timestamp Authority as the
  self-hosted option; FreeTSA explicitly marked development-only (no
  SLA, no audit certifications). See `design/research-findings.md` §4.
- **Auditor validation of FIM-class positioning.** §4.1 is a working
  hypothesis backed by precedent and the absence of contrary
  published guidance, not by a confirmed acceptance from a practicing
  IT auditor. The highest-leverage outstanding validation is to put a
  sample bundle in front of a Big Four IT audit senior and record the
  reaction. Until that happens, the positioning should be presented
  to deployers as "plausible, modeled on Tripwire/Wazuh acceptance,"
  not as "confirmed."
- **Publishing prior art.** No published academic work or industry
  spec covers cryptographic audit trails for AI agent tool calls;
  agent-wake's external-event-to-session signaling is in a similar
  gap. A short technical report or blog post establishing prior art
  would be cheap insurance against being scooped by a worse version
  of the idea, and would give auditors a citable artifact. Decision
  deferred; not blocking v1.

## 10. What this is *not*

- Not a substitute for endpoint management, DLP, MDM, or identity brokering.
- Not a substitute for legal/compliance review of the underlying workflow.
- Not a private blockchain. (See trust-model §4.)
- Not a vendor of the agent harness itself. We integrate with harnesses;
  we do not ship one.
- Not yet a *thing*. This README is the seed; the work is ahead.

## 11. Naming

The working name `agent-provenance` is descriptive but uninspired. The
shortlist (and the case for each) is in
[`product-concepts/001-naming.md`](product-concepts/001-naming.md). The
project owner will pick. Until then, anywhere this README says
`agent-provenance` is a placeholder.

## 12. Origin

This project crystallized out of a 2026-05-22 design conversation that
started with the question *"could substrate be adapted to provide
cryptographic tracking for agentic workflows?"* The compliance-substrate
project is the immediate ancestor; it is being tabled (not deleted) in favor
of this repositioning. Many of the substrate-level breadcrumbs that
compliance-substrate would have driven (BC-196 asymmetric signing, BC-197
delegation chain) remain relevant here and were filed during that
conversation.

## License

MIT (planned, matching substrate).
