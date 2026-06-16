# AP-012: global_seq CACHE gaps make every real bundle fail `cairn verify`

**Kind:** bug (blocks Plan 006 deliverable)
**Status:** resolved 2026-06-16 — Option 1 (global hash chain) implemented
**Severity:** high
**Component:** verifier / regista (cross-project)
**Found:** 2026-06-16, live dogfood (Plan 006 WI-1), Opus 4.8

## Resolution (Option 1: global hash chain)

regista migration 030 adds `prev_global_event_hash` = sha256(prev.canonical_envelope
+ prev.signature) of the immediately-preceding event in append order, bound into
the signed v3 envelope. Appends serialise on a single-row `event_chain_head`
table (`SELECT ... FOR UPDATE`) so concurrent cross-work-item appends chain onto
one line without forks — robust to global_seq being out of commit order under
CACHE 100. The cairn verifier (`_check_chain_contiguity`) now walks the signed
hash links instead of numeric `global_seq` contiguity (legacy pre-030 bundles
keep the numeric fallback). Validated end-to-end on a live Ed25519 bundle:
clean bundle verifies with the public key alone (no false positives); deleting a
whole work item is caught by the global chain *even after the bundle hash is
rebuilt* — the cross-work-item deletion nothing else could detect. regista
1069+2 tests green; cairn 140 tests green. Tail-truncation within a single
bundle remains out of scope (needs an external anchor — bundle chaining / TSA).

## Symptom

A complete, untampered bundle exported from a freshly-seeded regista fails
`cairn verify` with `VERIFICATION FAILED`. Ed25519 signatures verify, the
per-work-item `prev_event_hash` chain verifies — the *only* violations are
`global_seq_gap` ("N event(s) missing. Events may have been deleted or
truncated"). The DB held exactly 21 events; the bundle held exactly 21 events.
Nothing is missing.

## Root cause

`verifier._check_chain_contiguity` step (1) treats any `global_seq` gap > 1 as
a deletion/truncation. But regista's `events_global_seq_seq` is declared
`CACHE 100` (regista migration 017). Each Postgres backend connection caches a
100-value block and hands out one before the connection is returned to the
pool. The cairn hook architecture runs **one process per tool call**
(`cairn_hook.py` → `cairn-bridge` subprocess → new `Regista()` → new pooled
connection), so **every event lands on a fresh cache block and `global_seq`
jumps ~100 per event by design.** Contiguity therefore never holds for real
captures.

## Why it isn't a trivial fix

`global_seq` contiguity is **load-bearing**: `prev_event_hash` is computed
strictly per-work-item (`regista._events`: `WHERE work_item_id = %s AND
event_seq = next_seq - 1`). The per-WI chain catches edits/splices/deletions
*within* a work item; `global_seq` contiguity is the **only** mechanism that
detects deletion of a whole work item or truncation of the genesis prefix
*across* work items. There is **no global hash chain** in regista (events table
columns confirmed: per-WI `prev_event_hash` + numeric `global_seq` only).

So naively downgrading the gap check (cairn-only) unblocks verify but **loses
cross-work-item completeness coverage** — directly undercutting the project's
auditor-grade integrity thesis. The two integrity structures do not cover each
other once gaps are expected.

## Options (decision needed — spans regista, the system of record)

1. **regista: global hash chain.** Each event also stores
   `prev_global_event_hash` (hash of the immediately-preceding event in global
   order) bound into the signed envelope. Completeness becomes a hash walk,
   immune to numeric gaps. Principled and durable; substantial regista change
   (new column, backfill, envelope/version bump, verifier walks it instead of
   numeric contiguity).
2. **regista: gapless global_seq** (drop `CACHE`, or a gapless allocator).
   Smaller, but reintroduces per-event sequence contention (the reason CACHE
   exists) and *still* gaps on transaction rollback — fragile, not a real fix.
3. **cairn: drop global_seq contiguity as a hard failure** (note only). Quick;
   accepts reduced coverage (no whole-WI-deletion / genesis-truncation
   detection). Weakens the integrity claim — do not do silently.
4. **Interim:** (3) as an explicit, documented coverage caveat in the bundle +
   verify output, with (1) as the roadmap. Unblocks the Plan 006 demo honestly
   without overclaiming.

## Repro

```
docker compose -f ../regista/docker-compose.test.yml up -d
# register project + Ed25519 demo key, drive cairn_hook.py pre/post a few times,
# cairn export --dsn ... --project ... --keys signing.json --output b.json
# cairn verify --bundle-path b.json --keys public.json   ->  FAILS on global_seq_gap only
```
