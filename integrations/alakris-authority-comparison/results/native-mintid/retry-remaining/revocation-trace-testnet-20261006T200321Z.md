# Revocation trace — testnet — 2026-10-06T20:03:21.462Z

Chain `mintid-testnet-2`, issuer `3d2a9df3cc5cb853…`, verifier `6f4c5d1becd3c47e…`. Raw events: `revocation-trace-testnet-20261006T200321Z.jsonl`. Decision log: not read (operator only: MINTID_VERIFIER_CONSOLE_PASSWORD).

## Authority evidence

| Field | Value |
|---|---|
| Source | the issuer's status root on chain `mintid-testnet-2`, read by the verifier with an ics23 proof against the node's committed app hash at each decision (R15) |
| Revision | verifier `497509ebf0c3` (public-v2026-10-06.2), issuer `497509ebf0c3` (public-v2026-10-06.2); verifier engine `proof-core 0.4.0`, SDK 0.3.0, SPEC-1 v3.2 |
| Issuer signing key | `9ddd3b08a70e3506…` (a key id, not a revision) |
| Status/root | before: epoch 6284, finalized height 88998; after: epoch 6293, finalized height 89087 |
| Observation time | before 2026-10-06T20:03:22.000Z; after 2026-10-06T20:07:56.000Z (verifier `/v1/status`) |
| Actual age | before 29 s; after 33 s |
| Deployed freshness limit | 180 s maximum root age (heartbeat 30 s; verifier height lag 100 blocks; K = 5 s) |
| Check performed | condition 5: the proof is verified against the issuer definition (BBS key + accumulator) the newest *provable* finalized root anchors; condition 7: the presented root is the current root, or a ring entry inside its validity window, superseded within the height lag and followed by no emergency root; chain unreadable → refuse |

Presentation lifetime: 10 s (R14) — bounds replay, not revocation; a separate field from the revocation latency below.

## Temporal revocation

| Path | Trigger time (t0) | Authority evidence consulted at the denial | Last accepted action | Required deny point (bound) | First observed denial | Root carrying the revocation |
|---|---|---|---|---|---|---|
| kill_switch | 2026-10-06T20:04:20.518Z — the recording of the nullifier on chain (block time of the relay's tx) | current root epoch 6287 (finalized height 89024, generated 2026-10-06T20:04:23.000Z) | none after t0 (—) | t0 + 245 s (t0 + G + A + K) = 2026-10-06T20:08:25.518Z | 2026-10-06T20:04:28.918Z (+8.4 s), `status_root_stale` | — |
| cascade (cascade_agent_1) | 2026-10-06T20:05:24.000Z — generation of the trigger root (the root carrying the principal's revocation) | current root epoch 6291 (finalized height 89066, generated 2026-10-06T20:06:23.000Z) | 2026-10-06T20:06:20.617Z (+56.6 s) | t0 + 395 s (t_T + 7·H + A + K) = 2026-10-06T20:11:59.000Z | 2026-10-06T20:06:30.824Z (+66.8 s), `status_root_stale` | trigger root epoch 6289, finalized height 89047 at 2026-10-06T20:05:24.154Z |
| cascade (cascade_agent_2) | 2026-10-06T20:05:24.000Z — generation of the trigger root (the root carrying the principal's revocation) | current root epoch 6290 (finalized height 89055, generated 2026-10-06T20:05:53.000Z) | 2026-10-06T20:05:48.320Z (+24.3 s) | t0 + 395 s (t_T + 7·H + A + K) = 2026-10-06T20:11:59.000Z | 2026-10-06T20:06:06.705Z (+42.7 s), `status_root_stale` | trigger root epoch 6289, finalized height 89047 at 2026-10-06T20:05:24.154Z |

## Measured deny point per path

| Path | First observed denial − t0 | Bound | Within the bound |
|---|---|---|---|
| kill_switch | 8.4 s | 245 s | yes |
| cascade/cascade_agent_1 | 66.8 s | 395 s | yes |
| cascade/cascade_agent_2 | 42.7 s | 395 s | yes |

Times are wall-clock UTC of this machine; a root's "finalized at" is the CometBFT block time (BFT time), which trails wall-clock by up to about one block, so it can read earlier than the root's own `generated_at`. Each forced attempt takes about a second (proof + verdict), which is the granularity of the measured points.

## Decision-log lines (R18 fixed-slot records)

| Path | Decision | Verifier answer | Decision-log line |
|---|---|---|---|
| kill_switch first refused | 2026-10-06T20:04:28.918Z | `status_root_stale` | not read (operator only: MINTID_VERIFIER_CONSOLE_PASSWORD) |
| cascade/cascade_agent_1 last accepted | 2026-10-06T20:06:20.617Z | `accepted` | not read (operator only: MINTID_VERIFIER_CONSOLE_PASSWORD) |
| cascade/cascade_agent_1 first refused | 2026-10-06T20:06:30.824Z | `status_root_stale` | not read (operator only: MINTID_VERIFIER_CONSOLE_PASSWORD) |
| cascade/cascade_agent_2 last accepted | 2026-10-06T20:05:48.320Z | `accepted` | not read (operator only: MINTID_VERIFIER_CONSOLE_PASSWORD) |
| cascade/cascade_agent_2 first refused | 2026-10-06T20:06:06.705Z | `status_root_stale` | not read (operator only: MINTID_VERIFIER_CONSOLE_PASSWORD) |

## Attribution

The verifier's record shows the root a decision rested on; revocation is shown by the failed witness refresh.

A first refusal marks when a root newer than the agent's witness became provable to the verifier, which a never-revoked agent forcing an old witness meets too. A revoked agent cannot obtain a newer witness; a live one can, and is accepted again. Times are seconds after the path's t0.

| Path | Revoked agent | First refused | Witness refresh |
|---|---|---|---|
| kill_switch | `agent_kill_switch` | +8.4 s `status_root_stale` | refused +37.1 s, `credential_revoked` |
| cascade (cascade_agent_1) | `cascade_agent_1` | +66.8 s `status_root_stale` | refused +150.1 s, `credential_revoked` |
| cascade (cascade_agent_2) | `cascade_agent_2` | +42.7 s `status_root_stale` | refused +95.9 s, `credential_revoked` |

## Rule

- **kill_switch**: `status_root_stale`; its decision-log line was not read (not read (operator only: MINTID_VERIFIER_CONSOLE_PASSWORD)), so the rule that decided is not recorded here.
- **cascade (cascade_agent_1)**: `status_root_stale`; its decision-log line was not read (not read (operator only: MINTID_VERIFIER_CONSOLE_PASSWORD)), so the rule that decided is not recorded here.
- **cascade (cascade_agent_2)**: `status_root_stale`; its decision-log line was not read (not read (operator only: MINTID_VERIFIER_CONSOLE_PASSWORD)), so the rule that decided is not recorded here.

