# Fixtures

Made by Auditant's own TypeScript core (`@auditant/core`: `appendEvent`, `checkpointFromHead`, `signCheckpoint`, bundle format 1.0.0), not by `auditant_trace.py`, so the tests check this adapter against an independent producer. Each file passed Auditant's own `verifyBundle` with its key trusted before it was written here.

The events are synthetic and the P-256 signing key was generated for these files and discarded: they prove nothing about any real deployment.

| File | What it is |
|---|---|
| `auditant-full.json` | A whole log: 8 events from `seq` 0, checkpoints at tree size 4 and 8 |
| `auditant-ranged.json` | The same log exported from the middle: events 4 to 7, `startHead` at tree size 4, the same two checkpoints |
| `auditant-two-models.json` | 8 events whose two `model_call` events name different models, one checkpoint at 8 |
