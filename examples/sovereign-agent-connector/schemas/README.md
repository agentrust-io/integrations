# Schemas

No schema is frozen. The experiment uses Python structures so that the
standards delta can be validated before a wire format is fixed.

`aucp-semantic-delta-v0.1.json` is a machine-readable inventory of the semantics
this profile adds on top of the standards it reuses. Every entry is classified as a
projection, binding, join, normalized verdict, dispatch-state marker, or
completeness mechanism. It is not a wire schema.
