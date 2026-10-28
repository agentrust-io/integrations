# cMCP producer fixtures

Each release directory contains:

- `catalog.json`: exact bytes of `examples/minimal/catalog.json` at the release
  tag. `provenance.json` records its immutable source URL and Git blob ID.
- `audit.jsonl`: actual `SqliteAuditStore.payload` values produced by
  `AuditChain.append()` from the corresponding published `cmcp-runtime` wheel,
  via [cmcp_producer.py](../cmcp_producer.py). The records contain no agent IDs.
- `provenance.json`: the producer version and SHA-256 of each fixture file.

The fixture uses three synthetic session IDs. Session A attempts `echo` and
`delete_all`; sessions B and C attempt `echo`. Tests supply separate bindings
and an agent registry, then check registered/declaration controls, an
unregistered agent and an unmapped session. The cMCP tool catalog remains
invalid as an agent registry.

To reproduce the audit wire format in an isolated environment:

```bash
python -m venv /tmp/shadow-ai-cmcp-02
/tmp/shadow-ai-cmcp-02/bin/python -m pip install --no-deps cmcp-runtime==0.2.0
/tmp/shadow-ai-cmcp-02/bin/python shadow-ai/tests/cmcp_producer.py /tmp/cmcp-02-audit.jsonl
```

Repeat with `0.7.0` in a separate environment. UUIDs and timestamps vary on each
run. Interoperability tests generate fresh records, read them through the
adapter, and independently check their hashes and predecessor links. Fixture
hash checks detect accidental changes; they do not authenticate a gateway or
prove the operator-supplied session identity. No hardware or remote service is
used.
