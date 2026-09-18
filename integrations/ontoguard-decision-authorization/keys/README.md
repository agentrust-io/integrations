# Trusted key registries

- `ontoguard_jwks.json` — OntoGuard authorization signing keys.
- `execution_runtime_jwks.json` — execution-runtime receipt keys.

Keys with `test_only: true` are ignored unless
`ONTOGUARD_ADAPTER_ALLOW_TEST_KEYS=1` or `allow_test_keys=True`.

Production deployments must replace these files with operator-managed
allowlists. A caller-supplied JWK is accepted only when its thumbprint
matches an allowlisted key.
