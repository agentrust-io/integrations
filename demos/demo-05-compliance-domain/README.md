# Demo 5: attribute-based enforcement (compliance domain / BAA coverage)

**Duration:** ~90 seconds

Three ways to deny a tool call, one per demo:

- **demo-01** denies by the tool's **identity** (which tool, by name).
- **demo-04** denies by the **call context** (which workflow).
- **demo-05** (this one) denies by the tool's **compliance attributes**: a tool that is not BAA-covered is refused by a single guardrail rule, whatever it is named.

## Run

```bash
python demo-05-compliance-domain/run.py   # cross-platform
# or, bash only:
bash demo-05-compliance-domain/run.sh
```

## What to show the audience

The catalog tags each tool with a compliance domain and BAA status:

| tool | compliance_domain | baa_covered |
|------|-------------------|-------------|
| `write_file` | clinical | true |
| `read_file` | clinical | true |
| `list_dir` | external-analytics | false |

Three calls in one session:

1. `write_file` — **allowed** (`baa_covered=true`).
2. `read_file` — **allowed** (`baa_covered=true`).
3. `list_dir` — **denied, HTTP 403**. A `forbid` rule matches `context.baa_covered == false` and overrides the baseline permit. The call is refused on its attribute, not on its name.

## Why it matters

The guardrail is one rule: `forbid ... when { context.baa_covered == false }`. It covers every non-BAA-covered tool in the catalog, present and future. Add a tool tomorrow with `requires_baa: true` and it is refused on arrival, with no policy edit. That is the difference between allowlisting tool names one by one and enforcing a compliance property across the whole catalog.

## Policy

`policies/baa-guardrail.cedar`:

- baseline `permit` for `ReadFile`, `WriteFile`, `ListDir`.
- `forbid ... when { context.baa_covered == false }` — a Cedar `forbid` overrides any `permit`, so the guardrail holds regardless of the tool name or the baseline rule.

The runtime derives `context.compliance_domain` and `context.baa_covered` from the catalog entry (`baa_covered` is true when the entry does not set `requires_baa`). Runs software-only with `CMCP_DEV_MODE=1`; no hardware required.
