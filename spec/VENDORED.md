# Vendored spec artifacts — DO NOT EDIT BY HAND

The files under `schema/` and `vectors/` are **vendored copies** of the normative Auditable MCP
spec artifacts. Their single source of truth is the `mcp-audit-extension` repository
(`spec/schema/`, `spec/vectors/`), generated there from the TypeScript Zod source of truth.

They are copied here so this SDK builds, tests, and publishes standalone without depending on a
separate (currently private) spec checkout.

## Updating

```bash
python scripts/sync_spec.py            # re-copy from ../mcp-audit-extension/spec
python scripts/sync_spec.py --check    # verify no drift (used in CI)
```

Point at a spec checkout elsewhere with `--source <path>` or `AMCP_SPEC_SRC=<path>`.

## Why vendored, not edited

`spec_version` is `auditable-mcp/0.1.1`. A conforming implementation MUST reproduce every golden
vector byte-for-byte (spec §8.4, §11.1). Editing these files here would fork the contract; fix the
spec upstream and re-sync instead.
