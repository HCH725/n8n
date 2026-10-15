# HCH725 n8n workflows

This public fork tracks upstream `n8n-io/n8n`. Our workflows may be kept under `workflows/` as **sanitized JSON exports**; this does **not** require modifying or building n8n Core.

## Review and deployment contract

- Changes go through a GitHub PR, the existing signed webhook, and an independent Hermes `auditor` COMMENT review. The comment is advisory, **not** a GitHub-enforced approval. A human must inspect the result before merging.
- A merged workflow file is **not deployed** automatically. Import/update it explicitly in the existing official n8n runtime only after review and a separate, bounded deployment decision.
- This repository is **public**: never commit credentials, access tokens, private keys, credential exports, private research strategies, personal data, internal hostnames or private filesystem paths. Use native n8n Credentials and protected runtime configuration instead.
- Keep upstream n8n source files unchanged unless a separate, evidenced native capability defect demands a scoped fix. Prefer built-in SSH, HTTP Request, GitHub, Google Workspace and Error Trigger nodes; do not create another orchestration framework.

## Quant workflow boundary

The approved Quant Pipeline v8.7 Slides remain the architecture contract; this document is not a replacement.

- **Research**: Nodes 01–12 (Alpha research intake, native Qlib/MLflow, Hermes/Wiki, frozen OOS, reviewed Research Survivor promotion, then native Google Sheets sync).
- **Hummingbot**: Nodes 13–14 (native `/backtesting/tasks`, archive/config replay, event-level parity, independent certified promotion).
- **Error handling**: native n8n Error Trigger. Do **not** import retired C3/C4, Canvas, Shadow, Reconciler or Host Action Bridge workflows.
- **Qlib SSH**: design-only until the existing macOS host connection is explicitly enabled with restricted keys and fixed allowed commands. A successful SSH handshake is **not** evidence of a valid strategy, a Qlib run, or MLflow persistence.
- **First implementation scope**: research Nodes 01–05 only, using a verified executable strategy/config and the current native Qlib/MLflow entrypoints. Never treat HB_READY metadata alone as an executable controller or assume a historical replay is a current backtest.

## Formal Baseline 42-cell campaign

`WF-Research-42-cell-campaign.json` is the round0 coverage orchestration. It stays thin: it generates the frozen 7 symbols x 3 timeframes x 2 research leverages = 42 identities, binds each one to a materialized cell handoff (duplicate, missing, extra or mismatched cells hold the whole campaign before a single submit), runs every cell through the existing Node04 `research-submit` and Node05 `research-readback` forced verbs, and closes with one deterministic coverage aggregate. 42 is coverage, not a parameter sweep: no grid, optimizer or parameter domain exists in it, and a 43rd identity is rejected. A per-cell Node05 receipt keeps `performance_claimable=false`; only a complete 42/42 campaign with an approved research cost model can be claimable, and anything less is a HOLD with named gaps.

`campaign-42-cell-test.js` is the deterministic check for that workflow (`node workflows/campaign-42-cell-test.js`). It reads the Code nodes straight out of the workflow JSON, runs one full in-process campaign over 42 synthetic receipts, and proves the held cases.

This file only establishes a PR-reviewed source location and safety boundary. **No live workflow, new credential, SSH listener, GitHub Actions workflow, container change or auto-deployment is introduced here.**
