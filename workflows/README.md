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

This file only establishes a PR-reviewed source location and safety boundary. **No live workflow, new credential, SSH listener, GitHub Actions workflow, container change or auto-deployment is introduced here.**


## Single deploy target: WF-Research-01-12.json

`workflows/WF-Research-01-12.json` (workflow id `OhSN7BCpOVLMcUMQ`) is the one
deploy target of the Quant WF-Research 01-12 lane. It carries the frozen 01-05
transport plus the audited 06-09 learning loop and the audited 10-12 survivor
handoff, wired as one graph: 01->02->03->04->05->06->07->08->09, the 09 RETEST
round back into this same workflow's 04, 09 FINALIZE -> 10 -> the same 04/05 for
the OOS round -> 11 -> 12 -> the Node13 boundary. It ships `active=false` with no
schedule.

The component exports stay in the tree as validation fixtures:

* `WF-Research-01-03-manual-preflight.json` - validation fixture / NOT deploy target
* `WF-Research-06-09-learning-loop.json` - validation fixture / NOT deploy target
* `WF-Research-10-12-survivor-handoff.json` - validation fixture / NOT deploy target

Only `WF-Research-01-12.json` is a deploy target. The component fixtures keep the
frozen transport bytes that the single workflow must reproduce; the targeted test
`workflows/tests/test_wf_research_01_12_single.py` runs the exported graph with
Node.js and compares the carried 01-05 nodes and edges against
`WF-Research-01-03-manual-preflight.json` byte for byte.

Live credentials stay operator placeholders (never stored here): `Hermes Host SSH`
(native SSH, Node06 Hermes CLI turn), GitHub (`githubApi` predefined credential for
the native GitHub nodes plus the one REST branch/ref gap), and Google Sheets OAuth2
for the native registry upsert.
