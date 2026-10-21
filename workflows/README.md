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

`WF-Research-42-cell-campaign.json` is the round0 coverage orchestration. It stays thin: it generates the frozen 7 symbols x 3 timeframes x 2 research leverages = 42 identities, binds each one to a materialized cell handoff (duplicate, missing, extra or mismatched cells hold the whole campaign before a single submit), runs every cell through the existing Node04 `research-submit` and Node05 `research-readback` forced verbs, and closes with one deterministic coverage aggregate. 42 is coverage, not a parameter sweep: no grid, optimizer or parameter domain exists in it, and a 43rd identity is rejected. A per-cell Node05 receipt keeps `performance_claimable=false`.

Receipt coverage alone does not prove native executed cell identity. Node05 returns `native_identity` from the manifest-verified native readback params and `effective_config_sha256` from the submit receipt after it checks the config bytes again. The campaign compares native symbol, frequency and research leverage with the submitted cell. It uses the Qlib frequency map: `1h` to `60min`, `4h` to `240min`, and `1d` to `day`. The config hash must match the frozen handoff. Only a matching cell gets `native_identity_verified=true`. The aggregate permits `performance_claimable=true` only with complete 42/42 coverage, complete evidence, 42 verified native identities, declared research cost and an approved cost model. Missing or mismatched native identity holds the campaign. Outer labels and `run_inputs` alone are not execution evidence. Synthetic tests do not prove a live campaign.

`campaign-42-cell-test.js` is the deterministic check for that workflow (`node workflows/campaign-42-cell-test.js`). It reads the Code nodes straight out of the workflow JSON, runs one full in-process campaign over 42 synthetic receipts, and proves the held cases.

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
`workflows/tests/test_wf_research_01_12_single.py` runs exported Code-node contracts
with Node.js. It checks graph edges and compares the carried 01-05 parameters against
`WF-Research-01-03-manual-preflight.json` byte for byte.

Live credentials stay operator placeholders (never stored here): `Hermes Host SSH`
(restricted SSH, Node06 Hermes CLI turn), GitHub (`githubApi` predefined credential for
the native GitHub nodes plus the one REST branch/ref gap), and Google Sheets OAuth2
for the native registry upsert.

Before deployment, bind `Hermes Host SSH` to a separate restricted key. Do not
reuse the Qlib key or an unrestricted host key. Use this host `authorized_keys`
shape. Replace the placeholders with trusted absolute paths and the public key:

    restrict,command="<PYTHON> <TRANSPORT>/research-transport.py hermes-forced" ssh-ed25519 <PUBLIC_KEY>

The fixed command accepts only `research-hermes <base64 UTF-8 task>`, with the
native SSH node's optional `cd / ;` prefix. The encoded task limit is 65,536
characters. The host must resolve `hermes` through a trusted PATH. Do not permit
client environment overrides. The handler sends the decoded task through stdin
to this fixed argv, with a 1,800-second process timeout:

    hermes chat --query-file - --oneshot -Q --format stream-json -t wiki_brain

The existing no-argument Qlib forced command still accepts only `research-submit`
and `research-readback`. The Hermes key accepts neither. No key, listener or host
handler is installed by this PR.

Node12 sets one audit deadline at PR creation: 24 hours later. The existing Wait
node polls every 15 minutes. An open PR at or after the deadline goes to the
`NEEDS_REVIEW` endpoint with reason `audit_merge_timeout`. A missing deadline
also needs review. A closed PR needs review. A confirmed merge advances to merge
verification. The deadline is not renewed on retry.

These tests do not prove live n8n execution. Merge and a separate deployment
decision must precede local E2E acceptance. That acceptance must check the
restricted host key and installed handler, one Hermes turn and Wiki ACK, the
materialised RETEST/OOS handoffs and campaign readback, replay evidence, Wait
resume, GitHub reads, and the Sheets write/readback. Boundary fixtures in the
targeted test are not evidence that these live capabilities are available.
