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
`WF-Research-01-03-manual-preflight.json` for every node except the two the frozen-cell
lane extends (`01 Select candidate`, `03 Engineering readiness`) and the one edge it
rewires (`02 Read pinned record`).

### On-demand frozen-cell handoff (IMPLEMENTATION_NEEDED)

HB_READY admission is the only strategy admission. A selected candidate that has no
executable recipe for this run does not stop at a human endpoint: `02c Handoff
request` builds one fixed resolve request from the pinned record identity plus the
`handoff_policy` run input (the full effective identity: strategy, params,
warmup, window, sides, leverage, runtime, data, approved house overlay, cost model,
and the frozen evidence root). `02d` sends it to the host `research-handoff` verb on
the restricted Hermes key.

The host does not generate, write or import anything. It reads the frozen
`campaign-manifest.json` that the existing engineering flow (a Qlib
`materialize()` run) already produced, finds the cell for exactly that candidate and
exactly that effective identity, compares every byte with the digest the manifest
froze, and prints the executable handoff built from that evidence. `02e Handoff
envelope` passes the handoff into the same `03 Engineering readiness` gate, so the
lane continues at 04 without a second admission, a `QLIB_READY` flag or an Alpha
write-back.

Three answers are possible, and only one of them passes:

- `ready` — a frozen cell matches the requested identity byte for byte;
- `implementation_needed` — no frozen cell exists yet; the run holds and the reason
  names what the existing engineering flow still has to produce. The host writes no
  cell and never invents a strategy;
- `failed` — a cell exists but does not carry the requested identity (a changed
  `trade_cost`, `approved` flag, runtime, params, overlay or artifact hash), or its
  bytes no longer match the frozen manifest. The run holds; nothing is re-signed.

`03h HOLD lane gate` and `03i HOLD endpoint` make every non-ready route observable
(`IMPLEMENTATION_NEEDED`, `ENGINEERING_HOLD`, `NEEDS_REVIEW`, `WAITING_DATA`). A
capability the shell does not execute — today any declared side other than `long` —
routes `ENGINEERING_HOLD` instead of being accepted as a smaller strategy. The
strategy artifact is engineering evidence produced by the existing Hermes/Kanban
flow, not an admission record: this lane never batch-generates strategies, never
imports generated code on the host, and never adds a Markdown-to-Qlib compiler,
registry or second control plane.

Live credentials stay operator placeholders (never stored here): `Hermes Host SSH`
(restricted SSH, Node06 Hermes CLI turn), GitHub (`githubApi` predefined credential for
the native GitHub nodes plus the one REST branch/ref gap), and Google Sheets OAuth2
for the native registry upsert.

Before deployment, bind `Hermes Host SSH` to a separate restricted key. Do not
reuse the Qlib key or an unrestricted host key. Use this host `authorized_keys`
shape. Replace the placeholders with trusted absolute paths and the public key:

    restrict,command="<PYTHON> <TRANSPORT>/research-transport.py hermes-forced" ssh-ed25519 <PUBLIC_KEY>

The fixed command accepts only `research-hermes <base64 UTF-8 task>` and
`research-handoff <base64 JSON request>`, with the native SSH node's optional
`cd / ;` prefix. The encoded argument limit is 65,536 characters. The host must
resolve `hermes` through a trusted PATH. Do not permit client environment overrides.
The handler sends the decoded task through stdin to this fixed argv, with a
1,800-second process timeout:

    hermes chat --query-file - --oneshot -Q --format stream-json -t wiki_brain

`research-handoff` starts no subprocess at all. It reads one campaign manifest and
the cell files it names, compares their sha256 with the digests the manifest already
holds, and prints one JSON report. It writes no file, starts no shell, runs no Qlib
verb and imports no strategy artifact: executing the frozen artifact stays in the
native Qlib run path.

### Verified campaign-manifest readback (zero writes)

`research-handoff` takes a third request kind, `campaign-manifest-read-v1`:

```json
{"request": "campaign-manifest-read-v1", "source_commit": "<40 hex>",
 "candidate_path": "<file>.md", "source_blob_sha": "<40 hex>",
 "evidence_root": "/abs/evidence/root"}
```

The manifest is loaded from `evidence_root/campaign-manifest.json`, never from the
request. The reply is `status=ready` only when the file parses, its `schema` is
`qlib-formal-campaign-manifest-v1`, `cell_count` equals its `cells`, every cell ref
resolves inside `evidence_root`, every declared digest (entrypoint, effective config,
strategy artifact) equals the bytes on disk, every cell config still declares that
cell's own candidate/runtime/artifact identity, every cell carries the requested
candidate, and every cell shares one window. The reply returns the whitelisted cell
fields plus `manifest_ref`, `manifest_sha256`, `cell_count`, `window` (with
`identity_sha256`), `manifest_kind: "campaign"` and `phase_binding`.

This read is not the per-run `manifest.json`. A run manifest is a sha map with no
schema, and a run directory has no campaign manifest at all, so neither can pass
here. `phase_binding` is filled only when a verified `materialize-receipt.json` in
the same root binds that exact `manifest_sha256`; otherwise it is `null` with
`phase_bound: false` and the caller holds. Zero writes, no child process.

The caller supplies the evidence root, but nothing inside it is trusted: every
digest is recomputed, so a foreign root can only produce verified facts about its
own bytes, and a ref outside that root is refused.

### Native evidence in the Node05 receipt (additive)

After every existing manifest/hash/readback check, `research-readback` adds one
`native_evidence` object. It only re-exposes fields those checks already verified,
and it never fills in a value the native run did not write:

* `phase`, `phase_source`, `phase_bound`, `feeds_research`, `oos_isolated` — the
  phase comes only from a verified materialize receipt bound to this run's frozen
  config, so an unbound run reports `phase: null` and the caller holds;
* `window` — the approved start/end from the hash-verified effective config, the
  native evaluation start/end from `summary.json`, `native_inside_approved`, and the
  approved window `identity_sha256`;
* `metrics` — `total_trades` (required integer) plus the native net return, CAGR,
  Sharpe, max drawdown, win rate, profit factor, net profit, evaluation bars and
  funding paid; a metric the native run omitted stays `null` and is listed in
  `metrics_omitted`;
* `applied_economics` — the whitelisted native block verbatim (fees/funding/slippage
  truth, funding source identity and digests, `declared_model_matches_applied` and
  its reason);
* `performance_claimable` and `cost_model_approved` — the native claim, plus
  `limitations[]` assembled from those native facts;
* `identity` — candidate/commit, entrypoint, effective config, strategy artifact and
  params, run manifest sha256, and (when bound) the campaign manifest and spec
  sha256.

Malformed or contradictory native evidence fails closed: a non-numeric metric, a
malformed window, an evaluation window outside the approved one, params that differ
from the verified config, or a claim of performance claimability on a zero-trade run
all exit 2. The receipt's own top-level `performance_claimable` stays derived-false
(`coverage_complete` stays false), so a single cell never becomes a campaign claim.

### Bounded materialization (Qlib key only)

`research-materialize <base64 JSON>` is the third Qlib forced verb. It runs only the
existing materializer and never carries strategy semantics:

```json
{"request": "materialize-v1", "spec_ref": "/abs/spec.json", "root": "/abs/cells",
 "phase": "IS_BASELINE", "window": {"start_utc": "YYYY-MM-DD HH:MM:SS",
 "end_utc_inclusive": "YYYY-MM-DD HH:MM:SS"}, "source_commit": "<40 hex>",
 "candidate_path": "<file>.md", "source_blob_sha": "<40 hex>",
 "strategy_artifact_sha256": "<64 hex>", "qlib_runtime_commit": "<40 hex>"}
```

Every path (`spec_ref`, `root`, the spec's `materialize.cells_dir`,
`materialize.results_root` and the declared artifact source) must stay inside the
resolved results root, and `root` must equal the spec's `cells_dir`. The spec must
carry exactly that candidate, runtime commit, window and artifact sha256; a declared
side outside the verified `long` primitive is an `ENGINEERING_HOLD`. The only child
process is:

    <fixed runtime python> -m qlib.backtest.research_cell materialize --spec <validated> --root <validated>

No arbitrary argv, no shell, no `--force`. After the child, the transport verifies
the campaign manifest the Qlib run wrote (schema, per-cell digests recomputed,
per-cell candidate/runtime/window/artifact binding) and writes one deterministic
`materialize-receipt.json` in the cells root binding the request identity, runtime
commit/image/digest, spec sha256, artifact sha256, root, phase, window and window
identity, and the campaign manifest ref/sha256/cell count plus `cell_ids_sha256` and
`cell_evidence_sha256`.

An existing root converges only through that receipt: the same request returns the
same receipt and `state: "existing"`. A different spec, a different phase, a root
without a receipt, or any identity mismatch refuses (`refuse overwrite`); a receipt
is never reconstructed from a later spec, so a changed cost model or parameter block
cannot be retroactively bound to older cells. Concurrency uses one
`O_CREAT|O_EXCL` lock with a bounded wait and then converges by re-verification; a
still-held lock is a typed refusal.

An absent approved spec is an expected answer, not a transport failure: the verb
prints `{"ok": true, "status": "implementation_needed", "reason":
"MATERIALIZE_SPEC_MISSING: ..."}` and exits 0, exactly like `research-handoff`. A
malformed spec, a mismatched identity, an unsafe path or a runtime mismatch still
exits 2. **Residual capability boundary:** this PR adds no engineering verb, no
Markdown-to-Qlib compiler and no agent shell, so a candidate whose approved
spec/artifact does not exist yet cannot materialize itself; that still requires the
existing Hermes/Kanban engineering flow to produce the spec and the artifact.

### Out-of-scope dependency for the campaign lane

`WF-Research-42-cell-campaign.json` compares `receipt.refs.manifest` with
`handoff.evidence_refs.manifest`, but `_handoff_from_cell` overwrites that key with
the **campaign** manifest path while `research-readback` returns the **run**
manifest. That mismatch belongs to the campaign workflow card, not to this
transport PR, and no workflow JSON is changed here.

The existing no-argument Qlib forced command accepts only `research-submit`,
`research-readback` and `research-materialize`. The Hermes key accepts none of them.
No key, listener or host handler is installed by this PR.

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
