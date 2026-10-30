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

The fixed command accepts only `research-hermes <base64 UTF-8 task>`,
`research-handoff <base64 JSON request>`, `research-engineering-create <base64 JSON
request>` and `research-engineering-read <base64 JSON request>`, with the native SSH
node's optional `cd / ;` prefix. The encoded argument limit is 65,536 characters. The
host must resolve `hermes` through a trusted PATH. Do not permit client environment
overrides. The handler sends the decoded task through stdin to this fixed argv, with a
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
here. `phase_binding` is filled only when a `materialize-receipt.json` in the same
root verifies against evidence this file reads for itself:

* the receipt is a regular file inside the campaign root, its `schema` is
  `qlib-n8n-materialize-receipt-v1`, and it binds this exact `manifest_sha256`,
  this manifest ref and this `cell_count`;
* the `spec_ref` it names still exists as a regular contained file and its current
  bytes hash to the receipt's `spec_sha256`, and the manifest's own `generated_from`
  names that same spec;
* the spec's candidate, runtime commit, window, artifact source and `cells_dir`
  agree with the receipt and with every verified cell, and the artifact bytes hash
  to the receipt's `strategy_artifact.sha256`;
* the receipt's `runtime` block equals the runtime the spec declares, and inside
  the fixed runtime it equals the pinned commit, image and digest;
* the receipt's `cell_ids`, `cell_ids_sha256` and `cell_evidence_sha256` equal the
  values recomputed from the verified cells.

A missing receipt is an unbound answer (`null`, `phase_bound: false`) and the caller
holds. A present receipt that does not verify is contradictory evidence and exits 2;
it never silently downgrades to unbound. Zero writes, no child process.

The caller supplies the evidence root, but nothing inside it is trusted: every
digest is recomputed, so a foreign root can only produce verified facts about its
own bytes, and a ref outside that root is refused.

### Native evidence in the Node05 receipt (additive)

After every existing manifest/hash/readback check, `research-readback` adds one
`native_evidence` object. It only re-exposes fields those checks already verified,
and it never fills in a value the native run did not write:

* `phase`, `phase_source`, `phase_bound`, `feeds_research`, `oos_isolated` — the
  phase comes only from a materialize receipt that verifies against this run's
  frozen config **and** the approved spec bytes the receipt binds, so an unbound run
  reports `phase: null` and the caller holds, and a tampered receipt exits 2;
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
carry exactly that candidate, runtime commit, window, **approved `phase`** and
artifact sha256; a declared side outside the verified `long` primitive is an
`ENGINEERING_HOLD`. The approved phase is a property of the approved spec, not of the
request alone: the request phase must equal `spec.phase`, and the receipt records
that spec-bound phase. The only child process is:

    <fixed runtime python> -m qlib.backtest.research_cell materialize --spec <validated> --root <validated>

No arbitrary argv, no shell, no `--force`. After the child, the transport verifies
the campaign manifest the Qlib run wrote (schema, per-cell digests recomputed,
per-cell candidate/runtime/window/artifact binding) and creates one deterministic
`materialize-receipt.json` in the cells root binding the request identity, runtime
commit/image/digest, spec sha256, artifact sha256, root, phase, window and window
identity, and the campaign manifest ref/sha256/cell count plus `cell_ids_sha256` and
`cell_evidence_sha256`.

The receipt is created with `O_CREAT|O_EXCL|O_NOFOLLOW` and mode `0600`. It never
follows an existing path and never replaces one. A pre-existing
`materialize-receipt.json` without a completed manifest/receipt pair is refused
before the materializer starts, so a symlink, a dangling symlink or a foreign file in
the cells root cannot redirect a write outside the results root.

An existing root converges only through that receipt: the same request returns the
same receipt and `state: "existing"`. A different spec, a different phase, a root
without a receipt, or any identity mismatch refuses (`refuse overwrite`); a receipt
is never reconstructed from a later spec, so a changed cost model or parameter block
cannot be retroactively bound to older cells. Concurrency uses one
`O_CREAT|O_EXCL` lock with a bounded wait and then converges by re-verification; a
still-held lock is a typed refusal.

Every request-only constraint is checked before the spec is read: the fixed-runtime
commit identity, the phase and window shape, the candidate/source identity shape, the
results-root containment, and the `spec_ref` path type. A `spec_ref` that is a
directory, a symlink or an escaping path exits 2, and so does a known runtime
mismatch, even when no spec exists. An absent approved spec is an expected answer,
not a transport failure: the verb prints `{"ok": true, "status":
"implementation_needed", "reason": "MATERIALIZE_SPEC_MISSING: ..."}` and exits 0,
exactly like `research-handoff`, but only when the absent path is a regular-file path
in a real directory inside the results root and every other request constraint is
valid. A malformed spec, a mismatched identity, an unsafe path or a runtime mismatch
still exits 2. **Residual capability boundary:** this transport writes no strategy
artifact and no materialize spec. A candidate whose approved spec/artifact does not
exist yet is handed to the existing Hermes Kanban `default` worker by
`research-engineering-create`, and only its verified output is read back by
`research-engineering-read`. The transport itself still generates nothing.

### Bounded Kanban engineering adapter (two host verbs)

`research-engineering-create <base64 JSON>` submits one fixed-template task to the
EXISTING Hermes Kanban board `quant-strategy-research` for the existing `default`
worker. `research-engineering-read <base64 JSON>` reads that exact task back and
returns a typed state. Both verbs are Hermes-key only: the Qlib key, the container
forwarder and the CLI dispatch accept neither.

The request is `engineering-task-v1`. It carries only frozen inputs:

```json
{"request": "engineering-task-v1", "source_commit": "<40 hex>",
 "candidate_path": "<file>.md", "source_blob_sha": "<40 hex>",
 "family_id": "<strict id>", "round_index": 0, "phase": "IS_BASELINE|IS_RETEST",
 "window": {"start_utc": "...", "end_utc_inclusive": "..."},
 "spec_seed": {"candidate": {...}, "runtime": {...}, "data": {...},
               "strategy": {...}, "house_overlay": {...},
               "research_cost_model": {...}},
 "change_set": {"optional": "data only"}}
```

Every other field is derived and cannot be chosen: the runtime is pinned to commit
`f92320c1`, image `qlib:main-f92320c1-arm64` and digest `6081534f`, the board, the
assignee, the profile, the model, the provider, the workspace, the parents and the
worker prompt are constants, and the materialize block, the artifact source and the
candidate `blob_api_ref` come from the request hash and the pinned runtime. An OOS
phase, an unverified side, a caller-supplied `blob_api_ref` or URL, a host path in
any DATA field and any unknown field exit 2. `candidate_path` must be one ASCII
basename that ends in `.md`, and it reaches the worker only inside the escaped DATA
JSON, never in an instruction sentence.

**The immutable source is evidence, not prose.** The fixed template requires the
worker to fetch the exact Alpha blob from the derived `blob_api_ref`, to reject a
response whose `sha` differs from `source_blob_sha`, to base64-decode `content` and
to write exactly those bytes to `candidate-source.md`, to read that whole file
before writing any code, and to block the task without writing
`engineering-result.json` when any of those steps fails. The read verb enforces the
same rule by itself: it recomputes the Git object id of `candidate-source.md` as
`SHA1("blob " + decimal byte length + NUL + bytes)` and requires the pinned
`source_blob_sha`. Family, title, `params` and a worker declaration are never
authority. The transport performs no network fetch.

**Two filesystems, one mapping.** The worker runs on the host, so its workspace is
the host path `<host-backing-root>/production/engineering/<request_hash>`, where
`<host-backing-root>` is the directory the existing `RESEARCH_HOST_RESULTS_SOURCE`
setting names. Qlib runs in the fixed container, so
`materialize-spec.json` and the `spec_ref` returned to n8n carry guest `/results`
paths: `strategy_artifact.source`, `materialize.cells_dir`
(`.../<request_hash>/frozen-cells`) and `materialize.results_root`
(`/results/production`). One fixed helper maps guest to host, so a spec cannot name a
host location of its own. `cells_dir` is always a dedicated child, never the
workspace, because `research-materialize` refuses a non-empty cells root.

The create verb checks the fixed existing backing root, then builds only
`production` -> `engineering` -> `<request_hash>` with an `lstat` walk that refuses a
symlink, a dangling symlink or a plain file at every component. It creates nothing at
import, resolve or read time. It calls exactly one fixed argv, with no shell and with
every inherited `HERMES_KANBAN_*` identity removed:

    hermes kanban --board quant-strategy-research create <title> --body-file - \
      --assignee default --workspace dir:<leaf> --idempotency-key <derived> \
      --max-runtime 5400 --created-by n8n-research-engineering \
      --completion-contract local-only --json

The task body is a constant template plus one JSON DATA block, so a worker never
receives a free-form prompt. The read verb re-renders that body and requires an exact
match, which is how it proves the task came from this adapter for this exact request.
`show --json` does not expose the idempotency key, so provenance is the rendered body
plus the derived workspace, the fixed author, the fixed runtime cap and the absent
model/provider overrides.

The read verb returns `ready=false` with `status` `pending`, `blocked`, `failed` or
`timeout`, and `ready=true` only after it verifies, byte for byte: the workspace is
the derived contained real directory, `candidate-source.md` is a regular contained
file whose Git object id equals the pinned `source_blob_sha`,
`engineering-result.json` carries the schema, the request hash, the candidate
identity, the phase and the round, the artifact and the spec are regular contained
files whose sha256 match the result, every spec block is a JSON object, the spec
blocks equal the frozen request, the artifact source resolves to the verified
artifact, the runtime and candidate identity are exact, and the cells/results roots
are the derived ones. A result that exists is evidence under contract for every
task status: a present but malformed or inconsistent output exits 2 whatever the
card says, and a fully valid result on a non-terminal task stays non-ready with
that task status instead of being promoted early. It never downgrades to `pending`.

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
