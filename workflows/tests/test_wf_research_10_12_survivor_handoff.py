#!/usr/bin/env python3
"""Targeted test for WF-Research-10-12-survivor-handoff.json.

The test reads the exported workflow and runs each Code node with Node.js.
A small harness gives every node the n8n Code-node surface ($input, $, items).
The test then walks the exported connection graph from the manual trigger. It
verifies the contract cases of the Node10-12 handoff.

Run: python3 workflows/tests/test_wf_research_10_12_survivor_handoff.py
"""

from __future__ import annotations

import copy
import json
import re
import shutil
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
WORKFLOW = HERE.parent / "WF-Research-10-12-survivor-handoff.json"

TRIGGER = "10 \u00b7 Manual trigger"
FINALIZE_FIX = "10 \u00b7 09 FINALIZE input fixture"
SNAPSHOT_FIX = "10 \u00b7 frozen IS snapshot fixture"
FREEZE = "10 \u00b7 Freeze & OOS request"
BOUNDARY_04 = "10 \u00b7 OOS_TO_EXISTING_04 boundary"
OOS_READY_FIX = "05 \u00b7 OOS_READY fixture/re-entry"
OOS_GATE = "10 \u00b7 OOS_READY gate"
REVIEW_10 = "10 \u00b7 NEEDS_REVIEW endpoint"
POLICY_FIX = "11 \u00b7 promotion policy & identity boundary fixture"
EVAL = "11 \u00b7 Research Survivor evaluation"
HOLD_END = "11 \u00b7 HOLD endpoint"
REJECT_END = "11 \u00b7 REJECT endpoint"
REPLAY_FIX = "11 \u00b7 QLIB_REPLAY_PASS fixture"
ASSEMBLY = "11 \u00b7 Replay & PASS assembly"
RECORD = "12 \u00b7 Survivor record payload"
PR_BOUNDARY = "12 \u00b7 GITHUB_PR_CREATE boundary"
PR_END = "12 \u00b7 PR boundary endpoint"
REVIEW_12 = "12 \u00b7 NEEDS_REVIEW endpoint"
EVENT_FIX = "12 \u00b7 merged PR event fixture"
READBACK_FIX = "12 \u00b7 GitHub readback fixture"
MERGE_VERIFY = "12 \u00b7 Merge verification"
SHEETS_PLAN = "12 \u00b7 Sheets upsert plan"
WRITE_FIX = "12 \u00b7 Sheets write result fixture"
ACK_GATE = "12 \u00b7 Sheets ACK gate"
RETRY_END = "12 \u00b7 Sheets RETRY endpoint (bounded, same key)"
ERROR_END = "12 \u00b7 Sheets ERROR endpoint"
NODE13_PAYLOAD = "12 \u00b7 Node13 boundary payload"
NODE13_END = "12 \u00b7 Node13 boundary"

ENDPOINTS = {REVIEW_10, HOLD_END, REJECT_END, REVIEW_12, PR_END, RETRY_END, ERROR_END, NODE13_END}

REGISTRY_ID = "1fzO3zH5xSmQWMH856KY_Z2atLCHkDdRg_cBzltSB_rg"
FRONTMATTER_KEYS = {
    "schema", "survivor_id", "survivor_version", "family_id", "source_strategy_id",
    "source_repository_url", "source_strategy_path", "source_git_commit", "strategy_sha",
    "qlib_survivor_status", "hummingbot_validation_status", "hb_certified", "status",
    "adoption", "approval_scope",
}
BODY_SECTIONS = {
    "Provenance", "Frozen Strategy & Execution", "Dataset / IS / OOS",
    "Qlib Metrics & Artifacts", "42-Cell Coverage", "Hummingbot Validation & Parity",
    "Audit & GitHub History", "Wiki References", "Limitations & Authorization",
}

# The harness runs the workflow's own Code-node bodies. The code strings come
# from the exported workflow JSON in this repository, not from user input. The
# n8n sandbox gives a Code node the same surface, so new Function is the direct
# way to execute the frozen node bodies in a test. No untrusted string is
# interpolated into the function body.
HARNESS = r"""
const fs = require('fs');
const spec = JSON.parse(fs.readFileSync(0, 'utf8'));
const outputs = spec.outputs || {};
const source = (spec.inputs || []).map((json) => ({ json: json }));
function accessor(list, executed) {
  return {
    first: () => list[0],
    last: () => list[list.length - 1],
    all: () => list,
    item: list[0],
    isExecuted: executed !== undefined ? executed : list.length > 0,
    params: {},
  };
}
const $input = accessor(source);
const $json = source.length > 0 ? source[0].json : {};
const $node = { name: spec.node, id: spec.node, type: 'n8n-nodes-base.code' };
function $(name) {
  const list = (outputs[name] || []).map((json) => ({ json: json }));
  const ran = Object.prototype.hasOwnProperty.call(outputs, name);
  return accessor(list, ran);
}
const $execution = { id: 'wf-research-10-12-test', mode: 'manual' };
const report = (payload) => process.stdout.write(JSON.stringify(payload));
try {
  const fn = new Function(
    '$input', '$json', 'items', '$', '$node', '$execution', '$env', 'console', spec.code
  );
  const result = fn($input, $json, $input.all(), $, $node, $execution, {}, console);
  const list = result === undefined || result === null ? [] : (Array.isArray(result) ? result : [result]);
  const items = list.map((entry) => (entry && entry.json !== undefined ? entry.json : entry));
  report({ ok: true, items: items });
} catch (error) {
  report({ ok: false, error: String(error && error.message ? error.message : error) });
}
"""

_CACHE: dict[tuple[str, str], list] = {}


def find_node() -> str:
    """Return an executable Node.js binary."""
    found = shutil.which("node")
    if found:
        return found
    fallback = Path.home() / ".local" / "bin" / "node"
    if fallback.exists():
        return str(fallback)
    raise SystemExit("FAIL: Node.js is not on PATH")


def run_node(spec: dict) -> list:
    """Run one Code node body through the harness. The nodes never read $()."""
    key = (spec["code"], json.dumps(spec.get("inputs", []), sort_keys=True))
    if key in _CACHE:
        return copy.deepcopy(_CACHE[key])
    proc = subprocess.run(
        [find_node(), "-e", HARNESS],
        input=json.dumps(spec),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if proc.returncode != 0:
        raise AssertionError("harness crash: " + proc.stderr.strip()[:400])
    out = json.loads(proc.stdout)
    if not out.get("ok"):
        raise AssertionError("node error: " + str(out.get("error")))
    _CACHE[key] = out["items"]
    return copy.deepcopy(out["items"])


def deep_merge(base, patch):
    """Recursively merge the patch into a copy of the base. None overwrites."""
    merged = copy.deepcopy(base)
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


class Workflow:
    """Load the exported workflow and execute its Code nodes."""

    def __init__(self, path: Path):
        self.raw = json.loads(path.read_text(encoding="utf-8"))
        self.nodes = {node["name"]: node for node in self.raw["nodes"]}
        self.connections = self.raw["connections"]

    def code_of(self, name: str) -> str:
        return self.nodes[name]["parameters"]["jsCode"]

    def is_noop(self, name: str) -> bool:
        return self.nodes[name]["type"] == "n8n-nodes-base.noOp"

    def parents(self, name: str):
        found = []
        for source, outputs in self.connections.items():
            for group in outputs.get("main", []):
                for link in group:
                    if link["node"] == name:
                        found.append(source)
        return found

    def children(self, name: str):
        found = []
        for group in self.connections.get(name, {}).get("main", []):
            for link in group:
                found.append(link["node"])
        return found

    def execute(self, post: dict | None = None):
        """Execute the graph. Return the item list that each node holds.

        ``post`` patches a node's output after the node runs. A patch key with
        the value None clears that field.
        """
        post = post or {}
        outputs: dict[str, list] = {TRIGGER: [{}]}
        remaining = [n for n in self.nodes if n != TRIGGER]
        while remaining:
            progressed = False
            for name in list(remaining):
                incoming = self.parents(name)
                if not all(parent in outputs for parent in incoming):
                    continue
                items = []
                for parent in incoming:
                    items.extend(outputs[parent])
                if not items:
                    outputs[name] = []
                elif self.is_noop(name):
                    outputs[name] = items
                else:
                    outputs[name] = run_node(
                        {
                            "code": self.code_of(name),
                            "node": name,
                            "inputs": items,
                            "outputs": outputs,
                        }
                    )
                if outputs[name] and name in post:
                    outputs[name] = [deep_merge(outputs[name][0], post[name])]
                remaining.remove(name)
                progressed = True
            if not progressed:
                raise AssertionError("graph stalled: " + ", ".join(remaining))
        return outputs


class Case:
    """One contract case. It collects each failed check."""

    def __init__(self, name: str):
        self.name = name
        self.checks = 0
        self.failures: list[str] = []

    def check(self, condition: bool, message: str):
        self.checks += 1
        if not condition:
            self.failures.append(message)

    def equal(self, actual, expected, label: str):
        self.check(actual == expected, f"{label}: got {actual!r}, want {expected!r}")


def endpoint_route(outputs: dict, name: str) -> str:
    """Return the route that the reached endpoint holds."""
    if not outputs.get(name):
        raise AssertionError(f"endpoint not reached: {name}")
    return outputs[name][0].get("route")


def no_write(outputs: dict, case: Case, label: str):
    """The Sheets path and the Node13 boundary must stay empty."""
    case.check(not outputs.get(SHEETS_PLAN), f"{label}: Sheets plan must not run")
    case.check(not outputs.get(ACK_GATE), f"{label}: Sheets ACK gate must not run")
    case.check(not outputs.get(NODE13_PAYLOAD), f"{label}: Node13 payload must not run")
    case.check(not outputs.get(NODE13_END), f"{label}: Node13 boundary must not run")


def headers_of(workflow: Workflow) -> list:
    """Read the embedded registry headers from the Sheets plan node."""
    match = re.search(r"const HEADERS = (\[.*?\]);", workflow.code_of(SHEETS_PLAN), re.S)
    if not match:
        raise AssertionError("HEADERS constant not found")
    return json.loads(match.group(1))


def main() -> int:
    workflow = Workflow(WORKFLOW)
    base = workflow.execute()
    finalize = base[FINALIZE_FIX][0]["finalize"]
    snapshot = base[SNAPSHOT_FIX][0]["snapshot"]
    run_key = finalize["decision"]["selected_run_key"]
    oos_run_key = snapshot["oos_plan"]["oos_run_key"]
    merge_sha = base[READBACK_FIX][0]["readback"]["merge_commit_sha"]
    plan_row = base[WRITE_FIX][0]["write_result"]["rows_after"][0]
    headers = headers_of(workflow)

    cases: list[Case] = []

    # Case 1. The FINALIZE output feeds one frozen OOS request. The identity is
    # stable. The request holds no OOS result. The IS selection is not redone.
    case = Case("1 09 FINALIZE -> frozen one-time OOS request, identity stable")
    request = base[FREEZE][0]["oos_request"]
    case.equal(base[FREEZE][0]["route"], "OOS_REQUEST", "freeze route")
    case.check(
        set(request) == {
            "best_is_run_key", "frozen_version_sha", "effective_config_hash", "period_basis",
            "window_hash", "parent_is_run_key", "oos_run_key", "holdout_policy",
        },
        "request must carry the eight contract fields only",
    )
    case.equal(request["best_is_run_key"], run_key, "best_is_run_key")
    case.equal(request["best_is_run_key"], request["parent_is_run_key"], "parent_is_run_key")
    case.equal(request["frozen_version_sha"], snapshot["frozen_version_sha"], "frozen_version_sha")
    case.equal(request["effective_config_hash"], snapshot["effective_config_hash"], "effective_config_hash")
    case.equal(request["window_hash"], snapshot["oos_plan"]["window_hash"], "predefined window_hash")
    case.equal(request["oos_run_key"], oos_run_key, "predefined oos_run_key")
    case.equal(request["period_basis"], "OOS", "period_basis")
    case.equal(request["holdout_policy"], "ONE_TIME_NO_RETUNE", "holdout_policy")
    again = workflow.execute()
    case.equal(
        json.dumps(again[FREEZE][0]["oos_request"], sort_keys=True),
        json.dumps(request, sort_keys=True),
        "request identity is stable across runs",
    )
    blob = json.dumps(base[FREEZE][0])
    for banned in ("oos_metrics", "oos_result", "oos_equity"):
        case.check(banned not in blob, f"request must not carry {banned}")
    case.check(base[BOUNDARY_04] and base[OOS_READY_FIX], "request goes to the explicit 04 boundary")
    outs = workflow.execute(post={FINALIZE_FIX: {"finalize": {"decision": {"selected_run_key": f"{7:032x}"}}}})
    case.equal(endpoint_route(outs, REVIEW_10), "NEEDS_REVIEW", "changed selection route")
    case.equal(outs[REVIEW_10][0]["reason"], "selected_run_not_is_head", "changed selection reason")
    outs = workflow.execute(post={SNAPSHOT_FIX: {"snapshot": {"run_key": f"{8:032x}"}}})
    case.equal(outs[REVIEW_10][0]["reason"], "snapshot_identity_mismatch", "snapshot identity reason")
    outs = workflow.execute(post={SNAPSHOT_FIX: {"snapshot": {"oos_plan": {"oos_run_key": run_key}}}})
    case.equal(outs[REVIEW_10][0]["reason"], "oos_run_key_not_unique", "OOS key must be unique")
    outs = workflow.execute(post={SNAPSHOT_FIX: {"snapshot": {"oos_metrics": {"sharpe": 1.4}}}})
    case.equal(outs[REVIEW_10][0]["reason"], "oos_result_material_in_input", "OOS result gate")
    case.check(not outs[EVAL], "OOS result material must not reach evaluation")
    cases.append(case)

    # Case 2. An incomplete or mismatched OOS_READY needs review. A complete
    # reply reaches Node11.
    case = Case("2 OOS_READY mismatch/incomplete -> NEEDS_REVIEW; complete -> Node11")
    case.check(base[EVAL], "complete OOS_READY reaches Node11")
    case.equal(base[EVAL][0]["route"], "PERF_PASS", "evaluation route")
    outs = workflow.execute(post={OOS_READY_FIX: {"oos_ready": {"window_hash": "0" * 64}}})
    case.equal(outs[REVIEW_10][0]["reason"], "oos_window_hash_mismatch", "window hash mismatch")
    case.check(not outs[EVAL], "window mismatch must not reach Node11")
    outs = workflow.execute(post={OOS_READY_FIX: {"oos_ready": {"metrics": None}}})
    reason = outs[REVIEW_10][0]["reason"]
    case.check(reason.startswith("oos_ready_incomplete:") and "metrics" in reason, "incomplete metrics")
    outs = workflow.execute(post={OOS_READY_FIX: {"oos_ready": {"evidence_refs": {"equity": ""}}}})
    case.check(outs[EVAL], "an empty evidence ref is a Node11 HOLD, not a Node10 review")
    case.equal(endpoint_route(outs, HOLD_END), "HOLD", "empty evidence ref holds")
    outs = workflow.execute(post={OOS_READY_FIX: {"oos_ready": {"retune_performed": True}}})
    case.equal(outs[REVIEW_10][0]["reason"], "oos_retune_forbidden", "retune forbidden")
    outs = workflow.execute(post={OOS_READY_FIX: {"oos_ready": {"oos_attempt_index": 2}}})
    case.equal(outs[REVIEW_10][0]["reason"], "oos_not_one_time_attempt_1", "one-time attempt index")
    outs = workflow.execute(post={OOS_READY_FIX: {"oos_ready": {"holdout_policy": "FREE_RETUNE"}}})
    case.equal(outs[REVIEW_10][0]["reason"], "oos_holdout_policy_mismatch", "holdout policy")
    outs = workflow.execute(post={OOS_READY_FIX: {"oos_ready": {"manifest_complete": False}}})
    case.equal(outs[REVIEW_10][0]["reason"], "oos_manifest_incomplete", "manifest completeness")
    cases.append(case)

    # Case 3. Policy defects hold. A real performance shortfall rejects. PASS
    # plus replay reaches Node12.
    case = Case("3 policy HOLD, below-threshold REJECT, PASS+Replay -> Node12")
    case.equal(base[ASSEMBLY][0]["route"], "PASS", "default PASS")
    case.check(base[RECORD], "PASS reaches the record payload node")
    outs = workflow.execute(post={POLICY_FIX: {"policy": None}})
    case.equal(outs[HOLD_END][0]["reason"], "promotion_policy_input_missing", "policy missing")
    outs = workflow.execute(post={POLICY_FIX: {"policy": {"approved": False}}})
    case.equal(outs[HOLD_END][0]["reason"], "promotion_policy_not_approved", "policy not approved")
    outs = workflow.execute(post={POLICY_FIX: {"policy": {"draft_8pct_used": True, "thresholds": {"cagr_min_pct": 8, "sharpe_min": 1.0}}}})
    case.equal(outs[HOLD_END][0]["reason"], "draft_8pct_policy_forbidden", "8 percent draft")
    outs = workflow.execute(post={POLICY_FIX: {"policy": {"thresholds": {"cagr_min_pct": 8, "sharpe_min": 1.0}}}})
    case.equal(outs[HOLD_END][0]["reason"], "promotion_thresholds_not_authoritative", "threshold source")
    outs = workflow.execute(post={POLICY_FIX: {"policy": {"cost_basis_defined": False}}})
    case.equal(outs[HOLD_END][0]["reason"], "evaluation_basis_undefined", "cost basis")
    outs = workflow.execute(post={POLICY_FIX: {"policy": {"source_ref": "local-note://draft"}}})
    case.equal(outs[HOLD_END][0]["reason"], "promotion_policy_source_unreadable", "policy source")
    outs = workflow.execute(post={OOS_READY_FIX: {"oos_ready": {"metrics": {"cagr_pct": 5.0, "sharpe": 0.8}}}})
    case.equal(endpoint_route(outs, REJECT_END), "REJECT", "REJECT route")
    case.equal(outs[REJECT_END][0]["reason"], "performance_below_policy", "REJECT reason")
    case.check(not outs[HOLD_END], "REJECT is not HOLD")
    case.check(not outs[RECORD], "REJECT does not reach Node12")
    outs = workflow.execute(post={OOS_READY_FIX: {"oos_ready": {"metrics": {"cagr_pct": 10.0, "sharpe": 1.0}}}})
    case.equal(outs[ASSEMBLY][0]["route"], "PASS", "threshold boundary passes")
    outs = workflow.execute(post={REPLAY_FIX: {"replay": None}})
    case.equal(outs[HOLD_END][0]["reason"], "qlib_replay_evidence_missing", "replay missing")
    outs = workflow.execute(post={REPLAY_FIX: {"replay": {"status": "QLIB_REPLAY_FAIL"}}})
    case.equal(outs[HOLD_END][0]["reason"], "qlib_replay_not_pass", "replay not pass")
    outs = workflow.execute(post={REPLAY_FIX: {"replay": {"window_hash": "f" * 64}}})
    case.equal(outs[HOLD_END][0]["reason"], "qlib_replay_window_mismatch", "replay window mismatch")
    outs = workflow.execute(post={REPLAY_FIX: {"replay": {"effective_config_hash": "f" * 64}}})
    case.equal(outs[HOLD_END][0]["reason"], "qlib_replay_config_mismatch", "replay config mismatch")
    case.check(not outs[RECORD], "replay HOLD does not reach Node12")
    cases.append(case)

    # Case 4. The PASS fixture produces one valid research-survivor-record-v1.
    # The HB status stays PENDING. Node12 never fabricates Node13 evidence.
    case = Case("4 PASS fixture -> valid record, HB PENDING, no fake evidence")
    record_file = base[RECORD][0]["record_file"]
    frontmatter = record_file["frontmatter"]
    contract = record_file["record"]
    case.equal(frontmatter["schema"], "research-survivor-record-v1", "schema")
    case.check(set(frontmatter) == FRONTMATTER_KEYS, "frontmatter key set is the contract set")
    case.equal(frontmatter["qlib_survivor_status"], "PASS", "qlib status")
    case.equal(frontmatter["hummingbot_validation_status"], "PENDING", "HB status")
    case.equal(frontmatter["hb_certified"], False, "hb_certified")
    case.equal(frontmatter["status"], "research-only", "status")
    case.equal(frontmatter["adoption"], "not-approved", "adoption")
    case.equal(frontmatter["approval_scope"], "research-only", "approval scope")
    case.equal(
        record_file["path"],
        frontmatter["survivor_id"] + "-" + frontmatter["survivor_version"] + ".md",
        "record path pattern",
    )
    case.check(set(record_file["body_sections"]) == BODY_SECTIONS, "body sections")
    for group in ("config_snapshot", "data_snapshot", "is_window", "oos_window", "runtime", "cost_model",
                  "metrics", "evidence_refs", "coverage_42cell", "wiki_refs", "qlib_replay", "promotion",
                  "limitations", "is_run_id", "oos_run_id", "strategy_sha", "frozen_version_sha"):
        case.check(contract.get(group) is not None, f"record carries {group}")
    case.equal(contract["hummingbot_validation_status"], "PENDING", "contract HB status")
    case.equal(contract["hb_certified"], False, "contract hb_certified")
    blob = json.dumps(base[RECORD][0])
    for banned in ("hb_certified_at_utc", "parity_verification_status", "hummingbot_task_id", "CERTIFIED"):
        case.check(banned not in blob, f"record must not carry {banned}")
    outs = workflow.execute(post={ASSEMBLY: {"survivor_record_contract": {"hb_certified_at_utc": "2026-10-15T00:00:00Z"}}})
    case.equal(endpoint_route(outs, REVIEW_12), "NEEDS_REVIEW", "fabricated HB evidence route")
    case.equal(outs[REVIEW_12][0]["reason"], "fabricated_hb_evidence:hb_certified_at_utc", "fabricated HB reason")
    outs = workflow.execute(post={ASSEMBLY: {"survivor_record_contract": {"note": "CERTIFIED"}}})
    case.equal(outs[REVIEW_12][0]["reason"], "fabricated_hb_evidence:CERTIFIED", "fabricated certified text")
    case.check(not outs[PR_BOUNDARY], "a bad record never reaches the PR boundary")
    cases.append(case)

    # Case 5. PR open does not write Sheets. The PR boundary states are exact.
    case = Case("5 PR state: boundary blocker, AWAITING_AUDIT_MERGE, PR open writes nothing")
    pr = base[PR_BOUNDARY][0]
    case.equal(pr["route"], "AWAITING_PR_CREATE", "no GitHub credential gives the boundary")
    case.equal(pr["blocked_by"]["code"], "github_credential_missing_in_n8n_instance", "blocker code")
    case.equal(pr["blocked_by"]["required_capability"]["node"], "n8n-nodes-base.github", "required node")
    case.equal(pr["pr_request"]["base_branch"], "main", "base branch")
    case.check(pr["pr_request"]["head_branch"].startswith("promote/"), "head branch")
    case.equal(base[PR_END][0]["pr_state"], "AWAITING_PR_CREATE", "PR endpoint state")
    outs = workflow.execute(post={RECORD: {"pr_create_result": {
        "pr_number": 3,
        "pr_url": "https://github.com/HCH725/research-survivor/pull/3",
        "head_sha": "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12",
    }}})
    case.equal(outs[PR_BOUNDARY][0]["route"], "AWAITING_AUDIT_MERGE", "created PR state")
    case.equal(outs[PR_END][0]["pr_state"], "AWAITING_AUDIT_MERGE", "PR endpoint durable state")
    outs = workflow.execute(post={EVENT_FIX: {"event": {"pr_state": "OPEN"}}})
    case.equal(endpoint_route(outs, REVIEW_12), "NEEDS_REVIEW", "PR open route")
    case.equal(outs[MERGE_VERIFY][0]["reason"], "merge_not_merged:OPEN", "PR open reason")
    no_write(outs, case, "PR open")
    case.check(not base[SHEETS_PLAN] or base[SHEETS_PLAN][0]["route"] == "UPSERT_PLAN_READY", "plan state")
    cases.append(case)

    # Case 6. The Sheets upsert is idempotent by key. The row aligns with the
    # existing 84 headers. A readback mismatch is ERROR.
    case = Case("6 Sheets upsert idempotent by key; mismatch and duplicates are ERROR")
    plan = base[SHEETS_PLAN][0]["sheets"]
    case.equal(plan["spreadsheet_id"], REGISTRY_ID, "spreadsheet id")
    case.equal(plan["tab"], "Survivor Registry", "tab")
    case.equal(plan["key"], ["survivor_id", "survivor_version"], "upsert key")
    case.equal(plan["native_node"]["type"], "n8n-nodes-base.googleSheets", "native node")
    case.equal(plan["native_node"]["operation"], "appendOrUpdate", "native operation")
    case.equal(plan["native_node"]["matchingColumns"], ["survivor_id", "survivor_version"], "matching columns")
    case.equal(plan["headers_ref"]["count"], 84, "header count")
    columns = plan["columns"]
    case.check(all(key in headers for key in columns), "every column exists in the registry")
    case.check(len(columns) < 84, "sparse index: the row is a mapped subset")
    case.check(all(value is not None and value != "" for value in columns.values()), "no empty cell is written")
    case.check(not any("42" in key or "dca" in key.lower() for key in columns), "no 42-cell dump")
    case.equal(columns["survivor_git_commit"], merge_sha, "row commit")
    case.equal(plan["write_policy"]["duplicate_rows_forbidden"], True, "duplicate rows forbidden")
    case.equal(plan["write_policy"]["bounded_retries"], 3, "bounded retries")
    case.equal(plan["blocked_by"]["code"], "google_sheets_credential_missing_in_n8n_instance", "Sheets blocker")
    write = base[WRITE_FIX][0]["write_result"]
    case.equal(write["mode"], "upsert_by_key", "upsert mode updates the same key")
    case.equal(write["key"], {"survivor_id": columns["survivor_id"], "survivor_version": columns["survivor_version"]}, "same key")
    ack = base[ACK_GATE][0]
    case.equal(ack["route"], "SHEETS_ACK", "ACK route")
    case.equal(ack["sheets_ack"]["registry_sync_status"], "SYNCED", "ACK sync status")
    case.equal(ack["sheets_ack"]["survivor_git_commit"], merge_sha, "ACK commit")
    case.equal(ack["sheets_ack"]["full_config_sha256"], columns["full_config_sha256"], "ACK config hash")
    case.equal(ack["sheets_ack"]["is_run_id"], columns["is_run_id"], "ACK IS run id")
    case.equal(ack["sheets_ack"]["oos_run_id"], columns["oos_run_id"], "ACK OOS run id")
    bad = dict(plan_row, survivor_git_commit="0" * 40)
    outs = workflow.execute(post={WRITE_FIX: {"write_result": {"rows_after": [bad]}}})
    case.equal(outs[ERROR_END][0]["reason"], "readback_mismatch:survivor_git_commit", "commit mismatch")
    bad = dict(plan_row, is_run_id="0" * 32)
    outs = workflow.execute(post={WRITE_FIX: {"write_result": {"rows_after": [bad]}}})
    case.equal(outs[ERROR_END][0]["reason"], "readback_mismatch:is_run_id", "IS run id mismatch")
    outs = workflow.execute(post={WRITE_FIX: {"write_result": {"rows_after": [plan_row, dict(plan_row)]}}})
    case.equal(outs[ERROR_END][0]["reason"], "duplicate_rows_forbidden", "duplicate rows")
    outs = workflow.execute(post={WRITE_FIX: {"write_result": {"rows_after": []}}})
    case.equal(outs[ERROR_END][0]["reason"], "readback_row_missing", "missing row")
    bad = dict(plan_row, registry_sync_status="PENDING")
    outs = workflow.execute(post={WRITE_FIX: {"write_result": {"rows_after": [bad]}}})
    case.equal(outs[ERROR_END][0]["reason"], "readback_sync_status_not_synced", "sync status")
    case.check(not outs[NODE13_PAYLOAD] and not outs[NODE13_END], "readback error: no Node13 output")
    cases.append(case)

    # Case 7. A merge with a Sheets failure stays pending sync. The retry keeps
    # the same key. No duplicate record and no repository rollback.
    case = Case("7 merge success + Sheets failure -> bounded same-key retry, pending sync")
    outs = workflow.execute(post={WRITE_FIX: {"write_result": {"outcome": "transient_error", "attempt": 1, "max_attempts": 3}}})
    case.equal(endpoint_route(outs, RETRY_END), "RETRY", "retry route")
    case.equal(outs[RETRY_END][0]["reason"], "sheet_write_transient_error", "retry reason")
    retry = outs[RETRY_END][0]["retry"]
    case.equal(retry["same_key"], True, "same key retry")
    case.equal(retry["duplicate_allowed"], False, "no duplicate")
    case.equal(retry["rollback_repo"], False, "no repository rollback")
    case.equal(retry["next_attempt"], 2, "next attempt")
    case.check(not outs[NODE13_END], "no Node13 before the ACK")
    case.check(not outs[MERGE_VERIFY] or outs[MERGE_VERIFY][0]["route"] != "RETRY", "merge state is kept")
    outs = workflow.execute(post={WRITE_FIX: {"write_result": {"outcome": "rate_limited", "attempt": 3, "max_attempts": 3}}})
    case.equal(endpoint_route(outs, ERROR_END), "ERROR", "exhausted route")
    case.equal(outs[ERROR_END][0]["reason"], "sheet_retry_exhausted", "exhausted reason")
    case.equal(outs[ERROR_END][0]["retry"]["rollback_repo"], False, "no rollback on exhaustion")
    cases.append(case)

    # Case 8. A foreign or wrong merge entry needs review. No Sheet write.
    case = Case("8 foreign/wrong merge entry -> NEEDS_REVIEW, no Sheet write")
    outs = workflow.execute(post={EVENT_FIX: {"event": {"repo": "someone/fork"}}})
    case.equal(outs[MERGE_VERIFY][0]["reason"], "merge_repo_mismatch", "foreign repository")
    no_write(outs, case, "foreign repo")
    outs = workflow.execute(post={READBACK_FIX: {"readback": {"merge_commit_sha": "0" * 40}}})
    case.equal(outs[MERGE_VERIFY][0]["reason"], "merge_commit_not_confirmed", "commit not confirmed")
    no_write(outs, case, "commit mismatch")
    outs = workflow.execute(post={EVENT_FIX: {"event": {"path": "other-file.md"}}})
    case.equal(outs[MERGE_VERIFY][0]["reason"], "merge_identity_mismatch:event_path", "wrong path")
    no_write(outs, case, "wrong path")
    outs = workflow.execute(post={EVENT_FIX: {"event": {"survivor_version": "v2"}}})
    case.equal(outs[MERGE_VERIFY][0]["reason"], "merge_identity_mismatch:survivor", "wrong version")
    no_write(outs, case, "wrong version")
    outs = workflow.execute(post={READBACK_FIX: {"readback": {"pr_state": "CLOSED"}}})
    case.equal(outs[MERGE_VERIFY][0]["reason"], "merge_readback_not_merged:CLOSED", "readback state")
    no_write(outs, case, "closed PR")
    outs = workflow.execute(post={READBACK_FIX: {"readback": {"audited_pass_evidence": {"verdict": "FAIL"}}}})
    case.equal(outs[MERGE_VERIFY][0]["reason"], "audit_evidence_not_pass", "audit verdict")
    no_write(outs, case, "audit fail")
    outs = workflow.execute(post={READBACK_FIX: {"readback": {"audited_pass_evidence": {"reviewed_head_sha": "1" * 40}}}})
    case.equal(outs[MERGE_VERIFY][0]["reason"], "audit_head_sha_mismatch", "audit head")
    no_write(outs, case, "audit head mismatch")
    outs = workflow.execute(post={READBACK_FIX: {"readback": {"frontmatter": {"hummingbot_validation_status": "CERTIFIED", "hb_certified": True}}}})
    case.equal(outs[MERGE_VERIFY][0]["reason"], "record_hb_status_not_pending", "HB status on merge")
    no_write(outs, case, "certified record")
    cases.append(case)

    # Case 9. The ACK outputs the Node13 boundary payload. No ACK, no Node13.
    case = Case("9 ACK -> Node13 boundary payload; no ACK -> no Node13")
    payload = base[NODE13_PAYLOAD][0]["node13"]
    case.equal(base[NODE13_PAYLOAD][0]["route"], "NODE13_BOUNDARY_READY", "Node13 payload route")
    case.check(base[NODE13_END], "Node13 boundary node is reached")
    for field in ("survivor_repository_url", "survivor_strategy_path", "survivor_git_commit", "survivor_id",
                  "survivor_version", "strategy_sha", "frozen_version_sha", "effective_config_hash",
                  "is_run_id", "oos_run_id", "is_window_hash", "oos_window_hash", "data_snapshot", "cost_model"):
        case.check(payload.get(field) not in (None, ""), f"Node13 payload carries {field}")
    case.equal(payload["survivor_git_commit"], merge_sha, "Node13 merge commit")
    case.equal(payload["hummingbot_validation_status"], "PENDING", "Node13 HB status")
    case.equal(payload["hb_certified"], False, "Node13 hb_certified")
    case.equal(payload["sheets"]["registry_sync_status"], "SYNCED", "Node13 Sheets state")
    outs = workflow.execute(post={WRITE_FIX: {"write_result": {"outcome": "transient_error"}}})
    case.check(not outs[NODE13_PAYLOAD] and not outs[NODE13_END], "no ACK gives no Node13")
    cases.append(case)

    # Case 10. Static proof. The workflow stays inside its scope.
    case = Case("10 static proof: isolation, no new service, no scope creep")
    types = sorted({node["type"] for node in workflow.raw["nodes"]})
    case.check(
        set(types) <= {"n8n-nodes-base.manualTrigger", "n8n-nodes-base.code", "n8n-nodes-base.noOp"},
        f"unexpected node types: {types}",
    )
    blob = json.dumps(workflow.raw)
    for banned in ("n8n-nodes-base.ssh", "n8n-nodes-base.httpRequest", "n8n-nodes-base.executeCommand",
                   "n8n-nodes-base.github", "n8n-nodes-base.githubTrigger", "n8n-nodes-base.googleSheets",
                   "n8n-nodes-base.webhook", "n8n-nodes-base.scheduleTrigger", "research-transport",
                   "WF-Research-01-03"):
        case.check(f'"type": "{banned}"' not in blob, f"workflow must not carry {banned}")
    for banned in ("langchain", "openai", "lmchat", "chainllm"):
        case.check(
            not any(banned in node["type"].lower() for node in workflow.raw["nodes"]),
            f"workflow must not hold a second reasoning layer: {banned}",
        )
    case.check("require(" not in blob, "no require call in node code")
    case.check("/Users/" not in blob, "no local filesystem path")
    names = [node["name"] for node in workflow.raw["nodes"]]
    for banned in ("01 \u00b7", "02 \u00b7", "03 \u00b7", "04 \u00b7", "06 \u00b7", "07 \u00b7", "08 \u00b7", "09 \u00b7"):
        case.check(not any(name.startswith(banned) for name in names), f"workflow must not shadow {banned}")
    case.equal(names.count("05 \u00b7 OOS_READY fixture/re-entry"), 1, "one explicit 05 fixture")
    case.equal(names.count(TRIGGER), 1, "one manual trigger")
    case.equal(workflow.raw["active"], False, "workflow is inactive")
    case.equal(workflow.raw["settings"], {"executionOrder": "v1"}, "execution order")
    for name in names:
        if name in ENDPOINTS:
            continue
        case.check(bool(workflow.children(name)), f"no dead end at {name}")
    case.check(not workflow.children(RETRY_END), "retry endpoint is terminal")
    case.check(not workflow.children(ERROR_END), "error endpoint is terminal")
    case.equal(workflow.parents(SHEETS_PLAN), ["12 \u00b7 MERGE_VERIFIED lane gate"], "Sheets writes only after a verified merge")
    case.equal(workflow.parents(NODE13_PAYLOAD), ["12 \u00b7 SHEETS_ACK lane gate"], "Node13 needs the ACK")
    case.equal(len(headers), 84, "84 registry headers")
    case.equal(len(set(headers)), 84, "unique registry headers")
    for required in ("survivor_id", "survivor_version", "survivor_git_commit", "full_config_sha256", "is_run_id",
                     "oos_run_id", "is_window_hash", "oos_window_hash", "registry_sync_status",
                     "registry_last_synced_utc", "hummingbot_validation_status", "hummingbot_task_id"):
        case.check(required in headers, f"registry header {required}")
    cases.append(case)

    failed = 0
    for case in cases:
        status = "PASS" if not case.failures else "FAIL"
        if case.failures:
            failed += 1
        print(f"{status} case {case.name} ({case.checks} checks)")
        for failure in case.failures:
            print(f"     - {failure}")
    print(f"{len(cases) - failed}/{len(cases)} cases pass, {sum(c.checks for c in cases)} checks")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
