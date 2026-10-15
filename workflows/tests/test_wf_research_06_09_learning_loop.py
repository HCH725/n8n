#!/usr/bin/env python3
"""Targeted test for WF-Research-06-09-learning-loop.json.

The test reads the exported workflow and runs each Code node with Node.js.
A small harness gives every node the n8n Code-node surface ($input, $, items).
The test then walks the exported connection graph. It verifies the ten cases
of the vertical-slice contract.

Run: python3 workflows/tests/test_wf_research_06_09_learning_loop.py
"""

from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
WORKFLOW = HERE.parent / "WF-Research-06-09-learning-loop.json"

TRIGGER = "06 \u00b7 Manual trigger"
FIXTURE = "06 \u00b7 IS_READY fixture"
HERMES = "06 \u00b7 Hermes boundary fixture"
WIKI = "07 \u00b7 Wiki ACK fixture"
DECISION = "09 \u00b7 Decision"
RETEST_END = "09 \u00b7 RETEST_TO_04 boundary"
FINALIZE_END = "09 \u00b7 FINALIZE to Node10 boundary"
REVIEW_END = "09 \u00b7 NEEDS_REVIEW endpoint"

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
const $execution = { id: 'wf-research-06-09-test', mode: 'manual' };
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


def find_node() -> str:
    """Return an executable Node.js binary."""
    found = shutil.which("node")
    if found:
        return found
    fallback = Path.home() / ".local" / "bin" / "node"
    if fallback.exists():
        return str(fallback)
    raise SystemExit("FAIL: Node.js is not on PATH")


def run_node(spec: dict) -> dict:
    """Run one Code node body through the harness."""
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
    return out["items"]


def deep_merge(base: dict, patch: dict) -> dict:
    """Recursively merge the patch into a copy of the base."""
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

    def execute(self, patch: dict | None = None, overrides: dict | None = None):
        """Execute the graph. Return the item that each output node holds."""
        outputs = {TRIGGER: [{}]}
        fixture_items = run_node(
            {"code": self.code_of(FIXTURE), "node": FIXTURE, "inputs": [{}], "outputs": outputs}
        )
        base = fixture_items[0]
        if patch:
            base = deep_merge(base, patch)
        outputs[FIXTURE] = [base]

        remaining = [n for n in self.nodes if n not in (TRIGGER, FIXTURE)]
        while remaining:
            progressed = False
            for name in list(remaining):
                incoming = self.parents(name)
                if not all(parent in outputs for parent in incoming):
                    continue
                items = []
                for parent in incoming:
                    items.extend(outputs[parent])
                if items and name in (overrides or {}):
                    outputs[name] = [deep_merge(items[0], overrides[name])]
                elif not items:
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


def terminal(outputs: dict) -> tuple[str, dict]:
    """Return the route and payload of the reached endpoint."""
    reached = []
    for name, route in ((RETEST_END, "RETEST"), (FINALIZE_END, "FINALIZE"), (REVIEW_END, "NEEDS_REVIEW")):
        if outputs.get(name):
            reached.append((route, outputs[name][0]))
    if len(reached) != 1:
        raise AssertionError(f"expected exactly one endpoint, got {[r for r, _ in reached]}")
    route, payload = reached[0]
    if payload.get("route") != route:
        raise AssertionError(f"endpoint {route} holds route={payload.get('route')}")
    return route, payload


def main() -> int:
    workflow = Workflow(WORKFLOW)
    run_key = run_node(
        {"code": workflow.code_of(FIXTURE), "node": FIXTURE, "inputs": [{}], "outputs": {}}
    )[0]["run_key"]
    note_ref = f"quant/research-loop/{run_key}.md"
    hash_a = "a7d2f6b8c4e0193d5a6f7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e"
    hash_b = "b8e3a7c9d5f1204e6b7a8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f"
    fixture = run_node(
        {"code": workflow.code_of(FIXTURE), "node": FIXTURE, "inputs": [{}], "outputs": {}}
    )[0]
    analysis: dict = json.loads(fixture["hermes_raw"])
    fixture_key = fixture["run_key"]

    def round_patch(index: int, prior_ref, completed=None) -> dict:
        """Build the round series patch. Each round needs one canonical run_key."""
        series = completed
        if series is None:
            series = [
                {
                    "round_index": i,
                    "run_key": fixture_key if i == index else f"{i:032x}",
                    "status": "IS_SUCCESS",
                }
                for i in range(index + 1)
            ]
        return {
            "round_index": index,
            "completed_runs": series,
            "prior_hypothesis_ref": prior_ref,
            "hermes_raw": json.dumps(dict(analysis, previous_hypothesis_ref=prior_ref)),
        }

    cases: list[Case] = []

    # Case 1. A valid round 0 with a Wiki ACK and worth_retesting=true retests round 1.
    case = Case("1 round0 valid -> RETEST round1")
    route, payload = terminal(workflow.execute())
    case.equal(route, "RETEST", "route")
    decision = payload.get("decision", {})
    case.equal(decision.get("next_round_index"), 1, "next_round_index")
    case.equal(decision.get("next_parent_run_key"), run_key, "next_parent_run_key")
    case.equal(decision.get("next_prior_hypothesis_ref"), note_ref, "next_prior_hypothesis_ref")
    case.equal(decision.get("next_analysis_hash"), hash_a, "next_analysis_hash")
    case.equal(
        decision.get("next_change_set"),
        {"hypothesis_group": "donchian", "params": {"donchian.exit_window": 15}},
        "next_change_set",
    )
    case.check(
        set(decision) == {
            "next_round_index",
            "next_parent_run_key",
            "next_prior_hypothesis_ref",
            "next_change_set",
            "next_analysis_hash",
        },
        "RETEST payload must carry the five fields only",
    )
    case.check("oos" not in json.dumps(payload).lower(), "IS payload must not carry OOS material")
    case.equal(payload.get("analysis"), analysis, "07 must store the 06 analysis without rewriting it")
    cases.append(case)

    # Case 2. A valid round 0 with worth_retesting=false finalizes at once.
    case = Case("2 round0 worth_retesting=false -> FINALIZE")
    analysis_false = dict(analysis, worth_retesting=False, proposal={"source_run_key": run_key, "change_set": None})
    route, payload = terminal(workflow.execute(patch={"hermes_raw": json.dumps(analysis_false)}))
    case.equal(route, "FINALIZE", "route")
    case.equal(payload.get("decision", {}).get("finalize_reason"), "WORTH_RETESTING_FALSE", "finalize_reason")
    case.equal(payload.get("decision", {}).get("selected_run_key"), run_key, "selected_run_key")
    case.equal(payload.get("decision", {}).get("selected_wiki_note_ref"), note_ref, "selected_wiki_note_ref")
    case.equal(payload.get("decision", {}).get("period_basis"), "IS", "period_basis")
    cases.append(case)

    # Case 3. Round 3 with worth_retesting=true finalizes. The cap holds.
    case = Case("3 round3 worth_retesting=true -> FINALIZE at cap")
    route, payload = terminal(workflow.execute(patch=round_patch(3, note_ref)))
    case.equal(route, "FINALIZE", "route")
    case.equal(payload.get("decision", {}).get("finalize_reason"), "ROUND_CAP_REACHED", "finalize_reason")
    cases.append(case)

    # Case 4. Round 1 without a prior hypothesis needs review.
    case = Case("4 round1 without prior hypothesis -> NEEDS_REVIEW")
    route, payload = terminal(workflow.execute(patch=round_patch(1, None)))
    case.equal(route, "NEEDS_REVIEW", "route")
    case.equal(payload.get("reason"), "missing_prior_hypothesis", "reason")
    cases.append(case)

    # Case 5. Wiki ACK defects need review.
    case = Case("5 Wiki ACK missing / run_key mismatch / hash mismatch -> NEEDS_REVIEW")
    route, payload = terminal(
        workflow.execute(patch={"wiki_state": [{"run_key": run_key, "analysis_hash": hash_b, "note_ref": note_ref}]})
    )
    case.equal(route, "NEEDS_REVIEW", "conflict route")
    case.check(str(payload.get("reason", "")).startswith("wiki_ack_"), "conflict reason names the ACK")
    route, payload = terminal(workflow.execute(overrides={WIKI: {"wiki_ack": None}}))
    case.equal(route, "NEEDS_REVIEW", "missing ACK route")
    case.equal(payload.get("reason"), "wiki_ack_missing", "missing ACK reason")
    route, payload = terminal(
        workflow.execute(overrides={WIKI: {"wiki_ack": {"status": "ACK", "note_ref": note_ref, "run_key": f"{9:032x}", "analysis_hash": hash_a}}})
    )
    case.equal(payload.get("reason"), "wiki_ack_run_key_mismatch", "run_key mismatch reason")
    route, payload = terminal(
        workflow.execute(overrides={WIKI: {"wiki_ack": {"status": "ACK", "note_ref": note_ref, "run_key": run_key, "analysis_hash": hash_b}}})
    )
    case.equal(payload.get("reason"), "analysis_hash_mismatch", "hash mismatch reason")
    cases.append(case)

    # Case 6. The same run_key and hash acknowledge idempotently. A changed hash conflicts.
    case = Case("6 same run_key+hash idempotent ACK; changed hash conflicts")
    known = [{"run_key": run_key, "analysis_hash": hash_a, "note_ref": note_ref}]
    route, payload = terminal(workflow.execute(patch={"wiki_state": known}))
    case.equal(route, "RETEST", "idempotent route")
    case.equal(payload.get("wiki_ack", {}).get("note_ref"), note_ref, "idempotent note_ref")
    case.equal(payload.get("wiki_ack", {}).get("action"), "IDEMPOTENT", "idempotent action")
    case.equal(payload.get("wiki_ack", {}).get("analysis_hash"), hash_a, "idempotent hash")
    route, payload = terminal(
        workflow.execute(patch={"wiki_state": known, "hermes_raw": json.dumps(dict(analysis, analysis_hash=hash_b))})
    )
    case.equal(route, "NEEDS_REVIEW", "changed hash route")
    case.check(str(payload.get("reason", "")).startswith("wiki_ack_"), "changed hash reason")
    case.equal(payload.get("wiki_ack", {}).get("status"), "CONFLICT", "conflict status")
    case.equal(payload.get("wiki_ack", {}).get("note_ref"), note_ref, "conflict keeps the note_ref")
    cases.append(case)

    # Case 7. A change set must be one group, non-empty, and allowed upstream.
    case = Case("7 illegal param / empty change / multiple groups -> NEEDS_REVIEW")
    bad_param = json.dumps(
        dict(analysis, proposal={"source_run_key": run_key, "change_set": {"hypothesis_group": "donchian", "params": {"donchian.lookback": 30}}})
    )
    route, payload = terminal(workflow.execute(patch={"hermes_raw": bad_param}))
    case.equal(route, "NEEDS_REVIEW", "illegal param route")
    case.equal(payload.get("reason"), "override_param_not_allowed:donchian.lookback", "illegal param reason")
    empty = json.dumps(
        dict(analysis, proposal={"source_run_key": run_key, "change_set": {"hypothesis_group": "donchian", "params": {}}})
    )
    route, payload = terminal(workflow.execute(patch={"hermes_raw": empty}))
    case.equal(payload.get("reason"), "empty_change_set", "empty change reason")
    two_groups = json.dumps(
        dict(analysis, proposal={"source_run_key": run_key, "change_set": {"hypothesis_group": "donchian", "params": {"donchian.exit_window": 15, "risk.max_position": 0.5}}})
    )
    wide_allowed = ["donchian.entry_window", "donchian.exit_window", "donchian.atr_stop_mult", "risk.max_position"]
    route, payload = terminal(
        workflow.execute(patch={"hermes_raw": two_groups, "allowed_override_params": wide_allowed})
    )
    case.equal(payload.get("reason"), "params_span_multiple_groups:donchian,risk", "two groups reason")
    many_sets = json.dumps(
        dict(analysis, proposal={"source_run_key": run_key, "change_set": {"hypothesis_group": "donchian", "params": {"donchian.exit_window": 15}}, "change_sets": [{}, {}]})
    )
    route, payload = terminal(workflow.execute(patch={"hermes_raw": many_sets}))
    case.equal(payload.get("reason"), "multiple_change_sets", "multiple change sets reason")
    cases.append(case)

    # Case 8. OOS material in the analysis needs review.
    case = Case("8 OOS leakage -> NEEDS_REVIEW")
    oos_field = json.dumps(dict(analysis, oos_metrics={"sharpe": 1.4}))
    route, payload = terminal(workflow.execute(patch={"hermes_raw": oos_field}))
    case.equal(route, "NEEDS_REVIEW", "OOS field route")
    case.equal(payload.get("reason"), "unexpected_analysis_field:oos_metrics", "OOS field reason")
    oos_text = json.dumps(dict(analysis, lessons=["The holdout slice looks stable."]))
    route, payload = terminal(workflow.execute(patch={"hermes_raw": oos_text}))
    case.equal(payload.get("reason"), "oos_material_in_analysis", "OOS text reason")
    raw_copy = json.dumps(dict(analysis, lessons=[{"equity_curve": [1.0, 1.1]}]))
    route, payload = terminal(workflow.execute(patch={"hermes_raw": raw_copy}))
    case.equal(payload.get("reason"), "raw_result_material:equity_curve", "raw material reason")
    cases.append(case)

    # Case 9. The round series must be contiguous, unique, and canonical.
    case = Case("9 round gap / duplicate run / canonical conflict -> NEEDS_REVIEW")
    zero = f"{0:032x}"
    one = f"{1:032x}"
    two = f"{2:032x}"
    gap = [
        {"round_index": 0, "run_key": zero, "status": "IS_SUCCESS"},
        {"round_index": 2, "run_key": two, "status": "IS_SUCCESS"},
    ]
    route, payload = terminal(workflow.execute(patch=round_patch(2, note_ref, gap)))
    case.equal(payload.get("reason"), "round_series_not_contiguous", "gap reason")
    duplicate = [
        {"round_index": 0, "run_key": zero, "status": "IS_SUCCESS"},
        {"round_index": 1, "run_key": zero, "status": "IS_SUCCESS"},
    ]
    route, payload = terminal(workflow.execute(patch=round_patch(1, note_ref, duplicate)))
    case.equal(payload.get("reason"), "duplicate_run_key", "duplicate reason")
    conflict = [
        {"round_index": 0, "run_key": zero, "status": "IS_SUCCESS"},
        {"round_index": 1, "run_key": one, "status": "IS_SUCCESS"},
    ]
    route, payload = terminal(workflow.execute(patch=round_patch(1, note_ref, conflict)))
    case.equal(payload.get("reason"), "current_run_not_canonical_head", "canonical reason")
    not_is = [{"round_index": 0, "run_key": zero, "status": "OOS_SUCCESS"}]
    route, payload = terminal(workflow.execute(patch=round_patch(0, None, not_is)))
    case.equal(payload.get("reason"), "round_not_successful_is", "OOS round reason")
    cases.append(case)

    # Case 10. The workflow must not reach Node04 or the 01-05 files.
    case = Case("10 workflow isolation")
    types = sorted({node["type"] for node in workflow.raw["nodes"]})
    case.check(
        set(types) <= {"n8n-nodes-base.manualTrigger", "n8n-nodes-base.code", "n8n-nodes-base.noOp"},
        f"unexpected node types: {types}",
    )
    blob = json.dumps(workflow.raw)
    for banned in ("n8n-nodes-base.ssh", "n8n-nodes-base.httpRequest", "n8n-nodes-base.executeCommand", "research-transport", "WF-Research-01-03"):
        case.check(banned not in blob, f"workflow must not carry {banned}")
    for banned in ("langchain", "openai", "agent", "lmchat", "chainllm"):
        case.check(
            not any(banned in node["type"].lower() for node in workflow.raw["nodes"]),
            f"workflow must not hold a second reasoning layer: {banned}",
        )
    for name in ("Node04", "01 \u00b7", "02 \u00b7", "03 \u00b7", "04 \u00b7", "05 \u00b7"):
        case.check(
            name not in [node["name"] for node in workflow.raw["nodes"]],
            f"workflow must not hold a node named {name}",
        )
    case.equal([node["name"] for node in workflow.raw["nodes"]].count(TRIGGER), 1, "one manual trigger")
    case.equal(workflow.raw["active"], False, "workflow is inactive")
    case.equal(workflow.raw["settings"], {"executionOrder": "v1"}, "execution order")
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
