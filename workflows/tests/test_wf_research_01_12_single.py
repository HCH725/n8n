#!/usr/bin/env python3
"""Targeted test for WF-Research-01-12.json (the single deploy target).

The test runs exported Code nodes with Node.js in explicit contract sequences.
It checks graph edges separately. Fixtures represent live boundary replies.
It does not simulate n8n scheduling, loops, SSH or native integration nodes.

Run: python3 workflows/tests/test_wf_research_01_12_single.py
"""

from __future__ import annotations

import copy
import json
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
WORKFLOW = HERE.parent / "WF-Research-01-12.json"
COMPONENTS = [
    HERE.parent / "WF-Research-01-03-manual-preflight.json",
    HERE.parent / "WF-Research-06-09-learning-loop.json",
    HERE.parent / "WF-Research-10-12-survivor-handoff.json",
]
README = HERE.parent / "README.md"

TRIGGER = "01 \u00b7 Manual preflight"
READY_03 = "03 \u00b7 Engineering readiness"
READ_05 = "05 \u00b7 Verify artifact completeness"
GATE_05B = "06 \u00b7 IS_READY campaign gate"
HOLD_05B = "06 \u00b7 IS_READY HOLD endpoint"
TASK_06 = "06 \u00b7 Hermes task payload"
SSH_06 = "06 \u00b7 Hermes research (SSH)"
REQUEST_03C = "02c \u00b7 Handoff request"
SSH_MATERIALIZE = "02d \u00b7 Frozen-cell handoff (Hermes SSH)"
ENVELOPE_03E = "02e \u00b7 Handoff envelope"
HOLD_GATE_03H = "03h \u00b7 HOLD lane gate"
HOLD_03I = "03i \u00b7 HOLD endpoint"
READER_06 = "06 \u00b7 Hermes reply reader"
CONTRACT_06 = "06 \u00b7 Analysis contract gate"
WIKI_07 = "07 \u00b7 Wiki persistence gate"
NODE08 = "08 \u00b7 Deterministic validation"
NODE09 = "09 \u00b7 Decision"
RETEST_GATE = "09 \u00b7 RETEST gate"
RETEST_REENTRY = "09 \u00b7 RETEST re-entry (04 contract)"
RETEST_LANE = "09 \u00b7 RETEST lane gate"
FINALIZE_GATE = "09 \u00b7 FINALIZE gate"
REVIEW_ENDPOINT_09 = "09 \u00b7 NEEDS_REVIEW endpoint"
NODE04 = "04 \u00b7 Submit representative Qlib"
NODE05 = "05 \u00b7 Read representative artifacts"
FINALIZE_PAYLOAD = "10 \u00b7 FINALIZE payload"
IS_SNAPSHOT = "10 \u00b7 frozen IS snapshot (05 readback)"
FREEZE = "10 \u00b7 Freeze & OOS request"
OOS_REQUEST_GATE = "10 \u00b7 OOS_REQUEST gate"
OOS_REENTRY = "10 \u00b7 OOS re-entry (04/05 contract)"
OOS_LANE = "10 \u00b7 OOS lane gate"
OOS_BRIDGE = "10 \u00b7 OOS_READY from 05 readback"
OOS_READY_GATE = "10 \u00b7 OOS_READY gate"
OOS_READY_LANE = "10 \u00b7 OOS_READY lane gate"
REVIEW_ENDPOINT_10 = "10 \u00b7 NEEDS_REVIEW endpoint"
POLICY_READ_GITHUB = "11 \u00b7 Read survivor policy (GitHub)"
POLICY_PARSE = "11 \u00b7 Promotion policy (native read)"
EVAL_11 = "11 \u00b7 Research Survivor evaluation"
PERF_LANE = "11 \u00b7 PERF_PASS lane gate"
REPLAY_BOUNDARY = "11 \u00b7 Qlib replay readback (external boundary)"
ASSEMBLY_11 = "11 \u00b7 Replay & PASS assembly"
PASS_LANE = "11 \u00b7 PASS lane gate"
RECORD_12 = "12 \u00b7 Survivor record payload"
RECORD_FILE = "12 \u00b7 Record file content"
PR_CREATED = "12 \u00b7 PR created"
WAIT_12 = "12 \u00b7 Wait for audit merge"
READ_PR = "12 \u00b7 Read promotion PR"
PR_STATE = "12 \u00b7 PR merge state"
PR_OPEN_GATE = "12 \u00b7 PR open gate"
MERGE_LANE_GATE = "12 \u00b7 Merge lane gate"
MERGE_READBACK = "12 \u00b7 Merge readback"
MERGE_VERIFY = "12 \u00b7 Merge verification"
MERGE_LANE = "12 \u00b7 MERGE_VERIFIED lane gate"
SHEETS_PLAN = "12 \u00b7 Sheets upsert plan"
SHEETS_DECISION = "12 \u00b7 Sheets upsert decision"
SHEETS_UPDATE = "12 \u00b7 Update registry row"
SHEETS_APPEND = "12 \u00b7 Append registry row"
SHEETS_READBACK = "12 \u00b7 Read registry row back"
SHEETS_RESULT = "12 \u00b7 Sheets write result"
ACK_GATE = "12 \u00b7 Sheets ACK gate"
RETRY_ENDPOINT = "12 \u00b7 Sheets RETRY endpoint (bounded, same key)"
ERROR_ENDPOINT = "12 \u00b7 Sheets ERROR endpoint"
NODE13_PAYLOAD = "12 \u00b7 Node13 boundary payload"
NODE13_END = "12 \u00b7 Node13 boundary"

REGISTRY_ID = "1fzO3zH5xSmQWMH856KY_Z2atLCHkDdRg_cBzltSB_rg"
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
const $execution = { id: 'wf-research-01-12-test', mode: 'manual' };
const now = spec.now ?? Date.parse('2026-10-15T00:00:00Z');
const FixedDate = class extends Date {
  constructor(value = now) { super(value); }
  static now() { return now; }
};
const report = (payload) => process.stdout.write(JSON.stringify(payload));
try {
  // Execute only Code-node source from the checked-out export, not payload text.
  const fn = new Function(
    '$input', '$json', 'items', '$', '$node', '$execution', '$env', 'console', 'Date', spec.code
  );
  const result = fn($input, $json, $input.all(), $, $node, $execution, {}, console, FixedDate);
  const list = result === undefined || result === null ? [] : (Array.isArray(result) ? result : [result]);
  const items = list.map((entry) => (entry && entry.json !== undefined ? entry.json : entry));
  report({ ok: true, items: items });
} catch (error) {
  report({ ok: false, error: String(error && error.message ? error.message : error) });
}
"""


def find_node() -> str:
    found = shutil.which("node")
    if found:
        return found
    fallback = Path.home() / ".local" / "bin" / "node"
    if fallback.exists():
        return str(fallback)
    raise SystemExit("FAIL: Node.js is not on PATH")


def run_node(spec: dict) -> list:
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


class Workflow:
    """Load the export. Check topology and run explicit Code-node contracts."""

    def __init__(self, path: Path):
        self.raw = json.loads(path.read_text(encoding="utf-8"))
        self.nodes = {node["name"]: node for node in self.raw["nodes"]}
        self.connections = self.raw["connections"]

    def code_of(self, name: str) -> str:
        return self.nodes[name]["parameters"]["jsCode"]

    def type_of(self, name: str) -> str:
        return self.nodes[name]["type"]

    def parents(self, name: str) -> list[str]:
        found = []
        for source, outputs in self.connections.items():
            for group in outputs.get("main", []):
                for link in group:
                    if link["node"] == name:
                        found.append(source)
        return found

    def children(self, name: str) -> list[str]:
        found = []
        for group in self.connections.get(name, {}).get("main", []):
            for link in group:
                found.append(link["node"])
        return found

    def reachable(self, start: str) -> set[str]:
        seen: set[str] = set()
        stack = [start]
        while stack:
            name = stack.pop()
            for child in self.children(name):
                if child not in seen:
                    seen.add(child)
                    stack.append(child)
        return seen

    def codes(self, names: list[str], inputs: list, outputs: dict | None = None) -> dict:
        """Run only the listed Code nodes. Do not infer routes or scheduling."""
        outputs = dict(outputs or {})
        for name in names:
            assert self.type_of(name) == "n8n-nodes-base.code", name
            inputs = run_node({"code": self.code_of(name), "node": name,
                               "inputs": inputs, "outputs": outputs})
            outputs[name] = inputs
        return outputs


class Case:
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


# ------------------------------------------------------------------ fixtures

RUN_KEY = "3ad9f0c4b1e2487fa5c6d87013be92f4"
BLOB_SHA = "8a09f6e642261714ef72872b601b8f679e1f0d30"
CONFIG_SHA = "7a976cce5a6d418c635af073e9df7f553b6893259c79e59722f49b368c28d1d2"
OTHER_CONFIG_SHA = "1b2c3d4e5f60718293a4b5c6d7e8f901234567890abcdef1234567890abcdef1"
ENTRY_SHA = "000e23b739eb13a7c3b1077af5501556bd73fd2ec0e9d439ce1e6d5113d14c05"
ANALYSIS_HASH = "a7d2f6b8c4e0193d5a6f7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e"
OTHER_HASH = "b8e3a7c9d5f1204e6b7a8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f"
NOTE_REF = f"quant/research-loop/{RUN_KEY}.md"

HANDOFF = {
    "candidate_path": "donchian-20-10-breakout-btcusdt-1h-2026-10-06.md",
    "source_commit": "890da11cb50daadc4d59b7fd58a2e96638b17833",
    "source_blob_sha": BLOB_SHA,
    "entrypoint_ref": "/results/_validation/donchian-s01509-native-20261014/run_backtest.entrypoint.py",
    "entrypoint_sha256": ENTRY_SHA,
    "effective_config_ref": "/results/_validation/donchian-s01509-native-20261014/effective_config.json",
    "effective_config_sha256": CONFIG_SHA,
    "qlib_runtime_commit": "bee09f23d938b96c2c1ef82d891aa0abfa171cd0",
    "run_inputs": {"frequency": "60min", "symbol": "BTCUSDT"},
    "evidence_refs": {
        "candidate": f"https://api.github.com/repos/HCH725/alpha-strategy-research/git/blobs/{BLOB_SHA}",
        "manifest": "/results/_validation/n8n-live-8b37e4ca2140/manifest.json",
        "mlflow_readback": "/results/_validation/n8n-live-8b37e4ca2140/mlflow_readback.json",
    },
    "capabilities": {"data": ["binance-usdm-ohlcv"], "execution": ["qlib-native-backtest"], "timing": ["bar-close"]},
}


def ready_03(config_sha: str = CONFIG_SHA, allowlist: list | None = None) -> dict:
    handoff = json.loads(json.dumps(HANDOFF))
    handoff["effective_config_sha256"] = config_sha
    if allowlist is not None:
        handoff["allowed_override_params"] = allowlist
    return {
        "origin": "manual",
        "source_commit": handoff["source_commit"],
        "candidate_path": handoff["candidate_path"],
        "source_ref": "HCH725/alpha-strategy-research@" + handoff["source_commit"] + "/" + handoff["candidate_path"],
        "source_blob_sha": BLOB_SHA,
        "qlib_run_id": None,
        "run_state": "NOT_SUBMITTED",
        "schema": "strategy-research-record-v1",
        "hb_ready_status": "PASS",
        "implementation_status": "READY",
        "route": "READY",
        "market_data_ready": True,
        "executable_handoff": handoff,
        "resolution": {"status": "ready", "source": "frozen-cell", "reason": None},
        "capability_gap": [],
        "transport_payload_b64": "e30=",
    }


def read_05(claimable: bool, config_sha: str = CONFIG_SHA, allowlist: list | None = None) -> dict:
    # The frozen 05 node returns {...upstream}, so on the live path the readback
    # carries the very handoff that 03 loaded from the run input - allowlist
    # included. The fixture keeps that identity instead of a fresh copy.
    state = ready_03(config_sha, allowlist)
    handoff = state["executable_handoff"]
    state["run_state"] = "FINISHED"
    state["qlib_run_id"] = RUN_KEY
    state["performance_claimable"] = claimable
    state["node04_receipt"] = {"run_id": RUN_KEY, "out_dir": "/results/_validation/run", "experiment_id": "7"}
    state["node05_receipt"] = {
        "node05": "PASS",
        "run_id": RUN_KEY,
        "candidate_path": handoff["candidate_path"],
        "candidate_blob_sha": BLOB_SHA,
        "status": "FINISHED",
        "params_count": 12,
        "metrics_count": 9,
        "artifacts_count": 5,
        "out_dir": "/results/_validation/run",
        "experiment_id": "7",
        "refs": {
            "mlflow_run": "/results/_validation/run/mlruns/7/" + RUN_KEY,
            "manifest": "/results/_validation/run/manifest.json",
            "data": "/results/_validation/data/btcusdt-1h",
            "candidate": f"https://api.github.com/repos/HCH725/alpha-strategy-research/git/blobs/{BLOB_SHA}",
        },
        "readable": {"candidate": True, "data": True, "execution": True, "runtime": True, "evidence": True},
        "manifest_verified": True,
        "manifest_readback_run_id": RUN_KEY,
        "manifest_sha256": "c3" * 32,
        "coverage_complete": claimable,
        "performance_claimable": claimable,
    }
    return state


def analysis(worth_retesting: bool = True, prior: str | None = None, change_set=None, run_key: str = RUN_KEY) -> dict:
    if change_set is None:
        change_set = {"hypothesis_group": "donchian", "params": {"donchian.exit_window": 15}} if worth_retesting else None
    return {
        "source_run_key": run_key,
        "source_run_id": run_key,
        "period_basis": "IS",
        "previous_hypothesis_ref": prior,
        "expectation_vs_actual": [{"condition": "drawdown band", "expectation": "max_drawdown <= 0.20", "actual": 0.18, "verdict": "MET"}],
        "lessons": ["The 20/10 breakout keeps the drawdown inside the declared band."],
        "worth_retesting": worth_retesting,
        "analysis_ref": f"hermes-analysis://research-loop/{run_key}/round-0",
        "analysis_hash": ANALYSIS_HASH,
        "proposal": {"source_run_key": run_key, "change_set": change_set},
    }


def hermes_stdout(payload: dict, exit_code: int = 0) -> dict:
    events = [
        {"type": "text", "text": "working", "timestamp": 1},
        {"type": "result", "session_id": "test", "exit_code": exit_code, "text": json.dumps(payload), "timestamp": 2},
    ]
    return {"code": 0, "signal": None, "stdout": "\n".join(json.dumps(event) for event in events) + "\n", "stderr": ""}


def readme_snapshot(content: str, sha: str) -> dict:
    import base64

    return {
        "type": "file",
        "encoding": "base64",
        "sha": sha,
        "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
        "path": "README.md",
    }


POLICY_BLOCK = {
    "policy_version": "qlib-promotion-policy-v1",
    "approved": True,
    "thresholds": {"cagr_min_pct": 10, "sharpe_min": 1.0},
    "evaluation_period_defined": True,
    "cost_basis_defined": True,
    "evaluation_unit": "OOS window, net of declared fees and slippage",
    "draft_8pct_used": False,
    "promotion": {"survivor_id": "svr-donchian-exit15", "survivor_version": "v1"},
}


def readme(policy: dict | None = None) -> dict:
    block = json.dumps(POLICY_BLOCK if policy is None else policy, indent=2)
    text = "# research-survivor\n\n```json promotion-policy\n" + block + "\n```\n"
    return readme_snapshot(text, "384ab0df97ebaa48ddf7f1e398e347f210c57212")


OOS_READY = {
    "oos_run_key": "c8d9e0f1a2b3c4d5e6f708192a3b4c5d",
    "oos_run_id": "d9e0f1a2b3c4d5e6f708192a3b4c5d6e",
    "period_basis": "OOS",
    "window_hash": "7f608192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e",
    "frozen_version_sha": "2a1b3c4d5e6f70819a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7081",
    "effective_config_hash": CONFIG_SHA,
    "strategy_sha": ENTRY_SHA,
    "data_snapshot_sha256": "5d4e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c",
    "oos_attempt_index": 1,
    "retune_performed": False,
    "holdout_policy": "ONE_TIME_NO_RETUNE",
    "manifest_complete": True,
    "metrics": {"cagr_pct": 14.2, "sharpe": 1.21, "max_drawdown_pct": 19.0, "max_drawdown_definition": "peak_to_trough_net", "trades": 128, "net_return_pct": 14.2, "win_rate_pct": 48.4, "profit_factor": 1.62},
    "evaluation_period": {"start_utc": "2025-01-01", "end_utc": "2025-06-30"},
    "cost_model_applied": {"fee_rate_bps": 4, "slippage_bps": 2, "funding": "modelled"},
    "evidence_refs": {
        "oos_manifest": "mlflow://qlib/runs/c8d9e0f1a2b3c4d5e6f708192a3b4c5d/manifest.json",
        "metrics": "mlflow://qlib/runs/c8d9e0f1a2b3c4d5e6f708192a3b4c5d/metrics",
        "portfolio_report": "mlflow://qlib/runs/c8d9e0f1a2b3c4d5e6f708192a3b4c5d/portfolio_report",
        "trades": "mlflow://qlib/runs/c8d9e0f1a2b3c4d5e6f708192a3b4c5d/trades",
        "equity": "mlflow://qlib/runs/c8d9e0f1a2b3c4d5e6f708192a3b4c5d/equity",
    },
    "runtime": {"qlib_engine_version": "pyqlib-0.9.7", "runtime_git_commit_or_image": "qlib-arm64-container:2026-10-01"},
}

FREEZE_FACTS = {
    "frozen_version_sha": OOS_READY["frozen_version_sha"],
    "effective_config_hash": CONFIG_SHA,
    "strategy_sha": ENTRY_SHA,
    "source": {
        "family_id": "donchian-breakout",
        "family_name": "Donchian breakout",
        "source_strategy_id": "alpha-donchian-20-10",
        "source_strategy_version": "v1",
        "source_repository_url": "https://github.com/HCH725/alpha-strategy-research",
        "source_strategy_path": "strategies/donchian-20-10.md",
        "source_git_commit": "9a1b2c3d4e5f60718293a4b5c6d7e8f901234567",
        "change_note": "Exit window tightened to 15 after the Node06-09 IS loop.",
    },
    "config_snapshot": {"uri": "mlflow://qlib/runs/" + RUN_KEY + "/artifacts/frozen_config.json", "sha256": "4c3d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b"},
    "data_snapshot": {"uri": "research-data://klines/2022-01-01_2025-06-30/day", "sha256": OOS_READY["data_snapshot_sha256"], "dataset_version": "kline-day-v3"},
    "is_window": {"start_utc": "2022-01-01", "end_utc": "2024-12-31", "window_hash": "6e5f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d"},
    "oos_plan": {"start_utc": "2025-01-01", "end_utc": "2025-06-30", "window_hash": OOS_READY["window_hash"], "oos_run_key": OOS_READY["oos_run_key"]},
    "cost_model": {"uri": "mlflow://qlib/cost-models/futures-taker-v2.json", "sha256": "8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f", "fee_rate_bps": 4, "slippage_bps": 2, "funding_model": "modelled_v2"},
    "runtime": {"qlib_engine_version": "pyqlib-0.9.7", "runtime_git_commit_or_image": "qlib-arm64-container:2026-10-01"},
    "research_refs": {
        "coverage_42cell": {"planned_ref": "research-nav://42cell/donchian/planned.json", "tested_ref": "research-nav://42cell/donchian/tested.json", "excluded_ref": "research-nav://42cell/donchian/excluded.json"},
        "wiki_refs": [NOTE_REF],
    },
    "limitations": ["Funding uses the frozen modelled series. It is not live-verified."],
}

OOS_REQUEST = {
    "best_is_run_key": RUN_KEY,
    "frozen_version_sha": OOS_READY["frozen_version_sha"],
    "effective_config_hash": CONFIG_SHA,
    "period_basis": "OOS",
    "window_hash": OOS_READY["window_hash"],
    "parent_is_run_key": RUN_KEY,
    "oos_run_key": OOS_READY["oos_run_key"],
    "holdout_policy": "ONE_TIME_NO_RETUNE",
}


def oos_item() -> dict:
    return {
        "payload_kind": "oos_request",
        "stage": "10",
        "identity": {"best_is_run_key": RUN_KEY, "best_is_run_id": RUN_KEY, "round_index": 0, "analysis_ref": "hermes-analysis://research-loop/" + RUN_KEY + "/round-0", "analysis_hash": ANALYSIS_HASH, "wiki_note_ref": NOTE_REF, "finalize_reason": "WORTH_RETESTING_FALSE"},
        "freeze": FREEZE_FACTS,
        "oos_request": OOS_REQUEST,
        "route": "OOS_READY_OK",
        "oos_ready": OOS_READY,
    }


def oos_request_item() -> dict:
    # The 10 · OOS_REQUEST gate filters on route only: this is the freeze node's
    # own output item, the one the OOS re-entry contract consumes.
    item = oos_item()
    item["route"] = "OOS_REQUEST"
    item.pop("oos_ready", None)
    return item


def merge_event() -> dict:
    return {
        "payload_kind": "merged_pr_event",
        "route": "MERGED_PR_EVENT",
        "event": {
            "delivery": "github_pull_request_read",
            "repo": "HCH725/research-survivor",
            "pr_number": 3,
            "pr_state": "MERGED",
            "base_branch": "main",
            "head_branch": "promote/svr-donchian-exit15-v1",
            "head_sha": "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12",
            "merge_commit_sha": "cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34",
            "path": "svr-donchian-exit15-v1.md",
            "survivor_id": "svr-donchian-exit15",
            "survivor_version": "v1",
            "merged_at_utc": "2026-10-15T09:10:00Z",
        },
    }


def merge_readback() -> dict:
    return {
        "payload_kind": "github_readback",
        "readback": {
            "source": "github_pull_request_read + merged file read",
            "repo": "HCH725/research-survivor",
            "pr_number": 3,
            "pr_state": "MERGED",
            "base_branch": "main",
            "head_branch": "promote/svr-donchian-exit15-v1",
            "head_sha": "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12",
            "merge_commit_sha": "cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34",
            "merged_at_utc": "2026-10-15T09:10:00Z",
            "path": "svr-donchian-exit15-v1.md",
            "file_sha256": None,
            "file_blob_sha": "e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f",
            "frontmatter": {
                "schema": "research-survivor-record-v1",
                "survivor_id": "svr-donchian-exit15",
                "survivor_version": "v1",
                "family_id": "donchian-breakout",
                "source_strategy_id": "alpha-donchian-20-10",
                "source_repository_url": "https://github.com/HCH725/alpha-strategy-research",
                "source_strategy_path": "strategies/donchian-20-10.md",
                "source_git_commit": "9a1b2c3d4e5f60718293a4b5c6d7e8f901234567",
                "strategy_sha": ENTRY_SHA,
                "qlib_survivor_status": "PASS",
                "hummingbot_validation_status": "PENDING",
                "hb_certified": False,
                "status": "research-only",
                "adoption": "not-approved",
                "approval_scope": "research-only",
            },
            "audited_pass_evidence": {
                "verdict": "PASS",
                "reviewed_head_sha": "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12",
                "audit_record_ref": "github://HCH725/research-survivor/pull/3#review/1",
                "audit_merge_commit": "cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34",
                "audited_at_utc": "2026-10-15T09:05:00Z",
            },
            "record": {
                "schema": "research-survivor-record-v1",
                "survivor_repository_url": "https://github.com/HCH725/research-survivor",
                "survivor_strategy_path": "svr-donchian-exit15-v1.md",
                "family_name": "Donchian breakout",
                "frozen_version_sha": OOS_READY["frozen_version_sha"],
                "full_config_snapshot_uri": FREEZE_FACTS["config_snapshot"]["uri"],
                "full_config_sha256": CONFIG_SHA,
                "is_run_id": RUN_KEY,
                "oos_run_id": OOS_READY["oos_run_id"],
                "is_window_hash": FREEZE_FACTS["is_window"]["window_hash"],
                "oos_window_hash": OOS_READY["window_hash"],
                "backtest_start_utc": "2025-01-01",
                "backtest_end_utc": "2025-06-30",
                "data_source": FREEZE_FACTS["data_snapshot"]["uri"],
                "dataset_version_or_hash": OOS_READY["data_snapshot_sha256"],
                "data_snapshot": FREEZE_FACTS["data_snapshot"],
                "cost_model": FREEZE_FACTS["cost_model"],
                "qlib_engine_version": "pyqlib-0.9.7",
                "runtime_git_commit_or_image": "qlib-arm64-container:2026-10-01",
                "qlib_report_uri": "mlflow://qlib/runs/" + OOS_READY["oos_run_key"] + "/report",
                "trades_artifact_uri": "mlflow://qlib/runs/" + OOS_READY["oos_run_key"] + "/trades",
                "equity_curve_uri": "mlflow://qlib/runs/" + OOS_READY["oos_run_key"] + "/equity",
                "artifacts_manifest_uri": "mlflow://qlib/runs/" + OOS_READY["oos_run_key"] + "/artifacts/manifest.json",
                "artifacts_manifest_sha256": "a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5061728394a5b6c7d8e9f0",
                "research_note_uri": NOTE_REF,
                "coverage_42cell_ref": "research-nav://42cell/donchian/coverage.json",
                "metrics": {"cagr_pct": 14.2, "sharpe": 1.21, "max_drawdown_pct": 19.0, "max_drawdown_definition": "peak_to_trough_net", "win_rate_pct": 48.4, "total_trades": 128, "profit_factor": 1.62, "net_return_pct": 14.2},
                "survivor_gate_version": "qlib-promotion-policy-v1",
            },
        },
    }


# ------------------------------------------------------------------- checks


def static_checks(workflow: Workflow, case: Case) -> None:
    names = [node["name"] for node in workflow.raw["nodes"]]
    types = sorted({node["type"] for node in workflow.raw["nodes"]})
    case.equal(workflow.raw["id"], "OhSN7BCpOVLMcUMQ", "single deploy target id")
    case.equal(workflow.raw["active"], False, "workflow is inactive")
    case.equal(workflow.raw["settings"], {"executionOrder": "v1"}, "execution order")
    case.equal(len(set(names)), len(names), "node names are unique")
    case.equal(names.count(TRIGGER), 1, "one manual trigger")
    # H9. No forbidden orchestration surface.
    for banned in ("n8n-nodes-base.executeWorkflow", "n8n-nodes-base.webhook", "n8n-nodes-base.scheduleTrigger",
                   "n8n-nodes-base.executeCommand", "n8n-nodes-base.cron", "n8n-nodes-base.redis",
                   "n8n-nodes-base.mySql", "n8n-nodes-base.postgres"):
        case.check(banned not in types, f"workflow must not carry {banned}")
    for banned in ("langchain", "openai", "lmchat", "chainllm", "@n8n/n8n-nodes-langchain"):
        case.check(
            not any(banned in node["type"].lower() for node in workflow.raw["nodes"]),
            f"no second reasoning layer: {banned}",
        )
    blob = json.dumps(workflow.raw)
    # Check emitted records below. Guard code can name a value that it rejects.
    case.check("n8n-nodes-base.googleSheetsTrigger" not in types, "no Sheets trigger")
    # The only HTTP nodes are the frozen 01-05 reads and the GitHub branch/ref gap.
    http = [node for node in workflow.raw["nodes"] if node["type"] == "n8n-nodes-base.httpRequest"]
    case.equal(len(http), 4, "http nodes")
    gap = [node for node in http if "authentication" in node["parameters"]]
    case.equal(len(gap), 2, "GitHub branch/ref gap calls")
    for node in gap:
        case.equal(node["parameters"]["authentication"], "predefinedCredentialType", node["name"] + " predefined credential")
        case.equal(node["parameters"]["nodeCredentialType"], "githubApi", node["name"] + " credential type")
        case.check("api.github.com/repos/HCH725/research-survivor/git/" in node["parameters"]["url"], node["name"] + " is a git ref call")
    # One Hermes invocation, one native SSH to the host, no second model.
    ssh = [node for node in workflow.raw["nodes"] if node["type"] == "n8n-nodes-base.ssh"]
    case.equal(len(ssh), 4, "ssh nodes: two frozen 01-05 plus two Hermes host verbs")
    materialize_ssh = [node for node in ssh if node["name"] == SSH_MATERIALIZE]
    case.equal(len(materialize_ssh), 1, "one frozen-cell handoff SSH node")
    case.equal(materialize_ssh[0]["parameters"]["command"], "={{ 'research-handoff ' + $json.request_b64 }}",
               "fixed handoff verb and payload only")
    case.equal(materialize_ssh[0]["parameters"]["cwd"], "/", "handoff restricted-key working directory")
    case.equal(materialize_ssh[0]["credentials"]["sshPrivateKey"]["name"], "Hermes Host SSH",
               "the handoff reuses the Hermes host credential")
    case.check("record_text" not in blob, "the workflow sends no record text to the host")
    case.check("handoff_policy" in blob and "evidence_root" in blob,
               "the run input names the effective identity and the frozen evidence root")
    hermes = [node for node in ssh if node["name"] == SSH_06]
    case.equal(len(hermes), 1, "one Hermes host SSH node")
    case.equal(hermes[0]["credentials"]["sshPrivateKey"]["name"], "Hermes Host SSH", "Hermes host credential placeholder")
    case.equal(hermes[0]["parameters"]["command"], "={{ 'research-hermes ' + $json.hermes_task_b64 }}", "fixed Hermes verb and payload only")
    case.equal(hermes[0]["parameters"]["cwd"], "/", "restricted-key working directory")
    case.check("require(" not in blob, "no require call in node code")
    case.check("/Users/" not in blob, "no local filesystem path")
    case.check("sk-" not in blob and "BEGIN OPENSSH" not in blob, "no secret material")
    # Live path credentials stay placeholders.
    for node in workflow.raw["nodes"]:
        for kind, ref in (node.get("credentials") or {}).items():
            case.check(ref["id"] != "", node["name"] + " credential reference")
    case.check(
        not any(ref["id"] == "v87SSHca9d1549MAC" for node in workflow.raw["nodes"] for ref in (node.get("credentials") or {}).values() if node["name"] == SSH_06),
        "the Hermes node does not reuse the frozen 01-05 credential",
    )
    # No dead ends: every non-terminal node leads somewhere.
    terminals = {HOLD_05B, REVIEW_ENDPOINT_09, REVIEW_ENDPOINT_10, "11 \u00b7 HOLD endpoint", "11 \u00b7 REJECT endpoint",
                 RETRY_ENDPOINT, ERROR_ENDPOINT, NODE13_END, "12 \u00b7 NEEDS_REVIEW endpoint", HOLD_03I}
    for name in names:
        if name in terminals:
            continue
        case.check(bool(workflow.children(name)), f"no dead end at {name}")
    # H5. The OOS lane never returns to Nodes 06-09.
    for start in (OOS_BRIDGE, OOS_READY_GATE, OOS_READY_LANE):
        reach = workflow.reachable(start)
        case.check(
            not any(name.startswith(("06 \u00b7", "07 \u00b7", "08 \u00b7", "09 \u00b7")) for name in reach),
            f"{start} must not reach the IS learning loop",
        )
    case.check(NODE04 in workflow.reachable(OOS_LANE), "OOS re-entry reaches the existing 04")
    case.check(NODE05 in workflow.reachable(OOS_LANE), "OOS re-entry reaches the existing 05")
    case.check(NODE04 in workflow.reachable(RETEST_LANE), "retest reaches the same workflow's 04")
    case.equal(workflow.parents(NODE04), ["03b \u00b7 READY gate", RETEST_LANE, OOS_LANE], "04 parents")
    case.equal(workflow.children(REPLAY_BOUNDARY), [ASSEMBLY_11], "replay boundary feeds the assembly")
    case.check(TASK_06 in workflow.reachable("06 \u00b7 IS_READY lane gate"), "IS lane reaches the Hermes task")
    case.check("12 \u00b7 Read registry row" in workflow.reachable(MERGE_LANE), "Sheets writes only after a verified merge")
    case.equal(workflow.parents(NODE13_PAYLOAD), ["12 \u00b7 SHEETS_ACK lane gate"], "Node13 payload needs the Sheets ACK")
    case.check(NODE13_END in workflow.reachable(NODE13_PAYLOAD), "Node13 boundary is reached")
    native = [node["parameters"] for node in workflow.raw["nodes"] if node["type"] != "n8n-nodes-base.code"]
    case.check("hummingbot" not in json.dumps(native).lower(), "no native Hummingbot call")


def main() -> int:
    workflow = Workflow(WORKFLOW)
    cases: list[Case] = []

    # Case 1. One deployable export, valid graph, frozen 01-05 untouched.
    case = Case("1 single deploy target + frozen 01-05 + no forbidden surface")
    static_checks(workflow, case)
    base = json.loads(COMPONENTS[0].read_text(encoding="utf-8"))
    # The on-demand lane extends exactly three frozen preflight nodes and
    # rewires one edge. Every other frozen node keeps its exact parameters.
    extended = {"01 \u00b7 Select candidate", READY_03}
    rewired = {("02 \u00b7 Read pinned record", READY_03): REQUEST_03C}
    for node in base["nodes"]:
        carried = workflow.nodes.get(node["name"])
        case.check(carried is not None, f"carries {node['name']}")
        if carried:
            case.equal(carried["type"], node["type"], node["name"] + " type")
            case.equal(carried["typeVersion"], node["typeVersion"], node["name"] + " typeVersion")
            if node["name"] in extended:
                continue
            case.equal(json.dumps(carried["parameters"], sort_keys=True), json.dumps(node["parameters"], sort_keys=True), node["name"] + " parameters")
    for src, outputs in base["connections"].items():
        for group in outputs["main"]:
            for link in group:
                target = rewired.get((src, link["node"]), link["node"])
                case.check(target in workflow.children(src), f"frozen edge {src} -> {target}")
    readme_text = README.read_text(encoding="utf-8")
    for fixture in ("WF-Research-01-03-manual-preflight.json", "WF-Research-06-09-learning-loop.json", "WF-Research-10-12-survivor-handoff.json"):
        case.check(fixture in readme_text, f"README names {fixture}")
    case.check("NOT deploy target" in readme_text or "not deploy target" in readme_text, "README marks the components as fixtures")
    case.check("WF-Research-01-12.json" in readme_text, "README names the single deploy target")
    cases.append(case)

    case = Case("2 05 IS not claimable -> HOLD; campaign-level IS_READY -> Node06")
    is_lane = "06 \u00b7 IS_READY lane gate"
    outs = workflow.codes([GATE_05B, is_lane], [read_05(False)])
    case.equal(outs[GATE_05B][0]["route"], "HOLD", "representative receipt route")
    case.equal(outs[GATE_05B][0]["reason"], "performance_not_claimable", "missing claim")
    case.equal(outs[is_lane], [], "HOLD does not enter the IS lane")
    campaign = read_05(True, allowlist=["donchian.exit_window"])
    initial = workflow.codes([GATE_05B, is_lane, TASK_06], [campaign])
    case.equal(initial[GATE_05B][0]["route"], "IS_READY", "campaign-level route")
    case.equal(initial[GATE_05B][0]["period_basis"], "IS", "period basis")
    case.equal(initial[GATE_05B][0]["completed_runs"], [{"round_index": 0, "run_key": RUN_KEY, "status": "IS_SUCCESS"}], "round series")
    case.equal(initial[GATE_05B][0]["metrics_ref"], campaign["node05_receipt"]["refs"]["mlflow_run"], "readback ref")
    case.check(initial[TASK_06], "IS_READY builds the task")
    cases.append(case)

    case = Case("3 one Hermes turn -> analysis contract -> Wiki ACK -> validation")
    import base64

    task = initial[TASK_06][0]
    prompt = base64.b64decode(task["hermes_task_b64"], validate=True).decode("utf-8")
    case.check("STATE (single in-sample run):" in prompt and RUN_KEY in prompt, "task carries the IS identity")
    ack = {"status": "ACK", "action": "CREATED", "note_ref": NOTE_REF, "run_key": RUN_KEY, "analysis_hash": ANALYSIS_HASH}
    reply = hermes_stdout({"analysis": analysis(), "wiki_ack": ack})
    sequence = [READER_06, CONTRACT_06, WIKI_07, NODE08, NODE09]
    learning = workflow.codes(sequence, [reply], initial)
    for name, route in zip(sequence, ["ANALYSIS_PENDING", "ANALYSIS_OK", "WIKI_PERSISTED", "VALID", "RETEST"]):
        case.equal(learning[name][0]["route"], route, name)
    case.equal(learning[WIKI_07][0]["analysis"], analysis(), "analysis is not rewritten")
    case.equal(learning[NODE09][0]["decision"]["next_change_set"], analysis()["proposal"]["change_set"], "change set")
    undeclared = workflow.codes([GATE_05B, TASK_06], [read_05(True)])
    outs = workflow.codes(sequence, [reply], undeclared)
    case.equal(outs[NODE08][0]["reason"], "override_param_not_allowed:donchian.exit_window", "no guessed allowlist")
    case.equal(workflow.codes([FINALIZE_GATE], outs[NODE09])[FINALIZE_GATE], [], "held change does not finalize")
    for bad_ack, reason in [(dict(ack, status="CONFLICT"), "wiki_ack_conflict_no_overwrite"),
                            (dict(ack, note_ref="somewhere/else.md"), "wiki_note_ref_not_canonical")]:
        outs = workflow.codes(sequence, [hermes_stdout({"analysis": analysis(), "wiki_ack": bad_ack})], initial)
        case.equal(outs[WIKI_07][0]["reason"], reason, "Wiki ACK holds")
        case.equal(outs[NODE09][0]["route"], "NEEDS_REVIEW", "held ACK cannot retest")
    cases.append(case)

    case = Case("4 RETEST -> same workflow 04; round cap -> FINALIZE -> 10")
    refs = {READY_03: [ready_03()], READ_05: [campaign]}
    outs = workflow.codes([RETEST_REENTRY, RETEST_LANE], learning[NODE09], refs)
    case.equal(outs[RETEST_REENTRY][0]["reason"], "retest_handoff_not_materialised", "stale round refused")
    case.equal(outs[RETEST_REENTRY][0]["blocked_by"]["code"], "retest_materialisation_required", "operator action")
    case.equal(outs[RETEST_LANE], [], "no stale submit")
    refs[READY_03] = [ready_03(config_sha=OTHER_CONFIG_SHA)]
    outs = workflow.codes([RETEST_REENTRY, RETEST_LANE], learning[NODE09], refs)
    case.equal(outs[RETEST_REENTRY][0]["round_contract"]["round_index"], 1, "next round index")
    case.check(outs[RETEST_LANE], "materialised retest opens the lane")
    case.equal(workflow.children(RETEST_LANE), [NODE04], "same 04 target")
    cap_state = copy.deepcopy(learning[NODE08][0])
    k3 = f"{3:032x}"
    cap_state.update(run_key=k3, run_id=k3, round_index=3,
                     completed_runs=[{"round_index": i, "run_key": f"{i:032x}", "status": "IS_SUCCESS"} for i in range(4)])
    cap_read = read_05(True)
    cap_read.update(run_key=k3, qlib_run_id=k3)
    outs = workflow.codes([NODE09, FINALIZE_GATE, FINALIZE_PAYLOAD, IS_SNAPSHOT], [cap_state], {READ_05: [cap_read]})
    case.equal(outs[NODE09][0]["decision"]["finalize_reason"], "ROUND_CAP_REACHED", "cap finalizes")
    case.check(outs[FINALIZE_PAYLOAD], "finalize payload built")
    case.check(outs[IS_SNAPSHOT][0]["missing_facts"], "missing campaign facts named")
    frozen = workflow.codes([FREEZE, OOS_REQUEST_GATE], outs[FINALIZE_PAYLOAD] + outs[IS_SNAPSHOT])
    case.equal(frozen[FREEZE][0]["route"], "NEEDS_REVIEW", "incomplete freeze holds")
    case.equal(frozen[OOS_REQUEST_GATE], [], "no incomplete OOS submit")
    cases.append(case)

    case = Case("5 OOS re-entry -> 05 boundary -> Node11 contract; no IS return")
    outs = workflow.codes([OOS_REENTRY, OOS_LANE], [oos_request_item()], {READY_03: [ready_03()]})
    case.equal(outs[OOS_REENTRY][0]["reason"], "oos_handoff_not_materialised", "unmaterialised OOS holds")
    case.equal(outs[OOS_LANE], [], "no stale OOS submit")
    oos_state = ready_03()
    oos_state["executable_handoff"].update(period_basis="OOS", window_hash=OOS_REQUEST["window_hash"])
    reentry = workflow.codes([OOS_REENTRY, OOS_LANE], [oos_request_item()], {READY_03: [oos_state]})
    case.equal(reentry[OOS_REENTRY][0]["payload_kind"], "oos_request", "production re-entry payload kind")
    case.equal(reentry[OOS_REENTRY][0]["route"], "OOS_ROUND", "OOS lane contract")
    case.check(reentry[OOS_LANE], "materialised OOS lane opens")
    case.equal(workflow.children(OOS_LANE), [NODE04], "same 04/05 target")
    outs = workflow.codes([GATE_05B], [campaign], reentry)
    case.equal(outs[GATE_05B], [], "OOS never returns to IS")
    outs = workflow.codes([OOS_BRIDGE], [campaign], reentry)
    case.equal(outs[OOS_BRIDGE][0]["reason"], "oos_readback_not_oos", "IS reply is not OOS")
    # Only the live Node05 receipt is a fixture. Keep the re-entry output intact.
    oos_readback = read_05(True)
    oos_readback["node05_receipt"].update(copy.deepcopy(OOS_READY))
    oos_readback["node05_receipt"].update(run_id=OOS_READY["oos_run_id"], refs=OOS_READY["evidence_refs"])
    oos = workflow.codes([OOS_BRIDGE, OOS_READY_GATE, OOS_READY_LANE], [oos_readback], reentry)
    case.equal(oos[OOS_READY_GATE][0]["route"], "OOS_READY_OK", "OOS readback accepted")
    case.equal(oos[OOS_READY_LANE][0]["payload_kind"], "oos_request", "payload kind reaches Node11 unchanged")
    cases.append(case)

    case = Case("6 promotion policy native read; PASS reaches Node12, HOLD/REJECT do not")
    policy = workflow.codes([POLICY_PARSE], [readme()])[POLICY_PARSE]
    case.equal(policy[0]["route"], "POLICY_INPUT", "policy route")
    case.equal(policy[0]["policy"]["thresholds"], {"cagr_min_pct": 10, "sharpe_min": 1.0}, "thresholds")
    missing = readme_snapshot("# research-survivor\n\nno policy block\n", "384ab0df97ebaa48ddf7f1e398e347f210c57212")
    bad_policy = workflow.codes([POLICY_PARSE], [missing])[POLICY_PARSE]
    case.equal(bad_policy[0]["reason"], "promotion_policy_block_missing", "missing policy holds")
    evaluated = workflow.codes([EVAL_11], oos[OOS_READY_LANE] + policy)[EVAL_11]
    case.equal(evaluated[0]["route"], "PERF_PASS", "real re-entry payload reaches evaluation")
    unavailable = workflow.codes([REPLAY_BOUNDARY], evaluated)[REPLAY_BOUNDARY]
    held = workflow.codes([ASSEMBLY_11, PASS_LANE], evaluated + unavailable)
    case.equal(held[ASSEMBLY_11][0]["reason"], "qlib_replay_evidence_missing", "no fabricated replay")
    case.equal(held[PASS_LANE], [], "missing replay writes no record")
    replay_item = {
        "payload_kind": "qlib_replay",
        "route": "QLIB_REPLAY_INPUT",
        "replay": {"status": "QLIB_REPLAY_PASS", "run_key": RUN_KEY, "oos_run_key": OOS_REQUEST["oos_run_key"],
                   "frozen_version_sha": FREEZE_FACTS["frozen_version_sha"], "effective_config_hash": CONFIG_SHA,
                   "strategy_sha": ENTRY_SHA, "window_hash": OOS_REQUEST["window_hash"],
                   "evidence_uri": "mlflow://qlib/replays/" + RUN_KEY + "/replay.json", "replayed_at_utc": "2026-10-15T08:30:00Z"},
    }
    outs = workflow.codes([ASSEMBLY_11, PASS_LANE, RECORD_12, RECORD_FILE], evaluated + [replay_item])
    case.equal(outs[ASSEMBLY_11][0]["route"], "PASS", "assembly route")
    case.check(outs[RECORD_12], "PASS reaches the record payload")
    contract = outs[RECORD_12][0]["record_file"]["record"]
    case.equal(contract["hummingbot_validation_status"], "PENDING", "HB status stays pending")
    case.equal(contract["hb_certified"], False, "hb_certified stays false")
    promotion = outs
    for field, value in [("hb_certified", True), ("hummingbot_validation_status", "CERTIFIED")]:
        bad = copy.deepcopy(promotion[PASS_LANE][0])
        bad["survivor_record_contract"][field] = value
        refused = workflow.codes([RECORD_12], [bad])[RECORD_12][0]
        case.equal(refused["reason"], "hb_status_must_stay_pending", "certification is refused")
    held = workflow.codes([EVAL_11, PERF_LANE], oos[OOS_READY_LANE] + bad_policy)
    case.equal(held[EVAL_11][0]["route"], "HOLD", "bad policy holds")
    case.equal(held[PERF_LANE], [], "HOLD cannot reach record")
    reject_item = copy.deepcopy(oos[OOS_READY_LANE][0])
    reject_item["oos_ready"]["metrics"]["cagr_pct"] = 5.0
    reject_item["oos_ready"]["metrics"]["sharpe"] = 0.8
    outs = workflow.codes([EVAL_11, PERF_LANE], [reject_item] + policy)
    case.equal(outs[EVAL_11][0]["route"], "REJECT", "reject route")
    case.equal(outs[PERF_LANE], [], "REJECT cannot reach record")
    cases.append(case)

    case = Case("7 PR open -> retry; merged -> advance; closed/timeout -> review")
    record_file = promotion[RECORD_FILE][0]
    pr_response = {"number": 3, "html_url": "https://github.com/HCH725/research-survivor/pull/3", "state": "open",
                   "head": {"sha": "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12", "ref": "promote/svr-donchian-exit15-v1"}, "base": {"ref": "main"}}
    created = workflow.codes([PR_CREATED], [pr_response], promotion)
    case.check(record_file["record_content"].startswith("---\n"), "record file carries frontmatter")
    case.check("```json" in record_file["record_content"], "record file carries the machine readable block")
    case.equal(record_file["record_path"], "svr-donchian-exit15-v1.md", "record path")
    case.equal(created[PR_CREATED][0]["route"], "AWAITING_AUDIT_MERGE", "created state")
    case.equal(created[PR_CREATED][0]["audit_deadline_utc"], "2026-10-16T00:00:00.000Z", "fixed 24-hour deadline")
    case.equal(workflow.nodes[WAIT_12]["parameters"], {"resume": "timeInterval", "amount": 15, "unit": "minutes"}, "15-minute wait")
    case.equal(workflow.parents(WAIT_12), [PR_CREATED, PR_OPEN_GATE], "only an open PR retries")
    case.equal(workflow.children(WAIT_12), [READ_PR], "wait reads PR")
    case.equal(workflow.children(READ_PR), [PR_STATE], "read checks state")
    lanes = [PR_OPEN_GATE, MERGE_LANE_GATE, "12 \u00b7 NEEDS_REVIEW gate"]
    def routes(response, refs):
        result = workflow.codes([PR_STATE], [response], refs)
        for lane in lanes:
            result.update(workflow.codes([lane], result[PR_STATE]))
        return result

    opened = routes(pr_response, created)
    case.equal(opened[PR_STATE][0]["route"], "PR_OPEN", "open retries")
    case.check(opened[PR_OPEN_GATE], "open retry lane")
    case.equal(opened[MERGE_LANE_GATE], [], "open cannot advance")
    closed = routes(dict(pr_response, state="closed", merged=False), created)
    case.equal(closed[PR_STATE][0]["reason"], "merge_readback_not_merged:CLOSED", "closed needs review")
    case.check(closed[lanes[2]], "closed review lane")
    case.equal(closed[PR_OPEN_GATE], [], "closed cannot retry")
    for deadline, reason in [("2026-10-15T00:00:00.000Z", "audit_merge_timeout"),
                             ("2026-10-14T23:59:59.000Z", "audit_merge_timeout"),
                             ("invalid", "audit_deadline_missing")]:
        expired = {PR_CREATED: [dict(created[PR_CREATED][0], audit_deadline_utc=deadline)]}
        timed = routes(pr_response, expired)
        case.equal(timed[PR_STATE][0]["reason"], reason, "deadline holds")
        case.check(timed[lanes[2]], "timeout review lane")
        case.equal(timed[PR_OPEN_GATE], [], "timeout cannot retry")
        case.equal(timed[MERGE_LANE_GATE], [], "timeout cannot advance")
    case.equal(routes(pr_response, {})[PR_STATE][0]["reason"], "audit_deadline_missing", "missing deadline holds")
    merged_response = dict(pr_response, state="closed", merged=True,
                           merge_commit_sha=merge_event()["event"]["merge_commit_sha"], merged_at="2026-10-15T09:10:00Z")
    merged = routes(merged_response, created)
    case.equal(merged[PR_STATE][0]["route"], "MERGED_PR_EVENT", "merged advances")
    case.check(merged[MERGE_LANE_GATE], "merge lane opens")
    case.equal(merged[PR_OPEN_GATE], [], "merged cannot retry")
    case.equal(workflow.children(lanes[2]), ["12 \u00b7 NEEDS_REVIEW endpoint"], "review reaches endpoint")
    merged_file = {
        "type": "file",
        "encoding": "base64",
        "path": "svr-donchian-exit15-v1.md",
        "sha": "e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f",
        "content": base64.b64encode(record_file["record_content"].encode("utf-8")).decode("ascii"),
    }
    reviews = [{"id": 1, "state": "APPROVED", "commit_id": "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12", "submitted_at": "2026-10-15T09:05:00Z"}]
    refs = {PR_STATE: merged[PR_STATE], "12 \u00b7 Read audit reviews": reviews}
    readback = workflow.codes([MERGE_READBACK], [merged_file], refs)[MERGE_READBACK]
    outs = workflow.codes([MERGE_VERIFY, MERGE_LANE, SHEETS_PLAN], merged[PR_STATE] + readback)
    case.equal(readback[0]["payload_kind"], "github_readback", "readback payload")
    case.equal(readback[0]["readback"]["frontmatter"]["survivor_id"], "svr-donchian-exit15", "merged frontmatter")
    case.equal(readback[0]["readback"]["audited_pass_evidence"]["verdict"], "PASS", "native approval evidence")
    case.equal(outs[MERGE_VERIFY][0]["route"], "MERGE_VERIFIED", "merge verified")
    case.check(outs[SHEETS_PLAN], "the Sheets plan runs only after a verified merge")
    refs["12 \u00b7 Read audit reviews"] = []
    no_audit = workflow.codes([MERGE_READBACK], [merged_file], refs)[MERGE_READBACK]
    outs = workflow.codes([MERGE_VERIFY, MERGE_LANE], merged[PR_STATE] + no_audit)
    case.equal(outs[MERGE_VERIFY][0]["reason"], "audit_evidence_not_pass", "no approval, no merge verification")
    case.equal(outs[MERGE_LANE], [], "no audit evidence writes no Sheet")
    cases.append(case)

    case = Case("8 same survivor key updates, a new key appends, readback mismatch is ERROR")
    plan_input = {"route": "MERGE_VERIFIED", "merge": merge_readback()["readback"]}
    plans = workflow.codes([SHEETS_PLAN], [plan_input])
    plan = plans[SHEETS_PLAN][0]["sheets"]
    case.equal(plan["spreadsheet_id"], REGISTRY_ID, "registry id")
    case.equal(plan["tab"], "Survivor Registry", "registry tab")
    case.equal(plan["key"], ["survivor_id", "survivor_version"], "composite key")
    case.equal(plan["native_node"]["update"]["matchingColumns"], ["survivor_id"], "native update matches one column")
    case.equal(plan["native_node"]["append"]["operation"], "append", "native append")
    case.check("multiKeyMatch=false" in plan["schema_evidence"], "schema evidence for the minimal path")
    case.equal(len(plan["headers_ref"]["count"]) if isinstance(plan["headers_ref"]["count"], list) else plan["headers_ref"]["count"], 84, "84 registry columns")
    case.check(len(plan["columns"]) < 84, "the row is a mapped subset")
    row = plan["columns"]
    outs = workflow.codes([SHEETS_DECISION], [{"data": [dict(row)]}], plans)
    case.equal(outs[SHEETS_DECISION][0]["route"], "UPSERT_UPDATE", "existing key updates")
    outs = workflow.codes([SHEETS_DECISION], [{"data": [dict(row, survivor_id="other-survivor")]}], plans)
    case.equal(outs[SHEETS_DECISION][0]["route"], "UPSERT_APPEND", "new key appends")
    case.equal(outs[SHEETS_DECISION][0]["sheets_row"]["registry_sync_status"], "SYNCED", "row carries the sync status")
    outs = workflow.codes([SHEETS_DECISION], [{"data": [dict(row), dict(row)]}], plans)
    case.equal(outs[SHEETS_DECISION][0]["reason"], "duplicate_rows_forbidden", "duplicate rows refused")
    intent = workflow.codes([SHEETS_DECISION], [{"data": [dict(row)]}], plans)
    written_row = intent[SHEETS_DECISION][0]["sheets_row"]
    result = workflow.codes([SHEETS_RESULT], [{"data": [written_row]}], intent)[SHEETS_RESULT]
    outs = workflow.codes([ACK_GATE], plans[SHEETS_PLAN] + result)
    case.equal(outs[ACK_GATE][0]["route"], "SHEETS_ACK", "ACK route")
    case.equal(outs[ACK_GATE][0]["sheets_ack"]["survivor_git_commit"], row["survivor_git_commit"], "ACK commit")
    boundary = workflow.codes(["12 \u00b7 SHEETS_ACK lane gate", NODE13_PAYLOAD], outs[ACK_GATE])
    case.check(boundary[NODE13_PAYLOAD], "ACK produces the Node13 payload")
    case.equal(boundary[NODE13_PAYLOAD][0]["node13"]["hummingbot_validation_status"], "PENDING", "HB stays pending")
    case.equal(boundary[NODE13_PAYLOAD][0]["node13"]["hb_certified"], False, "hb_certified stays false")
    bad_row = dict(written_row, survivor_git_commit="0" * 40)
    bad_result = workflow.codes([SHEETS_RESULT], [{"data": [bad_row]}], intent)[SHEETS_RESULT]
    outs = workflow.codes([ACK_GATE, "12 \u00b7 SHEETS_ACK lane gate"], plans[SHEETS_PLAN] + bad_result)
    case.equal(outs[ACK_GATE][0]["route"], "ERROR", "mismatch route")
    case.equal(outs[ACK_GATE][0]["reason"], "readback_mismatch:survivor_git_commit", "mismatch reason")
    case.equal(outs["12 \u00b7 SHEETS_ACK lane gate"], [], "no Node13 without ACK")
    cases.append(case)

    # Case 9. The handoff lane resolves one frozen engineering cell.
    # The SSH node is a real boundary, so this case runs the real transport file
    # over the real 02c request instead of inventing a successful reply.
    case = Case("9 frozen cell resolves -> READY; missing or mismatched evidence holds")
    import base64 as _b64
    import hashlib as _hashlib
    import os as _os
    import tempfile as _tempfile

    read_02 = "02 \u00b7 Read pinned record"
    record_text = "---\nschema: strategy-research-record-v1\nhb_ready_status: PASS\n---\nbody\n"
    record_file = {"type": "file", "sha": BLOB_SHA,
                   "content": _b64.b64encode(record_text.encode()).decode()}
    fixed = {"02 \u00b7 Pin Alpha main": [{"sha": HANDOFF["source_commit"]}]}
    overlay = {"base_order_quote_pct": 0.06, "safety_order_quote_pct": 0.06,
               "safety_order_levels": 2, "so_spacing_pct": 0.04, "take_profit_pct": 0.05,
               "stop_loss_pct": 0.2, "trade_cost": 0.001, "initial_capital_quote": 1000}
    cost_model = {"approved": False, "fees_per_side": 0.001, "slippage": 0.0005, "funding": 0.0}
    selection = {"origin": "manual", "candidate_path": HANDOFF["candidate_path"], "market_data_ready": True}

    def fsha(path):
        return _hashlib.sha256(Path(path).read_bytes()).hexdigest()

    def frozen_root():
        """Write one frozen cell and manifest the way Qlib materialize() does."""
        root = Path(_tempfile.mkdtemp(prefix="wf-handoff-evidence-"))
        cell = root / "btcusdt-1h-3x"
        cell.mkdir()
        entry = cell / "run_cell.entrypoint.py"
        entry.write_text("#!/usr/bin/env python3\n")
        artifact = cell / "strategy_signal.py"
        artifact.write_text("def signal(**kwargs):\n    return [], None\n")
        config = {
            "schema": "qlib-formal-research-cell-v1",
            "candidate": {"path": HANDOFF["candidate_path"],
                          "source_commit": HANDOFF["source_commit"], "git_blob_sha": BLOB_SHA},
            "runtime": {"commit": HANDOFF["qlib_runtime_commit"]},
            "data": {"provider_ref": "/results/_validation/formal-cells-round0/provider"},
            "execution": {"entrypoint": str(entry)},
            "research_leverage": 3,
            "strategy": {"symbol": "BTCUSDT", "timeframe": "1h", "sides": ["long"],
                         "params": {"entry_len": 20, "exit_len": 10}, "warmup_days": 20,
                         "window_start_utc": "2025-04-19 16:00:00",
                         "window_end_utc_inclusive": "2026-04-19 16:00:00",
                         "artifact": {"ref": str(artifact), "sha256": fsha(artifact)}},
            "capabilities": {"execution": ["qlib-native-backtest"], "data": ["binance-usdm-ohlcv"],
                             "timing": ["bar-close"], "sides": ["long"]},
            "house_overlay": dict(overlay),
            "research_cost_model": dict(cost_model),
        }
        config_path = cell / "effective_config.json"
        config_path.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n")
        manifest = {"schema": "qlib-formal-campaign-manifest-v1", "cell_count": 1, "cells": [{
            "cell_id": "btcusdt-1h-3x", "symbol": "BTCUSDT", "timeframe": "1h",
            "research_leverage": 3,
            "source_commit": HANDOFF["source_commit"], "candidate_path": HANDOFF["candidate_path"],
            "source_blob_sha": BLOB_SHA,
            "entrypoint_ref": str(entry), "entrypoint_sha256": fsha(entry),
            "strategy_artifact_ref": str(artifact), "strategy_artifact_sha256": fsha(artifact),
            "effective_config_ref": str(config_path), "effective_config_sha256": fsha(config_path),
            "qlib_runtime_commit": HANDOFF["qlib_runtime_commit"],
            "capabilities": dict(config["capabilities"]),
            "evidence_refs": {"manifest": str(root / "campaign-manifest.json")},
            "research_cost_model": dict(cost_model),
        }]}
        (root / "campaign-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        return root, config_path

    transport = HERE.parent / "research-transport.py"

    def host_run(request_b64):
        """Run the real transport the way the restricted Hermes key would."""
        if request_b64 is None:
            return {"code": 2, "stdout": json.dumps({"ok": False, "error": "no request"})}
        env = dict(_os.environ, SSH_ORIGINAL_COMMAND="research-handoff " + request_b64)
        proc = subprocess.run([sys.executable, str(transport), "hermes-forced"], env=env,
                              capture_output=True, text=True, timeout=120)
        return {"code": proc.returncode, "stdout": proc.stdout.strip()}

    def envelope(sel, reply=None):
        outs = workflow.codes([REQUEST_03C], [record_file],
                              dict(fixed, **{"01 \u00b7 Select candidate": [sel]}))
        request = outs[REQUEST_03C][0]
        host = reply if reply is not None else host_run(request["request_b64"])
        outs[SSH_MATERIALIZE] = [host]
        env = workflow.codes([ENVELOPE_03E], [host], outs)
        return request, env[ENVELOPE_03E][0]

    def readiness(env):
        outs = workflow.codes([READY_03], [env],
                              dict(fixed, **{read_02: [record_file], ENVELOPE_03E: [env]}))
        return outs[READY_03][0]

    def ok_reply(handoff, status="ready"):
        return {"code": 0, "stdout": json.dumps({"ok": True, "status": status,
                                                 "source": "frozen-cell", "handoff": handoff})}

    command = workflow.nodes[SSH_MATERIALIZE]["parameters"]["command"]
    case.check("research-handoff" in command, "02d sends the frozen-cell handoff verb")

    root, config_path = frozen_root()
    policy = {"evidence_root": str(root),
              "strategy": {"symbol": "BTCUSDT", "timeframe": "1h", "sides": ["long"],
                           "params": {"entry_len": 20, "exit_len": 10}, "warmup_days": 20,
                           "window_start_utc": "2025-04-19 16:00:00",
                           "window_end_utc_inclusive": "2026-04-19 16:00:00"},
              "research_leverage": 3,
              "runtime": {"commit": HANDOFF["qlib_runtime_commit"]},
              "data": {"provider_ref": "/results/_validation/formal-cells-round0/provider"},
              "house_overlay": dict(overlay),
              "research_cost_model": dict(cost_model)}

    request, env = envelope(dict(selection, handoff_policy=policy))
    case.equal(request["request_kind"], "resolve", "a policy run resolves a frozen cell")
    case.equal(env["resolution"]["status"], "ready", "the real host resolves the frozen cell")
    route = readiness(env)
    case.equal(route["route"], "READY", "a verified frozen handoff reaches the same readiness")
    case.equal(route["executable_handoff"]["effective_config_sha256"], fsha(config_path),
               "the handoff binds the frozen config bytes")
    case.equal(route["executable_handoff"]["research_cost_model"]["approved"], False,
               "the approved flag comes from the frozen config, not the request")
    case.equal(json.loads(_b64.b64decode(route["transport_payload_b64"]).decode()),
               route["executable_handoff"], "the payload 04 submits is that handoff")

    absent = dict(selection, candidate_path="another-candidate.md", handoff_policy=policy)
    _, env = envelope(absent)
    case.equal(env["resolution"]["status"], "implementation_needed",
               "a candidate without a frozen cell is implementation_needed")
    route = readiness(env)
    case.equal(route["route"], "IMPLEMENTATION_NEEDED", "a missing cell holds instead of passing")
    hold_lane = workflow.codes([HOLD_GATE_03H], [route])
    case.equal(len(hold_lane[HOLD_GATE_03H]), 1, "the HOLD lane surfaces the missing implementation")

    for label, over in (("trade_cost", {"house_overlay": dict(overlay, trade_cost=0.01234)}),
                        ("approved", {"research_cost_model": dict(cost_model, approved=True)})):
        _, env = envelope(dict(selection, handoff_policy=dict(policy, **over)))
        case.equal(env["resolution"]["status"], "failed",
                   "a changed " + label + " is refused by the host")
        case.equal(readiness(env)["route"], "IMPLEMENTATION_NEEDED",
                   "a changed " + label + " never reaches READY")

    resolved = json.loads(host_run(
        workflow.codes([REQUEST_03C], [record_file],
                       dict(fixed, **{"01 \u00b7 Select candidate": [dict(selection, handoff_policy=policy)]})
                       )[REQUEST_03C][0]["request_b64"])["stdout"])["handoff"]
    request, env = envelope(dict(selection, executable_handoff=resolved))
    case.equal(request["request_kind"], "verify", "a run-input handoff is verified, not trusted")
    case.equal(env["resolution"]["status"], "ready", "the real host verifies the supplied handoff")
    case.equal(readiness(env)["route"], "READY", "the verified handoff reaches the same readiness")

    smuggle = json.loads(json.dumps(resolved))
    smuggle["research_cost_model"] = dict(cost_model, approved=True)
    _, env = envelope(dict(selection, executable_handoff=smuggle))
    case.equal(env["resolution"]["status"], "ready", "a smuggled cost model still resolves")
    case.equal(env["executable_handoff"]["research_cost_model"]["approved"], False,
               "the rebuilt handoff keeps the frozen approved flag")
    forged = json.loads(json.dumps(resolved))
    forged["entrypoint_sha256"] = "e" * 64
    _, env = envelope(dict(selection, executable_handoff=forged))
    case.equal(env["resolution"]["status"], "failed", "a forged entrypoint hash fails closed")
    case.equal(readiness(env)["route"], "IMPLEMENTATION_NEEDED", "a forged handoff never reaches READY")

    two_sided = json.loads(json.dumps(resolved))
    two_sided["capabilities"] = dict(two_sided["capabilities"], sides=["long", "short"])
    _, env = envelope(dict(selection, handoff_policy=policy), reply=ok_reply(two_sided))
    route = readiness(env)
    case.equal(route["route"], "ENGINEERING_HOLD", "a short side is a genuine capability gap")
    case.equal(route["capability_gap"], ["sides:short"], "the gap names the primitive")

    unknown = json.loads(json.dumps(resolved))
    unknown["capabilities"] = {"data": ["btcusdt-1h"], "execution": ["qlib-native-backtest"],
                               "timing": ["bar-close"], "sides": ["long"]}
    _, env = envelope(dict(selection, handoff_policy=policy), reply=ok_reply(unknown))
    route = readiness(env)
    case.equal(route["route"], "ENGINEERING_HOLD", "a per-symbol capability is not a verified primitive")
    case.equal(route["capability_gap"], ["data:btcusdt-1h"], "the gap names the primitive")

    mismatch = json.loads(json.dumps(resolved))
    mismatch["entrypoint_sha256"] = "not-a-digest"
    _, env = envelope(dict(selection, handoff_policy=policy), reply=ok_reply(mismatch))
    case.equal(readiness(env)["route"], "NEEDS_REVIEW", "an unbound handoff shape fails closed")

    no_policy = envelope(dict(selection, handoff_policy=None), reply={"code": 0, "stdout": ""})[0]
    case.equal(no_policy["request_problem"] is not None, True, "no policy is a declared problem")
    env = envelope(dict(selection, handoff_policy=None), reply={"code": 0, "stdout": ""})[1]
    case.equal(readiness(env)["route"], "IMPLEMENTATION_NEEDED", "no policy holds, never guesses")

    cases.append(case)

    # Case 10. The run input's market-data flag must survive the handoff lane.
    # Both request kinds run the real transport over a real frozen cell; the
    # envelope may not drop a false/'false'/'no'/'0' selection, and an explicit
    # false in the Alpha record still holds the same gate.
    case = Case("10 market_data_ready survives both handoff request kinds")
    record_ready = record_file
    record_false_text = "---\nschema: strategy-research-record-v1\nhb_ready_status: PASS\nmarket_data_ready: false\n---\nbody\n"
    record_false = {"type": "file", "sha": BLOB_SHA,
                    "content": _b64.b64encode(record_false_text.encode()).decode()}

    def readiness_with(env_item, rec):
        outs = workflow.codes([READY_03], [env_item],
                              dict(fixed, **{read_02: [rec], ENVELOPE_03E: [env_item]}))
        return outs[READY_03][0]

    resolved_once = json.loads(host_run(
        workflow.codes([REQUEST_03C], [record_ready],
                       dict(fixed, **{"01 \u00b7 Select candidate": [dict(selection, handoff_policy=policy)]})
                       )[REQUEST_03C][0]["request_b64"])["stdout"])["handoff"]

    for label, extra in (("handoff_policy", {"handoff_policy": policy}),
                         ("executable_handoff", {"executable_handoff": resolved_once})):
        for raw in (False, "false", "no", "0"):
            request, env_item = envelope(dict(selection, **extra, market_data_ready=raw))
            case.check("market_data_ready" in env_item,
                       label + " envelope keeps the selection flag")
            case.equal(env_item.get("market_data_ready"), raw, label + " keeps the raw value " + repr(raw))
            route = readiness_with(env_item, record_ready)
            case.equal(route["route"], "WAITING_DATA", label + " " + repr(raw) + " waits for data")
            case.equal(route["reason"], "Market data is not ready for this run",
                       label + " " + repr(raw) + " data reason")
        request, env_item = envelope(dict(selection, **extra, market_data_ready=True))
        case.equal(readiness_with(env_item, record_ready)["route"], "READY",
                   label + " with market data ready still reaches READY")

    request, env_item = envelope(dict(selection, handoff_policy=policy, market_data_ready=True))
    record_route = readiness_with(env_item, record_false)
    case.equal(record_route["route"], "WAITING_DATA", "an explicit false in the Alpha record waits for data")
    case.equal(record_route["reason"], "Market data is not ready for this run", "record data reason")

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
