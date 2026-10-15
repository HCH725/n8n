#!/usr/bin/env python3
"""Targeted test for WF-Research-01-12.json (the single deploy target).

The test reads the exported workflow and runs its Code nodes with Node.js. A
small harness gives every node the n8n Code-node surface ($input, $, items) and
the live nodes of the frozen 01-05 transport are injected as contract-shaped
data, exactly as a live run would deliver them. The walker then follows the
exported connection graph.

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


class _Outs(dict):
    """Node outputs. An unexecuted node reads as an empty list."""

    def __missing__(self, key):  # noqa: D105
        return []


class Workflow:
    """Load the export and execute its Code nodes over the exported graph."""

    def __init__(self, path: Path):
        self.raw = json.loads(path.read_text(encoding="utf-8"))
        self.nodes = {node["name"]: node for node in self.raw["nodes"]}
        self.connections = self.raw["connections"]
        self.cyclic = {
            name
            for name in self.nodes
            if any(parent in self.reachable(name) for parent in self.parents(name))
        }

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

    def _ready(self, name: str, parents: list[str], processed: set[str], outputs: dict) -> bool:
        """True when the node can run in this single pass.

        A node inside a loop (the Wait/Get audit loop, the retest return to 04)
        may run once even when a loop parent has not run in this pass. It still
        waits for a parent that really delivered items: a loop node that ran
        before its input arrived would run once with nothing, and this single
        pass never runs a node twice.
        """
        open_parents = [parent for parent in parents if parent not in processed]
        if not open_parents:
            return True
        if name in self.cyclic and all(parent in self.cyclic for parent in open_parents):
            if all(parent in processed for parent in parents):
                return True
            return any(outputs.get(parent) for parent in parents if parent in processed)
        return False

    def walk(self, injected: dict | None = None, stop_after: set[str] | None = None) -> dict:
        """Run the graph once. Live nodes come from ``injected``.

        A node whose parents produced no items produces no items. Nodes of a
        live type (ssh/http/sheets/github/wait) that are not injected stay
        unexecuted: nothing in this environment can run them.

        ``stop_after`` names the harness boundary nodes. A boundary node of a
        live type yields nothing - its input is not its output - while a Code
        boundary node still runs, because its result is the thing asserted.
        """
        injected = dict(injected or {})
        provided = {name: (value if isinstance(value, list) else [value]) for name, value in injected.items()}
        outputs: dict[str, list] = {}
        processed: set[str] = set()
        pending = [name for name in self.nodes]
        while pending:
            progressed = False
            for name in list(pending):
                parents = self.parents(name)
                strict = name in provided
                if strict:
                    # A live node runs after its parents in the real execution.
                    # A loop parent that has not run in this pass is not a
                    # reason to hold a node that carries its own live result.
                    open_parents = [parent for parent in parents if parent not in processed]
                    if open_parents and not all(parent in self.cyclic for parent in open_parents):
                        continue
                elif not self._ready(name, parents, processed, outputs):
                    continue
                items: list = []
                for parent in parents:
                    items.extend(outputs.get(parent, []))
                if name == TRIGGER:
                    outputs[name] = [{}]
                elif name in provided:
                    outputs[name] = provided[name]
                elif stop_after and name in stop_after and self.type_of(name) != "n8n-nodes-base.code":
                    # A live boundary node cannot run here, and its input is not
                    # its output: it yields nothing rather than a false result.
                    pass
                elif not items:
                    # n8n does not execute a node that receives no items.
                    pass
                elif self.type_of(name) == "n8n-nodes-base.noOp":
                    outputs[name] = items
                elif self.type_of(name) == "n8n-nodes-base.code":
                    outputs[name] = run_node(
                        {
                            "code": self.code_of(name),
                            "node": name,
                            "inputs": items,
                            "outputs": outputs,
                        }
                    )
                # Any other node type is a live node: nothing here can run it.
                processed.add(name)
                pending.remove(name)
                progressed = True
            if not progressed:
                # Nothing can run: every remaining node waits on a loop input
                # that never arrived in this pass. The walk ends here, exactly
                # as a live run would leave those nodes unexecuted.
                break
        return _Outs(outputs)


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
    "capabilities": {"data": ["btcusdt-1h"], "execution": ["qlib-native-backtest"], "timing": ["bar-close-1h"]},
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
    case.check("CERTIFIED" not in blob, "no fabricated Hummingbot certification")
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
    case.equal(len(ssh), 3, "ssh nodes: two frozen 01-05 plus one Hermes host")
    hermes = [node for node in ssh if node["name"] == SSH_06]
    case.equal(len(hermes), 1, "one Hermes host SSH node")
    case.equal(hermes[0]["credentials"]["sshPrivateKey"]["name"], "Hermes Host SSH", "Hermes host credential placeholder")
    case.check("hermes chat --query-file - --oneshot" in json.dumps(workflow.raw), "native Hermes CLI invocation")
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
                 RETRY_ENDPOINT, ERROR_ENDPOINT, NODE13_END}
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
    case.check("hummingbot" not in blob.lower().replace("hummingbot_validation_status", "").replace("hummingbot validation", ""), "no Hummingbot call")


def main() -> int:
    workflow = Workflow(WORKFLOW)
    cases: list[Case] = []

    # Case 1. One deployable export, valid graph, frozen 01-05 untouched.
    case = Case("1 single deploy target + frozen 01-05 + no forbidden surface")
    static_checks(workflow, case)
    base = json.loads(COMPONENTS[0].read_text(encoding="utf-8"))
    for node in base["nodes"]:
        carried = workflow.nodes.get(node["name"])
        case.check(carried is not None, f"carries {node['name']}")
        if carried:
            case.equal(carried["type"], node["type"], node["name"] + " type")
            case.equal(carried["typeVersion"], node["typeVersion"], node["name"] + " typeVersion")
            case.equal(json.dumps(carried["parameters"], sort_keys=True), json.dumps(node["parameters"], sort_keys=True), node["name"] + " parameters")
    for src, outputs in base["connections"].items():
        for group in outputs["main"]:
            for link in group:
                case.check(link["node"] in workflow.children(src), f"frozen edge {src} -> {link['node']}")
    readme_text = README.read_text(encoding="utf-8")
    for fixture in ("WF-Research-01-03-manual-preflight.json", "WF-Research-06-09-learning-loop.json", "WF-Research-10-12-survivor-handoff.json"):
        case.check(fixture in readme_text, f"README names {fixture}")
    case.check("NOT deploy target" in readme_text or "not deploy target" in readme_text, "README marks the components as fixtures")
    case.check("WF-Research-01-12.json" in readme_text, "README names the single deploy target")
    cases.append(case)

    # Case 2. The 05 -> 06 gate: a representative receipt holds, a campaign-level
    # contract enters the loop.
    case = Case("2 05 IS not claimable -> HOLD; campaign-level IS_READY -> Node06")
    outs = workflow.walk(injected={READY_03: ready_03(), READ_05: read_05(False)})
    case.equal(outs[GATE_05B][0]["route"], "HOLD", "representative receipt route")
    case.check(str(outs[GATE_05B][0]["reason"]).startswith("performance") or outs[GATE_05B][0]["reason"] == "coverage_incomplete", "reason names the missing claim")
    case.check(outs[HOLD_05B], "HOLD endpoint reached")
    case.check(not outs["06 \u00b7 IS_READY lane gate"], "no IS_READY lane")
    case.check(not outs[TASK_06], "no Hermes task for an unclaimable receipt")
    campaign = read_05(True, allowlist=["donchian.exit_window"])
    outs = workflow.walk(injected={READY_03: ready_03(allowlist=["donchian.exit_window"]), READ_05: campaign,
                                   SSH_06: hermes_stdout({"analysis": analysis(), "wiki_ack": {"status": "ACK", "action": "CREATED", "note_ref": NOTE_REF, "run_key": RUN_KEY, "analysis_hash": ANALYSIS_HASH}})},
                          stop_after={SSH_06})
    case.equal(outs[GATE_05B][0]["route"], "IS_READY", "campaign-level route")
    case.equal(outs[GATE_05B][0]["period_basis"], "IS", "period basis")
    case.equal(outs[GATE_05B][0]["completed_runs"], [{"round_index": 0, "run_key": RUN_KEY, "status": "IS_SUCCESS"}], "round series")
    case.equal(outs[GATE_05B][0]["metrics_ref"], campaign["node05_receipt"]["refs"]["mlflow_run"], "metrics ref is the readback ref")
    case.check(not outs[HOLD_05B], "no HOLD for a claimable receipt")
    cases.append(case)

    # Case 3. One Hermes invocation, deterministic 06/07/08 path.
    case = Case("3 one Hermes turn -> analysis contract -> Wiki ACK -> validation")
    outs = workflow.walk(injected={READY_03: ready_03(allowlist=["donchian.exit_window"]), READ_05: read_05(True, allowlist=["donchian.exit_window"]),
                                   SSH_06: hermes_stdout({"analysis": analysis(), "wiki_ack": {"status": "ACK", "action": "CREATED", "note_ref": NOTE_REF, "run_key": RUN_KEY, "analysis_hash": ANALYSIS_HASH}})},
                          stop_after={SSH_06})
    task = outs[TASK_06][0]
    case.check(task["hermes_command"].startswith("printf '%s' '"), "payload is piped, not interpolated")
    case.check(__import__("re").search(r"^printf '%s' '[A-Za-z0-9+/=]+' \| base64 -d \| hermes chat", task["hermes_command"]) is not None, "shell-safe payload")
    case.check("IS" in json.dumps(task), "state carries the period basis")
    case.equal(outs[READER_06][0]["route"], "ANALYSIS_PENDING", "reader route")
    case.equal(outs[CONTRACT_06][0]["route"], "ANALYSIS_OK", "analysis contract")
    case.equal(outs[WIKI_07][0]["route"], "WIKI_PERSISTED", "wiki gate")
    case.equal(outs[WIKI_07][0]["analysis"], analysis(), "the analysis is not rewritten")
    case.equal(outs[NODE08][0]["route"], "VALID", "deterministic validation")
    case.equal(outs[NODE09][0]["route"], "RETEST", "decision route")
    case.equal(outs[NODE09][0]["decision"]["next_change_set"], {"hypothesis_group": "donchian", "params": {"donchian.exit_window": 15}}, "change set")
    # An undeclared allowlist fails closed: no override is guessed.
    outs = workflow.walk(injected={READY_03: ready_03(), READ_05: read_05(True),
                                   SSH_06: hermes_stdout({"analysis": analysis(), "wiki_ack": {"status": "ACK", "action": "CREATED", "note_ref": NOTE_REF, "run_key": RUN_KEY, "analysis_hash": ANALYSIS_HASH}})})
    case.equal(outs[NODE08][0]["route"], "NEEDS_REVIEW", "undeclared allowlist holds the change set")
    case.equal(outs[NODE08][0]["reason"], "override_param_not_allowed:donchian.exit_window", "the holding param is named")
    case.check(not outs[FINALIZE_PAYLOAD], "no OOS request from a held change set")
    # A second Hermes turn is impossible: the nodes after 07 never call a model.
    for name in (WIKI_07, NODE08, NODE09):
        case.check(workflow.type_of(name) == "n8n-nodes-base.code", f"{name} is deterministic")
    # Wiki conflicts and bad ACKs fail closed.
    outs = workflow.walk(injected={READY_03: ready_03(allowlist=["donchian.exit_window"]), READ_05: read_05(True, allowlist=["donchian.exit_window"]),
                                   SSH_06: hermes_stdout({"analysis": analysis(), "wiki_ack": {"status": "CONFLICT", "action": "REJECTED", "note_ref": NOTE_REF, "run_key": RUN_KEY, "analysis_hash": OTHER_HASH}})})
    case.equal(outs[WIKI_07][0]["reason"], "wiki_ack_conflict_no_overwrite", "conflict fails closed")
    case.check(not outs[NODE08], "no validation after a conflict")
    outs = workflow.walk(injected={READY_03: ready_03(allowlist=["donchian.exit_window"]), READ_05: read_05(True, allowlist=["donchian.exit_window"]),
                                   SSH_06: hermes_stdout({"analysis": analysis(), "wiki_ack": {"status": "ACK", "action": "CREATED", "note_ref": "somewhere/else.md", "run_key": RUN_KEY, "analysis_hash": ANALYSIS_HASH}})})
    case.equal(outs[WIKI_07][0]["reason"], "wiki_note_ref_not_canonical", "non canonical note ref")
    outs = workflow.walk(injected={READY_03: ready_03(allowlist=["donchian.exit_window"]), READ_05: read_05(True, allowlist=["donchian.exit_window"])}, stop_after={SSH_06})
    case.check(not outs[TASK_06], "no Hermes task when the IS lane is closed")
    cases.append(case)

    # Case 4. RETEST returns to this workflow's 04; the round cap finalizes into 10.
    case = Case("4 RETEST -> same workflow 04; round cap -> FINALIZE -> 10")
    # The frozen 04/05 submit and its readback are live SSH nodes. The harness
    # leaves them unexecuted, so no made-up receipt reaches the frozen chain.
    outs = workflow.walk(injected={READY_03: ready_03(allowlist=["donchian.exit_window"]), READ_05: read_05(True, allowlist=["donchian.exit_window"]),
                                   SSH_06: hermes_stdout({"analysis": analysis(), "wiki_ack": {"status": "ACK", "action": "CREATED", "note_ref": NOTE_REF, "run_key": RUN_KEY, "analysis_hash": ANALYSIS_HASH}})},
                          stop_after={NODE04})
    case.equal(outs[RETEST_REENTRY][0]["reason"], "retest_handoff_not_materialised", "stale round is refused")
    case.check(outs[RETEST_REENTRY][0]["blocked_by"]["code"] == "retest_materialisation_required", "refusal names the operator action")
    case.check(REVIEW_ENDPOINT_09 in workflow.children("09 \u00b7 NEEDS_REVIEW gate"), "refusal lands on the review endpoint")
    case.check(not outs[RETEST_LANE], "no stale submit")
    case.check(not outs[RETEST_REENTRY][0].get("round_contract"), "the refused round carries no round contract")
    # A materialised round (the frozen handoff carries the retest config) passes.
    outs = workflow.walk(injected={READY_03: ready_03(allowlist=["donchian.exit_window"], config_sha=OTHER_CONFIG_SHA), READ_05: read_05(True, allowlist=["donchian.exit_window"]),
                                   SSH_06: hermes_stdout({"analysis": analysis(), "wiki_ack": {"status": "ACK", "action": "CREATED", "note_ref": NOTE_REF, "run_key": RUN_KEY, "analysis_hash": ANALYSIS_HASH}})},
                          stop_after={NODE04})
    case.equal(outs[RETEST_REENTRY][0]["route"], "RETEST_ROUND", "materialised round route")
    case.equal(outs[RETEST_REENTRY][0]["round_contract"]["round_index"], 1, "next round index")
    case.check(outs[RETEST_LANE], "the retest lane opens for a materialised round")
    case.check(NODE04 in workflow.children(RETEST_LANE), "the retest lane targets the existing 04")
    # Round cap: round 3 with worth_retesting=true finalizes at the cap.
    k3 = f"{3:032x}"
    cap_analysis = analysis(worth_retesting=True, prior=NOTE_REF, change_set={"hypothesis_group": "donchian", "params": {"donchian.exit_window": 16}}, run_key=k3)
    cap_state = {
        "route": "VALID",
        "run_key": k3,
        "run_id": k3,
        "round_index": 3,
        "period_basis": "IS",
        "metrics_summary": {"sharpe": 1.1},
        "metrics_ref": "mlflow://qlib/runs/" + k3 + "/metrics",
        "evidence_refs": {"run_manifest": "mlflow://qlib/runs/" + k3 + "/manifest.json"},
        "applied_change_set": {"hypothesis_group": "donchian", "params": {"donchian.exit_window": 16}},
        "prior_hypothesis_ref": NOTE_REF,
        "allowed_override_params": ["donchian.exit_window"],
        "completed_runs": [{"round_index": i, "run_key": (k3 if i == 3 else f"{i:032x}"), "status": "IS_SUCCESS"} for i in range(4)],
        "wiki_state": [],
        "analysis": cap_analysis,
        "wiki_ack": {"status": "ACK", "action": "IDEMPOTENT", "note_ref": NOTE_REF, "run_key": k3, "analysis_hash": ANALYSIS_HASH},
        "change_set": {"hypothesis_group": "donchian", "params": {"donchian.exit_window": 16}},
    }
    cap_read = read_05(True, allowlist=["donchian.exit_window"])
    cap_read["run_key"] = k3
    cap_read["qlib_run_id"] = k3
    outs = workflow.walk(injected={"08 \u00b7 Deterministic validation": cap_state, READ_05: cap_read})
    case.equal(outs[NODE09][0]["route"], "FINALIZE", "cap finalizes")
    case.equal(outs[NODE09][0]["decision"]["finalize_reason"], "ROUND_CAP_REACHED", "cap reason")
    case.check(outs[FINALIZE_PAYLOAD], "finalize payload is built")
    case.check(outs[IS_SNAPSHOT], "the frozen snapshot is projected from the readback")
    case.check(outs[IS_SNAPSHOT][0]["missing_facts"], "missing campaign facts are named")
    case.equal(outs[FREEZE][0]["route"], "NEEDS_REVIEW", "an incomplete freeze fails closed")
    case.equal(outs[FREEZE][0]["reason"], "frozen_version_sha_bad_shape", "freeze reason names the missing fact")
    case.check(outs[REVIEW_ENDPOINT_10], "the freeze review item reaches the endpoint")
    case.check(not outs[OOS_REQUEST_GATE], "no OOS request without a complete freeze")
    cases.append(case)

    # Case 5. The OOS request re-enters the existing 04/05 path and never the loop.
    case = Case("5 OOS -> existing 04/05 -> 11; OOS never returns to 06-09")
    outs = workflow.walk(injected={READY_03: ready_03(), READ_05: read_05(True, allowlist=["donchian.exit_window"]), OOS_REQUEST_GATE: oos_request_item()}, stop_after={NODE04})
    case.equal(outs[OOS_REENTRY][0]["reason"], "oos_handoff_not_materialised", "unmaterialised OOS holds")
    case.check(not outs[OOS_LANE], "no stale OOS submit")
    # A materialised OOS round passes into the same 04/05 path.
    oos_handoff = json.loads(json.dumps(HANDOFF))
    oos_handoff.update({"period_basis": "OOS", "window_hash": OOS_REQUEST["window_hash"], "effective_config_sha256": CONFIG_SHA})
    oos_state = ready_03()
    oos_state["executable_handoff"] = oos_handoff
    outs = workflow.walk(injected={READY_03: oos_state, READ_05: read_05(True, allowlist=["donchian.exit_window"]), OOS_REQUEST_GATE: oos_request_item()}, stop_after={NODE04})
    case.equal(outs[OOS_REENTRY][0]["route"], "OOS_ROUND", "materialised OOS round")
    case.check(outs[OOS_LANE], "the OOS lane opens")
    case.equal(workflow.children(OOS_LANE), [NODE04], "the OOS lane targets the existing 04")
    # The IS gate drops an OOS round instead of returning to 06-09.
    outs = workflow.walk(injected={READY_03: oos_state, READ_05: read_05(True, allowlist=["donchian.exit_window"]), OOS_REQUEST_GATE: oos_request_item()})
    case.check(not outs[GATE_05B], "an OOS round never enters the IS gate")
    case.check(not outs[TASK_06], "an OOS round never reaches Node06")
    # The readback bridge demands real OOS facts.
    outs = workflow.walk(injected={READY_03: oos_state, READ_05: read_05(True, allowlist=["donchian.exit_window"]), OOS_REQUEST_GATE: oos_request_item()}, stop_after={OOS_BRIDGE})
    case.equal(outs[OOS_BRIDGE][0]["reason"], "oos_readback_not_oos", "the IS readback is not accepted as OOS")
    cases.append(case)

    # Case 6. The promotion policy is a native read; a bad policy holds.
    case = Case("6 promotion policy native read; PASS reaches Node12, HOLD/REJECT do not")
    outs = workflow.walk(injected={POLICY_READ_GITHUB: readme()}, stop_after={POLICY_PARSE})
    case.equal(outs[POLICY_PARSE][0]["route"], "POLICY_INPUT", "policy route")
    case.equal(outs[POLICY_PARSE][0]["policy"]["thresholds"], {"cagr_min_pct": 10, "sharpe_min": 1.0}, "thresholds")
    case.check(str(outs[POLICY_PARSE][0]["policy"]["source_ref"]).startswith("https://github.com/HCH725/research-survivor/blob/"), "policy source ref")
    outs = workflow.walk(injected={POLICY_READ_GITHUB: readme_snapshot("# research-survivor\n\nno policy block\n", "384ab0df97ebaa48ddf7f1e398e347f210c57212")}, stop_after={POLICY_PARSE})
    case.equal(outs[POLICY_PARSE][0]["route"], "POLICY_UNREADABLE", "missing policy block")
    case.equal(outs[POLICY_PARSE][0]["reason"], "promotion_policy_block_missing", "policy reason")
    # PASS assembly needs real replay evidence.
    eval_out = workflow.walk(injected={OOS_READY_LANE: oos_item(), POLICY_READ_GITHUB: readme()}, stop_after={ASSEMBLY_11})
    case.equal(eval_out[EVAL_11][0]["route"], "PERF_PASS", "performance pass")
    case.check(eval_out[REPLAY_BOUNDARY], "the replay boundary is on the path")
    case.check(eval_out[ASSEMBLY_11] is not None, "the assembly runs")
    replay_item = {
        "payload_kind": "qlib_replay",
        "route": "QLIB_REPLAY_INPUT",
        "replay": {"status": "QLIB_REPLAY_PASS", "run_key": RUN_KEY, "oos_run_key": OOS_REQUEST["oos_run_key"],
                   "frozen_version_sha": FREEZE_FACTS["frozen_version_sha"], "effective_config_hash": CONFIG_SHA,
                   "strategy_sha": ENTRY_SHA, "window_hash": OOS_REQUEST["window_hash"],
                   "evidence_uri": "mlflow://qlib/replays/" + RUN_KEY + "/replay.json", "replayed_at_utc": "2026-10-15T08:30:00Z"},
    }
    outs = workflow.walk(injected={OOS_READY_LANE: oos_item(), POLICY_READ_GITHUB: readme(), REPLAY_BOUNDARY: replay_item}, stop_after={RECORD_12})
    case.equal(outs[ASSEMBLY_11][0]["route"], "PASS", "assembly route")
    case.check(outs[RECORD_12], "PASS reaches the record payload")
    contract = outs[RECORD_12][0]["record_file"]["record"]
    case.equal(contract["hummingbot_validation_status"], "PENDING", "HB status stays pending")
    case.equal(contract["hb_certified"], False, "hb_certified stays false")
    # The boundary alone (no readback) holds and writes nothing.
    outs = workflow.walk(injected={OOS_READY_LANE: oos_item(), POLICY_READ_GITHUB: readme()}, stop_after={RECORD_12})
    case.check(not outs[RECORD_12], "no replay evidence, no record")
    # REJECT writes nothing.
    reject_item = json.loads(json.dumps(oos_item()))
    reject_item["oos_ready"]["metrics"]["cagr_pct"] = 5.0
    reject_item["oos_ready"]["metrics"]["sharpe"] = 0.8
    outs = workflow.walk(injected={OOS_READY_LANE: reject_item, POLICY_READ_GITHUB: readme(), REPLAY_BOUNDARY: replay_item}, stop_after={RECORD_12})
    case.equal(outs[EVAL_11][0]["route"], "REJECT", "reject route")
    case.check(not outs[RECORD_12], "REJECT writes no record")
    cases.append(case)

    # Case 7. Node12: the PR path, the audit wait loop and the fail-closed states.
    case = Case("7 PR created -> Wait/Get loop; merged -> Sheets; closed -> NEEDS_REVIEW")
    import base64

    # The PASS contract comes from the assembly that produced it, exactly as the
    # live path hands it to the record payload.
    outs = workflow.walk(injected={OOS_READY_LANE: oos_item(), POLICY_READ_GITHUB: readme(), REPLAY_BOUNDARY: replay_item}, stop_after={PASS_LANE})
    pass_item = outs[PASS_LANE][0]
    main_ref = {"ref": "refs/heads/main", "object": {"sha": "8f0e1d2c3b4a5968778695a4b3c2d1e0f9a8b7c6", "type": "commit"}}
    commit_result = {"content": {"sha": "e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f"}, "commit": {"sha": "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12"}}
    pr_response = {"number": 3, "html_url": "https://github.com/HCH725/research-survivor/pull/3", "state": "open",
                   "head": {"sha": "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12", "ref": "promote/svr-donchian-exit15-v1"}, "base": {"ref": "main"}}
    outs = workflow.walk(injected={PASS_LANE: pass_item, "12 \u00b7 Read survivor main ref": main_ref,
                                   "12 \u00b7 Create survivor branch": {}, "12 \u00b7 Commit survivor record": commit_result,
                                   "12 \u00b7 Open promotion PR": pr_response})
    record_file = outs[RECORD_FILE][0]
    case.check(record_file["record_content"].startswith("---\n"), "record file carries frontmatter")
    case.check("```json" in record_file["record_content"], "record file carries the machine readable block")
    case.equal(record_file["record_path"], "svr-donchian-exit15-v1.md", "record path")
    case.equal(outs[PR_CREATED][0]["route"], "AWAITING_AUDIT_MERGE", "created PR state")
    case.equal(outs[PR_CREATED][0]["pr"]["head_sha"], "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12", "PR head sha")
    case.check(outs[WAIT_12] is not None, "the audit wait node is on the path")
    case.check(WAIT_12 in workflow.reachable(PR_CREATED), "a created PR waits for the audit merge")
    case.check(workflow.parents(WAIT_12) == [PR_CREATED, PR_OPEN_GATE], "the wait loops on an open PR")
    case.check(not outs["12 \u00b7 Sheets upsert plan"], "an open PR writes nothing")
    # The merged path, read back from GitHub.
    merged_file = {
        "type": "file",
        "encoding": "base64",
        "path": "svr-donchian-exit15-v1.md",
        "sha": "e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f",
        "content": base64.b64encode(record_file["record_content"].encode("utf-8")).decode("ascii"),
    }
    reviews = [{"id": 1, "state": "APPROVED", "commit_id": "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12", "submitted_at": "2026-10-15T09:05:00Z"}]
    outs = workflow.walk(injected={PR_STATE: merge_event(), "12 \u00b7 Read merged record": merged_file, "12 \u00b7 Read audit reviews": reviews})
    case.equal(outs[MERGE_READBACK][0]["payload_kind"], "github_readback", "readback payload")
    readback = outs[MERGE_READBACK][0]["readback"]
    case.equal(readback["frontmatter"]["survivor_id"], "svr-donchian-exit15", "readback reads the merged frontmatter")
    case.equal(readback["record"]["is_run_id"], RUN_KEY, "readback reads the merged record block")
    case.equal(readback["audited_pass_evidence"]["verdict"], "PASS", "audit evidence from the native review read")
    case.equal(readback["audited_pass_evidence"]["reviewed_head_sha"], "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12", "audit covers the merged head")
    case.equal(outs[MERGE_VERIFY][0]["route"], "MERGE_VERIFIED", "merge verified")
    case.equal(outs[MERGE_VERIFY][0]["merge"]["survivor_id"], "svr-donchian-exit15", "merged identity")
    case.check(outs[SHEETS_PLAN], "the Sheets plan runs only after a verified merge")
    # A merge without audit evidence needs review and writes nothing.
    outs = workflow.walk(injected={PR_STATE: merge_event(), "12 \u00b7 Read merged record": merged_file, "12 \u00b7 Read audit reviews": []})
    case.equal(outs[MERGE_VERIFY][0]["reason"], "audit_evidence_not_pass", "no approval, no merge verification")
    case.check(not outs[SHEETS_PLAN], "no audit evidence writes no Sheet")
    # A closed, unmerged PR needs review.
    outs = workflow.walk(injected={"12 \u00b7 Read promotion PR": {"number": 3, "state": "closed", "merged": False, "head": {"sha": "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12"}}})
    case.equal(outs[PR_STATE][0]["route"], "NEEDS_REVIEW", "closed PR route")
    case.equal(outs[PR_STATE][0]["reason"], "merge_readback_not_merged:CLOSED", "closed PR reason")
    case.check(not outs[SHEETS_PLAN], "a closed PR writes no Sheet")
    cases.append(case)

    # Case 8. The Sheets upsert: composite key decided in code, bounded readback.
    case = Case("8 same survivor key updates, a new key appends, readback mismatch is ERROR")
    plan_input = {"route": "MERGE_VERIFIED", "merge": merge_readback()["readback"]}
    outs = workflow.walk(injected={MERGE_LANE: plan_input}, stop_after={SHEETS_DECISION})
    plan = outs[SHEETS_PLAN][0]["sheets"]
    case.equal(plan["spreadsheet_id"], REGISTRY_ID, "registry id")
    case.equal(plan["tab"], "Survivor Registry", "registry tab")
    case.equal(plan["key"], ["survivor_id", "survivor_version"], "composite key")
    case.equal(plan["native_node"]["update"]["matchingColumns"], ["survivor_id"], "native update matches one column")
    case.equal(plan["native_node"]["append"]["operation"], "append", "native append")
    case.check("multiKeyMatch=false" in plan["schema_evidence"], "schema evidence for the minimal path")
    case.equal(len(plan["headers_ref"]["count"]) if isinstance(plan["headers_ref"]["count"], list) else plan["headers_ref"]["count"], 84, "84 registry columns")
    case.check(len(plan["columns"]) < 84, "the row is a mapped subset")
    row = plan["columns"]
    outs = workflow.walk(
        injected={MERGE_LANE: plan_input, "12 \u00b7 Read registry row": [dict(row, survivor_version="v0")]},
        stop_after={SHEETS_DECISION},
    )
    case.equal(outs[SHEETS_DECISION][0]["route"], "UPSERT_UPDATE", "existing key updates")
    outs = workflow.walk(
        injected={MERGE_LANE: plan_input, "12 \u00b7 Read registry row": [dict(row, survivor_id="other-survivor")]},
        stop_after={SHEETS_DECISION},
    )
    case.equal(outs[SHEETS_DECISION][0]["route"], "UPSERT_APPEND", "new key appends")
    case.equal(outs[SHEETS_DECISION][0]["sheets_row"]["registry_sync_status"], "SYNCED", "row carries the sync status")
    # A duplicate row for the same key is refused before any write.
    outs = workflow.walk(
        injected={MERGE_LANE: plan_input, "12 \u00b7 Read registry row": [dict(row), dict(row)]},
        stop_after={SHEETS_DECISION},
    )
    case.equal(outs[SHEETS_DECISION][0]["reason"], "duplicate_rows_forbidden", "duplicate rows refused")
    # The full merged path: readback ACK, Node13 boundary, fail-closed mismatch.
    outs = workflow.walk(injected={MERGE_LANE: plan_input, "12 \u00b7 Read registry row": [dict(row, survivor_version="v0")],
                                   "12 \u00b7 Read registry row back": [dict(row, registry_sync_status="SYNCED")]})
    case.equal(outs[ACK_GATE][0]["route"], "SHEETS_ACK", "ACK route")
    case.equal(outs[ACK_GATE][0]["sheets_ack"]["survivor_git_commit"], row["survivor_git_commit"], "ACK commit")
    case.check(outs[NODE13_PAYLOAD], "the ACK produces the Node13 boundary payload")
    case.check(outs[NODE13_END], "the Node13 boundary is reached")
    case.equal(outs[NODE13_PAYLOAD][0]["node13"]["hummingbot_validation_status"], "PENDING", "HB stays pending")
    case.equal(outs[NODE13_PAYLOAD][0]["node13"]["hb_certified"], False, "hb_certified stays false")
    outs = workflow.walk(injected={MERGE_LANE: plan_input, "12 \u00b7 Read registry row": [dict(row, survivor_version="v0")],
                                   "12 \u00b7 Read registry row back": [dict(row, survivor_git_commit="0" * 40, registry_sync_status="SYNCED")]})
    case.equal(outs[ACK_GATE][0]["route"], "ERROR", "mismatch route")
    case.equal(outs[ACK_GATE][0]["reason"], "readback_mismatch:survivor_git_commit", "mismatch reason")
    case.check(not outs[NODE13_PAYLOAD], "no Node13 payload without the ACK")
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
