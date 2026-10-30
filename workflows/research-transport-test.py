#!/usr/bin/env python3
"""Thin contract checks for research-transport.py. Stdlib only.

Run: python3 research-transport-test.py. Exit 0 means every check passed.
Each case runs the real transport in a temp results root; the golden submit
path runs a stub native entrypoint that honors the same minimal on-disk
contract (summary/signals/events + mlflow_readback/manifest + one native
mlruns run dir, refuse overwrite).

ponytail: one test file on purpose, directly against the contract. The prior
61-probe forensic framework is gone: no AST consumption probes, no file-store
meta/params/metrics parsing probes, no per-artifact byte attestation probes.
Kept probes map to the blocking boundaries only: command injection, path
escape, identity mismatch, receipt mismatch.
"""

import base64
import contextlib
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
TRANSPORT = HERE / "research-transport.py"
RUN_ID = "ab" * 16
EXP_ID = "123456"
CHECKS = []


#: Minimal stand-in for the shared engine. The transport must call the engine
#: for the artifact contract instead of carrying its own copy.
STUB_ENGINE = """
import hashlib

CELL_SYMBOLS = ("BTCUSDT", "ETHUSDT")
CELL_TIMEFRAMES = ("1h", "4h", "1d")
CELL_LEVERAGES = (3, 5)


def load_signal_artifact(cell_dir, artifact):
    path = artifact["ref"]
    with open(path, "rb") as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    if digest != artifact["sha256"]:
        raise SystemExit("HOLD: hash mismatch")
    namespace = {}
    with open(path, encoding="utf-8") as handle:
        exec(compile(handle.read(), path, "exec"), namespace)
    return namespace["signal"]


def problems_in_signal_rows(rows):
    if not rows:
        return ["no rows"]
    for row in rows:
        for key in ("datetime", "high", "low", "close", "entry_transition", "exit_transition"):
            if key not in row:
                return ["missing " + key]
    return []
"""

ARTIFACT = """
def signal(*, high, low, close, volume, times, params, window_start, window_end):
    length = params.get("entry_len")
    if not isinstance(length, int) or length <= 0:
        raise ValueError("entry_len must be a positive integer")
    rows, entry_ts, state = [], None, False
    for i in range(len(close)):
        prior = max(high[i - length:i]) if i >= length else None
        inside = window_start <= times[i] <= window_end
        up = prior is not None and close[i] > prior
        entry = False
        if not state and inside and up:
            state, entry, entry_ts = True, True, times[i]
        rows.append({"datetime": times[i], "high": float(high[i]), "low": float(low[i]),
                     "close": float(close[i]), "entry_transition": int(entry), "exit_transition": 0})
    return rows, entry_ts
"""

EMPTY_ARTIFACT = """
def signal(*, high, low, close, volume, times, params, window_start, window_end):
    return [], None
"""

#: Test double for ``qlib.backtest.research_cell``. The transport may spawn only
#: ``-m qlib.backtest.research_cell materialize --spec ... --root ...``, so this
#: module implements exactly that command over an isolated fixture tree. It is a
#: fixture, never production code: the real materializer lives in the pinned Qlib
#: runtime image.
STUB_MATERIALIZER = '''\
"""Fixture double for qlib.backtest.research_cell materialize."""
import hashlib, json, sys
from pathlib import Path

HERE = Path(__file__).resolve()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main(argv):
    spec_path = root = None
    args = list(argv)
    while args:
        arg = args.pop(0)
        if arg == "materialize":
            continue
        if arg == "--spec":
            spec_path = args.pop(0)
        elif arg == "--root":
            root = args.pop(0)
        else:
            raise SystemExit("HOLD: unexpected argv " + arg)
    if not spec_path or not root:
        raise SystemExit("HOLD: materialize needs --spec and --root")
    spec = json.loads(Path(spec_path).read_text())
    entry_bytes = (HERE.parents[2] / "cell_entrypoint.py").read_bytes()
    artifact_bytes = Path(spec["strategy_artifact"]["source"]).read_bytes()
    cells = []
    for symbol, timeframe in (("BTCUSDT", "1h"), ("ETHUSDT", "1h")):
        cell_id = "%s-%s-x3" % (symbol, timeframe)
        cell_dir = Path(root) / cell_id
        cell_dir.mkdir(parents=True, exist_ok=True)
        (cell_dir / "run_cell.entrypoint.py").write_bytes(entry_bytes)
        (cell_dir / "strategy_signal.py").write_bytes(artifact_bytes)
        config = {
            "schema": "qlib-formal-research-cell-v1",
            "candidate": dict(spec["candidate"]),
            "runtime": dict(spec["runtime"]),
            "data": dict(spec["data"]),
            "execution": {"entrypoint": str(cell_dir / "run_cell.entrypoint.py")},
            "research_leverage": 3,
            "strategy": dict(spec["strategy"], symbol=symbol, timeframe=timeframe,
                             artifact={"ref": str(cell_dir / "strategy_signal.py"),
                                       "sha256": sha(artifact_bytes)}),
            "capabilities": {"execution": ["qlib-native-backtest"],
                             "data": ["binance-usdm-ohlcv"], "timing": ["bar-close"],
                             "sides": list(spec["strategy"]["sides"])},
            "house_overlay": dict(spec["house_overlay"]),
            "research_cost_model": dict(spec["research_cost_model"]),
        }
        config_path = cell_dir / "effective_config.json"
        config_path.write_text(json.dumps(config, indent=2, sort_keys=True) + "\\n")
        cells.append({
            "cell_id": cell_id, "symbol": symbol, "timeframe": timeframe,
            "research_leverage": 3,
            "source_commit": spec["candidate"]["source_commit"],
            "candidate_path": spec["candidate"]["path"],
            "source_blob_sha": spec["candidate"]["git_blob_sha"],
            "entrypoint_ref": config["execution"]["entrypoint"],
            "entrypoint_sha256": sha(entry_bytes),
            "strategy_artifact_ref": config["strategy"]["artifact"]["ref"],
            "strategy_artifact_sha256": sha(artifact_bytes),
            "effective_config_ref": str(config_path),
            "effective_config_sha256": sha(config_path.read_bytes()),
            "qlib_runtime_commit": spec["runtime"]["commit"],
            "capabilities": dict(config["capabilities"]),
            "evidence_refs": {},
            "run_inputs": {"symbol": symbol, "timeframe": timeframe,
                           "research_leverage": 3},
            "research_cost_model": dict(spec["research_cost_model"]),
        })
    manifest = {"schema": "qlib-formal-campaign-manifest-v1",
                "generated_from": str(Path(spec_path).resolve()),
                "cell_count": len(cells), "cells": cells}
    (Path(root) / "campaign-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\\n")
    print(json.dumps({"materialized": len(cells)}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
'''

#: Fixture entrypoint for one materialized cell. It writes the same native
#: evidence contract the real cell writes, so submit/readback run for real.
STUB_CELL_ENTRY = '''\
"""Fixture double for one frozen cell entrypoint."""
import hashlib, json, os
from pathlib import Path

out = Path(os.environ["QLIB_OUT_DIR"])
if out.exists():
    raise SystemExit("refuse overwrite")
(out / "mlruns" / "123456" / ("ab" * 16)).mkdir(parents=True)
(out / "summary.json").write_text(json.dumps({
    "cycles_replayed": 1,
    "evaluation_window_start_utc": "2025-01-02T00:00:00",
    "evaluation_window_end_utc": "2025-12-30T00:00:00",
    "strategy_params": {"entry_len": 5},
    "applied_economics": {"slippage_applied": False, "funding_applied": False,
                          "funding_reconciled": False,
                          "declared_model_matches_applied": False,
                          "declared_model_match_reason": "research cost model is not approved"},
    "economics_boundary": {"performance_claimable": False, "cost_model_approved": False},
    "mlflow_metrics_omitted": []}))
(out / "metrics.json").write_text(json.dumps({
    "total_trades": 1, "net_return_pct": 1.0, "cagr_pct": None, "sharpe": None,
    "max_drawdown_pct": 0.0, "win_rate_pct": 100.0, "profit_factor": None,
    "net_profit_usdt": 10.0, "evaluation_bars": 2}))
(out / "signals.csv").write_text("datetime,close\\n1,2\\n")
(out / "events.csv").write_text(
    "cycle,stage,stage_price,stage_quote_amount,filled_quote\\n1,entry,2.0,100.0,100.0\\n")
readback = {"tracking_uri": "file://x", "experiment_id": "123456", "run_id": "ab" * 16,
            "status": "FINISHED",
            "params": {"qlib_version": "t", "symbol": "BTCUSDT", "frequency": "60min",
                       "research_leverage": "3"},
            "metrics": {"m": 1.0}, "artifact_names": ["summary.json"]}
(out / "mlflow_readback.json").write_text(json.dumps(readback, sort_keys=True))
manifest = {}
for path in sorted(out.rglob("*")):
    if path.is_file() and "mlruns" not in path.parts and path.name != "manifest.json":
        manifest[str(path.relative_to(out))] = {
            "bytes": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
(out / "manifest.json").write_text(json.dumps(manifest, sort_keys=True))
print(json.dumps({"summary": {}, "mlflow": readback, "manifest": manifest}))
'''

#: The frozen f923 evidence contract: one integer count in summary.json, one
#: integer count in metrics.json, and one events row per replayed stage.
EVENT_HEADER = "cycle,stage,stage_price,stage_quote_amount,filled_quote"
EVENT_ROW = "1,entry,2.0,100.0,100.0"

STUB_ENTRYPOINT = """\
import hashlib, json, os, sys
from pathlib import Path
out = Path(os.environ["QLIB_OUT_DIR"])
if out.exists():
    sys.exit("refuse overwrite")
(out / "mlruns" / EXP / RUN).mkdir(parents=True)
summary = {"cycles_replayed": __CYCLES__,
           "evaluation_window_start_utc": "2025-01-02T00:00:00",
           "evaluation_window_end_utc": "2025-12-30T00:00:00",
           "strategy_params": {"entry_len": 5},
           "applied_economics": {"applied": "frozen primitive", "slippage_applied": False,
                                 "funding_applied": False, "funding_reconciled": False,
                                 "declared_model_matches_applied": False,
                                 "declared_model_match_reason": "research cost model is not approved",
                                 "funding_total_payment_quote": 0.0, "funding_charged_event_count": 0,
                                 "funding_basis": None, "funding_source_ref": None,
                                 "funding_source_sha256": None},
           "economics_boundary": {"performance_claimable": False, "cost_model_approved": False},
           "mlflow_metrics_omitted": ["cagr_pct", "sharpe"]}
(out / "summary.json").write_text(json.dumps(summary))
(out / "metrics.json").write_text(json.dumps({"total_trades": __TRADES__, "net_return_pct": 1.5,
    "cagr_pct": None, "sharpe": None, "max_drawdown_pct": 0.0, "win_rate_pct": 100.0,
    "profit_factor": None, "net_profit_usdt": 10.0, "evaluation_bars": 2}))
(out / "signals.csv").write_text("datetime,close\\n1,2\\n")
(out / "events.csv").write_text(__EVENTS__)
readback = {"tracking_uri": "file://x", "experiment_id": EXP, "run_id": RUN,
            "status": "FINISHED", "params": {"qlib_version": "t", "symbol": "BTCUSDT", "frequency": "60min", "research_leverage": "3"},
            "metrics": {"m": 1.0}, "artifact_names": ["summary.json", "metrics.json", "signals.csv", "events.csv"]}
(out / "mlflow_readback.json").write_text(json.dumps(readback, sort_keys=True))
manifest = {}
for p in sorted(out.rglob("*")):
    if p.is_file() and "mlruns" not in p.parts and p.name != "manifest.json":
        manifest[str(p.relative_to(out))] = {"bytes": p.stat().st_size,
            "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
(out / "manifest.json").write_text(json.dumps(manifest, sort_keys=True))
print(json.dumps({"summary": {"ok": True}, "mlflow": readback, "manifest": manifest}))
"""


def stub_source(cycles=1, trades=1, events=None):
    """Build one native stub that writes the frozen f923 execution evidence."""
    if events is None:
        events = EVENT_HEADER + "\n" + EVENT_ROW + "\n"
    return (STUB_ENTRYPOINT
            .replace("__CYCLES__", repr(cycles))
            .replace("__TRADES__", repr(trades))
            .replace("__EVENTS__", repr(events)))


def run(cmd, *args, root=None, py_path=None):
    env = dict(os.environ)
    if root is not None:
        env["RESEARCH_RESULTS_ROOT"] = str(root)
    if py_path is not None:
        prefix = str(py_path)
        env["PYTHONPATH"] = prefix + ((os.pathsep + env["PYTHONPATH"]) if env.get("PYTHONPATH") else "")
    proc = subprocess.run(
        [sys.executable, str(TRANSPORT), cmd, *args],
        env=env, capture_output=True, text=True, timeout=120,
    )
    return proc.returncode, proc.stdout.strip()


def b64(obj):
    return base64.b64encode(json.dumps(obj).encode()).decode()


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


#: The immutable candidate body the engineering fixtures pin. The transport
#: recomputes its Git object id, so the fixture must carry the real bytes.
SOURCE_TEXT = "# demo candidate\n\nEntry: close crosses SMA(5) up.\n"
SOURCE_BYTES = SOURCE_TEXT.encode("utf-8")


def git_blob_sha1(raw):
    """Canonical Git object id of one blob, computed from its exact bytes."""
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


SOURCE_BLOB = git_blob_sha1(SOURCE_BYTES)


def make_handoff(root, entry, config, blob="a" * 40, caps=None, cost=True):
    handoff = {
        "source_commit": "b" * 40,
        "candidate_path": "demo-candidate.md",
        "source_blob_sha": blob,
        "entrypoint_ref": str(entry),
        "entrypoint_sha256": sha(entry),
        "effective_config_ref": str(config),
        "effective_config_sha256": sha(config),
        "qlib_runtime_commit": "c" * 40,
        "evidence_refs": {"mlflow_readback": "x", "manifest": "y"},
    }
    handoff["capabilities"] = caps or {
        "execution": ["qlib-native-backtest"],
        "data": ["binance-usdm-ohlcv"],
        "timing": ["bar-close"],
    }
    if cost:
        handoff["run_inputs"] = {"symbol": "BTCUSDT"}
    return handoff


def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name + (" " + str(extra) if extra and not cond else ""))
    CHECKS.append(name)
    if not cond:
        raise SystemExit("FAILED: " + name + " " + str(extra))


def write_stub_files(root, blob="a" * 40, cycles=1, trades=1, events=None):
    """Write one frozen stub pair whose formal fields match make_handoff."""
    entry = root / "run_stub.entrypoint.py"
    config = root / "effective_config.json"
    config.write_text(json.dumps({
        "candidate": {"path": "demo-candidate.md", "git_blob_sha": blob},
        "execution": {"entrypoint": str(entry)},
        "runtime": {"commit": "c" * 40},
        "strategy": {"window_start_utc": "2025-01-01 00:00:00",
                     "window_end_utc_inclusive": "2025-12-31 00:00:00",
                     "params": {"entry_len": 5}},
    }, sort_keys=True))
    entry.write_text(
        stub_source(cycles, trades, events).replace("EXP", '"%s"' % EXP_ID)
        .replace("RUN", '"%s"' % RUN_ID)
    )
    return entry, config


def fresh_run(**stub):
    """Submit one stub run in a fresh root and return (root, out_dir)."""
    root = Path(tempfile.mkdtemp(prefix="transport-evidence-"))
    entry, config = write_stub_files(root, **stub)
    rc, out = run("research-submit", b64(make_handoff(root, entry, config)), root=root)
    if rc != 0:
        raise SystemExit("FAILED: golden setup for a fresh run " + out)
    return root, Path(json.loads(out)["out_dir"])


def run_forced(forced_command, root):
    """Run the transport with no argv, like the fixed forced-command launch."""
    env = dict(os.environ, RESEARCH_RESULTS_ROOT=str(root),
               SSH_ORIGINAL_COMMAND=forced_command)
    proc = subprocess.run([sys.executable, str(TRANSPORT)], env=env,
                          capture_output=True, text=True, timeout=120)
    return proc.returncode, proc.stdout.strip()


FAKE_KANBAN_CLI = '''#!__PYTHON__
"""Test-only stand-in for `hermes kanban create|show`. No board, no network."""

import hashlib
import json
import os
import sys

STORE = os.environ["FAKE_KANBAN_STORE"]


def load():
    if not os.path.exists(STORE):
        return {"tasks": {}, "runs": {}, "calls": [], "idem": {}}
    with open(STORE, encoding="utf-8") as handle:
        return json.load(handle)


def save(store):
    with open(STORE, "w", encoding="utf-8") as handle:
        json.dump(store, handle, indent=2, sort_keys=True)


def parse_flags(args):
    flags, index = {}, 1
    while index < len(args):
        key = args[index]
        if key == "--json":
            index += 1
            continue
        value = args[index + 1] if index + 1 < len(args) else None
        if key == "--body-file":
            flags["body"] = sys.stdin.read() if value == "-" else ""
        else:
            flags[key.lstrip("-").replace("-", "_")] = value
        index += 2
    return flags


def main(argv):
    if argv[:1] != ["kanban"]:
        print("fake: expected the kanban group", file=sys.stderr)
        return 2
    store = load()
    store["calls"].append(list(argv))
    rest = argv[1:]
    board = None
    if rest[:1] == ["--board"]:
        board, rest = rest[1], rest[2:]
    verb, args = rest[0], rest[1:]
    if verb == "create":
        flags = parse_flags(args)
        key = flags.get("idempotency_key")
        task_id = store["idem"].get(key)
        if task_id is None or store["tasks"].get(task_id, {}).get("status") == "archived":
            digest = hashlib.sha256((key or args[0]).encode("utf-8")).hexdigest()[:8]
            task_id = "t_" + digest
            workspace = flags.get("workspace") or ""
            store["tasks"][task_id] = {
                "id": task_id,
                "title": args[0],
                "body": flags.get("body"),
                "assignee": flags.get("assignee"),
                "status": "ready",
                "workspace_kind": workspace.split(":", 1)[0],
                "workspace_path": workspace.split(":", 1)[-1],
                "created_by": flags.get("created_by"),
                "max_runtime_seconds": int(flags.get("max_runtime") or 0),
                "model_override": None,
                "provider_override": None,
                "completion_contract": flags.get("completion_contract"),
                "last_failure_error": None,
                "board": board,
            }
            store["runs"][task_id] = []
            if key:
                store["idem"][key] = task_id
        task = store["tasks"][task_id]
        save(store)
        print(json.dumps(task))
        return 0
    if verb == "show":
        task_id = args[0]
        task = store["tasks"].get(task_id)
        if task is None:
            print("kanban: unknown task " + task_id, file=sys.stderr)
            return 1
        save(store)
        print(json.dumps({"task": task, "runs": store["runs"].get(task_id, [])}))
        return 0
    print("kanban: unsupported verb " + verb, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
'''


def main():
    tmp = Path(tempfile.mkdtemp(prefix="transport-test-"))
    entry, config = write_stub_files(tmp)

    rc, out = run("research-submit", "!!!not-base64!!!", root=tmp)
    check("T1 malformed base64 fails closed", rc == 2 and '"ok": false' in out, out)

    bad = make_handoff(tmp, entry, config)
    bad["evil"] = 1
    rc, out = run("research-submit", b64(bad), root=tmp)
    check("T2a unknown field fails closed", rc == 2, out)

    bad = make_handoff(tmp, entry, config)
    bad["entrypoint_ref"] = "/tmp/../evil.py"
    rc, out = run("research-submit", b64(bad), root=tmp)
    check("T2b parent-hop path fails closed", rc == 2, out)

    bad = make_handoff(tmp, entry, config)
    bad["entrypoint_sha256"] = "zz"
    rc, out = run("research-submit", b64(bad), root=tmp)
    check("T2c bad hash shape fails closed", rc == 2, out)

    bad = make_handoff(tmp, entry, config,
                        caps={"execution": ["future-engine"], "data": ["binance-usdm-ohlcv"],
                              "timing": ["bar-close"]})
    rc, out = run("research-submit", b64(bad), root=tmp)
    check("T3 unknown capability holds without executing",
          rc == 2 and "ENGINEERING_HOLD" in out and not list(tmp.glob("n8n-live-*")), out)

    for label, caps in (
        ("unknown data primitive", {"execution": ["qlib-native-backtest"],
                                    "data": ["coinbase-spot-1m"], "timing": ["bar-close"]}),
        ("unknown timing primitive", {"execution": ["qlib-native-backtest"],
                                     "data": ["binance-usdm-ohlcv"], "timing": ["bar-close-1m"]}),
        ("the retired per-cell data name", {"execution": ["qlib-native-backtest"],
                                            "data": ["btcusdt-1h"], "timing": ["bar-close"]}),
        ("the retired per-cell timing name", {"execution": ["qlib-native-backtest"],
                                              "data": ["binance-usdm-ohlcv"], "timing": ["bar-close-1h"]}),
        ("a per-cell identity name", {"execution": ["qlib-native-backtest"],
                                      "data": ["dogeusdt-1d"], "timing": ["bar-close"]}),
    ):
        bad = make_handoff(tmp, entry, config, caps=caps)
        rc, out = run("research-submit", b64(bad), root=tmp)
        check("T3b " + label + " fails closed",
              rc == 2 and "ENGINEERING_HOLD" in out and not list(tmp.glob("n8n-live-*")), out)

    # The gate is one reusable primitive for every covered cell, so a non-BTC/1h
    # cell must reach the native submit path without a new declaration.
    doge = Path(tempfile.mkdtemp(prefix="transport-doge-"))
    dentry, dconfig = write_stub_files(doge, blob="d" * 40)
    handoff = make_handoff(doge, dentry, dconfig, blob="d" * 40)
    handoff["run_inputs"] = {"symbol": "DOGEUSDT", "timeframe": "1d", "research_leverage": 5}
    rc, out = run("research-submit", b64(handoff), root=doge)
    receipt = json.loads(out) if rc == 0 else {}
    check("T3c a non-BTC/1h cell passes the reusable capability gate",
          rc == 0 and receipt.get("node04") == "PASS", out)

    bad = make_handoff(tmp, entry, config)
    bad["entrypoint_sha256"] = "0" * 64
    rc, out = run("research-submit", b64(bad), root=tmp)
    check("T4 hash mismatch fails before executing",
          rc == 2 and "mismatch" in out and not list(tmp.glob("n8n-live-*")), out)

    good = make_handoff(tmp, entry, config)
    rc, out = run("research-submit", b64(good), root=tmp)
    receipt = json.loads(out) if rc == 0 else {}
    check("T5 golden submit prints Node04 receipt",
          rc == 0 and receipt.get("node04") == "PASS" and receipt.get("run_id") == RUN_ID
          and receipt.get("entrypoint_sha256") == sha(entry)
          and receipt.get("experiment_id") == EXP_ID, out)
    out_dir = Path(receipt["out_dir"])
    check("T5 submit receipt persisted", (out_dir / "submit-receipt.json").is_file())
    check("T5 native run dir exists", (out_dir / "mlruns" / EXP_ID / RUN_ID).is_dir())
    rc, out = run("research-submit", b64(good), root=tmp)
    check("T5 re-submit refuses overwrite", rc == 2 and "refuse overwrite" in out, out)

    rc, out = run("research-readback", RUN_ID, root=tmp)
    back = json.loads(out) if rc == 0 else {}
    check("T6 golden readback prints Node05 receipt",
          rc == 0 and back.get("node05") == "PASS" and back.get("run_id") == RUN_ID
          and back.get("out_dir") == str(out_dir)
          and back.get("performance_claimable") is False
          and back.get("manifest_readback_run_id") == RUN_ID
          and len(back.get("manifest_sha256", "")) == 64, out)
    check("T6 readback refs are bound to the run",
          back["refs"]["mlflow_run"].endswith("mlruns/%s/%s" % (EXP_ID, RUN_ID))
          and back["refs"]["candidate"].endswith("/git/blobs/" + "a" * 40)
          and Path(back["refs"]["effective_config"]).is_file()
          and Path(back["refs"]["entrypoint"]).is_file(), out)

    check("T6 readback returns the native identity and verified config hash",
          back.get("native_identity") == {
              "symbol": "BTCUSDT", "frequency": "60min", "research_leverage": 3,
          } and back.get("effective_config_sha256") == good["effective_config_sha256"], out)

    readback_path = out_dir / "mlflow_readback.json"
    manifest_path = out_dir / "manifest.json"
    original_readback = readback_path.read_bytes()
    original_manifest = manifest_path.read_bytes()
    native_readback = json.loads(original_readback)

    def write_params(params):
        changed = dict(native_readback, params=params)
        raw = json.dumps(changed, sort_keys=True).encode()
        readback_path.write_bytes(raw)
        manifest = json.loads(original_manifest)
        manifest["mlflow_readback.json"] = {
            "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
        }
        manifest_path.write_text(json.dumps(manifest, sort_keys=True))

    for leverage in ("3", "5", 3, 5, 3.0, 5.0):
        write_params(dict(native_readback["params"], research_leverage=leverage))
        rc, out = run("research-readback", RUN_ID, root=tmp)
        identity = json.loads(out).get("native_identity", {})
        check("T6 native leverage is an exact integer: " + repr(leverage),
              rc == 0 and type(identity.get("research_leverage")) is int
              and identity["research_leverage"] == int(leverage), out)
    for key in ("symbol", "frequency", "research_leverage"):
        missing = dict(native_readback["params"])
        del missing[key]
        write_params(missing)
        rc, out = run("research-readback", RUN_ID, root=tmp)
        check("T6 missing native " + key + " fails closed",
              rc == 2 and "native identity" in out and key in out, out)
    for key in ("symbol", "frequency"):
        for value in (None, "", " \t", 3, [], {}):
            params = dict(native_readback["params"])
            params[key] = value
            write_params(params)
            rc, out = run("research-readback", RUN_ID, root=tmp)
            check("T6 invalid native " + key + ": " + repr(value),
                  rc == 2 and "native identity" in out and key in out, out)
    for leverage in (None, "", "3x", "3.5", 3.5, 0, 4, 6, True, False, [], {}, "03"):
        write_params(dict(native_readback["params"], research_leverage=leverage))
        rc, out = run("research-readback", RUN_ID, root=tmp)
        check("T6 invalid native leverage: " + repr(leverage),
              rc == 2 and "native identity" in out and "research_leverage" in out, out)
    for params in (None, [], ["symbol"], "params", 1, True):
        write_params(params)
        rc, out = run("research-readback", RUN_ID, root=tmp)
        check("T6 native params must be an object: " + repr(params),
              rc == 2 and "native identity params" in out, out)
    readback_path.write_bytes(original_readback)
    manifest_path.write_bytes(original_manifest)

    original_config = config.read_bytes()
    config.write_bytes(original_config + b" ")
    rc, out = run("research-readback", RUN_ID, root=tmp)
    check("T6 changed config bytes fail closed",
          rc == 2 and "submit/executable identity mismatch" in out, out)
    config.write_bytes(original_config)
    submit_path = out_dir / "submit-receipt.json"
    original_submit = submit_path.read_bytes()
    submit = json.loads(original_submit)
    submit["effective_config_sha256"] = "0" * 64
    submit_path.write_text(json.dumps(submit))
    rc, out = run("research-readback", RUN_ID, root=tmp)
    check("T6 config hash must match the submit receipt",
          rc == 2 and "submit/executable identity mismatch" in out, out)
    submit_path.write_bytes(original_submit)

    rc, out = run("research-readback", "zz", root=tmp)
    check("T7a malformed run_id fails closed", rc == 2, out)
    rc, out = run("research-readback", "00" * 16, root=tmp)
    check("T7b unknown run_id fails closed", rc == 2, out)

    tampered = {"run_id": RUN_ID, "status": "FINISHED", "experiment_id": EXP_ID,
                "params": {"a": "b"}, "metrics": {"m": 2.0}, "artifact_names": ["x"]}
    (out_dir / "mlflow_readback.json").write_text(json.dumps(tampered))
    rc, out = run("research-readback", RUN_ID, root=tmp)
    check("T8 tampered readback fails closed", rc == 2 and "mismatch" in out, out)

    neg = Path(tempfile.mkdtemp(prefix="transport-neg-"))
    entry2, config2 = write_stub_files(neg)
    lying = json.loads(config2.read_text())
    lying["candidate"] = {"path": "different-candidate.md", "git_blob_sha": "d" * 40}
    lying["runtime"] = {"commit": "d" * 40}
    config2.write_text(json.dumps(lying))
    rc, out = run("research-submit", b64(make_handoff(neg, entry2, config2)), root=neg)
    check("T9 wrong-candidate config fails before executing",
          rc == 2 and "identity mismatch" in out and not list(neg.glob("n8n-live-*")), out)

    g2 = Path(tempfile.mkdtemp(prefix="transport-neg-"))
    e2, c2 = write_stub_files(g2)
    rc, out = run("research-submit", b64(make_handoff(g2, e2, c2)), root=g2)
    if rc != 0:
        raise SystemExit("FAILED: golden setup for T10 " + out)
    o2 = Path(json.loads(out)["out_dir"])
    (o2 / "events.csv").unlink()
    rc, out = run("research-readback", RUN_ID, root=g2)
    check("T10 missing manifested evidence fails closed",
          rc == 2 and "missing" in out, out)

    xroot = Path(tempfile.mkdtemp(prefix="transport-neg-"))
    xentry, xconfig = write_stub_files(xroot)
    xentry.write_text(xentry.read_text().replace(
        'print(json.dumps({"summary": {"ok": True}, "mlflow": readback, "manifest": manifest}))',
        'printed = dict(readback)\nprinted["experiment_id"] = "987654"\n'
        'print(json.dumps({"summary": {"ok": True}, "mlflow": printed, "manifest": manifest}))'))
    rc, out = run("research-submit", b64(make_handoff(xroot, xentry, xconfig)), root=xroot)
    check("T11 stdout/disk experiment split fails closed",
          rc == 2 and "experiment identity mismatch" in out
          and not list(xroot.glob("n8n-live-*/submit-receipt.json")), out)

    g3 = Path(tempfile.mkdtemp(prefix="transport-neg-"))
    e3, c3 = write_stub_files(g3)
    rc, out = run("research-submit", b64(make_handoff(g3, e3, c3)), root=g3)
    if rc != 0:
        raise SystemExit("FAILED: golden setup for T12 " + out)
    rc, out = run_forced("cd / ; research-readback " + RUN_ID, g3)
    back = json.loads(out) if rc == 0 else {}
    check("T12a forced-command shape dispatches without argv",
          rc == 0 and back.get("node05") == "PASS", out)
    rc, out = run_forced("research-readback " + RUN_ID + "; touch evil", g3)
    check("T12b forced-command shell chaining fails closed", rc == 2, out)
    rc, out = run_forced("research-readback", g3)
    check("T12c forced-command bare verb fails closed", rc == 2, out)

    import importlib.util as _ilu
    _spec = _ilu.spec_from_file_location("transport_fwd", TRANSPORT)
    assert _spec is not None and _spec.loader is not None
    _t = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_t)
    bad = _t.build_forward_command("evil", RUN_ID)
    check("T13a forward rejects unknown verb", bad is None)
    bad = _t.build_forward_command("research-readback", "zz")
    check("T13b forward rejects bad run id", bad is None)
    good = _t.build_forward_command("research-readback", RUN_ID)
    check("T13c forward uses fixed image and python",
          good is not None and _t.FIXED_IMAGE in good
          and _t.FIXED_GUEST_PYTHON in good and good[-2:] == ["research-readback", RUN_ID]
          and not any(";" in a or "|" in a or "$" in a for a in good), str(good))
    check("T13d forced verbs are research-only plus the one bounded materializer",
          set(_t.FORCED_VERBS) == {"research-submit", "research-readback", "research-materialize"},
          str(_t.FORCED_VERBS))
    check("T13e the runtime pin is the exact f923 build",
          _t.FIXED_IMAGE == "qlib:main-f92320c1-arm64"
          and _t.FIXED_RUNTIME_COMMIT == "f92320c176521b269f5dee361a2172b8e6cde25c"
          and _t.FIXED_IMAGE_DIGEST ==
          "sha256:6081534f5b223c7ee53b28a05670b3351cfe0878cc0c05cf81790bf86d48efc8",
          "%s %s %s" % (_t.FIXED_IMAGE, _t.FIXED_RUNTIME_COMMIT, _t.FIXED_IMAGE_DIGEST))
    forward_payload = base64.b64encode(b'{"x": 1}').decode()
    submit_cmd = _t.build_forward_command("research-submit", forward_payload)
    check("T13f a forwarded submit pins the new image with no shell expansion",
          submit_cmd is not None and _t.FIXED_IMAGE in submit_cmd
          and submit_cmd[-2:] == ["research-submit", forward_payload]
          and "target=/results" in " ".join(submit_cmd)
          and not any(";" in a or "|" in a or "$" in a or "`" in a for a in submit_cmd),
          str(submit_cmd))

    from unittest.mock import patch

    task = "Read the IS evidence. Return one research result.\n$(not-a-command); 'quoted'"
    encoded = base64.b64encode(task.encode()).decode()
    command = "cd / ; research-hermes " + encoded
    check("T14a Hermes key accepts its fixed verb",
          _t.parse_forced_command(command, hermes=True) == ((_t.HERMES_VERB, encoded), None))
    check("T14b Qlib key does not accept the Hermes verb",
          _t.parse_forced_command(command)[0] is None)
    for text in ("research-submit " + encoded, "research-readback " + RUN_ID,
                 command + "; true", command + " extra", "hermes chat", "cd ~ ; " + command,
                 "research-hermes " + "A" * (_t.HERMES_PAYLOAD_LIMIT + 1)):
        check("T14c Hermes key rejects other input", _t.parse_forced_command(text, hermes=True)[0] is None)
    with patch.object(_t, "should_forward_host", side_effect=AssertionError("host only")), \
         patch.object(_t.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")) as child, \
         patch.dict(os.environ, {"SSH_ORIGINAL_COMMAND": command}):
        check("T14d Hermes forced mode completes", _t.main(["hermes-forced"]) == 0)
        child.assert_called_once_with(
            ["hermes", "chat", "--query-file", "-", "--oneshot", "-Q",
             "--format", "stream-json", "-t", "wiki_brain"],
            input=task, cwd="/", capture_output=True, text=True, timeout=_t.SUBMIT_TIMEOUT)
        check("T14e fixed argv and stdin match", True)
    with patch.object(_t.subprocess, "run") as child:
        for payload in ("!!!!", "/w==", "IA==", "A"):
            check("T14f invalid task does not start Hermes", _t.cmd_hermes(payload) == 2)
        check("T14g invalid tasks start no child", child.call_count == 0)
    for code in (0, 1):
        with patch.object(_t.subprocess, "run", return_value=subprocess.CompletedProcess([], code, "", "")):
            check("T14h child exit status is kept", _t.cmd_hermes(encoded) == code)
    with patch.object(_t.subprocess, "run", side_effect=subprocess.TimeoutExpired("hermes", 1800)):
        check("T14i timeout fails closed", _t.cmd_hermes(encoded) == 2)
    check("T14j Hermes verb is never forwarded", _t.build_forward_command(_t.HERMES_VERB, encoded) is None)

    # T15 frozen-cell resolve: verify one existing engineering cell and print
    # its handoff. The transport must never generate, write or import anything.
    overlay = {
        "base_order_quote_pct": 0.06, "safety_order_quote_pct": 0.06,
        "safety_order_levels": 2, "so_spacing_pct": 0.04,
        "take_profit_pct": 0.05, "stop_loss_pct": None,
        "trade_cost": 0.0004, "initial_capital_quote": 100000.0,
    }
    cost_model = {"fees_per_side": 0.0004, "slippage": 0.0, "funding": "not_modeled", "approved": False}
    identity = {
        "strategy": {"symbol": "BTCUSDT", "timeframe": "1h", "sides": ["long"],
                     "params": {"entry_len": 5}, "warmup_days": 5,
                     "window_start_utc": "2025-01-01 00:00:00",
                     "window_end_utc_inclusive": "2025-12-31 00:00:00"},
        "research_leverage": 3,
        "runtime": {"commit": "c" * 40},
        "data": {"provider_ref": "/results/_validation/provider"},
        "house_overlay": overlay,
        "research_cost_model": cost_model,
    }

    def frozen_root(marker=None):
        """Write one frozen cell plus manifest, the way Qlib materialize() does."""
        root = Path(tempfile.mkdtemp(prefix="transport-evidence-"))
        cell_dir = root / "btcusdt-1h-3x"
        cell_dir.mkdir()
        entry = cell_dir / "run_cell.entrypoint.py"
        entry.write_text("#!/usr/bin/env python3\n# frozen engine copy\n")
        artifact = cell_dir / "strategy_signal.py"
        body = "def signal(**kwargs):\n    return [], None\n"
        if marker is not None:
            body = "from pathlib import Path\nPath(%r).write_text('imported')\n\n" % str(marker) + body
        artifact.write_text(body)
        config = {
            "schema": "qlib-formal-research-cell-v1",
            "candidate": {"path": "demo-candidate.md", "source_commit": "b" * 40,
                          "git_blob_sha": "a" * 40},
            "runtime": {"commit": "c" * 40},
            "data": {"provider_ref": "/results/_validation/provider"},
            "execution": {"entrypoint": str(entry)},
            "research_leverage": 3,
            "strategy": {"symbol": "BTCUSDT", "timeframe": "1h", "sides": ["long"],
                         "params": {"entry_len": 5}, "warmup_days": 5,
                         "window_start_utc": "2025-01-01 00:00:00",
                         "window_end_utc_inclusive": "2025-12-31 00:00:00",
                         "artifact": {"ref": str(artifact), "sha256": sha(artifact)}},
            "capabilities": {"execution": ["qlib-native-backtest"], "data": ["binance-usdm-ohlcv"],
                             "timing": ["bar-close"], "sides": ["long"]},
            "house_overlay": dict(overlay),
            "research_cost_model": dict(cost_model),
        }
        config_path = cell_dir / "effective_config.json"
        config_path.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n")
        cell = {
            "cell_id": "btcusdt-1h-3x", "symbol": "BTCUSDT", "timeframe": "1h",
            "research_leverage": 3,
            "source_commit": "b" * 40, "candidate_path": "demo-candidate.md",
            "source_blob_sha": "a" * 40,
            "entrypoint_ref": str(entry), "entrypoint_sha256": sha(entry),
            "strategy_artifact_ref": str(artifact),
            "strategy_artifact_sha256": sha(artifact),
            "effective_config_ref": str(config_path),
            "effective_config_sha256": sha(config_path),
            "qlib_runtime_commit": "c" * 40,
            "capabilities": dict(config["capabilities"]),
            "evidence_refs": {"manifest": str(root / "campaign-manifest.json")},
            "research_cost_model": dict(cost_model),
        }
        (root / "campaign-manifest.json").write_text(json.dumps(
            {"schema": "qlib-formal-campaign-manifest-v1", "cell_count": 1, "cells": [cell]},
            indent=2, sort_keys=True) + "\n")
        return root

    def resolve_request(root, **over):
        request = {
            "request": "handoff-resolve-v1",
            "source_commit": "b" * 40,
            "candidate_path": "demo-candidate.md",
            "source_blob_sha": "a" * 40,
            "evidence_root": str(root),
            "identity": json.loads(json.dumps(identity)),
        }
        for key, value in over.items():
            if key in ("identity",):
                request["identity"].update(value)
            else:
                request[key] = value
        return request

    def handoff_call(forced_command):
        """Run one handoff command the way the restricted Hermes key does."""
        env = dict(os.environ, SSH_ORIGINAL_COMMAND=forced_command)
        proc = subprocess.run([sys.executable, str(TRANSPORT), "hermes-forced"], env=env,
                              capture_output=True, text=True, timeout=120)
        return proc.returncode, proc.stdout.strip()

    def handoff_resolve(request):
        return handoff_call("research-handoff " + b64(request))

    def snapshot(root):
        return sorted((str(p.relative_to(root)), p.stat().st_size, p.stat().st_mtime_ns)
                      for p in Path(root).rglob("*"))

    root = frozen_root()
    before = snapshot(root)
    rc, out = handoff_resolve(resolve_request(root))
    report = json.loads(out) if out.startswith("{") else {}
    check("T15a resolve returns the frozen handoff", rc == 0 and report.get("status") == "ready", out)
    check("T15b the handoff is built from the frozen evidence",
          report["handoff"]["effective_config_sha256"] == sha(root / "btcusdt-1h-3x/effective_config.json")
          and report["handoff"]["entrypoint_sha256"] == sha(root / "btcusdt-1h-3x/run_cell.entrypoint.py")
          and report["handoff"]["source_blob_sha"] == "a" * 40, out)
    check("T15c the handoff carries the frozen cost model and capability set",
          report["handoff"]["research_cost_model"]["approved"] is False
          and report["handoff"]["capabilities"]["sides"] == ["long"], out)
    check("T15d resolve writes nothing", snapshot(root) == before)

    marker = Path(tempfile.mkdtemp(prefix="transport-marker-")) / "marker.txt"
    root2 = frozen_root(marker=marker)
    rc, out = handoff_resolve(resolve_request(root2))
    check("T15e resolve reads the artifact but never imports it", rc == 0 and not marker.exists(), out)

    rc, out = handoff_resolve(resolve_request(root, identity={"house_overlay": dict(overlay, trade_cost=0.01234)}))
    check("T15f a changed trade_cost is an identity conflict, not a silent reuse",
          rc == 2 and "house_overlay.trade_cost" in out, out)
    rc, out = handoff_resolve(resolve_request(root, identity={"research_cost_model": dict(cost_model, approved=True)}))
    check("T15g a changed approved flag is an identity conflict",
          rc == 2 and "research_cost_model.approved" in out, out)
    rc, out = handoff_resolve(resolve_request(root, identity={"runtime": {"commit": "d" * 40}}))
    check("T15h a different runtime is a different identity", rc == 2 and "runtime.commit" in out, out)
    rc, out = handoff_resolve(resolve_request(root, evidence_root=str(Path(tempfile.mkdtemp(prefix="transport-empty-")))))
    check("T15i a missing evidence manifest fails closed", rc == 2, out)
    rc, out = handoff_resolve(resolve_request(root, candidate_path="other-candidate.md"))
    check("T15j an absent cell is implementation_needed, not a pass",
          rc == 0 and json.loads(out).get("status") == "implementation_needed", out)
    rc, out = handoff_resolve(resolve_request(root, candidate_path=""))
    check("T15k a bad candidate path fails closed", rc == 2, out)
    bad = resolve_request(root)
    bad["record_text"] = "anything"
    rc, out = handoff_resolve(bad)
    check("T15l there is no record_text path at all", rc == 2 and "unknown field" in out, out)

    # The frozen evidence is immutable: changing the bytes on disk is a mismatch
    # against the manifest digest, never a new self-signed hash.
    tampered = frozen_root()
    config_path = tampered / "btcusdt-1h-3x/effective_config.json"
    cfg = json.loads(config_path.read_text())
    cfg["candidate"].pop("source_commit")
    config_path.write_text(json.dumps(cfg, indent=2, sort_keys=True) + "\n")
    rc, out = handoff_resolve(resolve_request(tampered))
    check("T15m a rewritten config fails against the frozen manifest digest",
          rc == 2 and "frozen manifest digest" in out, out)
    tampered_artifact = frozen_root()
    (tampered_artifact / "btcusdt-1h-3x/strategy_signal.py").write_text("def signal(**kwargs):\n    return [{}], None\n")
    rc, out = handoff_resolve(resolve_request(tampered_artifact))
    check("T15n a rewritten artifact fails against the frozen manifest digest",
          rc == 2 and "frozen manifest digest" in out, out)

    # T16 verify: a handoff carried in the run input is re-derived from evidence.
    root = frozen_root()
    canonical = json.loads(handoff_resolve(resolve_request(root))[1])["handoff"]
    verify = {"request": "handoff-verify-v1", "source_commit": "b" * 40,
              "candidate_path": "demo-candidate.md", "source_blob_sha": "a" * 40,
              "handoff": dict(canonical, research_cost_model=dict(cost_model, approved=True))}
    rc, out = handoff_call("research-handoff " + b64(verify))
    report = json.loads(out) if out.startswith("{") else {}
    check("T16a a supplied handoff is rebuilt from the frozen evidence",
          rc == 0 and report["handoff"]["research_cost_model"]["approved"] is False, out)
    forged = dict(verify)
    forged["handoff"] = dict(canonical, entrypoint_sha256="e" * 64)
    rc, out = handoff_call("research-handoff " + b64(forged))
    check("T16b a forged entrypoint hash fails closed", rc == 2 and "entrypoint_sha256" in out, out)
    forged = dict(verify)
    forged["source_blob_sha"] = "f" * 40
    rc, out = handoff_call("research-handoff " + b64(forged))
    check("T16c a handoff for another pinned blob fails closed", rc == 2, out)
    forged = dict(verify)
    forged["handoff"] = dict(canonical, effective_config_ref="/nowhere/effective_config.json")
    rc, out = handoff_call("research-handoff " + b64(forged))
    check("T16d a handoff without frozen evidence fails closed", rc == 2, out)
    unknown = dict(verify)
    unknown["existing_handoff"] = canonical
    rc, out = handoff_call("research-handoff " + b64(unknown))
    check("T16e an unknown request field fails closed", rc == 2, out)

    # Freeze each declaration into a valid manifest. These checks must reject
    # inconsistent fields, not just a changed config digest.
    invalid = (
        ("two sides with long-only capabilities", "capabilities.sides",
         lambda cfg: cfg["strategy"].update(sides=["long", "short"])),
        ("missing strategy sides", "strategy.sides", lambda cfg: cfg["strategy"].pop("sides")),
        ("empty strategy sides", "strategy.sides", lambda cfg: cfg["strategy"].update(sides=[])),
        ("non-list strategy sides", "strategy.sides", lambda cfg: cfg["strategy"].update(sides="long")),
        ("non-string strategy side", "strategy.sides", lambda cfg: cfg["strategy"].update(sides=[1])),
        ("missing capability sides", "capabilities.sides", lambda cfg: cfg["capabilities"].pop("sides")),
        ("missing config capabilities", "capabilities.sides", lambda cfg: cfg.pop("capabilities")),
        ("non-list capability sides", "capabilities.sides", lambda cfg: cfg["capabilities"].update(sides="long")),
        ("non-string capability side", "capabilities.sides", lambda cfg: cfg["capabilities"].update(sides=[1])),
        ("missing artifact ref", "strategy.artifact.ref", lambda cfg: cfg["strategy"]["artifact"].pop("ref")),
        ("missing artifact file", "strategy.artifact.ref", lambda cfg: cfg["strategy"]["artifact"].update(
            ref=str(Path(cfg["strategy"]["artifact"]["ref"]).with_name("unchecked_signal.py")))),
        ("different artifact with identical bytes", "strategy.artifact.ref", lambda cfg: cfg["strategy"]["artifact"].update(
            ref=str(Path(cfg["strategy"]["artifact"]["ref"]).with_name("same_bytes.py")))),
        ("artifact ref outside the root", "strategy.artifact.ref", lambda cfg: cfg["strategy"]["artifact"].update(ref=__file__)),
        ("different artifact digest", "strategy.artifact.sha256", lambda cfg: cfg["strategy"]["artifact"].update(sha256="0" * 64)),
        ("missing artifact digest", "strategy.artifact.sha256", lambda cfg: cfg["strategy"]["artifact"].pop("sha256")),
    )
    for label, field, change in invalid:
        root = frozen_root()
        canonical = json.loads(handoff_resolve(resolve_request(root))[1])["handoff"]
        config_path = Path(canonical["effective_config_ref"])
        cfg = json.loads(config_path.read_text())
        artifact_path = Path(cfg["strategy"]["artifact"]["ref"])
        artifact_path.with_name("same_bytes.py").write_bytes(artifact_path.read_bytes())
        change(cfg)
        config_path.write_text(json.dumps(cfg, indent=2, sort_keys=True) + "\n")
        manifest_path = root / "campaign-manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["cells"][0]["effective_config_sha256"] = sha(config_path)
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        canonical["effective_config_sha256"] = sha(config_path)
        request = resolve_request(root)
        if label == "two sides with long-only capabilities":
            request["identity"]["strategy"]["sides"] = ["long", "short"]
        verify = {"request": "handoff-verify-v1", "source_commit": "b" * 40,
                  "candidate_path": "demo-candidate.md", "source_blob_sha": "a" * 40,
                  "handoff": canonical}
        for kind, payload in (("resolve", request), ("verify", verify)):
            rc, out = handoff_resolve(payload)
            check("T16f " + kind + " rejects " + label,
                  rc == 2 and field in out and json.loads(out).get("status") != "ready", out)

    # A genuine short requirement stays visible to the existing capability gate.
    # Order does not change which sides the strategy declares.
    root = frozen_root()
    config_path = root / "btcusdt-1h-3x/effective_config.json"
    cfg = json.loads(config_path.read_text())
    cfg["strategy"]["sides"] = ["long", "short"]
    cfg["capabilities"]["sides"] = ["short", "long"]
    ref = cfg["strategy"]["artifact"]["ref"]
    cfg["strategy"]["artifact"]["ref"] = str(Path(ref).parent) + "/./strategy_signal.py"
    config_path.write_text(json.dumps(cfg, indent=2, sort_keys=True) + "\n")
    manifest_path = root / "campaign-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["cells"][0]["effective_config_sha256"] = sha(config_path)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    request = resolve_request(root)
    request["identity"]["strategy"]["sides"] = ["long", "short"]
    rc, out = handoff_resolve(request)
    report = json.loads(out)
    check("T16g matching sides and a normalized artifact path keep the short capability gap",
          rc == 0 and _t.capability_gap(report.get("handoff", {})) == ["sides:short"], out)
    verify = {"request": "handoff-verify-v1", "source_commit": "b" * 40,
              "candidate_path": "demo-candidate.md", "source_blob_sha": "a" * 40,
              "handoff": report["handoff"]}
    verify["handoff"]["capabilities"] = dict(cfg["capabilities"], sides=["long"])
    rc, out = handoff_resolve(verify)
    report = json.loads(out)
    check("T16h verify derives sides from the frozen config, not the caller",
          rc == 0 and report["handoff"]["capabilities"]["sides"] == ["short", "long"]
          and _t.capability_gap(report["handoff"]) == ["sides:short"], out)

    # T17 verb surface: one fixed verb on the restricted Hermes key only.
    encoded = b64(resolve_request(frozen_root()))
    check("T17a the Qlib key does not accept the handoff verb",
          _t.parse_forced_command("research-handoff " + encoded)[0] is None)
    check("T17b the Hermes key accepts the handoff verb",
          _t.parse_forced_command("research-handoff " + encoded, hermes=True)
          == ((_t.HANDOFF_VERB, encoded), None))
    check("T17c the handoff verb is never forwarded to the fixed runtime",
          _t.build_forward_command(_t.HANDOFF_VERB, encoded) is None)
    check("T17d the Qlib verb set carries no Hermes verb",
          set(_t.FORCED_VERBS) == {"research-submit", "research-readback", "research-materialize"}
          and _t.HERMES_VERB not in _t.FORCED_VERBS, str(_t.FORCED_VERBS))
    # The read paths still import no strategy code and start no child process. The
    # materialize verb is the ONE bounded child allowed, and T22 proves its argv.
    check("T17e the verified read paths import no strategy code",
          not hasattr(_t, "artifact_source") and not hasattr(_t, "ARTIFACT_SMOKE")
          and "importlib" not in Path(_t.__file__).read_text())
    with patch.object(_t.subprocess, "run", side_effect=AssertionError("no child process allowed")):
        with contextlib.redirect_stdout(io.StringIO()):
            rc = _t.cmd_handoff(encoded)
        check("T17f resolve starts no child process", rc == 0)

    # T18 zero-trade: a completed execution that filled no trade is valid
    # evidence. It must never become performance evidence.
    header_only = EVENT_HEADER + "\n"

    def readback_of(**stub):
        """Submit one fresh stub run and read it back."""
        root, _ = fresh_run(**stub)
        code, text = run("research-readback", RUN_ID, root=root)
        return code, text

    zroot, zout = fresh_run(cycles=0, trades=0, events=header_only)
    rc, out = run("research-readback", RUN_ID, root=zroot)
    zback = json.loads(out) if rc == 0 else {}
    check("T18a zero-trade run prints the Node05 receipt",
          rc == 0 and zback.get("node05") == "PASS", out)
    check("T18b zero-trade counts as completed execution",
          zback.get("readable", {}).get("execution") is True, out)
    check("T18c zero-trade is not performance claimable",
          zback.get("performance_claimable") is False
          and zback.get("coverage_complete") is False, out)

    rc, out = readback_of(cycles=0, trades=0, events=header_only + EVENT_ROW + "\n")
    check("T18d zero cycles with an event row fails closed",
          rc == 2 and "does not match the replayed cycle count" in out, out)
    rc, out = readback_of(cycles=1, trades=1, events=header_only)
    check("T18e a replayed cycle with no event row fails closed",
          rc == 2 and "does not match the replayed cycle count" in out, out)
    rc, out = readback_of(cycles=1, trades=0)
    check("T18f a cycle/trade mismatch fails closed",
          rc == 2 and "cycle/trade mismatch" in out, out)
    rc, out = readback_of(cycles=0, trades=1)
    check("T18g a trade without a cycle fails closed",
          rc == 2 and "cycle/trade mismatch" in out, out)

    root, out_dir = fresh_run()
    (out_dir / "metrics.json").unlink()
    rc, out = run("research-readback", RUN_ID, root=root)
    check("T18h missing metrics evidence fails closed",
          rc == 2 and "metrics.json" in out, out)

    root, out_dir = fresh_run()
    manifest = json.loads((out_dir / "manifest.json").read_text())
    manifest.pop("metrics.json")
    (out_dir / "manifest.json").write_text(json.dumps(manifest, sort_keys=True))
    rc, out = run("research-readback", RUN_ID, root=root)
    check("T18i metrics absent from the manifest fails closed",
          rc == 2 and "required evidence is missing from the manifest: metrics.json" in out, out)

    root, out_dir = fresh_run()
    (out_dir / "metrics.json").write_text("not json")
    rc, out = run("research-readback", RUN_ID, root=root)
    check("T18j malformed metrics fails closed",
          rc == 2 and "run evidence is not readable" in out, out)

    root, out_dir = fresh_run()
    (out_dir / "summary.json").write_text(json.dumps([]))
    (out_dir / "metrics.json").write_text(json.dumps({"total_trades": 0}))
    rc, out = run("research-readback", RUN_ID, root=root)
    check("T18k a non-object summary fails closed",
          rc == 2 and "no usable cycle count" in out, out)

    for label, summary, run_metrics in (
        ("a boolean cycle count", {"cycles_replayed": True}, {"total_trades": 1}),
        ("a string cycle count", {"cycles_replayed": "1"}, {"total_trades": 1}),
        ("a negative cycle count", {"cycles_replayed": -1}, {"total_trades": -1}),
        ("a float trade count", {"cycles_replayed": 1}, {"total_trades": 1.0}),
        ("a boolean trade count", {"cycles_replayed": 1}, {"total_trades": True}),
    ):
        root, out_dir = fresh_run()
        (out_dir / "summary.json").write_text(json.dumps(summary))
        (out_dir / "metrics.json").write_text(json.dumps(run_metrics))
        rc, out = run("research-readback", RUN_ID, root=root)
        check("T18l " + label + " fails closed",
              rc == 2 and ("no usable cycle count" in out or "no usable trade count" in out), out)

    rc, out = readback_of(events="cycle,stage,stage_price,stage_quote_amount\n" + EVENT_ROW + "\n")
    check("T18m an events header without every required field fails closed",
          rc == 2 and "bad header" in out, out)
    rc, out = readback_of(events="")
    check("T18n an events file without a header fails closed",
          rc == 2 and "bad header" in out, out)
    rc, out = readback_of(events=EVENT_HEADER + "\n1,entry\n")
    check("T18o an events row without every required field fails closed",
          rc == 2 and "bad row" in out, out)

    # T18p/T18q an unfinished quoted field is malformed CSV, not evidence. The
    # non-strict reader folded it into a legal field and passed both the header
    # and the width checks.
    rc, out = readback_of(events=EVENT_HEADER + "\n1,0,2.0,100.0,\"100.0")
    check("T18p an unterminated quoted data field fails closed",
          rc == 2 and "event evidence is not readable CSV" in out, out)
    rc, out = readback_of(cycles=0, trades=0,
                          events=EVENT_HEADER[:-len("filled_quote")] + "\"filled_quote")
    check("T18q an unterminated quoted header field fails closed",
          rc == 2 and "event evidence is not readable CSV" in out, out)

    # T19 production namespace: the default root is production, the test
    # override still works, and forwarding follows the configured root.
    check("T19a the default results root is production",
          _t.RESULTS_ROOT_DEFAULT == "/results/production", _t.RESULTS_ROOT_DEFAULT)
    check("T19b no hardcoded validation root remains",
          "_validation" not in Path(_t.__file__ or str(TRANSPORT)).read_text())
    with patch.dict(os.environ, {"RESEARCH_RESULTS_ROOT": str(tmp)}):
        check("T19c the test override still resolves",
              _t.resolve_root() == Path(os.path.realpath(tmp)), str(_t.resolve_root()))
    existing = Path(tempfile.mkdtemp(prefix="transport-root-"))
    with patch.dict(os.environ, {}, clear=True), \
         patch.object(_t, "resolve_container_cli", return_value="/usr/local/bin/container"), \
         patch.object(_t, "host_results_source", return_value=str(existing)), \
         patch.object(_t, "RESULTS_ROOT_DEFAULT", str(existing)):
        check("T19d a present configured root keeps the launch local",
              _t.should_forward_host() is False)
    with patch.dict(os.environ, {}, clear=True), \
         patch.object(_t, "resolve_container_cli", return_value="/usr/local/bin/container"), \
         patch.object(_t, "host_results_source", return_value=str(existing)), \
         patch.object(_t, "RESULTS_ROOT_DEFAULT", str(existing / "absent")):
        check("T19e forwarding follows the configured root, not a literal",
              _t.should_forward_host() is True)

    # T20 verified campaign-manifest readback. One zero-write read of the frozen
    # manifest, never a caller copy and never the per-run manifest.
    def campaign_request(root, **over):
        request = {"request": "campaign-manifest-read-v1", "source_commit": "b" * 40,
                   "candidate_path": "demo-candidate.md", "source_blob_sha": "a" * 40,
                   "evidence_root": str(root)}
        request.update(over)
        return request

    root = frozen_root()
    before = snapshot(root)
    rc, out = handoff_resolve(campaign_request(root))
    report = json.loads(out) if out.startswith("{") else {}
    check("T20a the campaign read returns the verified manifest",
          rc == 0 and report.get("manifest_kind") == "campaign"
          and report.get("schema") == "qlib-formal-campaign-manifest-v1"
          and report.get("cell_count") == 1
          and report.get("manifest_sha256") == sha(root / "campaign-manifest.json")
          and report["cells"][0]["cell_id"] == "btcusdt-1h-3x"
          and report["cells"][0]["effective_config_sha256"] == sha(
              root / "btcusdt-1h-3x/effective_config.json"), out)
    check("T20b the campaign read writes nothing", snapshot(root) == before)
    check("T20c an unbound campaign read reports no phase instead of guessing",
          report.get("phase_bound") is False and report.get("phase_binding") is None
          and report["window"]["start_utc"] == "2025-01-01 00:00:00"
          and len(report["window"]["identity_sha256"]) == 64, out)
    bad = frozen_root()
    manifest = json.loads((bad / "campaign-manifest.json").read_text())
    manifest["schema"] = "qlib-formal-run-manifest-v1"
    (bad / "campaign-manifest.json").write_text(json.dumps(manifest))
    rc, out = handoff_resolve(campaign_request(bad))
    check("T20d a wrong manifest schema fails closed", rc == 2 and "schema" in out, out)
    run_only = Path(tempfile.mkdtemp(prefix="transport-runmanifest-"))
    (run_only / "manifest.json").write_text(json.dumps({"summary.json": {"sha256": "0" * 64}}))
    rc, out = handoff_resolve(campaign_request(run_only))
    check("T20e a per-run manifest is not a campaign manifest",
          rc == 2 and "campaign-manifest.json" in out, out)
    copied = Path(tempfile.mkdtemp(prefix="transport-runmanifest-"))
    (copied / "campaign-manifest.json").write_text(json.dumps({"summary.json": {"sha256": "0" * 64}}))
    rc, out = handoff_resolve(campaign_request(copied))
    check("T20f a run manifest copied to the campaign name fails closed",
          rc == 2 and "schema" in out, out)
    rc, out = handoff_resolve(campaign_request(Path(tempfile.mkdtemp(prefix="transport-empty-"))))
    check("T20g an empty evidence root fails closed", rc == 2, out)
    tampered = frozen_root()
    (tampered / "btcusdt-1h-3x/strategy_signal.py").write_text(
        "def signal(**kwargs):\n    return [{}], None\n")
    rc, out = handoff_resolve(campaign_request(tampered))
    check("T20h a tampered cell digest fails the campaign read",
          rc == 2 and "frozen manifest digest" in out, out)
    outside = frozen_root()
    manifest = json.loads((outside / "campaign-manifest.json").read_text())
    manifest["cells"][0]["entrypoint_ref"] = str(Path(__file__).resolve())
    manifest["cells"][0]["entrypoint_sha256"] = sha(__file__)
    (outside / "campaign-manifest.json").write_text(json.dumps(manifest))
    rc, out = handoff_resolve(campaign_request(outside))
    check("T20i a cell ref outside the evidence root fails closed",
          rc == 2 and "outside the evidence root" in out, out)
    rc, out = handoff_resolve(campaign_request(frozen_root(), candidate_path="other-candidate.md"))
    check("T20j a manifest for another candidate fails closed",
          rc == 2 and "requested candidate" in out, out)
    rc, out = handoff_resolve(campaign_request(frozen_root(), evidence_root="/tmp/../etc"))
    check("T20k a parent-hop evidence root fails closed", rc == 2, out)
    extra = campaign_request(frozen_root())
    extra["identity"] = json.loads(json.dumps(identity))
    rc, out = handoff_resolve(extra)
    check("T20l the campaign kind accepts no identity field",
          rc == 2 and "unknown field" in out, out)
    with patch.object(_t.subprocess, "run", side_effect=AssertionError("no child process allowed")):
        with contextlib.redirect_stdout(io.StringIO()):
            rc = _t.cmd_handoff(b64(campaign_request(frozen_root())))
        check("T20m the campaign read starts no child process", rc == 0)

    # T21 native readback enrichment. Additive, whitelisted, never synthesized.
    root, out_dir = fresh_run()
    rc, out = run("research-readback", RUN_ID, root=root)
    back = json.loads(out) if rc == 0 else {}
    native = back.get("native_evidence") or {}
    receipt_on_disk = json.loads((out_dir / "submit-receipt.json").read_text()) if rc == 0 else {}
    check("T21a readback exposes one additive native evidence object",
          rc == 0 and isinstance(native, dict) and native.get("phase") is None
          and native.get("phase_bound") is False and native.get("feeds_research") is None, out)
    check("T21b the native window is bound to the verified config window",
          native.get("window", {}).get("approved_start_utc") == "2025-01-01 00:00:00"
          and native["window"]["native_evaluation_start_utc"] == "2025-01-02T00:00:00"
          and native["window"]["native_inside_approved"] is True
          and len(native["window"].get("identity_sha256") or "") == 64, out)
    check("T21c native metrics expose total_trades and keep omitted values null",
          native.get("metrics", {}).get("total_trades") == 1
          and native["metrics"]["cagr_pct"] is None
          and native["metrics"]["net_return_pct"] == 1.5
          and native.get("metrics_omitted") == ["cagr_pct", "sharpe"], out)
    check("T21d native economics and claimability are reported, not rewritten",
          native.get("applied_economics", {}).get("funding_applied") is False
          and native.get("applied_economics", {}).get("declared_model_matches_applied") is False
          and native.get("performance_claimable") is False
          and native.get("cost_model_approved") is False
          and any("not approved" in item for item in native.get("limitations") or []), out)
    check("T21e the receipt's own claimability stays derived-false",
          back.get("performance_claimable") is False and back.get("coverage_complete") is False)
    check("T21f the native identity block binds the verified hashes",
          native.get("identity", {}).get("effective_config_sha256")
          == receipt_on_disk.get("effective_config_sha256")
          and len(native["identity"].get("run_manifest_sha256") or "") == 64
          and native["identity"].get("campaign_manifest_sha256") is None
          and native["identity"].get("strategy_params") == {"entry_len": 5}, out)

    def readback_with(summary_change=None, metrics_change=None, **stub):
        """Submit one fresh stub run, rewrite one evidence file, read it back."""
        root, out_dir = fresh_run(**stub)
        if summary_change is not None:
            summary = json.loads((out_dir / "summary.json").read_text())
            summary_change(summary)
            (out_dir / "summary.json").write_text(json.dumps(summary))
        if metrics_change is not None:
            metrics = json.loads((out_dir / "metrics.json").read_text())
            metrics_change(metrics)
            (out_dir / "metrics.json").write_text(json.dumps(metrics))
        code, text = run("research-readback", RUN_ID, root=root)
        return code, text

    rc, out = readback_with(summary_change=lambda s: s.update(applied_economics="nope"))
    check("T21g malformed native applied economics fails closed",
          rc == 2 and "applied economics" in out, out)
    rc, out = readback_with(summary_change=lambda s: s.update(
        evaluation_window_end_utc="2027-01-01T00:00:00"))
    check("T21h a native window outside the approved window fails closed",
          rc == 2 and "escapes the approved window" in out, out)
    rc, out = readback_with(summary_change=lambda s: s.update(
        evaluation_window_start_utc="not-a-date"))
    check("T21i a malformed native window fails closed",
          rc == 2 and "not readable UTC" in out, out)
    rc, out = readback_with(metrics_change=lambda m: m.update(net_return_pct="1.5"))
    check("T21j a non-numeric native metric fails closed",
          rc == 2 and "net_return_pct" in out, out)
    rc, out = readback_with(summary_change=lambda s: s.update(strategy_params={"entry_len": 99}))
    check("T21k native params that differ from the verified config fail closed",
          rc == 2 and "strategy params" in out, out)
    rc, out = readback_with(
        cycles=0, trades=0, events=EVENT_HEADER + "\n",
        summary_change=lambda s: s.update(
            economics_boundary={"performance_claimable": True, "cost_model_approved": True}))
    check("T21l a zero-trade run can never claim performance",
          rc == 2 and "zero-trade" in out, out)
    rc, out = readback_with(summary_change=lambda s: s.update(
        economics_boundary={"performance_claimable": True, "cost_model_approved": False}))
    check("T21m a claim without an approved cost model fails closed",
          rc == 2 and "without an approved cost model" in out, out)

    # T22 bounded materialize. One fixed command, no --force, no arbitrary argv.
    def materialize_fixture(phase="IS_BASELINE"):
        """Write one isolated stub Qlib materializer under a fresh results root."""
        root = Path(tempfile.mkdtemp(prefix="transport-materialize-"))
        pkg = root / "stub-qlib"
        (pkg / "qlib" / "backtest").mkdir(parents=True)
        (pkg / "qlib" / "__init__.py").write_text("")
        (pkg / "qlib" / "backtest" / "__init__.py").write_text("")
        (pkg / "qlib" / "backtest" / "research_cell.py").write_text(STUB_MATERIALIZER)
        (pkg / "cell_entrypoint.py").write_text(STUB_CELL_ENTRY)
        artifact = root / "strategy_signal.py"
        artifact.write_text("def signal(**kwargs):\n    return [], None\n")
        spec = {
            "phase": phase,
            "candidate": {"path": "demo-candidate.md", "source_commit": "b" * 40,
                          "git_blob_sha": "a" * 40},
            "runtime": {"commit": "c" * 40},
            "data": {"provider_ref": str(root / "provider")},
            "strategy": {"sides": ["long"], "params": {"entry_len": 5}, "warmup_days": 5,
                         "window_start_utc": "2025-01-01 00:00:00",
                         "window_end_utc_inclusive": "2025-12-31 00:00:00"},
            "strategy_artifact": {"source": str(artifact)},
            "house_overlay": {"base_order_quote_pct": 0.06, "safety_order_quote_pct": 0.06,
                              "safety_order_levels": 2, "so_spacing_pct": 0.04,
                              "take_profit_pct": 0.05, "stop_loss_pct": None,
                              "trade_cost": 0.0004, "initial_capital_quote": 100000.0},
            "research_cost_model": {"fees_per_side": 0.0004, "slippage": 0.0,
                                    "funding": "not_modeled", "approved": False},
            "materialize": {"cells_dir": str(root / "frozen-cells"),
                            "results_root": str(root / "runs")},
        }
        spec_path = root / "fixture-spec.json"
        spec_path.write_text(json.dumps(spec, indent=2, sort_keys=True) + "\n")
        return root, pkg, spec_path, spec, artifact

    def materialize_request(spec_path, spec, **over):
        request = {
            "request": "materialize-v1",
            "spec_ref": str(spec_path),
            "root": spec["materialize"]["cells_dir"],
            "phase": spec["phase"],
            "window": {"start_utc": spec["strategy"]["window_start_utc"],
                       "end_utc_inclusive": spec["strategy"]["window_end_utc_inclusive"]},
            "source_commit": spec["candidate"]["source_commit"],
            "candidate_path": spec["candidate"]["path"],
            "source_blob_sha": spec["candidate"]["git_blob_sha"],
            "strategy_artifact_sha256": sha(spec["strategy_artifact"]["source"]),
            "qlib_runtime_commit": spec["runtime"]["commit"],
        }
        request.update(over)
        return request

    def run_materialize(payload, root, pkg):
        return run(MATERIALIZE_VERB_LOCAL, b64(payload), root=root, py_path=pkg)

    MATERIALIZE_VERB_LOCAL = "research-materialize"
    froot, pkg, spec_path, spec, artifact = materialize_fixture()
    request = materialize_request(spec_path, spec)
    cells_root = Path(spec["materialize"]["cells_dir"])
    manifest_path = cells_root / "campaign-manifest.json"
    rc, out = run_materialize(request, froot, pkg)
    receipt = json.loads(out) if out.startswith("{") else {}
    check("T22a materialize runs the fixed Qlib command and verifies its manifest",
          rc == 0 and receipt.get("status") == "materialized"
          and receipt.get("state") == "created"
          and receipt.get("campaign_manifest", {}).get("sha256") == sha(manifest_path)
          and receipt.get("campaign_manifest", {}).get("cell_count") == 2
          and (cells_root / "materialize-receipt.json").is_file(), out)
    check("T22b the receipt binds the request identity, phase and window",
          receipt.get("phase") == "IS_BASELINE" and receipt.get("window") == request["window"]
          and receipt.get("window_identity_sha256") == _t._window_identity(request["window"])
          and receipt.get("spec_sha256") == sha(spec_path)
          and receipt.get("strategy_artifact", {}).get("sha256")
          == request["strategy_artifact_sha256"]
          and receipt.get("source_commit") == request["source_commit"]
          and len(receipt.get("cell_evidence_sha256") or "") == 64, out)
    stored = (cells_root / "materialize-receipt.json").read_bytes()
    manifest_bytes = manifest_path.read_bytes()
    rc, out = run_materialize(request, froot, pkg)
    again = json.loads(out) if out.startswith("{") else {}
    check("T22c the same request converges without writing again",
          rc == 0 and again.get("state") == "existing"
          and (cells_root / "materialize-receipt.json").read_bytes() == stored
          and manifest_path.read_bytes() == manifest_bytes, out)
    retest = json.loads(spec_path.read_text())
    retest["phase"] = "IS_RETEST"
    retest_path = spec_path.with_name("retest-spec.json")
    retest_path.write_text(json.dumps(retest, indent=2, sort_keys=True) + "\n")
    rc, out = run_materialize(materialize_request(retest_path, retest), froot, pkg)
    check("T22d a conflicting phase over an existing root refuses",
          rc == 2 and "refuse overwrite" in out and "different request" in out, out)
    rc, out = run_materialize(dict(request, phase="IS_RETEST"), froot, pkg)
    check("T22d1 a request phase the spec does not declare fails closed",
          rc == 2 and "spec phase does not match the requested phase" in out, out)
    rc, out = run_materialize(dict(request, candidate_path="other-candidate.md"), froot, pkg)
    check("T22d2 a candidate that is not the spec candidate fails closed",
          rc == 2 and "spec candidate.path" in out, out)
    for label, change, expect in (
        ("a spec outside the results root",
         lambda req: dict(req, spec_ref="/etc/passwd"), "escapes the results root"),
        ("a parent-hop root",
         lambda req: dict(req, root=req["root"] + "/../evil"), "root is not an absolute path"),
        ("a candidate path with a slash",
         lambda req: dict(req, candidate_path="a/b.md"), "candidate_path has a bad shape"),
        ("an unapproved phase",
         lambda req: dict(req, phase="IS_SIDE"), "phase is not one of"),
        ("an invented window",
         lambda req: dict(req, window={"start_utc": "2025-02-01 00:00:00",
                                       "end_utc_inclusive": "2025-12-31 00:00:00"}),
         "does not match the approved window"),
        ("a runtime that is not the spec runtime",
         lambda req: dict(req, qlib_runtime_commit="d" * 40), "spec runtime.commit"),
        ("an artifact hash that is not the spec artifact",
         lambda req: dict(req, strategy_artifact_sha256="0" * 64),
         "does not match the requested sha256"),
        ("an unknown request field",
         lambda req: dict(req, force=True), "unknown field"),
    ):
        froot2, pkg2, spec_path2, spec2, _artifact2 = materialize_fixture()
        bad_request = change(materialize_request(spec_path2, spec2))
        rc, out = run_materialize(bad_request, froot2, pkg2)
        check("T22e " + label + " fails closed", rc == 2 and expect in out, out)
        check("T22e " + label + " writes no frozen cell",
              not (Path(spec2["materialize"]["cells_dir"]) / "campaign-manifest.json").exists(),
              out)
    # An absent spec is an expected typed answer (exit 0, like research-handoff),
    # while a malformed spec at the same path is a transport failure (exit 2). The
    # caller must be able to tell those two apart.
    nroot, npkg, nspec_path, nspec, _nartifact = materialize_fixture()
    absent = str(nspec_path.with_name("absent-spec.json"))
    rc, out = run_materialize(dict(materialize_request(nspec_path, nspec), spec_ref=absent),
                              nroot, npkg)
    missing = json.loads(out) if out.startswith("{") else {}
    check("T22f a missing spec is a typed implementation_needed answer at exit 0",
          rc == 0 and missing.get("status") == "implementation_needed"
          and "MATERIALIZE_SPEC_MISSING" in str(missing.get("reason")), out)
    check("T22f2 the expected implementation_needed answer writes nothing",
          not Path(nspec["materialize"]["cells_dir"]).exists(), out)
    broken_root, broken_pkg, broken_spec_path, broken_spec, _broken = materialize_fixture()
    broken_spec_path.write_text("{not json")
    rc, out = run_materialize(
        dict(materialize_request(broken_spec_path, broken_spec), spec_ref=str(broken_spec_path)),
        broken_root, broken_pkg)
    check("T22f3 a malformed spec is still a transport failure at exit 2",
          rc == 2 and "not readable JSON" in out and "implementation_needed" not in out, out)

    froot, pkg, spec_path, spec, artifact = materialize_fixture()
    short_spec = json.loads(spec_path.read_text())
    short_spec["strategy"]["sides"] = ["long", "short"]
    short_path = spec_path.with_name("short-spec.json")
    short_path.write_text(json.dumps(short_spec, indent=2, sort_keys=True) + "\n")
    rc, out = run_materialize(materialize_request(short_path, short_spec), froot, pkg)
    check("T22g a declared short side holds before anything is written",
          rc == 2 and "ENGINEERING_HOLD" in out
          and not (Path(short_spec["materialize"]["cells_dir"]) / "campaign-manifest.json").exists(),
          out)

    # An existing root converges only through its own receipt: a changed spec, a
    # changed cost, or a prefix-era root without a receipt all refuse. A receipt is
    # never reconstructed from a later spec.
    rroot, rpkg, rspec_path, rspec, _rart = materialize_fixture()
    rrequest = materialize_request(rspec_path, rspec)
    rc, out = run_materialize(rrequest, rroot, rpkg)
    if rc != 0:
        raise SystemExit("FAILED: existing-root setup " + out)
    rreceipt = Path(rspec["materialize"]["cells_dir"]) / "materialize-receipt.json"
    first_receipt = rreceipt.read_bytes()
    changed = json.loads(rspec_path.read_text())
    changed["house_overlay"]["trade_cost"] = 0.0011
    changed["strategy"]["params"] = {"entry_len": 7}
    changed_path = rspec_path.with_name("changed-spec.json")
    changed_path.write_text(json.dumps(changed, indent=2, sort_keys=True) + "\n")
    rc, out = run_materialize(materialize_request(changed_path, changed), rroot, rpkg)
    check("T22r a changed spec over an existing root refuses instead of rebinding",
          rc == 2 and "refuse overwrite" in out and rreceipt.read_bytes() == first_receipt, out)
    cost_only = json.loads(rspec_path.read_text())
    cost_only["research_cost_model"]["fees_per_side"] = 0.0006
    cost_path = rspec_path.with_name("cost-spec.json")
    cost_path.write_text(json.dumps(cost_only, indent=2, sort_keys=True) + "\n")
    rc, out = run_materialize(materialize_request(cost_path, cost_only), rroot, rpkg)
    check("T22s a cost-only spec change cannot rebind existing cells",
          rc == 2 and "refuse overwrite" in out and rreceipt.read_bytes() == first_receipt, out)
    rreceipt.unlink()
    rc, out = run_materialize(rrequest, rroot, rpkg)
    check("T22t a materialization without its receipt refuses and stays unrepaired",
          rc == 2 and "no receipt" in out and not rreceipt.exists(), out)

    # Runtime provenance: inside the fixed runtime the receipt binds the image and
    # digest this process is actually executing; on the host it invents none.
    host_runtime = _t._receipt_runtime(rrequest, rspec)
    check("T22u the host receipt does not invent an image",
          host_runtime["commit"] == rrequest["qlib_runtime_commit"]
          and host_runtime["image"] is None and host_runtime["image_digest"] is None,
          str(host_runtime))
    with patch.object(_t, "is_fixed_runtime", return_value=True):
        fixed_runtime = _t._receipt_runtime(rrequest, rspec)
    check("T22v the fixed runtime binds the pinned image and digest",
          fixed_runtime["commit"] == _t.FIXED_RUNTIME_COMMIT
          and fixed_runtime["image"] == _t.FIXED_IMAGE
          and fixed_runtime["image_digest"] == _t.FIXED_IMAGE_DIGEST, str(fixed_runtime))

    # The only child process is the fixed Qlib materialize argv: no shell, no
    # arbitrary argument, no --force.
    froot, pkg, spec_path, spec, artifact = materialize_fixture()
    request = materialize_request(spec_path, spec)
    with patch.object(_t, "resolve_root", return_value=Path(os.path.realpath(froot))), \
         patch.object(_t.subprocess, "run",
                      return_value=subprocess.CompletedProcess([], 1, "", "boom")) as child:
        with contextlib.redirect_stdout(io.StringIO()):
            rc = _t.cmd_materialize(b64(request))
        argv = list(child.call_args[0][0]) if child.call_args else []
        kwargs = dict(child.call_args[1]) if child.call_args else {}
    check("T22h the only child is the fixed Qlib materialize argv",
          rc == 2 and argv == [sys.executable, "-m", "qlib.backtest.research_cell",
                               "materialize", "--spec", str(spec_path),
                               "--root", spec["materialize"]["cells_dir"]]
          and kwargs.get("shell") in (None, False)
          and not any(";" in arg or "|" in arg or "$" in arg or "`" in arg for arg in argv), str(argv))
    payload = b64(request)
    check("T22i the materialize verb accepts one base64 request and no shell chaining",
          _t.parse_forced_command("research-materialize " + payload)[0]
          == ("research-materialize", payload)
          and _t.parse_forced_command("research-materialize " + payload + "; touch evil")[0] is None
          and _t.parse_forced_command("research-materialize " + payload, hermes=True)[0] is None)
    forwarded = _t.build_forward_command("research-materialize", payload)
    check("T22j the Qlib key forwards materialize to the fixed image without a shell",
          forwarded is not None and _t.FIXED_IMAGE in forwarded
          and forwarded[-2:] == ["research-materialize", payload]
          and "target=/results" in " ".join(forwarded)
          and not any(";" in arg or "|" in arg or "$" in arg for arg in forwarded), str(forwarded))

    # Concurrency: one exclusive lock, bounded wait, typed refuse instead of racing.
    froot, pkg, spec_path, spec, artifact = materialize_fixture()
    request = materialize_request(spec_path, spec)
    cells_root = Path(spec["materialize"]["cells_dir"])
    cells_root.mkdir(parents=True, exist_ok=True)
    (cells_root / _t.MATERIALIZE_LOCK).write_text("")
    with patch.object(_t, "MATERIALIZE_LOCK_WAIT", 0.2), \
         patch.object(_t, "resolve_root", return_value=Path(os.path.realpath(froot))), \
         contextlib.redirect_stdout(io.StringIO()) as buf:
        rc = _t.cmd_materialize(b64(request))
    check("T22k a held lock refuses instead of racing",
          rc == 2 and "another materialization holds" in buf.getvalue(), buf.getvalue())
    (cells_root / _t.MATERIALIZE_LOCK).unlink()
    rc, out = run_materialize(request, froot, pkg)
    check("T22l the same request converges once the lock is released",
          rc == 0 and json.loads(out).get("status") == "materialized", out)

    # T22m..T22q phase/window: a materialized root answers a phase-bound campaign
    # read, and a run from one of its cells carries that phase into Node05.
    def submit_from_cells(root, pkg_path, cells_dir):
        """Submit one materialized cell through the real transport path."""
        manifest = json.loads((Path(cells_dir) / "campaign-manifest.json").read_text())
        cell = manifest["cells"][0]
        handoff = {
            "source_commit": cell["source_commit"], "candidate_path": cell["candidate_path"],
            "source_blob_sha": cell["source_blob_sha"],
            "entrypoint_ref": cell["entrypoint_ref"],
            "entrypoint_sha256": cell["entrypoint_sha256"],
            "effective_config_ref": cell["effective_config_ref"],
            "effective_config_sha256": cell["effective_config_sha256"],
            "qlib_runtime_commit": cell["qlib_runtime_commit"],
            "capabilities": dict(cell["capabilities"]),
            "evidence_refs": {"manifest": str(Path(cells_dir) / "campaign-manifest.json")},
            "run_inputs": {"symbol": cell["symbol"]},
        }
        return run("research-submit", b64(handoff), root=root)

    active_manifest = Path(spec["materialize"]["cells_dir"]) / "campaign-manifest.json"
    rc, out = handoff_resolve({"request": "campaign-manifest-read-v1",
                               "source_commit": request["source_commit"],
                               "candidate_path": request["candidate_path"],
                               "source_blob_sha": request["source_blob_sha"],
                               "evidence_root": spec["materialize"]["cells_dir"]})
    report = json.loads(out) if out.startswith("{") else {}
    check("T22m the campaign read returns the verified phase binding",
          rc == 0 and report.get("phase_bound") is True
          and report["phase_binding"]["phase"] == "IS_BASELINE"
          and report["phase_binding"]["window_identity_sha256"]
          == _t._window_identity(request["window"])
          and report.get("cell_count") == 2
          and report["manifest_sha256"] == sha(active_manifest), out)
    rc, out = submit_from_cells(froot, pkg, spec["materialize"]["cells_dir"])
    if rc != 0:
        raise SystemExit("FAILED: materialized cell submit " + out)
    rc, out = run("research-readback", RUN_ID, root=froot)
    back = json.loads(out) if rc == 0 else {}
    native = back.get("native_evidence") or {}
    check("T22n a run from a materialized IS cell carries its approved phase",
          rc == 0 and native.get("phase") == "IS_BASELINE" and native.get("phase_bound") is True
          and native.get("feeds_research") is True and native.get("oos_isolated") is False
          and native.get("identity", {}).get("campaign_manifest_sha256") == sha(active_manifest)
          and native["identity"].get("materialize_spec_sha256") == sha(spec_path), out)

    oroot, opkg, ospec_path, ospec, _oartifact = materialize_fixture(phase="OOS")
    orequest = materialize_request(ospec_path, ospec)
    rc, out = run_materialize(orequest, oroot, opkg)
    if rc != 0:
        raise SystemExit("FAILED: OOS materialize setup " + out)
    rc, out = submit_from_cells(oroot, opkg, ospec["materialize"]["cells_dir"])
    if rc != 0:
        raise SystemExit("FAILED: OOS cell submit " + out)
    rc, out = run("research-readback", RUN_ID, root=oroot)
    oback = json.loads(out) if rc == 0 else {}
    onative = oback.get("native_evidence") or {}
    check("T22o an OOS run is marked isolated and never feeds research",
          rc == 0 and onative.get("phase") == "OOS" and onative.get("phase_bound") is True
          and onative.get("feeds_research") is False and onative.get("oos_isolated") is True, out)
    check("T22p an OOS run is not performance claimable at the transport",
          oback.get("performance_claimable") is False
          and onative.get("performance_claimable") is False, out)

    # T24 receipt identity (B1). A receipt is authoritative only when every
    # identity it declares verifies against evidence this file reads itself.
    def bound_fixture(phase="IS_BASELINE"):
        """Materialize one campaign and submit one of its cells."""
        root, pkg_path, spec_path_, spec_, _art = materialize_fixture(phase=phase)
        rc, out = run_materialize(materialize_request(spec_path_, spec_), root, pkg_path)
        if rc != 0:
            raise SystemExit("FAILED: bound fixture materialize " + out)
        rc, out = submit_from_cells(root, pkg_path, spec_["materialize"]["cells_dir"])
        if rc != 0:
            raise SystemExit("FAILED: bound fixture submit " + out)
        return root, pkg_path, spec_path_, spec_, Path(spec_["materialize"]["cells_dir"])

    def campaign_read_for(cells_dir, spec):
        return handoff_resolve({"request": "campaign-manifest-read-v1",
                                "source_commit": spec["candidate"]["source_commit"],
                                "candidate_path": spec["candidate"]["path"],
                                "source_blob_sha": spec["candidate"]["git_blob_sha"],
                                "evidence_root": str(cells_dir)})

    def rewrite_receipt(cells_dir, payload):
        ref = Path(cells_dir) / "materialize-receipt.json"
        if payload is None:
            ref.unlink()
        elif isinstance(payload, str):
            ref.write_text(payload)
        else:
            ref.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        return ref

    # T24a the auditor exploit: edit only receipt.phase on a materialized OOS
    # campaign, then read the campaign and the run back.
    oos_cells = Path(ospec["materialize"]["cells_dir"])
    oos_receipt = json.loads((oos_cells / "materialize-receipt.json").read_text())
    rewrite_receipt(oos_cells, dict(oos_receipt, phase="IS_BASELINE"))
    rc, out = campaign_read_for(oos_cells, ospec)
    check("T24a a phase-only receipt tamper fails the campaign read closed",
          rc == 2 and "phase does not match the approved spec" in out, out)
    rc, out = run("research-readback", RUN_ID, root=oroot)
    check("T24a2 a phase-only receipt tamper cannot relabel an OOS run as IS",
          rc == 2 and '"feeds_research": true' not in out
          and "phase does not match the approved spec" in out, out)
    rewrite_receipt(oos_cells, oos_receipt)

    root, pkg_path, spec_path_, spec_, cells_dir = bound_fixture()
    receipt_path = cells_dir / "materialize-receipt.json"
    original_receipt = json.loads(receipt_path.read_text())
    original_spec_text = spec_path_.read_text()
    minimal = {key: original_receipt[key] for key in
               ("schema", "request", "phase", "window", "window_identity_sha256",
                "campaign_manifest", "root", "cells_root")}
    rewrite_receipt(cells_dir, minimal)
    rc, out = campaign_read_for(cells_dir, spec_)
    check("T24b a minimal receipt without spec identity fails the campaign read closed",
          rc == 2 and "spec reference" in out, out)
    rc, out = run("research-readback", RUN_ID, root=root)
    check("T24b2 a minimal receipt fails the readback closed instead of unbinding",
          rc == 2 and "spec reference" in out, out)

    rewrite_receipt(cells_dir, "{not json")
    rc, out = campaign_read_for(cells_dir, spec_)
    check("T24c a malformed receipt fails the campaign read closed",
          rc == 2 and "not readable JSON" in out, out)
    rc, out = run("research-readback", RUN_ID, root=root)
    check("T24c2 a malformed receipt fails the readback closed, never silently unbound",
          rc == 2 and "not readable JSON" in out and "phase_bound" not in out, out)

    rewrite_receipt(cells_dir, None)
    inner = spec_path_.with_name("receipt-copy.json")
    inner.write_text(json.dumps(original_receipt, indent=2, sort_keys=True) + "\n")
    receipt_path.symlink_to(inner)
    rc, out = campaign_read_for(cells_dir, spec_)
    check("T24d a receipt symlink is refused instead of followed",
          rc == 2 and "not a regular file" in out, out)
    rc, out = run("research-readback", RUN_ID, root=root)
    check("T24d2 a receipt symlink fails the readback closed",
          rc == 2 and "not a regular file" in out, out)
    receipt_path.unlink()
    outer = Path(tempfile.mkdtemp(prefix="transport-outside-")) / "receipt.json"
    outer.write_text(json.dumps(original_receipt, indent=2, sort_keys=True) + "\n")
    receipt_path.symlink_to(outer)
    rc, out = campaign_read_for(cells_dir, spec_)
    check("T24d3 a receipt symlink out of the campaign root is refused",
          rc == 2 and "outside the evidence root" in out, out)
    receipt_path.unlink()
    rewrite_receipt(cells_dir, original_receipt)

    changed_spec = json.loads(original_spec_text)
    changed_spec["house_overlay"]["trade_cost"] = 0.0009
    spec_path_.write_text(json.dumps(changed_spec, indent=2, sort_keys=True) + "\n")
    rc, out = campaign_read_for(cells_dir, spec_)
    check("T24e a spec rewritten after materialization fails the campaign read closed",
          rc == 2 and "spec bytes do not match the receipt" in out, out)
    rc, out = run("research-readback", RUN_ID, root=root)
    check("T24e2 a spec rewritten after materialization fails the readback closed",
          rc == 2 and "spec bytes do not match the receipt" in out, out)
    spec_path_.write_text(original_spec_text)

    rewrite_receipt(cells_dir, dict(original_receipt, cell_evidence_sha256="0" * 64))
    rc, out = campaign_read_for(cells_dir, spec_)
    check("T24f a receipt that does not bind the campaign cells fails closed",
          rc == 2 and "does not bind these campaign cells" in out, out)
    rewrite_receipt(cells_dir, {key: value for key, value in original_receipt.items()
                                if key != "phase"})
    rc, out = campaign_read_for(cells_dir, spec_)
    check("T24g a receipt without an approved phase fails closed",
          rc == 2 and "phase does not match the approved spec" in out, out)

    rewrite_receipt(cells_dir, None)
    rc, out = campaign_read_for(cells_dir, spec_)
    report = json.loads(out) if out.startswith("{") else {}
    check("T24h a missing receipt stays an explicitly unbound answer",
          rc == 0 and report.get("phase_bound") is False
          and report.get("phase_binding") is None, out)
    rc, out = run("research-readback", RUN_ID, root=root)
    back = json.loads(out) if rc == 0 else {}
    unbound = back.get("native_evidence") or {}
    check("T24h2 a missing receipt leaves the readback phase null, never guessed",
          rc == 0 and unbound.get("phase") is None and unbound.get("phase_bound") is False
          and unbound.get("feeds_research") is None, out)
    rewrite_receipt(cells_dir, original_receipt)
    rc, out = run("research-readback", RUN_ID, root=root)
    back = json.loads(out) if rc == 0 else {}
    restored = back.get("native_evidence") or {}
    check("T24i the restored receipt binds the phase again",
          rc == 0 and restored.get("phase") == "IS_BASELINE"
          and restored.get("feeds_research") is True, out)

    # T25 receipt creation (B2). A pre-existing receipt path never redirects a
    # write, and an external file never changes.
    def hostile_receipt(kind):
        hroot, hpkg, hspec_path, hspec, _hart = materialize_fixture()
        hcells = Path(hspec["materialize"]["cells_dir"])
        hcells.mkdir(parents=True, exist_ok=True)
        outside_dir = Path(tempfile.mkdtemp(prefix="transport-outside-"))
        sentinel = outside_dir / "sentinel.txt"
        sentinel.write_text("sentinel\n")
        hreceipt = hcells / "materialize-receipt.json"
        if kind == "symlink":
            hreceipt.symlink_to(sentinel)
        elif kind == "dangling":
            hreceipt.symlink_to(outside_dir / "never-created.json")
        else:
            hreceipt.write_text('{"stale": true}\n')
        before = sorted((p.name, p.stat().st_size) for p in outside_dir.iterdir())
        code, text = run_materialize(materialize_request(hspec_path, hspec), hroot, hpkg)
        after = sorted((p.name, p.stat().st_size) for p in outside_dir.iterdir())
        return code, text, hcells, outside_dir, sentinel, before, after

    rc, out, cells_dir, outside_dir, sentinel, before, after = hostile_receipt("symlink")
    check("T25a a receipt symlink refuses before the native materializer runs",
          rc == 2 and "already carries materialize-receipt.json" in out, out)
    check("T25a2 the external sentinel stays byte-identical",
          sentinel.read_bytes() == b"sentinel\n" and before == after, str(before))
    check("T25a3 no cell or manifest is written over a hostile receipt path",
          sorted(p.name for p in Path(cells_dir).iterdir()) == ["materialize-receipt.json"]
          and not (Path(cells_dir) / "campaign-manifest.json").exists(), out)

    rc, out, cells_dir, outside_dir, sentinel, before, after = hostile_receipt("dangling")
    check("T25b a dangling receipt symlink refuses instead of following it",
          rc == 2 and "already carries materialize-receipt.json" in out, out)
    check("T25b2 the dangling target is never created outside the root",
          not (outside_dir / "never-created.json").exists()
          and sentinel.read_bytes() == b"sentinel\n" and before == after, str(before))

    rc, out, cells_dir, outside_dir, sentinel, before, after = hostile_receipt("regular")
    check("T25c a pre-existing receipt file refuses instead of being replaced",
          rc == 2 and "already carries materialize-receipt.json" in out
          and (Path(cells_dir) / "materialize-receipt.json").read_text() == '{"stale": true}\n',
          out)

    unit_root = Path(tempfile.mkdtemp(prefix="transport-receipt-"))
    unit_target = unit_root.parent / (unit_root.name + "-sentinel.txt")
    unit_target.write_text("sentinel\n")
    (unit_root / "materialize-receipt.json").symlink_to(unit_target)
    wrote = _t._write_receipt(str(unit_root), {"schema": "x"})
    check("T25d the receipt writer itself never follows an existing target",
          wrote is False and unit_target.read_text() == "sentinel\n", str(wrote))
    fresh_root = Path(tempfile.mkdtemp(prefix="transport-receipt-"))
    first = _t._write_receipt(str(fresh_root), {"schema": "y"})
    second = _t._write_receipt(str(fresh_root), {"schema": "z"})
    check("T25e the receipt writer creates once and never replaces",
          first is True and second is False
          and json.loads((fresh_root / "materialize-receipt.json").read_text()) == {"schema": "y"},
          "%s %s" % (first, second))

    # T26 request-only guards (B3). A missing spec never hides another defect.
    groot, gpkg, gspec_path, gspec, _gart = materialize_fixture()
    gcells = Path(gspec["materialize"]["cells_dir"])
    gcells.mkdir(parents=True, exist_ok=True)
    grequest = materialize_request(gspec_path, gspec)
    absent_spec = str(gcells / "absent-spec.json")

    def local_materialize(payload):
        with patch.object(_t, "resolve_root", return_value=Path(os.path.realpath(groot))), \
             contextlib.redirect_stdout(io.StringIO()) as buf:
            code = _t.cmd_materialize(b64(payload))
        return code, buf.getvalue()

    with patch.object(_t, "is_fixed_runtime", return_value=True):
        rc, out = local_materialize(dict(grequest, spec_ref=absent_spec,
                                         qlib_runtime_commit="d" * 40))
    check("T26a a wrong fixed runtime plus a missing spec fails at exit 2",
          rc == 2 and "config/runtime identity mismatch" in out, out)

    spec_dir = gcells / "spec-dir"
    spec_dir.mkdir(parents=True, exist_ok=True)
    rc, out = local_materialize(dict(grequest, spec_ref=str(spec_dir)))
    check("T26b a directory spec_ref fails at exit 2",
          rc == 2 and "not a regular file" in out, out)

    real_spec = gcells / "real-spec.json"
    real_spec.write_text(json.dumps(gspec, indent=2, sort_keys=True) + "\n")
    spec_link = gcells / "spec-link.json"
    spec_link.symlink_to(real_spec)
    rc, out = local_materialize(dict(grequest, spec_ref=str(spec_link)))
    check("T26c a symlinked spec_ref fails at exit 2",
          rc == 2 and "not a regular file" in out, out)

    escape_dir = gcells / "escape"
    escape_dir.symlink_to(Path(tempfile.mkdtemp(prefix="transport-outside-")))
    rc, out = local_materialize(dict(grequest, spec_ref=str(escape_dir / "absent-spec.json")))
    check("T26d a spec_ref that escapes the results root fails at exit 2",
          rc == 2 and "escapes the results root" in out, out)

    rc, out = local_materialize(dict(grequest, spec_ref=absent_spec,
                                     window={"start_utc": "yesterday",
                                             "end_utc_inclusive": "today"}))
    check("T26e a malformed window plus a missing spec fails at exit 2",
          rc == 2 and "window.start_utc" in out, out)
    rc, out = local_materialize(dict(grequest, spec_ref=absent_spec, phase="IS_SIDE"))
    check("T26f an unapproved phase plus a missing spec fails at exit 2",
          rc == 2 and "phase is not one of" in out, out)
    rc, out = local_materialize(dict(grequest, spec_ref=absent_spec))
    payload = json.loads(out) if out.strip().startswith("{") else {}
    check("T26g a valid request with a truly absent spec stays implementation_needed",
          rc == 0 and payload.get("status") == "implementation_needed"
          and "MATERIALIZE_SPEC_MISSING" in str(payload.get("reason")), out)

    # T23 mutation control: the new guards are load-bearing. A weakened copy must
    # ACCEPT exactly what the shipped guard rejects, so a mutation is detectable.
    source_text = Path(TRANSPORT).read_text()

    def mutated_copy(old, new):
        if old not in source_text:
            raise SystemExit("FAILED: mutation anchor missing: " + old[:60])
        mutant = Path(tempfile.mkdtemp(prefix="transport-mutant-")) / "research-transport.py"
        mutant.write_text(source_text.replace(old, new, 1))
        return mutant

    def forced_copy(path, command, root):
        env = dict(os.environ, RESEARCH_RESULTS_ROOT=str(root))
        proc = subprocess.run([sys.executable, str(path), "hermes-forced"],
                              env=dict(env, SSH_ORIGINAL_COMMAND=command),
                              capture_output=True, text=True, timeout=120)
        return proc.returncode, proc.stdout.strip()

    bad_root = frozen_root()
    (bad_root / "btcusdt-1h-3x/strategy_signal.py").write_text(
        "def signal(**kwargs):\n    return [{}], None\n")
    mutant = mutated_copy(
        'problems = _cell_byte_problems(cell, evidence_root)\n'
        '        if problems:\n'
        '            return None, "; ".join(sorted(set(problems))[:4])',
        'problems = _cell_byte_problems(cell, evidence_root)\n'
        '        if False:\n'
        '            return None, "; ".join(sorted(set(problems))[:4])')
    rc, out = forced_copy(mutant, "research-handoff " + b64(campaign_request(bad_root)), bad_root)
    check("T23a the campaign cell-digest guard is load-bearing", rc == 0, out)

    root, out_dir = fresh_run(cycles=0, trades=0, events=EVENT_HEADER + "\n")
    summary = json.loads((out_dir / "summary.json").read_text())
    summary["economics_boundary"] = {"performance_claimable": True, "cost_model_approved": True}
    (out_dir / "summary.json").write_text(json.dumps(summary))
    mutant = mutated_copy("    if zero_trade and claimable is True:",
                          "    if False and zero_trade and claimable is True:")
    env = dict(os.environ, RESEARCH_RESULTS_ROOT=str(root))
    proc = subprocess.run([sys.executable, str(mutant), "research-readback", RUN_ID],
                          env=env, capture_output=True, text=True, timeout=120)
    check("T23b the zero-trade claimability guard is load-bearing",
          proc.returncode == 0, proc.stdout.strip())

    # T27 bounded Kanban engineering adapter. Hermes-key only, host workspace,
    # guest spec paths, fixed board, no shell. The fake CLI is a local process:
    # the test never touches the live board.
    eng = Path(tempfile.mkdtemp(prefix="transport-engineering-"))
    backing = eng / "results"
    backing.mkdir()
    host_root = Path(os.path.realpath(str(backing))) / "production"
    fake_cli = eng / "fake-hermes"
    fake_cli.write_text(FAKE_KANBAN_CLI.replace("__PYTHON__", sys.executable))
    fake_cli.chmod(0o755)
    store_path = eng / "kanban-store.json"
    guest_root = _t.GUEST_RESULTS_ROOT

    def eng_env(**over):
        env = dict(os.environ, RESEARCH_HOST_RESULTS_SOURCE=str(backing),
                   RESEARCH_HERMES_CLI=str(fake_cli), FAKE_KANBAN_STORE=str(store_path))
        env.pop("RESEARCH_RESULTS_ROOT", None)
        env.update(over)
        return env

    def eng_forced(command, env=None):
        env = dict(env or eng_env(), SSH_ORIGINAL_COMMAND=command)
        proc = subprocess.run([sys.executable, str(TRANSPORT), "hermes-forced"], env=env,
                              capture_output=True, text=True, timeout=120)
        return proc.returncode, proc.stdout.strip()

    def eng_create(request, env=None):
        return eng_forced("research-engineering-create " + b64(request), env)

    def eng_read(payload, env=None):
        return eng_forced("research-engineering-read " + b64(payload), env)

    def read_store():
        if not store_path.exists():
            return {"tasks": {}, "runs": {}, "calls": [], "idem": {}}
        return json.loads(store_path.read_text())

    def write_store(data):
        store_path.write_text(json.dumps(data))

    def engineering_request():
        return {
            "request": "engineering-task-v1",
            "source_commit": "b" * 40,
            "candidate_path": "demo-candidate.md",
            "source_blob_sha": SOURCE_BLOB,
            "family_id": "dca-btcusdt-1h",
            "round_index": 1,
            "phase": "IS_RETEST",
            "window": {"start_utc": "2025-01-01 00:00:00",
                       "end_utc_inclusive": "2025-12-31 00:00:00"},
            "spec_seed": {
                "candidate": {"path": "demo-candidate.md", "source_commit": "b" * 40,
                              "git_blob_sha": SOURCE_BLOB},
                "runtime": {"commit": _t.FIXED_RUNTIME_COMMIT, "image": _t.FIXED_IMAGE,
                            "image_digest": _t.FIXED_IMAGE_DIGEST},
                "data": {"provider_ref": guest_root + "/provider"},
                "strategy": {"sides": ["long"], "params": {"entry_len": 5}, "warmup_days": 5},
                "house_overlay": {"base_order_quote_pct": 0.06, "safety_order_quote_pct": 0.06,
                                  "safety_order_levels": 2, "so_spacing_pct": 0.04,
                                  "take_profit_pct": 0.05, "stop_loss_pct": None,
                                  "trade_cost": 0.0004, "initial_capital_quote": 100000.0},
                "research_cost_model": {"fees_per_side": 0.0004, "slippage": 0.0,
                                        "funding": "not_modeled", "approved": False},
            },
            "change_set": {"hypothesis": "widen the entry window", "ref": "cs-001"},
        }

    def eng_with(path, value):
        request = json.loads(json.dumps(engineering_request()))
        block = request
        keys = path.split(".")
        for key in keys[:-1]:
            block = block[key]
        block[keys[-1]] = value
        return request

    def host_leaf(request):
        return host_root / "engineering" / _t.engineering_hash(request)

    def guest_leaf(request):
        return guest_root + "/engineering/" + _t.engineering_hash(request)

    def write_completion(request, task_id, leaf,
                         artifact_text="def signal(**kwargs):\n    return [], None\n",
                         source_text=SOURCE_TEXT):
        leaf.mkdir(parents=True, exist_ok=True)

        def put(name, text):
            """Write one fixture file, replacing a leftover link instead of following it."""
            target = leaf / name
            if os.path.lexists(str(target)):
                target.unlink()
            target.write_text(text)
            return target

        put(_t.ENGINEERING_SOURCE_NAME, source_text)
        artifact = put(_t.ENGINEERING_ARTIFACT_NAME, artifact_text)
        spec_path = put(_t.ENGINEERING_SPEC_NAME,
                        json.dumps(_t.engineering_spec(request, _t.engineering_hash(request)),
                                   indent=2, sort_keys=True) + "\n")
        result = {
            "schema": _t.ENGINEERING_RESULT_SCHEMA,
            "request_hash": _t.engineering_hash(request),
            "task_id": task_id,
            "candidate": {"path": request["candidate_path"],
                          "source_commit": request["source_commit"],
                          "git_blob_sha": request["source_blob_sha"],
                          "family_id": request["family_id"]},
            "phase": request["phase"],
            "round_index": request["round_index"],
            "candidate_source": {"ref": _t.ENGINEERING_SOURCE_NAME,
                                 "git_blob_sha": request["source_blob_sha"]},
            "strategy_artifact": {"ref": _t.ENGINEERING_ARTIFACT_NAME, "sha256": sha(artifact)},
            "materialize_spec": {"ref": _t.ENGINEERING_SPEC_NAME, "sha256": sha(spec_path)},
            "status": "complete",
        }
        put(_t.ENGINEERING_RESULT_NAME, json.dumps(result, indent=2, sort_keys=True) + "\n")

    # The parser is the trust boundary: the Hermes key takes the two new verbs,
    # the Qlib key and the container forwarder take neither.
    seed_payload = b64(engineering_request())
    check("T27a the Hermes key accepts the two bounded engineering verbs",
          _t.parse_forced_command("research-engineering-create " + seed_payload, hermes=True)
          == ((_t.ENGINEERING_CREATE_VERB, seed_payload), None)
          and _t.parse_forced_command("research-engineering-read " + seed_payload, hermes=True)
          == ((_t.ENGINEERING_READ_VERB, seed_payload), None))
    check("T27b the Qlib key and the forwarder reject both engineering verbs",
          _t.parse_forced_command("research-engineering-create " + seed_payload)[0] is None
          and _t.parse_forced_command("research-engineering-read " + seed_payload)[0] is None
          and _t.build_forward_command(_t.ENGINEERING_CREATE_VERB, seed_payload) is None
          and _t.build_forward_command(_t.ENGINEERING_READ_VERB, seed_payload) is None)
    check("T27c shell chaining and extra tokens are rejected for the new verbs",
          _t.parse_forced_command("research-engineering-create " + seed_payload + "; touch evil",
                                  hermes=True)[0] is None
          and _t.parse_forced_command("cd / ; research-engineering-create " + seed_payload + " extra",
                                      hermes=True)[0] is None
          and _t.parse_forced_command("research-engineering-create " + seed_payload
                                      + " --board default", hermes=True)[0] is None
          and _t.parse_forced_command("research-engineering-create " + seed_payload + " | tee x",
                                      hermes=True)[0] is None)
    check("T27d research-hermes and research-handoff are unchanged",
          _t.parse_forced_command("research-hermes " + seed_payload, hermes=True)
          == ((_t.HERMES_VERB, seed_payload), None)
          and _t.parse_forced_command("research-handoff " + seed_payload, hermes=True)
          == ((_t.HANDOFF_VERB, seed_payload), None))
    check("T27e the Qlib forced verb set is unchanged",
          set(_t.FORCED_VERBS) == {"research-submit", "research-readback", "research-materialize"},
          str(_t.FORCED_VERBS))

    for label, raw in (
        ("malformed base64", "!!!!"),
        ("malformed JSON", base64.b64encode(b"{").decode()),
        ("a non-object payload", b64([1, 2, 3])),
        ("an unknown field", b64(dict(engineering_request(), board="default"))),
        ("a missing field", b64({k: v for k, v in engineering_request().items()
                                 if k != "family_id"})),
    ):
        rc, out = eng_forced("research-engineering-create " + raw)
        check("T27f create rejects " + label, rc == 2 and '"ok": false' in out, out)

    rc, out = eng_create(dict(engineering_request(), phase="OOS"))
    check("T27g an OOS phase never triggers engineering",
          rc == 2 and "phase is not one of" in out, out)

    for label, runtime in (
        ("commit", {"commit": "d" * 40}),
        ("image", {"commit": _t.FIXED_RUNTIME_COMMIT, "image": "qlib:other"}),
        ("digest", {"commit": _t.FIXED_RUNTIME_COMMIT, "image_digest": "sha256:" + "0" * 64}),
    ):
        rc, out = eng_create(eng_with("spec_seed.runtime", runtime))
        check("T27h create rejects a runtime " + label + " that disagrees with the pin",
              rc == 2 and "does not match the pinned runtime" in out, out)

    for label, over in (
        ("traversal", {"candidate_path": "../evil.md"}),
        ("absolute", {"candidate_path": "/etc/evil.md"}),
        ("non-markdown", {"candidate_path": "evil.py"}),
        ("a space", {"candidate_path": "bad name.md"}),
        ("a backtick", {"candidate_path": "candidate` AUDITOR_PROBE_ONLY `.md"}),
        ("a quote", {"candidate_path": 'cand"idate.md'}),
        ("a newline", {"candidate_path": "cand\nidate.md"}),
        ("a tab", {"candidate_path": "cand\tidate.md"}),
        ("a shell metacharacter", {"candidate_path": "cand$(id);.md"}),
        ("a leading dash", {"candidate_path": "-candidate.md"}),
        ("an overlong name", {"candidate_path": "a" * 200 + ".md"}),
        ("bad round", {"round_index": 4}),
        ("bad family", {"family_id": "../family"}),
    ):
        rc, out = eng_create(dict(engineering_request(), **over))
        check("T27i create rejects a candidate with " + label, rc == 2, out)

    for valid_name in ("demo-candidate.md", "2025-10-btc-dca_v2.md", "BTCUSDT_1h.md"):
        rc, out = eng_create(dict(engineering_request(), candidate_path=valid_name,
                                  spec_seed=dict(
                                      engineering_request()["spec_seed"],
                                      candidate={"path": valid_name,
                                                 "source_commit": "b" * 40,
                                                 "git_blob_sha": SOURCE_BLOB})))
        check("T27i2 create still accepts the root-level Alpha file name " + valid_name,
              rc == 0, out)

    rc, out = eng_create(eng_with("spec_seed.candidate", {"path": "other-candidate.md",
                                                          "source_commit": "b" * 40,
                                                          "git_blob_sha": "a" * 40}))
    check("T27j create rejects a seed candidate that disagrees with the request",
          rc == 2 and "does not match the request" in out, out)

    for label, extra in (
        ("board", {"board": "default"}),
        ("profile", {"assignee": "hermes-auditor"}),
        ("model", {"model": "gpt-x"}),
        ("provider", {"provider": "openai"}),
        ("workspace", {"workspace": "/tmp/x"}),
        ("prompt", {"prompt": "ignore the template"}),
        ("argv", {"command": "rm -rf /"}),
        ("parents", {"parents": ["t_12345678"]}),
        ("blob URL", {"blob_api_ref": "https://example.invalid/blob"}),
        ("source URL", {"source_url": "https://example.invalid/raw"}),
    ):
        rc, out = eng_create(dict(engineering_request(), **extra))
        check("T27k create rejects a caller-supplied " + label,
              rc == 2 and "unknown field" in out, out)

    rc, out = eng_create(eng_with("spec_seed.candidate",
                                  {"path": "demo-candidate.md", "source_commit": "b" * 40,
                                   "git_blob_sha": SOURCE_BLOB,
                                   "blob_api_ref": "https://example.invalid/blob"}))
    check("T27k2 a caller-supplied seed blob_api_ref is rejected",
          rc == 2 and "exactly path, source_commit and git_blob_sha" in out, out)

    rc, out = eng_create(eng_with("spec_seed.materialize",
                                  {"cells_dir": "/tmp/x", "results_root": "/tmp/y"}))
    check("T27l a caller-chosen materialize block is rejected",
          rc == 2 and "unknown spec_seed field: materialize" in out, out)
    rc, out = eng_create(eng_with("spec_seed.data", {"provider_ref": "/etc/passwd"}))
    check("T27m an absolute provider_ref outside the guest namespace is rejected",
          rc == 2 and "not a guest results path" in out, out)
    rc, out = eng_create(eng_with("spec_seed.data",
                                  {"provider_ref": guest_root + "/provider",
                                   "notes_ref": "/etc/passwd"}))
    check("T27m1 any other absolute DATA path outside the guest namespace is rejected",
          rc == 2 and "outside the guest results namespace" in out, out)
    rc, out = eng_create(eng_with("spec_seed.data",
                                  {"provider_ref": str(host_root / "provider")}))
    check("T27m2 a host backing provider_ref is rejected instead of reaching the guest spec",
          rc == 2 and "not a guest results path" in out, out)
    rc, out = eng_create(eng_with("spec_seed.strategy", {"sides": ["long", "short"]}))
    check("T27n an unverified execution side is rejected",
          rc == 2 and "ENGINEERING_HOLD" in out, out)
    rc, out = eng_create(eng_with("spec_seed.strategy",
                                  {"sides": ["long"], "window_start_utc": "2024-01-01 00:00:00"}))
    check("T27o a seed window that disagrees with the frozen window is rejected",
          rc == 2 and "frozen window" in out, out)

    good = engineering_request()
    good_leaf = host_leaf(good)
    rc, out = eng_create(good)
    created = json.loads(out) if out.startswith("{") else {}
    after_create = read_store()
    create_call = after_create["calls"][-1] if after_create["calls"] else []
    check("T27p create submits through the fixed Kanban argv only",
          rc == 0 and created.get("status") == "submitted"
          and create_call[:4] == ["kanban", "--board", "quant-strategy-research", "create"]
          and create_call[4] == _t.engineering_title(good, created.get("request_hash"))
          and "--body-file" in create_call and "-" in create_call
          and create_call[create_call.index("--assignee") + 1] == "default"
          and create_call[create_call.index("--workspace") + 1] == "dir:" + str(good_leaf)
          and create_call[create_call.index("--idempotency-key") + 1]
          == created.get("idempotency_key")
          and create_call[create_call.index("--max-runtime") + 1] == str(_t.ENGINEERING_MAX_RUNTIME)
          and create_call[create_call.index("--created-by") + 1] == _t.ENGINEERING_CREATED_BY
          and create_call[create_call.index("--completion-contract") + 1] == "local-only"
          and not any(flag in create_call for flag in
                      ("--model", "--provider", "--parent", "--skill", "--project")),
          str(create_call))
    task = after_create["tasks"][created["task_id"]]
    check("T27q the task is bounded to the derived host workspace and the fixed board",
          task["assignee"] == "default" and task["workspace_kind"] == "dir"
          and task["workspace_path"] == str(good_leaf)
          and task["created_by"] == _t.ENGINEERING_CREATED_BY
          and task["max_runtime_seconds"] == _t.ENGINEERING_MAX_RUNTIME
          and task["completion_contract"] == "local-only"
          and task["model_override"] is None and task["provider_override"] is None
          and task["board"] == "quant-strategy-research", str(task))
    check("T27r the body is the fixed template plus escaped DATA",
          task["body"] == _t.engineering_task_body(good, created["request_hash"], str(host_root))
          and "Do not run OOS" in task["body"]
          and "strategy-artifact.py" in task["body"]
          and guest_leaf(good) in task["body"], task["body"][:200])
    check("T27s create writes only the derived leaf workspace",
          good_leaf.is_dir() and list(good_leaf.iterdir()) == []
          and all(len(name) == 64 and set(name) <= set("0123456789abcdef")
                  for name in (entry.name for entry in (host_root / "engineering").iterdir())),
          str([entry.name for entry in (host_root / "engineering").iterdir()]))

    before_repeat = read_store()
    rc, out = eng_create(good)
    again = json.loads(out) if out.startswith("{") else {}
    after_repeat = read_store()
    check("T27t a repeated create converges on the same task and workspace",
          rc == 0 and again.get("task_id") == created.get("task_id")
          and again.get("request_hash") == created.get("request_hash")
          and len(after_repeat["tasks"]) == len(before_repeat["tasks"]), str(again))

    outside = Path(tempfile.mkdtemp(prefix="transport-engineering-outside-"))
    link_request = engineering_request()
    link_request["family_id"] = "link-case"
    link_leaf = host_leaf(link_request)
    link_leaf.parent.mkdir(parents=True, exist_ok=True)
    link_leaf.symlink_to(outside)
    rc, out = eng_create(link_request)
    check("T27u a symlinked leaf workspace fails closed without an outside write",
          rc == 2 and "not a real directory" in out and not list(outside.iterdir()), out)

    dangling = Path(tempfile.mkdtemp(prefix="transport-engineering-dangling-"))
    (dangling / "results").mkdir()
    (dangling / "results" / "production").mkdir()
    (dangling / "results" / "production" / "engineering").symlink_to(dangling / "missing")
    rc, out = eng_create(engineering_request(),
                         env=eng_env(RESEARCH_HOST_RESULTS_SOURCE=str(dangling / "results")))
    check("T27v a dangling engineering-root symlink fails closed",
          rc == 2 and "not a real directory" in out and not (dangling / "missing").exists(), out)

    rc, out = eng_create(good, env=eng_env(RESEARCH_HERMES_CLI=str(eng / "not-executable")))
    check("T27w an unusable CLI override fails closed instead of using the live board",
          rc == 2 and "Hermes CLI is not available" in out, out)

    read_payload = {"request": "engineering-read-v1", "engineering": good,
                    "task_id": created["task_id"]}
    rc, out = eng_read(read_payload)
    state = json.loads(out) if out.startswith("{") else {}
    check("T27x a ready task reads as typed pending, never ready",
          rc == 0 and state.get("ready") is False and state.get("status") == "pending"
          and state.get("task_id") == created["task_id"]
          and state.get("workspace") == str(good_leaf), out)

    data = read_store()
    data["tasks"][created["task_id"]]["status"] = "blocked"
    data["tasks"][created["task_id"]]["last_failure_error"] = "worker stopped"
    write_store(data)
    rc, out = eng_read(read_payload)
    state = json.loads(out) if out.startswith("{") else {}
    check("T27y a blocked task reads as typed blocked",
          rc == 0 and state.get("status") == "blocked" and state.get("ready") is False
          and "worker stopped" in str(state.get("reason")), out)
    data["tasks"][created["task_id"]]["status"] = "archived"
    write_store(data)
    rc, out = eng_read(read_payload)
    state = json.loads(out) if out.startswith("{") else {}
    check("T27y2 an archived task reads as typed failed",
          rc == 0 and state.get("status") == "failed" and state.get("ready") is False, out)
    data["tasks"][created["task_id"]]["status"] = "running"
    data["runs"][created["task_id"]] = [{"id": 1, "status": "running",
                                         "started_at": 1, "ended_at": None}]
    write_store(data)
    rc, out = eng_read(read_payload)
    state = json.loads(out) if out.startswith("{") else {}
    check("T27y3 a running task past its bounded runtime reads as typed timeout",
          rc == 0 and state.get("status") == "timeout" and state.get("ready") is False, out)

    data["tasks"][created["task_id"]]["status"] = "done"
    data["tasks"][created["task_id"]]["workspace_path"] = str(outside)
    write_store(data)
    rc, out = eng_read(read_payload)
    check("T27z a task whose workspace is not the derived one fails closed",
          rc == 2 and "derived workspace" in out, out)
    data["tasks"][created["task_id"]]["workspace_path"] = str(good_leaf)
    data["tasks"][created["task_id"]]["created_by"] = "someone-else"
    write_store(data)
    rc, out = eng_read(read_payload)
    check("T27z2 a task created by another author fails closed",
          rc == 2 and "not created by this adapter" in out, out)
    data["tasks"][created["task_id"]]["created_by"] = _t.ENGINEERING_CREATED_BY
    write_store(data)
    other = engineering_request()
    other["family_id"] = "other-family"
    rc, out = eng_read({"request": "engineering-read-v1", "engineering": other,
                        "task_id": created["task_id"]})
    check("T27z3 a task id from another request fails closed",
          rc == 2 and "does not match" in out, out)

    for label, payload in (
        ("a foreign request kind", {"request": "engineering-task-v1", "engineering": good,
                                    "task_id": created["task_id"]}),
        ("a bad task id", {"request": "engineering-read-v1", "engineering": good,
                           "task_id": "../../etc/passwd"}),
        ("an extra field", {"request": "engineering-read-v1", "engineering": good,
                            "task_id": created["task_id"], "board": "default"}),
        ("a missing task id", {"request": "engineering-read-v1", "engineering": good}),
    ):
        rc, out = eng_read(payload)
        check("T27aa read rejects " + label, rc == 2, out)

    rc, out = eng_read(read_payload, env=eng_env(FAKE_KANBAN_STORE=str(eng / "empty-store.json")))
    check("T27ab an unknown task id fails closed", rc == 2 and "Kanban call failed" in out, out)

    rc, out = eng_read(read_payload)
    check("T27ac a done task without engineering-result.json fails closed",
          rc == 2 and "engineering-result.json" in out, out)

    write_completion(good, created["task_id"], good_leaf)
    rc, out = eng_read(read_payload)
    ready = json.loads(out) if out.startswith("{") else {}
    check("T27ad a valid isolated completion becomes ready with exact verified refs",
          rc == 0 and ready.get("ready") is True and ready.get("status") == "done"
          and ready.get("spec_ref") == guest_leaf(good) + "/" + _t.ENGINEERING_SPEC_NAME
          and ready.get("spec_sha256") == sha(good_leaf / _t.ENGINEERING_SPEC_NAME)
          and ready.get("strategy_artifact_ref")
          == guest_leaf(good) + "/" + _t.ENGINEERING_ARTIFACT_NAME
          and ready.get("strategy_artifact_sha256")
          == sha(good_leaf / _t.ENGINEERING_ARTIFACT_NAME)
          and ready.get("cells_root") == guest_leaf(good) + "/" + _t.ENGINEERING_FROZEN_NAME
          and ready.get("results_root") == guest_root
          and ready.get("request_hash") == _t.engineering_hash(good), out)
    check("T27ae the verified refs are guest paths for research-materialize",
          str(ready.get("spec_ref", "")).startswith("/results/")
          and str(ready.get("strategy_artifact_ref", "")).startswith("/results/")
          and str(ready.get("workspace", "")).startswith(str(host_root)), str(ready))

    derived = _t.engineering_spec(good, _t.engineering_hash(good))
    check("T27ae2 the derived cells root is a dedicated empty child, not the workspace",
          derived["materialize"]["cells_dir"]
          == guest_leaf(good) + "/" + _t.ENGINEERING_FROZEN_NAME
          and derived["materialize"]["cells_dir"] != guest_leaf(good)
          and derived["materialize"]["results_root"] == guest_root
          and derived["strategy_artifact"]["source"]
          == guest_leaf(good) + "/" + _t.ENGINEERING_ARTIFACT_NAME, str(derived["materialize"]))

    spec_path = good_leaf / _t.ENGINEERING_SPEC_NAME
    result_path = good_leaf / _t.ENGINEERING_RESULT_NAME
    source_path = good_leaf / _t.ENGINEERING_SOURCE_NAME

    # T27ae3.. Source authority (B1): the completion is valid only when the
    # workspace carries the exact immutable blob bytes, and the fixed template
    # has to say so in the rendered body.
    body = _t.engineering_task_body(good, _t.engineering_hash(good), str(host_root))
    prose = body.split("## DATA")[0]
    check("T27ae3 the fixed template renders the derived blob URL and the source file",
          (_t.CANDIDATE_BLOB_API + good["source_blob_sha"]) in body
          and _t.ENGINEERING_SOURCE_NAME in prose, prose[:300])
    check("T27ae4 the fixed template renders the fail-closed source-read instructions",
          "block the task" in prose.lower()
          and "write no `engineering-result.json`" in " ".join(prose.split())
          and "Never infer strategy logic" in " ".join(prose.split()), prose[:300])
    check("T27ae5 no caller value reaches the instruction prose",
          good["candidate_path"] not in prose, prose[:300])
    check("T27ae6 the ready reply names the verified source evidence",
          ready.get("source_ref") == guest_leaf(good) + "/" + _t.ENGINEERING_SOURCE_NAME
          and ready.get("source_blob_sha") == good["source_blob_sha"], str(ready))
    check("T27ae7 the frozen spec keeps the guest provider_ref",
          derived["data"]["provider_ref"] == guest_root + "/provider"
          and str(derived["data"]["provider_ref"]).startswith("/results/production/"),
          str(derived["data"]))
    check("T27ae8 the blob id is the canonical Git object id of the exact bytes",
          _t.git_blob_sha1(SOURCE_BYTES) == SOURCE_BLOB
          and len(SOURCE_BLOB) == 40 and _t.git_blob_sha1(b"") == "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391",
          SOURCE_BLOB)

    write_completion(good, created["task_id"], good_leaf)
    source_path.unlink()
    rc, out = eng_read(read_payload)
    check("T27ae9 a completion with no candidate-source.md fails closed",
          rc == 2 and _t.ENGINEERING_SOURCE_NAME in out and '"ready": true' not in out, out)

    write_completion(good, created["task_id"], good_leaf, source_text="# a different body\n")
    rc, out = eng_read(read_payload)
    check("T27ae10 candidate-source.md with the wrong bytes fails closed",
          rc == 2 and "does not reproduce the pinned blob" in out, out)

    write_completion(good, created["task_id"], good_leaf)
    result = json.loads(result_path.read_text())
    result["candidate_source"] = {"ref": _t.ENGINEERING_SOURCE_NAME, "git_blob_sha": "0" * 40}
    result_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    rc, out = eng_read(read_payload)
    check("T27ae11 a result that declares another source blob fails closed",
          rc == 2 and "candidate_source" in out, out)

    write_completion(good, created["task_id"], good_leaf)
    copy_source = eng / "source-copy.md"
    copy_source.write_bytes(source_path.read_bytes())
    source_path.unlink()
    source_path.symlink_to(copy_source)
    rc, out = eng_read(read_payload)
    check("T27ae12 a symlinked candidate-source.md fails closed",
          rc == 2 and "not a regular file" in out, out)
    write_completion(good, created["task_id"], good_leaf)

    # T27af0.. A present result is evidence under contract for every task
    # status (B2). Only ``done`` promotes.
    def store_status(status, runs=None):
        store = read_store()
        store["tasks"][created["task_id"]]["status"] = status
        store["runs"][created["task_id"]] = runs or []
        write_store(store)

    for status in ("ready", "running", "blocked", "archived"):
        write_completion(good, created["task_id"], good_leaf)
        result = json.loads(result_path.read_text())
        result["schema"] = "not-the-schema"
        result_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        store_status(status)
        rc, out = eng_read(read_payload)
        check("T27af0 a malformed present result fails closed while the task is " + status,
              rc == 2 and "schema is not" in out, out)

    write_completion(good, created["task_id"], good_leaf)
    for status in ("ready", "running", "blocked", "archived"):
        store_status(status)
        rc, out = eng_read(read_payload)
        state = json.loads(out) if out.startswith("{") else {}
        check("T27af00 a valid present result on a " + status + " task stays non-ready",
              rc == 0 and state.get("ready") is False
              and state.get("status") in ("pending", "blocked", "failed", "timeout"), out)
    store_status("done")
    write_completion(good, created["task_id"], good_leaf)

    def spec_case(label, mutate, expect):
        write_completion(good, created["task_id"], good_leaf)
        spec = json.loads(spec_path.read_text())
        mutate(spec)
        spec_path.write_text(json.dumps(spec, indent=2, sort_keys=True) + "\n")
        result = json.loads(result_path.read_text())
        result["materialize_spec"]["sha256"] = sha(spec_path)
        result_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        rc, out = eng_read(read_payload)
        check("T27af " + label, rc == 2 and expect in out, out)
        write_completion(good, created["task_id"], good_leaf)

    spec_case("a changed spec window fails closed",
              lambda spec: spec["strategy"].__setitem__("window_end_utc_inclusive",
                                                        "2024-12-31 00:00:00"),
              "window")
    spec_case("a changed house overlay fails closed",
              lambda spec: spec["house_overlay"].__setitem__("trade_cost", 0.01234),
              "frozen request")
    spec_case("a changed spec candidate fails closed",
              lambda spec: spec["candidate"].__setitem__("path", "other-candidate.md"),
              "candidate.path does not match the request")
    spec_case("a changed spec runtime fails closed",
              lambda spec: spec["runtime"].__setitem__("commit", "d" * 40),
              "runtime.commit does not match the request")
    spec_case("a cells root that is the workspace fails closed",
              lambda spec: spec["materialize"].__setitem__("cells_dir", guest_leaf(good)),
              "not the derived cells directory")
    spec_case("a results root outside production fails closed",
              lambda spec: spec["materialize"].__setitem__("results_root", "/results/other"),
              "results_root is not the approved results root")
    spec_case("an artifact source outside the workspace fails closed",
              lambda spec: spec["strategy_artifact"].__setitem__(
                  "source", guest_leaf(good) + "/other-artifact.py"),
              "does not resolve to the verified artifact")
    spec_case("an OOS spec phase fails closed",
              lambda spec: spec.__setitem__("phase", "OOS"),
              "phase")
    # B3: every block shape is validated before any mapping access, so a wrong
    # type is the same typed rejection and never an AttributeError traceback.
    for label, mutate, expect in (
        ("a strategy_artifact list", lambda spec: spec.__setitem__("strategy_artifact", ["invalid"]),
         "strategy_artifact block is not a JSON object"),
        ("a materialize list", lambda spec: spec.__setitem__("materialize", ["invalid"]),
         "materialize block is not a JSON object"),
        ("a candidate list", lambda spec: spec.__setitem__("candidate", ["invalid"]),
         "candidate block is not a JSON object"),
        ("a data string", lambda spec: spec.__setitem__("data", "invalid"),
         "data block is not a JSON object"),
        ("a house_overlay list", lambda spec: spec.__setitem__("house_overlay", []),
         "house_overlay block is not a JSON object"),
        ("a phase integer", lambda spec: spec.__setitem__("phase", 7),
         "phase is not a string"),
    ):
        spec_case("a malformed spec with " + label + " fails closed as typed JSON",
                  mutate, expect)

    write_completion(good, created["task_id"], good_leaf)
    (good_leaf / _t.ENGINEERING_ARTIFACT_NAME).write_text("def signal(**kwargs):\n    return [], 0\n")
    rc, out = eng_read(read_payload)
    check("T27ag tampered artifact bytes fail closed",
          rc == 2 and "bytes do not match" in out, out)

    write_completion(good, created["task_id"], good_leaf)
    result = json.loads(result_path.read_text())
    result["request_hash"] = "0" * 64
    result_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    rc, out = eng_read(read_payload)
    check("T27ah a result that names another request fails closed",
          rc == 2 and "request hash" in out, out)

    write_completion(good, created["task_id"], good_leaf)
    copy_path = eng / "artifact-copy.py"
    copy_path.write_bytes((good_leaf / _t.ENGINEERING_ARTIFACT_NAME).read_bytes())
    (good_leaf / _t.ENGINEERING_ARTIFACT_NAME).unlink()
    (good_leaf / _t.ENGINEERING_ARTIFACT_NAME).symlink_to(copy_path)
    rc, out = eng_read(read_payload)
    check("T27ai a symlinked strategy artifact fails closed",
          rc == 2 and "not a regular file" in out, out)
    write_completion(good, created["task_id"], good_leaf)

    # Fresh Start: the host backing root exists and ``production`` does not.
    # Read must never create it, and one valid create builds only the
    # deterministic chain.
    fresh_backing = eng / "fresh-results"
    fresh_backing.mkdir()
    fresh_host_root = Path(os.path.realpath(str(fresh_backing))) / "production"
    fresh_request = engineering_request()
    fresh_request["family_id"] = "fresh-case"
    fresh_hash = _t.engineering_hash(fresh_request)
    fresh_leaf = fresh_host_root / "engineering" / fresh_hash
    fresh_store = eng / "fresh-store.json"
    fresh_store.write_text(json.dumps({
        "tasks": {"t_0000beef": {
            "id": "t_0000beef",
            "title": _t.engineering_title(fresh_request, fresh_hash),
            "body": _t.engineering_task_body(fresh_request, fresh_hash, str(fresh_host_root)),
            "assignee": "default", "status": "done", "workspace_kind": "dir",
            "workspace_path": str(fresh_leaf), "created_by": _t.ENGINEERING_CREATED_BY,
            "max_runtime_seconds": _t.ENGINEERING_MAX_RUNTIME,
            "model_override": None, "provider_override": None,
            "completion_contract": "local-only", "last_failure_error": None,
        }},
        "runs": {"t_0000beef": []}, "calls": [], "idem": {},
    }))
    fresh_env = eng_env(RESEARCH_HOST_RESULTS_SOURCE=str(fresh_backing),
                        FAKE_KANBAN_STORE=str(fresh_store))
    rc, out = eng_read({"request": "engineering-read-v1", "engineering": fresh_request,
                        "task_id": "t_0000beef"}, env=fresh_env)
    check("T27ak read never creates the production chain",
          rc == 2 and "does not exist" in out and list(fresh_backing.iterdir()) == [], out)
    rc, out = eng_create(fresh_request, env=fresh_env)
    check("T27al create builds only production/engineering/<hash> under an existing backing root",
          rc == 0
          and sorted(path.relative_to(fresh_backing).as_posix()
                     for path in fresh_backing.rglob("*"))
          == ["production", "production/engineering", "production/engineering/" + fresh_hash],
          "%s %s" % (out, sorted(path.as_posix() for path in fresh_backing.rglob("*"))))

    sym_backing = eng / "sym-results"
    sym_backing.mkdir()
    sym_target = Path(tempfile.mkdtemp(prefix="transport-engineering-production-target-"))
    (sym_backing / "production").symlink_to(sym_target)
    rc, out = eng_create(engineering_request(),
                         env=eng_env(RESEARCH_HOST_RESULTS_SOURCE=str(sym_backing),
                                     FAKE_KANBAN_STORE=str(eng / "sym-store.json")))
    check("T27am a symlinked production root fails closed without an outside write",
          rc == 2 and "not a real directory" in out and not list(sym_target.iterdir()), out)

    with patch.dict(os.environ, eng_env()), \
         patch.object(_t.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "{}", "")) as child, \
         contextlib.redirect_stdout(io.StringIO()):
        _t.cmd_engineering_create(b64(good))
        create_argv = child.call_args[0][0]
        _t.cmd_engineering_read(b64(read_payload))
        read_argv = child.call_args[0][0]
    check("T27aj create and read start only the fixed Kanban verbs",
          create_argv == [str(fake_cli), "kanban", "--board", "quant-strategy-research",
                          "create"] + create_argv[5:]
          and create_argv[5] == _t.engineering_title(good, _t.engineering_hash(good))
          and read_argv == [str(fake_cli), "kanban", "--board", "quant-strategy-research",
                            "show", created["task_id"], "--json"],
          "%s %s" % (create_argv, read_argv))

    print("%d checks passed" % len(CHECKS))
    print("ALL THIN CHECKS PASSED")


if __name__ == "__main__":
    main()
