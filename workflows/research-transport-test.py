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
(out / "summary.json").write_text(json.dumps({"cycles_replayed": __CYCLES__}))
(out / "metrics.json").write_text(json.dumps({"total_trades": __TRADES__}))
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


def run(cmd, *args, root=None):
    env = dict(os.environ)
    if root is not None:
        env["RESEARCH_RESULTS_ROOT"] = str(root)
    proc = subprocess.run(
        [sys.executable, str(TRANSPORT), cmd, *args],
        env=env, capture_output=True, text=True, timeout=120,
    )
    return proc.returncode, proc.stdout.strip()


def b64(obj):
    return base64.b64encode(json.dumps(obj).encode()).decode()


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


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
    check("T13d forced verbs are research-only",
          set(_t.FORCED_VERBS) == {"research-submit", "research-readback"}, str(_t.FORCED_VERBS))
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
    check("T17d the Qlib verb set is unchanged",
          set(_t.FORCED_VERBS) == {"research-submit", "research-readback"}, str(_t.FORCED_VERBS))
    check("T17e the transport imports no strategy code and starts no subprocess",
          not hasattr(_t, "cmd_materialize") and not hasattr(_t, "artifact_source")
          and not hasattr(_t, "ARTIFACT_SMOKE") and "importlib" not in Path(_t.__file__).read_text())
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

    print("%d checks passed" % len(CHECKS))
    print("ALL THIN CHECKS PASSED")


if __name__ == "__main__":
    main()
