#!/usr/bin/env python3
"""Deterministic contract checks for research-transport.py. Stdlib only.

Run: python3 research-transport-test.py. Exit 0 means every check passed.
Each case runs the real transport in a temp results root; the golden submit
path runs a stub native entrypoint that honors the same on-disk contract
(summary/signals/events + mlflow_readback/manifest, refuse overwrite).
"""

import base64
import hashlib
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

STUB_ENTRYPOINT = """\
import hashlib, json, os, sys
from pathlib import Path
out = Path(os.environ["QLIB_OUT_DIR"])
if out.exists():
    sys.exit("refuse overwrite")
(out / "mlruns" / EXP / RUN / "artifacts" / "backtest").mkdir(parents=True)
(out / "mlruns" / EXP / RUN / "artifacts" / "repro").mkdir(parents=True)
(out / "summary.json").write_text(json.dumps({"evaluation_rows_including_force_flat": 10}))
(out / "signals.csv").write_text("a\\n" + "1\\n")
(out / "events.csv").write_text("a\\n" + "1\\n")
cfg = {"candidate_path": CAND, "git_blob_sha": BLOB}
(out / "mlruns" / EXP / RUN / "artifacts" / "repro" / "effective_config.json").write_text(json.dumps(cfg))
(out / "mlruns" / EXP / RUN / "artifacts" / "repro" / "provider-manifest.json").write_text("{}")
(out / "mlruns" / EXP / RUN / "artifacts" / "repro" / "STUB.py").write_text("# stub\\n")
(out / "mlruns" / EXP / RUN / "artifacts" / "backtest" / "a.csv").write_text("x\\n")
readback = {"tracking_uri": "file://x", "experiment_id": EXP, "run_id": RUN,
            "status": "FINISHED", "params": {"qlib_version": "t", "symbol": "s", "frequency": "f"},
            "metrics": {"m": 1.0}, "artifact_names": ["backtest/a.csv",
            "repro/effective_config.json", "repro/provider-manifest.json", "repro/STUB.py"]}
(out / "mlflow_readback.json").write_text(json.dumps(readback, sort_keys=True))
manifest = {}
for p in sorted(out.rglob("*")):
    if p.is_file() and "mlruns" not in p.parts and p.name != "manifest.json":
        manifest[str(p.relative_to(out))] = {"bytes": p.stat().st_size,
            "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
(out / "manifest.json").write_text(json.dumps(manifest, sort_keys=True))
print(json.dumps({"summary": {"ok": True}, "mlflow": readback, "manifest": manifest}))
"""


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
        "data": ["btcusdt-1h"],
        "timing": ["bar-close-1h"],
    }
    if cost:
        handoff["run_inputs"] = {"symbol": "BTCUSDT"}
    return handoff


def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name + (" " + str(extra) if extra and not cond else ""))
    if not cond:
        raise SystemExit("FAILED: " + name + " " + str(extra))


def main():
    tmp = Path(tempfile.mkdtemp(prefix="transport-test-"))
    entry = tmp / "run_stub.entrypoint.py"
    config = tmp / "effective_config.json"
    config.write_text('{"stub": true}')
    entry.write_text(
        STUB_ENTRYPOINT.replace("EXP", '"%s"' % EXP_ID)
        .replace("RUN", '"%s"' % RUN_ID)
        .replace("CAND", '"demo-candidate.md"')
        .replace("BLOB", '"%s"' % ("a" * 40))
    )

    rc, out = run("submit", "!!!not-base64!!!", root=tmp)
    check("T1 malformed base64 fails closed", rc == 2 and '"ok": false' in out, out)

    bad = make_handoff(tmp, entry, config)
    bad["evil"] = 1
    rc, out = run("submit", b64(bad), root=tmp)
    check("T2a unknown field fails closed", rc == 2, out)
    bad = make_handoff(tmp, entry, config)
    bad["entrypoint_ref"] = "/tmp/../evil.py"
    rc, out = run("submit", b64(bad), root=tmp)
    check("T2b parent-hop path fails closed", rc == 2, out)
    bad = make_handoff(tmp, entry, config)
    bad["entrypoint_sha256"] = "zz"
    rc, out = run("submit", b64(bad), root=tmp)
    check("T2c bad hash shape fails closed", rc == 2, out)

    bad = make_handoff(tmp, entry, config,
                        caps={"execution": ["future-engine"], "data": ["btcusdt-1h"], "timing": ["bar-close-1h"]})
    rc, out = run("submit", b64(bad), root=tmp)
    check("T3 unknown capability holds without executing",
          rc == 2 and "ENGINEERING_HOLD" in out and not list(tmp.glob("n8n-live-*")), out)

    bad = make_handoff(tmp, entry, config)
    bad["entrypoint_sha256"] = "0" * 64
    rc, out = run("submit", b64(bad), root=tmp)
    check("T4 hash mismatch fails before executing",
          rc == 2 and "mismatch" in out and not list(tmp.glob("n8n-live-*")), out)

    good = make_handoff(tmp, entry, config)
    rc, out = run("research-submit", b64(good), root=tmp)
    receipt = json.loads(out) if rc == 0 else {}
    check("T5 golden submit prints Node04 receipt",
          rc == 0 and receipt.get("node04") == "PASS" and receipt.get("run_id") == RUN_ID
          and receipt.get("entrypoint_sha256") == sha(entry), out)
    out_dir = Path(receipt["out_dir"])
    check("T5 submit receipt persisted", (out_dir / "submit-receipt.json").is_file())
    rc, out = run("submit", b64(good), root=tmp)
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

    rc, out = run("readback", "zz", root=tmp)
    check("T7a malformed run_id fails closed", rc == 2, out)
    rc, out = run("readback", "00" * 16, root=tmp)
    check("T7b unknown run_id fails closed", rc == 2, out)

    tampered = {"run_id": RUN_ID, "status": "FINISHED", "experiment_id": EXP_ID,
                "params": {"a": "b"}, "metrics": {"m": 2.0}, "artifact_names": ["x"]}
    (out_dir / "mlflow_readback.json").write_text(json.dumps(tampered))
    rc, out = run("readback", RUN_ID, root=tmp)
    check("T8 tampered readback fails closed", rc == 2 and "mismatch" in out, out)

    print("ALL DETERMINISTIC CHECKS PASSED")


if __name__ == "__main__":
    main()
