#!/usr/bin/env python3
"""Deterministic contract checks for research-transport.py. Stdlib only.

Run: python3 research-transport-test.py. Exit 0 means every check passed.
Each case runs the real transport in a temp results root; the golden submit
path runs a stub native entrypoint that honors the same on-disk contract
(summary/signals/events + mlflow_readback/manifest + native
params/metrics/meta.yaml/artifact inventory, refuse overwrite).
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
(out / "mlruns" / EXP / RUN / "params").mkdir(parents=True)
(out / "mlruns" / EXP / RUN / "metrics").mkdir(parents=True)
(out / "summary.json").write_text(json.dumps({"evaluation_rows_including_force_flat": 10}))
(out / "signals.csv").write_text("a\\n" + "1\\n")
(out / "events.csv").write_text("a\\n" + "1\\n")
frozen_cfg = {"candidate": {"path": CAND, "git_blob_sha": BLOB},
              "execution": {"entrypoint": str(Path(__file__))},
              "runtime": {"commit": "c" * 40}}
(out / "mlruns" / EXP / RUN / "artifacts" / "repro" / "effective_config.json").write_text(
    json.dumps(frozen_cfg, sort_keys=True))
(out / "mlruns" / EXP / RUN / "artifacts" / "repro" / "provider-manifest.json").write_text("{}")
(out / "mlruns" / EXP / RUN / "artifacts" / "repro" / "run_stub.entrypoint.py").write_bytes(
    Path(__file__).read_bytes())
(out / "mlruns" / EXP / RUN / "artifacts" / "backtest" / "a.csv").write_text("x\\n")
(out / "mlruns" / EXP / RUN / "params" / "qlib_version").write_text("t")
(out / "mlruns" / EXP / RUN / "params" / "symbol").write_text("s")
(out / "mlruns" / EXP / RUN / "params" / "frequency").write_text("f")
(out / "mlruns" / EXP / RUN / "metrics" / "m").write_text("1 1.0 0\\n")
meta_lines = ["run_id: " + RUN, "experiment_id: '" + EXP + "'",
              "status: 3", "lifecycle_stage: active", ""]
(out / "mlruns" / EXP / RUN / "meta.yaml").write_text("\\n".join(meta_lines))
readback = {"tracking_uri": "file://x", "experiment_id": EXP, "run_id": RUN,
            "status": "FINISHED", "params": {"qlib_version": "t", "symbol": "s", "frequency": "f"},
            "metrics": {"m": 1.0}, "artifact_names": ["backtest/a.csv",
            "repro/effective_config.json", "repro/provider-manifest.json", "repro/run_stub.entrypoint.py"]}
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


def write_stub_files(root, blob="a" * 40):
    """Write one frozen stub pair whose formal fields match make_handoff."""
    entry = root / "run_stub.entrypoint.py"
    config = root / "effective_config.json"
    config.write_text(json.dumps({
        "candidate": {"path": "demo-candidate.md", "git_blob_sha": blob},
        "execution": {"entrypoint": str(entry)},
        "runtime": {"commit": "c" * 40},
    }, sort_keys=True))
    entry.write_text(
        STUB_ENTRYPOINT.replace("EXP", '"%s"' % EXP_ID)
        .replace("RUN", '"%s"' % RUN_ID)
        .replace("CAND", '"demo-candidate.md"')
        .replace("BLOB", '"%s"' % blob)
    )
    return entry, config


def golden_submit():
    """Submit one bound stub handoff in a fresh root. Return (root, out_dir)."""
    root = Path(tempfile.mkdtemp(prefix="transport-neg-"))
    entry, config = write_stub_files(root)
    rc, out = run("submit", b64(make_handoff(root, entry, config)), root=root)
    if rc != 0:
        raise SystemExit("FAILED: golden setup submit " + out)
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

    neg = Path(tempfile.mkdtemp(prefix="transport-neg-"))
    entry, config = write_stub_files(neg)
    lying = json.loads(config.read_text())
    lying["candidate"] = {"path": "different-candidate.md", "git_blob_sha": "d" * 40}
    lying["runtime"] = {"commit": "d" * 40}
    config.write_text(json.dumps(lying))
    rc, out = run("submit", b64(make_handoff(neg, entry, config)), root=neg)
    check("T9a wrong-candidate config fails before executing",
          rc == 2 and "identity mismatch" in out and not list(neg.glob("n8n-live-*")), out)

    marker = neg / "marker_entry.py"
    seen = neg / "execution-marker.txt"
    marker.write_text("from pathlib import Path\nPath(" + repr(str(seen)) + ').write_text("x")\n')
    plain = neg / "plain_config.json"
    plain.write_text('{"stub": true}')
    rc, out = run("submit", b64(make_handoff(neg, marker, plain)), root=neg)
    check("T9b unbound in-root python never executes",
          rc == 2 and "identity" in out and not seen.exists()
          and not list(neg.glob("n8n-live-*")), out)

    g1, o1 = golden_submit()
    (o1 / "summary.json").write_text(json.dumps({"evaluation_rows_including_force_flat": 999}))
    rc, out = run("readback", RUN_ID, root=g1)
    check("T10a tampered manifested summary fails closed",
          rc == 2 and "mismatch" in out, out)

    g2, o2 = golden_submit()
    (o2 / "events.csv").unlink()
    rc, out = run("readback", RUN_ID, root=g2)
    check("T10b missing manifested evidence fails closed",
          rc == 2 and "mismatch" in out, out)

    g3, o3 = golden_submit()
    (o3 / "mlruns" / EXP_ID / RUN_ID / "metrics" / "m").write_text("1 2.0 0\n")
    rc, out = run("readback", RUN_ID, root=g3)
    check("T11a tampered native metric fails closed",
          rc == 2 and "native metrics mismatch" in out, out)

    g4, o4 = golden_submit()
    (o4 / "mlruns" / EXP_ID / RUN_ID / "meta.yaml").unlink()
    rc, out = run("readback", RUN_ID, root=g4)
    check("T11b missing native run metadata fails closed",
          rc == 2 and "native run metadata is missing" in out, out)

    g5, o5 = golden_submit()
    receipt = json.loads((o5 / "submit-receipt.json").read_text())
    receipt["experiment_id"] = "0"
    (o5 / "submit-receipt.json").write_text(json.dumps(receipt))
    rc, out = run("readback", RUN_ID, root=g5)
    check("T11c submit/receipt experiment drift fails closed",
          rc == 2 and "experiment identity mismatch" in out, out)

    g6, o6 = golden_submit()
    (o6 / "mlruns" / EXP_ID / RUN_ID / "artifacts" / "repro" / "run_stub.entrypoint.py").write_text("# replaced\n")
    rc, out = run("readback", RUN_ID, root=g6)
    check("T12a replaced repro entrypoint fails closed",
          rc == 2 and "repro/executable identity mismatch" in out, out)

    g7, o7 = golden_submit()
    repro_cfg_path = o7 / "mlruns" / EXP_ID / RUN_ID / "artifacts" / "repro" / "effective_config.json"
    repro_cfg = json.loads(repro_cfg_path.read_text())
    repro_cfg["candidate"] = {"path": "different-candidate.md", "git_blob_sha": "d" * 40}
    repro_cfg["note"] = "decoy " + "a" * 40 + " demo-candidate.md"
    repro_cfg_path.write_text(json.dumps(repro_cfg))
    rc, out = run("readback", RUN_ID, root=g7)
    check("T12b decoy-text repro candidate fails closed",
          rc == 2 and "repro/candidate identity mismatch" in out, out)

    g8, o8 = golden_submit()
    outside = g8 / "outside-evidence.py"
    outside.write_text("# harmless outside-root fixture\n")
    target = o8 / "mlruns" / EXP_ID / RUN_ID / "artifacts" / "repro" / "run_stub.entrypoint.py"
    target.unlink()
    target.symlink_to(outside)
    rc, out = run("readback", RUN_ID, root=g8)
    check("T13a repro symlink escape fails closed", rc == 2, out)

    g9, o9 = golden_submit()
    moved = g9.parent / (o9.name + "-outside")
    o9.rename(moved)
    o9.symlink_to(moved, target_is_directory=True)
    rc, out = run("readback", RUN_ID, root=g9)
    check("T13b whole-run symlink escape finds no run",
          rc == 2 and "unknown or ambiguous" in out, out)

    xroot = Path(tempfile.mkdtemp(prefix="transport-neg-"))
    xentry, xconfig = write_stub_files(xroot)
    xentry.write_text(xentry.read_text().replace(
        'print(json.dumps({"summary": {"ok": True}, "mlflow": readback, "manifest": manifest}))',
        'printed = dict(readback)\nprinted["experiment_id"] = "987654"\n'
        'print(json.dumps({"summary": {"ok": True}, "mlflow": printed, "manifest": manifest}))'))
    rc, out = run("submit", b64(make_handoff(xroot, xentry, xconfig)), root=xroot)
    check("T14 stdout/disk experiment split fails closed",
          rc == 2 and "experiment identity mismatch" in out
          and not list(xroot.glob("n8n-live-*/submit-receipt.json")), out)

    g10, o10 = golden_submit()
    rc, out = run_forced("cd / ; research-readback " + RUN_ID, g10)
    back = json.loads(out) if rc == 0 else {}
    check("T15a forced-command shape dispatches without argv",
          rc == 0 and back.get("node05") == "PASS", out)
    rc, out = run_forced("research-readback " + RUN_ID + "; touch evil", g10)
    check("T15b forced-command shell chaining fails closed", rc == 2, out)
    rc, out = run_forced("research-readback", g10)
    check("T15c forced-command bare verb fails closed", rc == 2, out)

    print("ALL DETERMINISTIC CHECKS PASSED")


if __name__ == "__main__":
    main()
