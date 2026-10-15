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

    # ponytail: B1 exact consumed file, not any sibling with matching fields.
    sroot = Path(tempfile.mkdtemp(prefix="transport-neg-"))
    sentry, scfg = write_stub_files(sroot)
    other = json.loads(scfg.read_text())
    other["candidate"] = {"path": "wrong-consumed-config.md", "git_blob_sha": "d" * 40}
    scfg.write_text(json.dumps(other))
    declared = sroot / "declared_config.json"
    declared.write_text(json.dumps({
        "candidate": {"path": "demo-candidate.md", "git_blob_sha": "a" * 40},
        "execution": {"entrypoint": str(sentry)}, "runtime": {"commit": "c" * 40},
    }, sort_keys=True))
    code = sentry.read_text()
    start = code.index("frozen_cfg = {")
    end = code.index("(out / \"mlruns\"", start)
    code = code[:start] + "frozen_cfg = json.loads(Path(__file__).with_name(\"effective_config.json\").read_text())\n" + code[end:]
    sentry.write_text(code)
    rc, out = run("submit", b64(make_handoff(sroot, sentry, declared)), root=sroot)
    check("T16a sibling decoy config fails before executing",
          rc == 2 and "identity mismatch" in out and not list(sroot.glob("n8n-live-*")), out)

    mroot = Path(tempfile.mkdtemp(prefix="transport-neg-"))
    mentry, mcfg = write_stub_files(mroot)
    seen = mroot / "execution-marker.txt"
    mentry.write_text("from pathlib import Path\nPath(" + repr(str(seen)) + ").write_text(\"x\")\n")
    rc, out = run("submit", b64(make_handoff(mroot, mentry, mcfg)), root=mroot)
    check("T16b unbound marker never executes",
          rc == 2 and "identity" in out and not seen.exists()
          and not list(mroot.glob("n8n-live-*")), out)

    # ponytail: B2 native bytes, not only inventory names.
    b1, ob1 = golden_submit()
    (ob1 / "mlruns" / EXP_ID / RUN_ID / "artifacts" / "backtest" / "a.csv").write_text("different\n")
    rc, out = run("readback", RUN_ID, root=b1)
    check("T17a tampered native backtest bytes fail closed",
          rc == 2 and "mismatch" in out, out)

    b2, ob2 = golden_submit()
    (ob2 / "mlruns" / EXP_ID / RUN_ID / "artifacts" / "backtest" / "unreported.csv").write_text("x\n")
    rc, out = run("readback", RUN_ID, root=b2)
    check("T17b unreported native artifact fails closed",
          rc == 2 and "inventory mismatch" in out, out)

    nroot = Path(tempfile.mkdtemp(prefix="transport-neg-"))
    nentry, ncfg = write_stub_files(nroot)
    nentry.write_text(nentry.read_text().replace(
        "print(json.dumps({\"summary\": {\"ok\": True}, \"mlflow\": readback, \"manifest\": manifest}))",
        "(out / \"mlruns\" / \"%s\" / \"%s\" / \"meta.yaml\").unlink()\nprint(json.dumps({\"summary\": {\"ok\": True}, \"mlflow\": readback, \"manifest\": manifest}))" % (EXP_ID, RUN_ID)))
    rc, out = run("submit", b64(make_handoff(nroot, nentry, ncfg)), root=nroot)
    check("T17c submit without native meta fails before PASS",
          rc == 2 and "metadata is missing" in out
          and not list(nroot.glob("n8n-live-*/submit-receipt.json")), out)

    # ponytail: B3 artifact directory root must stay inside its native run.
    droot, odir = golden_submit()
    nrun = odir / "mlruns" / EXP_ID / RUN_ID
    outside = odir / "evidence-outside-native-run"
    (nrun / "artifacts").rename(outside)
    (nrun / "artifacts").symlink_to(outside, target_is_directory=True)
    rc, out = run("readback", RUN_ID, root=droot)
    check("T18 artifacts dir symlink fails closed", rc == 2, out)

    # ponytail: B4 bounded host-to-fixed-runtime forwarding, isolated.
    import importlib.util as _ilu
    _spec = _ilu.spec_from_file_location("transport_fwd", TRANSPORT)
    assert _spec is not None and _spec.loader is not None
    _t = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_t)
    bad = _t.build_forward_command("evil", RUN_ID)
    check("T19a forward rejects unknown verb", bad is None)
    bad = _t.build_forward_command("research-readback", "zz")
    check("T19b forward rejects bad run id", bad is None)
    good = _t.build_forward_command("research-readback", RUN_ID)
    check("T19c forward uses fixed image and python",
          good is not None and _t.FIXED_IMAGE in good
          and _t.FIXED_GUEST_PYTHON in good and good[-2:] == ["research-readback", RUN_ID]
          and not any(";" in a or "|" in a or "$" in a for a in good), str(good))
    hroot = Path(tempfile.mkdtemp(prefix="transport-fwd-"))
    hsrc = hroot / "qlib-results"
    (hsrc / "_validation").mkdir(parents=True)
    fentry, fcfg = write_stub_files(hsrc / "_validation")
    # Move stub pair into a temp host source and submit locally there first.
    rc, out = run("submit", b64(make_handoff(hsrc / "_validation", fentry, fcfg)), root=hsrc / "_validation")
    check("T19d forward fixture submit", rc == 0, out)
    fake_bin = hroot / "fakebin" / "container"
    fake_bin.parent.mkdir(parents=True)
    seen_fwd = hroot / "forward-seen.json"
    fake_bin.write_text(
        "#!/usr/bin/env python3\nimport json,os,sys,subprocess\n"
        "from pathlib import Path\n"
        "argv=sys.argv[1:]\n"
        "Path(r'" + str(seen_fwd) + "').write_text(json.dumps(argv))\n"
        "assert 'run' in argv, argv\n"
        "assert '" + _t.FIXED_IMAGE + "' in argv, argv\n"
        "assert '" + _t.FIXED_GUEST_PYTHON + "' in argv, argv\n"
        "verb=argv[-2]; arg=argv[-1]\n"
        "assert verb in ('submit','research-submit','readback','research-readback'), verb\n"
        "src=[a.split('source=',1)[1].split(',',1)[0] for a in argv if 'target=/results' in a][0]\n"
        "env=dict(os.environ, RESEARCH_RESULTS_ROOT=src+'/_validation', RESEARCH_FORWARDED='1')\n"
        "env.pop('SSH_ORIGINAL_COMMAND', None)\n"
        "p=subprocess.run([sys.executable, r'" + str(TRANSPORT) + "', verb, arg], env=env, capture_output=True, text=True)\n"
        "sys.stdout.write(p.stdout)\n"
        "sys.stderr.write(p.stderr)\n"
        "sys.exit(p.returncode)\n")
    fake_bin.chmod(0o755)
    env = dict(os.environ, RESEARCH_CONTAINER_CLI=str(fake_bin),
               RESEARCH_HOST_RESULTS_SOURCE=str(hsrc),
               SSH_ORIGINAL_COMMAND="research-readback " + RUN_ID)
    env.pop("RESEARCH_RESULTS_ROOT", None)
    env.pop("RESEARCH_FORWARDED", None)
    proc = subprocess.run([sys.executable, str(TRANSPORT)], env=env,
                          capture_output=True, text=True, timeout=120)
    check("T19e host shape forwards to fixed runtime",
          proc.returncode == 0 and seen_fwd.is_file()
          and _t.FIXED_IMAGE in seen_fwd.read_text()
          and _t.FIXED_GUEST_PYTHON in seen_fwd.read_text(), proc.stdout + proc.stderr)
    back = json.loads(proc.stdout) if proc.returncode == 0 else {}
    check("T19f forwarded readback is PASS",
          back.get("node05") == "PASS" and back.get("run_id") == RUN_ID, proc.stdout)

    # ponytail: B1 comment-only tokens never execute. Code literals required.
    croot = Path(tempfile.mkdtemp(prefix="transport-neg-"))
    centry, ccfg = write_stub_files(croot)
    seen_marker = croot / "execution-marker.txt"
    centry.write_text(
        "# effective_config.json QLIB_OUT_DIR\nfrom pathlib import Path\n"
        "Path(" + repr(str(seen_marker)) + ").write_text(\"executed\")\n"
    )
    rc, out = run("submit", b64(make_handoff(croot, centry, ccfg)), root=croot)
    check("T20a comment-token marker never executes",
          rc == 2 and "identity" in out and not seen_marker.exists()
          and not list(croot.glob("n8n-live-*")), out)

    # ponytail: B1 same-basename sibling must not mask another consumed root.
    sroot = Path(tempfile.mkdtemp(prefix="transport-neg-"))
    sentry, scfg = write_stub_files(sroot)
    actual_root = sroot / "actual-native-root"
    actual_root.mkdir()
    wrong_cfg = json.loads(scfg.read_text())
    wrong_cfg["candidate"] = {"path": "wrong-consumed.md", "git_blob_sha": "d" * 40}
    (actual_root / "effective_config.json").write_text(json.dumps(wrong_cfg, sort_keys=True))
    scode = sentry.read_text()
    start = scode.index("frozen_cfg = {")
    end = scode.index("(out / \"mlruns\"", start)
    scode = (
        scode[:start]
        + "frozen_cfg = json.loads(Path("
        + repr(str(actual_root / "effective_config.json"))
        + ").read_text())\n"
        + scode[end:]
    )
    smarker = sroot / "execution-marker.txt"
    scode = (
        "from pathlib import Path\nPath(" + repr(str(smarker)) + ").write_text(\"executed\")\n" + scode
    )
    sentry.write_text(scode)
    rc, out = run("submit", b64(make_handoff(sroot, sentry, scfg)), root=sroot)
    check("T20b same-basename wrong consumed config fails before executing",
          rc == 2 and "identity mismatch" in out and not smarker.exists()
          and not list(sroot.glob("n8n-live-*/submit-receipt.json")), out)

    # ponytail: B1 fixed runtime binds the declared commit/digest. Local
    # stubs skip this; the fixed python enforces the frozen values.
    check("T21a fixed runtime constants are frozen",
          _t.FIXED_RUNTIME_COMMIT == "bee09f23d938b96c2c1ef82d891aa0abfa171cd0"
          and _t.FIXED_IMAGE_DIGEST
          == "sha256:8bee2a8beed672b17096ad44db5064dbaadcafe124c2ee989cd03b47683355b9"
          and _t.FIXED_IMAGE == "qlib:main-bee09f23-arm64", "")
    rroot = Path(tempfile.mkdtemp(prefix="transport-neg-"))
    rentry, rcfg = write_stub_files(rroot)
    rh = make_handoff(rroot, rentry, rcfg)
    check("T21b local stub passes frozen binding", _t.check_frozen_binding(rh) is None)
    orig_fixed = _t.is_fixed_runtime
    try:
        setattr(_t, "is_fixed_runtime", lambda: True)
        wrong_cfg = json.loads(rcfg.read_text())
        wrong_cfg["runtime"] = {"commit": "d" * 40}
        rcfg.write_text(json.dumps(wrong_cfg, sort_keys=True))
        wrong_h = make_handoff(rroot, rentry, rcfg)
        wrong_h["qlib_runtime_commit"] = "d" * 40
        check("T21c wrong runtime commit fails in fixed runtime",
              _t.check_frozen_binding(wrong_h) is not None
              and "runtime" in str(_t.check_frozen_binding(wrong_h)), "")
        good_cfg = json.loads(rcfg.read_text())
        good_cfg["runtime"] = {
            "commit": _t.FIXED_RUNTIME_COMMIT,
            "image": _t.FIXED_IMAGE,
            "image_digest": "sha256:" + "0" * 64,
        }
        rcfg.write_text(json.dumps(good_cfg, sort_keys=True))
        good_h = make_handoff(rroot, rentry, rcfg)
        good_h["qlib_runtime_commit"] = _t.FIXED_RUNTIME_COMMIT
        check("T21d wrong runtime digest fails in fixed runtime",
              _t.check_frozen_binding(good_h) is not None
              and "runtime" in str(_t.check_frozen_binding(good_h)), "")
        fixed_cfg = {
            "candidate": {"path": "demo-candidate.md", "git_blob_sha": "a" * 40},
            "execution": {"entrypoint": str(rentry)},
            "runtime": {
                "commit": _t.FIXED_RUNTIME_COMMIT,
                "image": _t.FIXED_IMAGE,
                "image_digest": _t.FIXED_IMAGE_DIGEST,
            },
        }
        rcfg.write_text(json.dumps(fixed_cfg, sort_keys=True))
        fixed_h = make_handoff(rroot, rentry, rcfg)
        fixed_h["qlib_runtime_commit"] = _t.FIXED_RUNTIME_COMMIT
        check("T21e correct fixed runtime passes frozen binding",
              _t.check_frozen_binding(fixed_h) is None,
              str(_t.check_frozen_binding(fixed_h)))
    finally:
        setattr(_t, "is_fixed_runtime", orig_fixed)

    # ponytail: B2 submit verifies complete evidence before Node04 PASS.
    tail = "print(json.dumps({\"summary\": {\"ok\": True}, \"mlflow\": readback, \"manifest\": manifest}))"
    for name, action in [
        ("T22a submit without manifest fails before PASS", "(out / \"manifest.json\").unlink()"),
        ("T22b submit without root events fails before PASS", "(out / \"events.csv\").unlink()"),
        (
            "T22c submit with stale summary fails before PASS",
            "(out / \"summary.json\").write_text(\"{\\\"evaluation_rows_including_force_flat\\\": 999}\")",
        ),
        (
            "T22d submit with wrong repro candidate fails before PASS",
            "p=out / \"mlruns\" / \"%s\" / \"%s\" / \"artifacts/repro/effective_config.json\"\n"
            "x=json.loads(p.read_text())\nx[\"candidate\"][\"path\"]=\"different.md\"\n"
            "p.write_text(json.dumps(x))" % (EXP_ID, RUN_ID),
        ),
    ]:
        eroot = Path(tempfile.mkdtemp(prefix="transport-neg-"))
        eentry, ecfg = write_stub_files(eroot)
        ecode = eentry.read_text()
        assert ecode.count(tail) == 1
        eentry.write_text(ecode.replace(tail, action + "\n" + tail))
        rc, out = run("submit", b64(make_handoff(eroot, eentry, ecfg)), root=eroot)
        check(name, rc == 2 and not list(eroot.glob("n8n-live-*/submit-receipt.json")), out)

    # ponytail: B1 consuming literals, not keyword mentions.
    droot = Path(tempfile.mkdtemp(prefix="transport-neg-"))
    dentry, dcfg = write_stub_files(droot)
    dseen = droot / "execution-marker.txt"
    dentry.write_text(
        '"""effective_config.json QLIB_OUT_DIR"""\nfrom pathlib import Path\n'
        "Path(" + repr(str(dseen)) + ').write_text("executed")\n'
    )
    rc, out = run("submit", b64(make_handoff(droot, dentry, dcfg)), root=droot)
    check("T23a docstring both tokens never executes",
          rc == 2 and "identity" in out and not dseen.exists()
          and not list(droot.glob("n8n-live-*")), out)

    uroot = Path(tempfile.mkdtemp(prefix="transport-neg-"))
    uentry, ucfg = write_stub_files(uroot)
    useen = uroot / "execution-marker.txt"
    uentry.write_text(
        "from pathlib import Path\nunused=(\"effective_config.json\", \"QLIB_OUT_DIR\")\n"
        "Path(" + repr(str(useen)) + ').write_text("executed")\n'
    )
    rc, out = run("submit", b64(make_handoff(uroot, uentry, ucfg)), root=uroot)
    check("T23b unused tuple both tokens never executes",
          rc == 2 and "identity" in out and not useen.exists()
          and not list(uroot.glob("n8n-live-*")), out)

    rroot = Path(tempfile.mkdtemp(prefix="transport-neg-"))
    rentry, rcfg = write_stub_files(rroot)
    actual = rroot / "actual-native-root"
    actual.mkdir()
    wrong = json.loads(rcfg.read_text())
    wrong["candidate"] = {"path": "wrong-consumed.md", "git_blob_sha": "d" * 40}
    (actual / "effective_config.json").write_text(json.dumps(wrong, sort_keys=True))
    rcode = rentry.read_text()
    start = rcode.index("frozen_cfg = {")
    end = rcode.index('(out / "mlruns"', start)
    stub_cfg = 'frozen_cfg = json.loads(Path(__file__).with_name("effective_config.json").read_text())\n'
    rcode = rcode[:start] + stub_cfg + rcode[end:]
    replacement = 'ROOT: Path = Path(__file__).with_name("actual-native-root")\n'
    replacement += 'frozen_cfg=json.loads((ROOT / "effective_config.json").read_text())\n'
    rcode = rcode.replace(stub_cfg, replacement)
    rseen = rroot / "execution-marker.txt"
    rcode = "from pathlib import Path\nPath(" + repr(str(rseen)) + ').write_text("executed")\n' + rcode
    rentry.write_text(rcode)
    rc, out = run("submit", b64(make_handoff(rroot, rentry, rcfg)), root=rroot)
    check("T23c relative other-root with ROOT pin fails before executing",
          rc == 2 and "identity mismatch" in out and not rseen.exists()
          and not list(rroot.glob("n8n-live-*/submit-receipt.json")), out)

    # ponytail: B2 shared live proof rejects native drift before PASS.
    live_commit = "bee09f23d938b96c2c1ef82d891aa0abfa171cd0"
    live_image = "qlib:main-bee09f23-arm64"
    live_digest = "sha256:8bee2a8beed672b17096ad44db5064dbaadcafe124c2ee989cd03b47683355b9"

    def write_live_stub(root):
        entry, config = write_stub_files(root)
        value = json.loads(config.read_text())
        value["runtime"] = {"commit": live_commit, "image": live_image, "image_digest": live_digest}
        value["data"] = {"provider_file_count": 0,
                         "provider_manifest_sha256": hashlib.sha256(b"[]").hexdigest()}
        value["strategy"] = {"family": "test-only"}
        config.write_text(json.dumps(value, sort_keys=True))
        code = entry.read_text()
        start = code.index("frozen_cfg = {")
        end = code.index('(out / "mlruns"', start)
        code = code[:start] + stub_cfg + code[end:]
        code = code.replace('write_text("{}")', 'write_text("[]")')
        addition = '(out / "portfolio_report.csv").write_text("a\\n1\\n")\n'
        addition += '(out / "trade_indicators.csv").write_text("a\\n1\\n")\n'
        addition += 'adir = out / "mlruns" / "%s" / "%s" / "artifacts"\n' % (EXP_ID, RUN_ID)
        addition += 'for name in ("events.csv", "signals.csv", "summary.json", "portfolio_report.csv"):\n'
        addition += '    (adir / "backtest" / name).write_bytes((out / name).read_bytes())\n'
        code = code.replace("readback = {", addition + "readback = {", 1)
        code = code.replace('(out / "mlflow_readback.json").write_text(',
                            'readback["artifact_names"] = '
                            '[p.relative_to(adir).as_posix() for p in sorted(adir.rglob("*")) '
                            'if p.is_file()]\n(out / "mlflow_readback.json").write_text(', 1)
        entry.write_text(code)
        return entry, config

    def live_handoff(root, entry, config):
        handoff = make_handoff(root, entry, config)
        handoff["qlib_runtime_commit"] = live_commit
        return handoff

    for name, action in [
        ("T24a submit native events drift fails before PASS",
         '(adir / "backtest/events.csv").write_text("changed-native-only\\n1\\n")'),
        ("T24b submit native summary drift fails before PASS",
         '(adir / "backtest/summary.json").write_text("{\\"evaluation_rows_including_force_flat\\": 999}\\n")'),
        ("T24c submit native provider drift fails before PASS",
         '(adir / "repro/provider-manifest.json").write_text("{}")'),
        ("T24d submit missing portfolio fails before PASS",
         '(out / "portfolio_report.csv").unlink()\n'
         '(adir / "backtest/portfolio_report.csv").unlink()\n'
         'manifest.pop("portfolio_report.csv")\n'
         'readback["artifact_names"].remove("backtest/portfolio_report.csv")\n'
         '(out / "mlflow_readback.json").write_text(json.dumps(readback, sort_keys=True))\n'
         'p = out / "mlflow_readback.json"\n'
         'manifest[p.name] = {"bytes": p.stat().st_size, '
         '"sha256": hashlib.sha256(p.read_bytes()).hexdigest()}\n'
         '(out / "manifest.json").write_text(json.dumps(manifest, sort_keys=True))'),
        ("T24e submit missing trade indicators fails before PASS",
         '(out / "trade_indicators.csv").unlink()\n'
         'manifest.pop("trade_indicators.csv")\n'
         '(out / "manifest.json").write_text(json.dumps(manifest, sort_keys=True))'),
    ]:
        lroot = Path(tempfile.mkdtemp(prefix="transport-neg-"))
        lentry, lcfg = write_live_stub(lroot)
        lcode = lentry.read_text()
        assert lcode.count(tail) == 1
        lentry.write_text(lcode.replace(tail, action + "\n" + tail))
        rc, out = run("submit", b64(live_handoff(lroot, lentry, lcfg)), root=lroot)
        check(name, rc == 2 and not list(lroot.glob("n8n-live-*/submit-receipt.json")), out)

    lroot = Path(tempfile.mkdtemp(prefix="transport-neg-"))
    lentry, lcfg = write_live_stub(lroot)
    rc, out = run("submit", b64(live_handoff(lroot, lentry, lcfg)), root=lroot)
    check("T24f live-shape positive still passes",
          rc == 0 and "PASS" in out and list(lroot.glob("n8n-live-*/submit-receipt.json")), out)

    print("ALL DETERMINISTIC CHECKS PASSED")


if __name__ == "__main__":
    main()
