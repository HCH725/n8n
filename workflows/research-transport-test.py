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
(out / "mlruns" / EXP / RUN).mkdir(parents=True)
(out / "summary.json").write_text(json.dumps({"evaluation_rows_including_force_flat": 10}))
(out / "signals.csv").write_text("a\\n" + "1\\n")
(out / "events.csv").write_text("a\\n" + "1\\n")
readback = {"tracking_uri": "file://x", "experiment_id": EXP, "run_id": RUN,
            "status": "FINISHED", "params": {"qlib_version": "t", "symbol": "BTCUSDT", "frequency": "60min", "research_leverage": "3"},
            "metrics": {"m": 1.0}, "artifact_names": ["summary.json", "signals.csv", "events.csv"]}
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
    )
    return entry, config


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
                        caps={"execution": ["future-engine"], "data": ["btcusdt-1h"], "timing": ["bar-close-1h"]})
    rc, out = run("research-submit", b64(bad), root=tmp)
    check("T3 unknown capability holds without executing",
          rc == 2 and "ENGINEERING_HOLD" in out and not list(tmp.glob("n8n-live-*")), out)

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

    print("ALL THIN CHECKS PASSED")


if __name__ == "__main__":
    main()
