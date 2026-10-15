#!/usr/bin/env python3
"""Thin SSH-side transport: validated handoff -> existing Qlib native path -> MLflow readback.

submit: check one base64 handoff, verify file hashes, run the existing native
entrypoint, print one Node04 receipt. readback: find one run id under the fixed
results root, verify its manifest, print one Node05 receipt. Exit 0 means valid,
exit 2 means invalid. This file never fabricates a PASS receipt: every receipt
field comes from hashes checked here or files the native run wrote.

ponytail: single-file bridge on purpose. Synchronous subprocess only, one fixed
results root, one out_dir per frozen executable (a re-submit refuses instead of
clobbering evidence), single-candidate coverage only. Ceilings: RESULTS_ROOT
holds at most a few hundred run dirs (readback scans one filename per dir);
SUBMIT_TIMEOUT bounds one native run; run_inputs/cost ride along as declared
facts and never steer the frozen entrypoint.
"""

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

HEX40 = re.compile(r"^[a-f0-9]{40}$")
HEX64 = re.compile(r"^[a-f0-9]{64}$")
RUNID = re.compile(r"^[a-f0-9]{32}$")

REQUIRED = [
    "source_commit",
    "candidate_path",
    "source_blob_sha",
    "entrypoint_ref",
    "entrypoint_sha256",
    "effective_config_ref",
    "effective_config_sha256",
    "qlib_runtime_commit",
]

OPTIONAL = [
    "research_cost_model",
    "run_inputs",
    "capabilities",
    "capability_declaration",
    "evidence_refs",
]

# ponytail: same three verified primitives as the Node03 contract. Reuse only;
# any value outside these fails closed here and routes to ENGINEERING_HOLD.
VERIFIED_PRIMITIVES = {
    "execution": ["qlib-native-backtest"],
    "data": ["btcusdt-1h"],
    "timing": ["bar-close-1h"],
}

CANDIDATE_BLOB_API = "https://api.github.com/repos/HCH725/alpha-strategy-research/git/blobs/"

RESULTS_ROOT_DEFAULT = "/results/_validation"
OUT_PREFIX = "n8n-live-"
SUBMIT_TIMEOUT = 1800
MAX_SCAN_DIRS = 500


def fail(reason):
    """Print a rejection report and return exit code 2."""
    print(json.dumps({"ok": False, "error": reason}))
    return 2


PATH_CHARS = re.compile(r"^/[A-Za-z0-9_@+./-]{1,511}$")


def check_abs_path(value):
    """Accept absolute paths only. Reject parent hops and hostile chars."""
    return (
        isinstance(value, str)
        and PATH_CHARS.match(value) is not None
        and ".." not in value
    )


def resolve_root():
    """Return the fixed results root, or None when it is unusable."""
    raw = os.environ.get("RESEARCH_RESULTS_ROOT", RESULTS_ROOT_DEFAULT)
    if not check_abs_path(raw):
        return None
    root = Path(raw)
    if not root.is_dir():
        return None
    return root.resolve()


def under_root(path_value, root):
    """True when the real path stays inside the fixed results root."""
    try:
        real = Path(os.path.realpath(path_value))
    except (OSError, ValueError):
        return False
    try:
        return os.path.commonpath([str(real), str(root)]) == str(root)
    except ValueError:
        return False


def file_sha256(path_value):
    """Return hex sha256 of a file, or None when unreadable."""
    try:
        digest = hashlib.sha256()
        with open(path_value, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def check_handoff(obj):
    """Check the payload shape. Return None when valid, else a reason."""
    if not isinstance(obj, dict):
        return "payload is not a JSON object"
    allowed = set(REQUIRED) | set(OPTIONAL)
    for key in obj:
        if key not in allowed:
            return "unknown field: " + str(key)
    for key in REQUIRED:
        if obj.get(key) is None:
            return "missing field: " + key
    if not HEX40.match(str(obj["source_commit"])):
        return "source_commit has a bad shape"
    name = obj["candidate_path"]
    if not isinstance(name, str) or "/" in name or ".." in name:
        return "candidate_path has a bad shape"
    if not name.endswith(".md") or len(name) > 256:
        return "candidate_path has a bad shape"
    if not HEX40.match(str(obj["source_blob_sha"])):
        return "source_blob_sha has a bad shape"
    if not check_abs_path(obj["entrypoint_ref"]):
        return "entrypoint_ref has a bad shape"
    if not HEX64.match(str(obj["entrypoint_sha256"])):
        return "entrypoint_sha256 has a bad shape"
    if not check_abs_path(obj["effective_config_ref"]):
        return "effective_config_ref has a bad shape"
    if not HEX64.match(str(obj["effective_config_sha256"])):
        return "effective_config_sha256 has a bad shape"
    if not HEX40.match(str(obj["qlib_runtime_commit"])):
        return "qlib_runtime_commit has a bad shape"
    if obj.get("research_cost_model") is None and obj.get("run_inputs") is None:
        return "declared cost or run inputs are missing"
    if (
        "capabilities" not in obj
        and "capability_declaration" not in obj
    ):
        return "capability declaration is missing"
    refs = obj.get("evidence_refs")
    if refs is not None:
        if not isinstance(refs, dict) or len(refs) == 0:
            return "evidence refs are missing"
        for key, ref in refs.items():
            if not isinstance(ref, str) or len(ref) == 0:
                return "evidence ref has a bad shape: " + str(key)
    return None


def capability_gap(obj):
    """List declared primitives outside the verified set. Empty means clean."""
    gap = []
    count = 0
    bucketed = obj.get("capabilities")
    if isinstance(bucketed, dict):
        for key, vals in bucketed.items():
            vals = vals if isinstance(vals, list) else [vals]
            for val in vals:
                if not isinstance(val, str):
                    gap.append(str(key) + ":non-string")
                    continue
                count += 1
                if key not in VERIFIED_PRIMITIVES or val not in VERIFIED_PRIMITIVES[key]:
                    gap.append(str(key) + ":" + val)
    declared = obj.get("capability_declaration")
    if isinstance(declared, list):
        for item in declared:
            if not isinstance(item, str) or ":" not in item:
                gap.append("malformed:" + str(item))
                continue
            bucket, _, val = item.partition(":")
            count += 1
            if bucket not in VERIFIED_PRIMITIVES or val not in VERIFIED_PRIMITIVES[bucket]:
                gap.append(item)
    if count == 0:
        gap.append("capability declaration is missing")
    return gap


def out_dir_for(handoff, root):
    """Derive one bounded out_dir from the frozen executable identity."""
    frozen = {
        "source_blob_sha": handoff["source_blob_sha"],
        "entrypoint_sha256": handoff["entrypoint_sha256"],
        "effective_config_sha256": handoff["effective_config_sha256"],
        "qlib_runtime_commit": handoff["qlib_runtime_commit"],
    }
    short = hashlib.sha256(
        json.dumps(frozen, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:12]
    return root / (OUT_PREFIX + short)


def decode_handoff(payload_b64):
    """Decode one base64 handoff object, or return (None, reason)."""
    try:
        raw = base64.b64decode(payload_b64, validate=True)
    except (binascii.Error, ValueError):
        return None, "payload is not base64"
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None, "payload is not JSON"
    return obj, None


def cmd_submit(payload_b64):
    """Verify one handoff, run the existing native entrypoint, print receipt."""
    obj, reason = decode_handoff(payload_b64)
    if obj is None:
        return fail(reason)
    reason = check_handoff(obj)
    if reason is not None:
        return fail(reason)
    gap = capability_gap(obj)
    if gap:
        return fail("ENGINEERING_HOLD: new unverified capability: " + ", ".join(gap))
    root = resolve_root()
    if root is None:
        return fail("results root is not usable")
    for key in ("entrypoint_ref", "effective_config_ref"):
        if not under_root(obj[key], root):
            return fail(key + " escapes the results root")
    entry_digest = file_sha256(obj["entrypoint_ref"])
    if entry_digest is None or entry_digest != obj["entrypoint_sha256"]:
        return fail("entrypoint hash mismatch")
    config_digest = file_sha256(obj["effective_config_ref"])
    if config_digest is None or config_digest != obj["effective_config_sha256"]:
        return fail("effective_config hash mismatch")
    out_dir = out_dir_for(obj, root)
    if out_dir.exists():
        return fail("result exists; refuse overwrite: " + out_dir.name)
    env = dict(os.environ)
    env["QLIB_OUT_DIR"] = str(out_dir)
    try:
        proc = subprocess.run(
            [sys.executable, obj["entrypoint_ref"]],
            env=env,
            cwd="/",
            capture_output=True,
            text=True,
            timeout=SUBMIT_TIMEOUT,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return fail("native run did not start: " + str(exc)[:200])
    if proc.returncode != 0:
        return fail("native run failed: " + proc.stderr[-2000:])
    try:
        child = json.loads(proc.stdout)
        mlflow = child["mlflow"]
        run_id = mlflow["run_id"]
        experiment_id = str(mlflow["experiment_id"])
        status = mlflow["status"]
    except (ValueError, KeyError, TypeError):
        return fail("native run output is not readable")
    if not RUNID.match(run_id or ""):
        return fail("native run_id has a bad shape")
    if status != "FINISHED":
        return fail("native run is not FINISHED")
    try:
        disk = json.loads((out_dir / "mlflow_readback.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return fail("native readback file is missing")
    if disk.get("run_id") != run_id:
        return fail("native run identity mismatch")
    cost_declared = obj.get("research_cost_model") is not None or obj.get("run_inputs") is not None
    receipt = {
        "candidate_path": obj["candidate_path"],
        "candidate_blob_sha": obj["source_blob_sha"],
        "entrypoint_ref": obj["entrypoint_ref"],
        "entrypoint_sha256": obj["entrypoint_sha256"],
        "effective_config_ref": obj["effective_config_ref"],
        "effective_config_sha256": obj["effective_config_sha256"],
        "run_id": run_id,
        "experiment_id": experiment_id,
        "cost_declared": bool(cost_declared),
        "evidence_refs": obj.get("evidence_refs") or {},
    }
    try:
        (out_dir / "submit-receipt.json").write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except OSError:
        return fail("submit receipt is not writable")
    run_ref = str(out_dir / "mlruns" / experiment_id / run_id)
    print(
        json.dumps(
            {
                "node04": "PASS",
                "candidate_path": obj["candidate_path"],
                "candidate_blob_sha": obj["source_blob_sha"],
                "entrypoint_sha256": obj["entrypoint_sha256"],
                "effective_config_sha256": obj["effective_config_sha256"],
                "run_id": run_id,
                "experiment_id": experiment_id,
                "out_dir": str(out_dir),
                "status": "FINISHED",
                "refs": {
                    "mlflow_run": run_ref,
                    "mlflow_readback": str(out_dir / "mlflow_readback.json"),
                    "manifest": str(out_dir / "manifest.json"),
                },
            }
        )
    )
    return 0


def find_run_dir(root, run_id):
    """Find the one out_dir whose readback names this run id, else None."""
    try:
        entries = list(root.iterdir())
    except OSError:
        return None
    if len(entries) > MAX_SCAN_DIRS:
        return None
    hits = []
    for entry in entries:
        readback = entry / "mlflow_readback.json"
        if not readback.is_file():
            continue
        try:
            payload = json.loads(readback.read_bytes().decode("utf-8"))
        except (OSError, ValueError, UnicodeDecodeError):
            continue
        if isinstance(payload, dict) and payload.get("run_id") == run_id:
            hits.append(entry)
    if len(hits) != 1:
        return None
    return hits[0]


def cmd_readback(run_id):
    """Read one existing run and print its Node05 receipt."""
    if not RUNID.match(run_id or ""):
        return fail("run_id has a bad shape")
    root = resolve_root()
    if root is None:
        return fail("results root is not usable")
    out_dir = find_run_dir(root, run_id)
    if out_dir is None:
        return fail("run_id is unknown or ambiguous")
    try:
        readback_bytes = (out_dir / "mlflow_readback.json").read_bytes()
        readback = json.loads(readback_bytes.decode("utf-8"))
        manifest = json.loads((out_dir / "manifest.json").read_text(encoding="utf-8"))
        submit = json.loads((out_dir / "submit-receipt.json").read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return fail("run evidence is not readable")
    if readback.get("run_id") != run_id or readback.get("status") != "FINISHED":
        return fail("run is not FINISHED")
    experiment_id = str(readback.get("experiment_id") or "")
    if not re.match(r"^[0-9]+$", experiment_id):
        return fail("experiment reference is invalid")
    params = readback.get("params") or {}
    metrics = readback.get("metrics") or {}
    artifacts = readback.get("artifact_names") or []
    counts = (len(params), len(metrics), len(artifacts))
    if not all(isinstance(n, int) and n > 0 for n in counts):
        return fail("run evidence is empty")
    manifest_entry = manifest.get("mlflow_readback.json") or {}
    if manifest_entry.get("sha256") != hashlib.sha256(readback_bytes).hexdigest():
        return fail("manifest/readback identity mismatch")
    manifest_sha256 = file_sha256(str(out_dir / "manifest.json"))
    if manifest_sha256 is None or not HEX64.match(manifest_sha256):
        return fail("manifest identity is invalid")
    if submit.get("run_id") != run_id:
        return fail("submit/run identity mismatch")
    for key in ("entrypoint_ref", "effective_config_ref"):
        ref = submit.get(key)
        if not isinstance(ref, str) or not under_root(ref, root):
            return fail("submit reference escapes the results root")
    for ref_key, sha_key in (
        ("entrypoint_ref", "entrypoint_sha256"),
        ("effective_config_ref", "effective_config_sha256"),
    ):
        digest = file_sha256(submit[ref_key])
        if digest is None or digest != submit.get(sha_key):
            return fail("submit/executable identity mismatch")
    run_ref = out_dir / "mlruns" / experiment_id / run_id
    if not run_ref.is_dir():
        return fail("mlflow run is missing")
    repro = [a for a in artifacts if isinstance(a, str) and a.startswith("repro/")]
    configs = [a for a in repro if a.endswith("/effective_config.json")]
    entries = [a for a in repro if a.endswith(".py")]
    providers = [a for a in repro if a.endswith("provider-manifest.json")]
    if len(configs) != 1 or len(entries) != 1 or len(providers) > 1:
        return fail("repro artifacts are ambiguous")
    refs = {
        "candidate": CANDIDATE_BLOB_API + str(submit["candidate_blob_sha"]),
        "mlflow_run": str(run_ref),
        "mlflow_readback": str(out_dir / "mlflow_readback.json"),
        "manifest": str(out_dir / "manifest.json"),
        "effective_config": str(run_ref / "artifacts" / configs[0]),
        "entrypoint": str(run_ref / "artifacts" / entries[0]),
    }
    if providers:
        refs["provider_manifest"] = str(run_ref / "artifacts" / providers[0])
    for key, ref in refs.items():
        if key == "candidate":
            continue
        if not Path(ref).exists():
            return fail("evidence reference is missing")
    blob_sha = str(submit["candidate_blob_sha"])
    candidate_ok = (
        HEX40.match(blob_sha) is not None
        and blob_sha in (run_ref / "artifacts" / configs[0]).read_text(encoding="utf-8", errors="replace")
        and str(submit["candidate_path"]) in (run_ref / "artifacts" / configs[0]).read_text(encoding="utf-8", errors="replace")
    )
    try:
        summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
        signals = (out_dir / "signals.csv").read_text(encoding="utf-8").splitlines()
        events = (out_dir / "events.csv").read_text(encoding="utf-8").splitlines()
    except (OSError, ValueError, UnicodeDecodeError):
        return fail("run evidence is not readable")
    data_ok = (
        isinstance(params.get("symbol"), str) and len(params["symbol"]) > 0
        and isinstance(params.get("frequency"), str) and len(params["frequency"]) > 0
        and isinstance(summary, dict)
        and any("rows" in k and isinstance(v, int) and v > 0 for k, v in summary.items())
        and len(signals) >= 2
    )
    execution_ok = len(events) >= 2
    runtime_ok = isinstance(params.get("qlib_version"), str) and len(params["qlib_version"]) > 0
    readable = {
        "candidate": bool(candidate_ok),
        "data": bool(data_ok),
        "execution": bool(execution_ok),
        "runtime": bool(runtime_ok),
        "evidence": True,
    }
    if not all(readable.values()):
        return fail("unreadable evidence: " + ",".join(k for k, v in readable.items() if not v))
    # ponytail: one live proof never equals full coverage, so claimability
    # stays derived-false here; evidence completeness was already enforced
    # above by fail-closed manifest verification.
    coverage_complete = False
    cost_declared = submit.get("cost_declared", False) is True
    derived = bool(coverage_complete and cost_declared)
    print(
        json.dumps(
            {
                "node05": "PASS",
                "run_id": run_id,
                "experiment_id": experiment_id,
                "candidate_path": submit["candidate_path"],
                "candidate_blob_sha": blob_sha,
                "status": "FINISHED",
                "params_count": counts[0],
                "metrics_count": counts[1],
                "artifacts_count": counts[2],
                "out_dir": str(out_dir),
                "refs": refs,
                "readable": readable,
                "manifest_verified": True,
                "manifest_readback_run_id": run_id,
                "manifest_sha256": manifest_sha256,
                "coverage_complete": coverage_complete,
                "performance_claimable": derived,
            }
        )
    )
    return 0


def main(argv):
    """Parse args and dispatch to one subcommand."""
    parser = argparse.ArgumentParser(description="Bridge a handoff to the native Qlib path.")
    parser.add_argument(
        "cmd",
        choices=["submit", "research-submit", "readback", "research-readback"],
        help="submit/research-submit take a base64 handoff; readback/research-readback take a run id",
    )
    parser.add_argument("arg", help="base64 handoff JSON or 32-hex run id")
    args = parser.parse_args(argv)
    if args.cmd in ("submit", "research-submit"):
        return cmd_submit(args.arg)
    return cmd_readback(args.arg)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
