#!/usr/bin/env python3
"""Thin SSH-side transport: validated handoff -> existing Qlib native path -> MLflow readback.

submit: check one base64 handoff, verify file hashes, run the existing native
entrypoint, print one Node04 receipt. readback: find one run id under the fixed
results root, verify its manifest, print one Node05 receipt. Exit 0 means valid,
exit 2 means invalid. This file never fabricates a PASS receipt: every receipt
field comes from hashes checked here or files the native run wrote.

hermes-forced: a separate restricted key sends one base64 UTF-8 task to the
fixed host Hermes argv. This mode accepts no Qlib verb and starts no shell. The
same key serves ``research-materialize``: it asks that argv for one strategy code
block, checks the block against the engine's own contract, writes one run-scoped
cell directory and prints the executable handoff. It binds identity and evidence.
The workflow's readiness gate still decides admission.

ponytail: single-file bridge on purpose. Synchronous subprocess only, one fixed
results root, one out_dir per frozen executable (a re-submit refuses instead of
clobbering evidence), single-candidate coverage only. Deliberate simplifications
vs the prior attestation engine, per thin-orchestration contract:
- No AST consumption analysis. Entrypoint hash plus the verified
  capability/family implementation represents verified execution ability. If an
  implementation never uses the config, that belongs to capability verification,
  not to per-run transport.
- No hand-rolled MLflow file-store parser. The native run already writes
  mlflow_readback.json plus manifest.json; this bridge reuses those two files
  as the native evidence instead of re-parsing meta.yaml, params/metrics files,
  or walking artifact inventories.
- No per-submit backtest byte attestation. Submit and readback keep only what
  proves run identity, manifest/readback correspondence, and necessary evidence
  existence. Ceilings:
RESULTS_ROOT holds at most a few hundred run dirs (readback scans one filename
per dir); SUBMIT_TIMEOUT bounds one native run; run_inputs/cost ride along as
declared facts and never steer the frozen entrypoint.
"""

import argparse
import base64
import binascii
import hashlib
import importlib.util
import json
import os
import re
import shutil
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

# ponytail: verified primitives, one reusable name for each capability. A
# symbol or timeframe combination is not a new capability. One Binance USD-M
# OHLCV read at bar close serves every covered cell. Do not add a per-cell
# entry here. Coverage is a measured provider-readiness fact on the campaign.
# A value outside this set fails closed to ENGINEERING_HOLD. A new primitive
# needs one representative validation first.
VERIFIED_PRIMITIVES = {
    "execution": ["qlib-native-backtest"],
    "data": ["binance-usdm-ohlcv"],
    "timing": ["bar-close"],
}

CANDIDATE_BLOB_API = "https://api.github.com/repos/HCH725/alpha-strategy-research/git/blobs/"

RESULTS_ROOT_DEFAULT = "/results/_validation"
OUT_PREFIX = "n8n-live-"
SUBMIT_TIMEOUT = 1800
MAX_SCAN_DIRS = 500

# ponytail: the forced-command entry accepts exactly these two verbs, one arg
# each. The short aliases (submit/readback) are gone on purpose: production
# Node04/Node05 already use the research- prefix, and one spelling keeps the
# SSH trust boundary auditable.
FORCED_VERBS = ("research-submit", "research-readback")
HERMES_VERB = "research-hermes"
#: Second host verb on the same restricted key: bind one strategy artifact into
#: one run-scoped cell directory. It reuses the fixed Hermes argv for the code
#: block and never starts a shell.
MATERIALIZE_VERB = "research-materialize"
HERMES_VERBS = (HERMES_VERB, MATERIALIZE_VERB)
HERMES_PAYLOAD_LIMIT = 65536
MATERIALIZE_ROOT_DEFAULT = "/results/_materialize"
SIGNAL_ARTIFACT_NAME = "strategy_signal.py"
ENGINE_ENTRYPOINT_NAME = "run_cell.entrypoint.py"
CONFIG_NAME = "effective_config.json"
RECEIPT_NAME = "materialization.json"
SMOKE_TIMEOUT = 120
MATERIALIZE_RECORD_LIMIT = 32768

# ponytail: readback actually reads these four files, so the manifest must
# cover them. Only existence plus the readback sha correspondence is checked;
# per-file byte attestation lives with the native run, not here.
REQUIRED_MANIFEST = ("mlflow_readback.json", "summary.json", "signals.csv", "events.csv")

# ponytail: bounded host-to-fixed-runtime forwarding. The host key runs this
# file with no argv; when the guest /results root is missing on the host but
# the fixed container runtime exists, forward the same bounded verb/arg to
# that fixed runtime. Never accept arbitrary shell/image/argv here.
FIXED_CONTAINER = "qlib-run"
FIXED_GUEST_PYTHON = "/opt/venv/bin/python"
FIXED_IMAGE = "qlib:main-bee09f23-arm64"
FIXED_IMAGE_DIGEST = "sha256:8bee2a8beed672b17096ad44db5064dbaadcafe124c2ee989cd03b47683355b9"
FIXED_RUNTIME_COMMIT = "bee09f23d938b96c2c1ef82d891aa0abfa171cd0"
HOST_RESULTS_SOURCE = "/Volumes/ExpansionDrive/qlib-results"


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


def contained(base, target):
    """True when target resolves inside base. Used for every readback read."""
    try:
        real_base = Path(os.path.realpath(base))
        real_target = Path(os.path.realpath(target))
    except (OSError, ValueError):
        return False
    try:
        return os.path.commonpath([str(real_target), str(real_base)]) == str(real_base)
    except ValueError:
        return False


def safe_rel(name):
    """True when name is a safe relative evidence path, never absolute."""
    if not isinstance(name, str) or not name or name.startswith("/"):
        return False
    return all(part not in ("", ".", "..") for part in name.split("/"))


def read_contained(base, name):
    """Read base/name bytes only when the resolved path stays inside base."""
    if not safe_rel(name):
        return None
    path = Path(base) / name
    try:
        if not contained(str(base), str(path)):
            return None
        return path.read_bytes()
    except OSError:
        return None


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


def is_fixed_runtime():
    """True when this process runs as the fixed Qlib runtime python."""
    try:
        return os.path.realpath(sys.executable) == os.path.realpath(FIXED_GUEST_PYTHON)
    except (OSError, ValueError):
        return False


def check_frozen_binding(obj):
    """Bind the caller hashes to the frozen config formal fields.

    The native entrypoint reads its sibling effective_config.json, so bind
    the caller hashes to that file's formal identity fields before running
    anything. No AST here on purpose: whether the implementation consumes a
    config literal is a capability question, answered once at capability
    verification, not on every transport run. No execution here.
    """
    try:
        raw = Path(obj["effective_config_ref"]).read_bytes().decode("utf-8")
        cfg = json.loads(raw)
    except (OSError, ValueError, UnicodeDecodeError):
        return "effective_config is not readable JSON"
    if not isinstance(cfg, dict):
        return "effective_config is not a JSON object"
    cand = cfg.get("candidate")
    if not isinstance(cand, dict):
        return "config/candidate identity is missing"
    if cand.get("path") != obj["candidate_path"]:
        return "config/candidate identity mismatch"
    if cand.get("git_blob_sha") != obj["source_blob_sha"]:
        return "config/candidate identity mismatch"
    runtime = cfg.get("runtime")
    if not isinstance(runtime, dict):
        return "config/runtime identity is missing"
    if runtime.get("commit") != obj["qlib_runtime_commit"]:
        return "config/runtime identity mismatch"
    execution = cfg.get("execution")
    if not isinstance(execution, dict):
        return "config/execution identity is missing"
    if execution.get("entrypoint") != obj["entrypoint_ref"]:
        return "config/execution identity mismatch"
    try:
        same_dir = Path(os.path.realpath(obj["entrypoint_ref"])).parent == Path(
            os.path.realpath(obj["effective_config_ref"])
        ).parent
    except (OSError, ValueError):
        return "config/execution identity is not resolvable"
    if not same_dir:
        return "config/execution identity mismatch"
    # ponytail: the native entry reads <entry_dir>/effective_config.json, so
    # the declared config must be exactly that sibling file, not any other
    # file with matching fields.
    if Path(obj["effective_config_ref"]).name != "effective_config.json":
        return "config/execution identity mismatch"
    try:
        want = os.path.realpath(
            str(Path(os.path.realpath(obj["entrypoint_ref"])).parent / "effective_config.json")
        )
        got = os.path.realpath(obj["effective_config_ref"])
    except (OSError, ValueError):
        return "config/execution identity is not resolvable"
    if want != got:
        return "config/execution identity mismatch"
    # ponytail: bind the declared runtime to the fixed runtime that executes
    # it. Local stub pythons skip this; the fixed runtime python enforces the
    # frozen commit and, when declared, the fixed image digest.
    if is_fixed_runtime():
        if obj.get("qlib_runtime_commit") != FIXED_RUNTIME_COMMIT:
            return "config/runtime identity mismatch"
        if runtime.get("commit") != FIXED_RUNTIME_COMMIT:
            return "config/runtime identity mismatch"
        declared_image = runtime.get("image")
        if declared_image is not None and declared_image != FIXED_IMAGE:
            return "config/runtime identity mismatch"
        declared_digest = runtime.get("image_digest")
        if declared_digest is not None and declared_digest != FIXED_IMAGE_DIGEST:
            return "config/runtime identity mismatch"
    return None


def check_manifest_minimal(out_dir, readback_bytes):
    """Check required evidence exists and the readback sha corresponds.

    Only this, on purpose: full per-file byte attestation and native
    file-store parsing stay with the native run that wrote these files.
    Return (manifest, reason); manifest is None when the check fails.
    """
    try:
        manifest_bytes = (out_dir / "manifest.json").read_bytes()
    except OSError:
        return None, "required evidence is missing from the manifest: manifest.json"
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None, "run evidence is not readable"
    if not isinstance(manifest, dict):
        return None, "run evidence is not readable"
    for name in REQUIRED_MANIFEST:
        if name not in manifest:
            return None, "required evidence is missing from the manifest: " + name
        if read_contained(out_dir, name) is None:
            return None, "required evidence is missing: " + name
    entry = manifest.get("mlflow_readback.json") or {}
    if entry.get("sha256") != hashlib.sha256(readback_bytes).hexdigest():
        return None, "manifest/readback identity mismatch"
    return manifest, None


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
    reason = check_frozen_binding(obj)
    if reason is not None:
        return fail(reason)
    out_dir = out_dir_for(obj, root)
    if out_dir.is_symlink() or out_dir.exists():
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
    if str(disk.get("experiment_id")) != experiment_id:
        return fail("native experiment identity mismatch")
    if disk.get("status") != "FINISHED":
        return fail("native run is not FINISHED")
    # ponytail: the native run directory must exist under this out_dir.
    # Existence only; its internal file format belongs to MLflow, not here.
    run_ref = out_dir / "mlruns" / experiment_id / run_id
    try:
        if not contained(str(out_dir), str(run_ref)) or not run_ref.is_dir():
            return fail("mlflow run is missing")
    except OSError:
        return fail("mlflow run is missing")
    try:
        readback_bytes = (out_dir / "mlflow_readback.json").read_bytes()
    except OSError:
        return fail("native readback file is missing")
    _, reason = check_manifest_minimal(out_dir, readback_bytes)
    if reason is not None:
        return fail(reason)
    cost_declared = obj.get("research_cost_model") is not None or obj.get("run_inputs") is not None
    receipt = {
        "candidate_path": obj["candidate_path"],
        "candidate_blob_sha": obj["source_blob_sha"],
        "source_commit": obj["source_commit"],
        "entrypoint_ref": obj["entrypoint_ref"],
        "entrypoint_sha256": obj["entrypoint_sha256"],
        "effective_config_ref": obj["effective_config_ref"],
        "effective_config_sha256": obj["effective_config_sha256"],
        "qlib_runtime_commit": obj["qlib_runtime_commit"],
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
    run_ref_str = str(out_dir / "mlruns" / experiment_id / run_id)
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
                    "mlflow_run": run_ref_str,
                    "mlflow_readback": str(out_dir / "mlflow_readback.json"),
                    "manifest": str(out_dir / "manifest.json"),
                },
            }
        )
    )
    return 0


def find_run_dir(root, run_id):
    """Find the one contained out_dir naming this run id, else None."""
    try:
        entries = list(root.iterdir())
    except OSError:
        return None
    if len(entries) > MAX_SCAN_DIRS:
        return None
    hits = []
    for entry in entries:
        try:
            real = Path(os.path.realpath(entry))
        except (OSError, ValueError):
            continue
        if not contained(str(root), str(real)):
            continue
        payload = read_contained(real, "mlflow_readback.json")
        if payload is None:
            continue
        try:
            data = json.loads(payload.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            continue
        if isinstance(data, dict) and data.get("run_id") == run_id:
            hits.append(real)
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
    real_out = out_dir
    readback_bytes = read_contained(real_out, "mlflow_readback.json")
    manifest_bytes = read_contained(real_out, "manifest.json")
    submit_bytes = read_contained(real_out, "submit-receipt.json")
    if readback_bytes is None or manifest_bytes is None or submit_bytes is None:
        return fail("run evidence is not readable")
    try:
        readback = json.loads(readback_bytes.decode("utf-8"))
        manifest = json.loads(manifest_bytes.decode("utf-8"))
        submit = json.loads(submit_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return fail("run evidence is not readable")
    if not isinstance(readback, dict) or not isinstance(manifest, dict):
        return fail("run evidence is not readable")
    if not isinstance(submit, dict):
        return fail("run evidence is not readable")
    if (
        is_fixed_runtime()
        and "qlib_runtime_commit" in submit
        and submit.get("qlib_runtime_commit") != FIXED_RUNTIME_COMMIT
    ):
        return fail("config/runtime identity mismatch")
    if readback.get("run_id") != run_id or readback.get("status") != "FINISHED":
        return fail("run is not FINISHED")
    experiment_id = str(readback.get("experiment_id") or "")
    if not re.match(r"^[0-9]+$", experiment_id):
        return fail("experiment reference is invalid")
    params = readback.get("params")
    if not isinstance(params, dict):
        return fail("native identity params are not a JSON object")
    metrics = readback.get("metrics") or {}
    artifacts = readback.get("artifact_names") or []
    counts = (len(params), len(metrics), len(artifacts))
    if not all(isinstance(n, int) and n > 0 for n in counts):
        return fail("run evidence is empty")
    if not isinstance(artifacts, list) or not all(safe_rel(a) for a in artifacts):
        return fail("artifact inventory has an unsafe path")
    # ponytail: reuse the native readback/manifest instead of parsing the
    # MLflow file store. Required files must exist and the readback sha must
    # correspond; native params/metrics/artifact internals are read from the
    # readback JSON the native run wrote, never re-parsed from mlruns files.
    for name in REQUIRED_MANIFEST:
        if name not in manifest:
            return fail("required evidence is missing from the manifest: " + name)
        if read_contained(real_out, name) is None:
            return fail("required evidence is missing: " + name)
    manifest_entry = manifest.get("mlflow_readback.json") or {}
    if manifest_entry.get("sha256") != hashlib.sha256(readback_bytes).hexdigest():
        return fail("manifest/readback identity mismatch")
    manifest_sha256 = file_sha256(str(real_out / "manifest.json"))
    if manifest_sha256 is None or not HEX64.match(manifest_sha256):
        return fail("manifest identity is invalid")
    if submit.get("run_id") != run_id:
        return fail("submit/run identity mismatch")
    if str(submit.get("experiment_id")) != experiment_id:
        return fail("submit/experiment identity mismatch")
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
    for key in ("symbol", "frequency"):
        value = params.get(key)
        if not isinstance(value, str) or not value.strip():
            return fail("native identity has an invalid " + key)
    leverage = params.get("research_leverage")
    if type(leverage) not in (str, int, float) or leverage not in ("3", "5", 3, 5):
        return fail("native identity has an invalid research_leverage")
    native_identity = {
        "symbol": params["symbol"],
        "frequency": params["frequency"],
        "research_leverage": int(leverage),
    }
    # ponytail: the native run directory must exist. Existence only; meta.yaml
    # and params/metrics file formats belong to MLflow, not to this bridge.
    run_ref = real_out / "mlruns" / experiment_id / run_id
    if not contained(str(real_out), str(run_ref)) or not run_ref.is_dir():
        return fail("mlflow run is missing")
    refs = {
        "candidate": CANDIDATE_BLOB_API + str(submit["candidate_blob_sha"]),
        "mlflow_run": str(run_ref),
        "mlflow_readback": str(real_out / "mlflow_readback.json"),
        "manifest": str(real_out / "manifest.json"),
        "effective_config": str(submit["effective_config_ref"]),
        "entrypoint": str(submit["entrypoint_ref"]),
    }
    for key, ref in refs.items():
        if key == "candidate":
            continue
        if key in ("effective_config", "entrypoint"):
            # ponytail: these two are the frozen submit inputs. They live
            # under the results root beside the out_dir, not inside it, so
            # root containment (not out_dir containment) is the right bound.
            if not under_root(ref, root) or not Path(ref).exists():
                return fail("evidence reference is missing")
            continue
        if not contained(str(real_out), ref) or not Path(ref).exists():
            return fail("evidence reference is missing")
    blob_sha = str(submit["candidate_blob_sha"])
    candidate_ok = HEX40.match(blob_sha) is not None
    if not candidate_ok:
        return fail("candidate identity is invalid")
    try:
        summary_bytes = read_contained(real_out, "summary.json")
        signals_bytes = read_contained(real_out, "signals.csv")
        events_bytes = read_contained(real_out, "events.csv")
        if summary_bytes is None or signals_bytes is None or events_bytes is None:
            return fail("run evidence is not readable")
        summary = json.loads(summary_bytes.decode("utf-8"))
        signals = signals_bytes.decode("utf-8").splitlines()
        events = events_bytes.decode("utf-8").splitlines()
    except (ValueError, UnicodeDecodeError, OSError):
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
                "native_identity": native_identity,
                "effective_config_sha256": submit["effective_config_sha256"],
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


def cmd_hermes(payload_b64):
    """Send one UTF-8 task to the fixed host Hermes command. Do not use a shell."""
    try:
        task = base64.b64decode(payload_b64, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return fail("Hermes task is not base64 UTF-8")
    if not task.strip():
        return fail("Hermes task is empty")
    try:
        proc = subprocess.run(
            ["hermes", "chat", "--query-file", "-", "--oneshot", "-Q",
             "--format", "stream-json", "-t", "wiki_brain"],
            input=task, cwd="/", capture_output=True, text=True, timeout=SUBMIT_TIMEOUT,
        )
    except (OSError, subprocess.SubprocessError):
        return fail("Hermes research turn did not complete")
    sys.stdout.write(proc.stdout)
    sys.stderr.write(proc.stderr)
    return proc.returncode


MATERIALIZE_PROMPT = """You write one strategy rule as a python code block.
Answer with exactly one fenced python block and nothing else.

def signal(*, high, low, close, volume, times, params, window_start, window_end):
    ...

Rules:
- Return (rows, entry_ts). rows is one dict for each bar, with at least
  datetime, high, low, close, entry_transition (0 or 1), exit_transition (0 or 1).
  entry_ts is the datetime of the first entry inside the window, or None.
- Standard library only. No file, network, shell, import, print, random or global
  state. The same bars must give the same rows.
- Read every parameter from params. Invent no default, size, cost or leverage.
- A rule that needs volume must stop when volume is None.
- Implement only the rule the record states. Add no filter, search or portfolio
  logic.

Frozen record:
%s
"""

#: One bounded subprocess. It loads the artifact through the engine's own
#: hash-bound loader and checks the engine's own row contract, so this file
#: carries no second copy of the strategy contract.
ARTIFACT_SMOKE = r'''
import importlib.util, json, sys
from datetime import datetime, timedelta
from pathlib import Path

engine_path, artifact_path, params_json = sys.argv[1], sys.argv[2], sys.argv[3]
spec = importlib.util.spec_from_file_location("cell_engine", engine_path)
engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(engine)
artifact = Path(artifact_path)
identity = {"ref": str(artifact), "sha256": engine.hashlib.sha256(artifact.read_bytes()).hexdigest()}
function = engine.load_signal_artifact(str(artifact.parent), identity)
start = datetime(2025, 1, 1)
closes = [100.0 - i * 0.25 for i in range(10)] + [110.0] + [110.0 + i * 0.75 for i in range(1, 21)]
volumes = [1000.0 + i * 5.0 for i in range(10)] + [8000.0] + [3000.0 + i * 20.0 for i in range(1, 21)]
times = [start + timedelta(hours=i) for i in range(len(closes))]
call = {
    "high": [value * 1.001 for value in closes],
    "low": [value * 0.999 for value in closes],
    "close": closes,
    "volume": volumes,
    "times": times,
    "params": json.loads(params_json),
    "window_start": start - timedelta(days=1),
    "window_end": times[-1],
}
first, second = function(**call), function(**call)
problems = engine.problems_in_signal_rows(first[0])
if first[0] != second[0] or first[1] != second[1]:
    problems.append("artifact is not deterministic on the same bars")
print(json.dumps({"ok": not problems, "error": "; ".join(problems) or None}))
'''

FENCE = re.compile(r"```(?:python|py)?[ \t]*\r?\n(.*?)```", re.S)
STRATEGY_KEYS = ("symbol", "timeframe", "params", "warmup_days", "window_start_utc",
                 "window_end_utc_inclusive", "force_flat_bar_utc")
OVERLAY_KEYS = ("base_order_quote_pct", "safety_order_quote_pct", "safety_order_levels",
                "so_spacing_pct", "take_profit_pct", "stop_loss_pct", "trade_cost",
                "initial_capital_quote")
OVERLAY_NUMERIC_KEYS = ("base_order_quote_pct", "safety_order_quote_pct", "safety_order_levels",
                        "so_spacing_pct", "trade_cost", "initial_capital_quote")
COST_MODEL_KEYS = ("fees_per_side", "slippage", "funding", "approved")


def materialize_problems(request):
    """Return the fail-closed problems in one materialization request."""
    if not isinstance(request, dict):
        return ["materialization request is not a JSON object"]
    for key in ("source_commit", "candidate_path", "source_blob_sha", "record_text", "strategy",
                "research_leverage", "runtime", "data", "house_overlay", "research_cost_model",
                "engine_ref"):
        if request.get(key) is None:
            return ["missing field: " + key]
    if not HEX40.match(str(request["source_commit"])):
        return ["source_commit has a bad shape"]
    if not HEX40.match(str(request["source_blob_sha"])):
        return ["source_blob_sha has a bad shape"]
    name = request["candidate_path"]
    if not isinstance(name, str) or "/" in name or ".." in name or not name.endswith(".md") or len(name) > 256:
        return ["candidate_path has a bad shape"]
    record = request["record_text"]
    if not isinstance(record, str) or not record.strip():
        return ["record_text is empty"]
    # The forced-command token carries base64, so the decoded record must stay
    # well below HERMES_PAYLOAD_LIMIT or the SSH handler refuses the whole call.
    if len(record) > MATERIALIZE_RECORD_LIMIT:
        return ["record_text is too large"]
    strategy = request["strategy"]
    if not isinstance(strategy, dict):
        return ["strategy is not a JSON object"]
    unknown = [key for key in strategy if key not in STRATEGY_KEYS]
    if unknown:
        return ["unknown strategy field: " + str(unknown[0])]
    if not re.match(r"^[A-Z0-9]{2,20}$", str(strategy.get("symbol"))):
        return ["strategy symbol is not a usable instrument name"]
    if not re.match(r"^[0-9]{1,2}[mhd]$", str(strategy.get("timeframe"))):
        return ["strategy timeframe is not a bar size"]
    if strategy.get("params") is not None and not isinstance(strategy["params"], dict):
        return ["strategy params is not a JSON object"]
    warmup = strategy.get("warmup_days", 0)
    if not isinstance(warmup, (int, float)) or isinstance(warmup, bool) or warmup < 0:
        return ["strategy warmup_days is not a non-negative number"]
    for key in ("window_start_utc", "window_end_utc_inclusive"):
        if not isinstance(strategy.get(key), str) or not strategy[key]:
            return ["strategy %s is missing" % key]
    leverage = request["research_leverage"]
    if not isinstance(leverage, int) or isinstance(leverage, bool) or leverage <= 0:
        return ["research_leverage is not a positive integer"]
    runtime, data = request["runtime"], request["data"]
    if not isinstance(runtime, dict) or not HEX40.match(str(runtime.get("commit"))):
        return ["runtime commit is missing or invalid"]
    if not isinstance(data, dict) or not check_abs_path(data.get("provider_ref")):
        return ["data provider_ref is missing or invalid"]
    overlay = request["house_overlay"]
    if not isinstance(overlay, dict):
        return ["house_overlay is not a JSON object"]
    for key in OVERLAY_KEYS:
        if key not in overlay:
            return ["house_overlay has no approved value for " + key]
    for key in OVERLAY_NUMERIC_KEYS:
        value = overlay.get(key)
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            return ["house_overlay.%s is not a usable number" % key]
    cost = request["research_cost_model"]
    if not isinstance(cost, dict) or [key for key in COST_MODEL_KEYS if key not in cost]:
        return ["research_cost_model does not declare every field"]
    if not check_abs_path(request["engine_ref"]):
        return ["engine_ref is not an absolute path"]
    return []


def materialize_name(request):
    """Return the stable run-scoped directory name for one frozen identity."""
    frozen = {
        "source_commit": request["source_commit"],
        "source_blob_sha": request["source_blob_sha"],
        "record_sha256": hashlib.sha256(request["record_text"].encode("utf-8")).hexdigest(),
        "strategy": request["strategy"],
        "research_leverage": request["research_leverage"],
    }
    return hashlib.sha256(
        json.dumps(frozen, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:12]


def artifact_source(request):
    """Return (source, generator, None) or (None, None, reason).

    ``RESEARCH_MATERIALIZE_ARTIFACT`` is a test seam: it supplies the block a
    generator would return, so the deterministic binding path is testable
    without a model. The block still passes every check below.
    """
    injected = os.environ.get("RESEARCH_MATERIALIZE_ARTIFACT")
    if injected:
        try:
            source = Path(injected).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return None, None, "the injected artifact file is not readable"
        if not source.strip():
            return None, None, "the injected artifact file is empty"
        return source, "artifact-file", None
    try:
        proc = subprocess.run(
            ["hermes", "chat", "--query-file", "-", "--oneshot", "-Q", "--format", "text"],
            input=MATERIALIZE_PROMPT % request["record_text"], cwd="/",
            capture_output=True, text=True, timeout=SUBMIT_TIMEOUT,
        )
    except (OSError, subprocess.SubprocessError):
        return None, None, "the Hermes materialization turn did not complete"
    if proc.returncode != 0:
        return None, None, "the Hermes materialization turn failed"
    blocks = [match.group(1) for match in FENCE.finditer(proc.stdout or "")]
    if len(blocks) != 1 or not blocks[0].strip():
        return None, None, "the generator reply must carry exactly one python block"
    return blocks[0].strip() + "\n", "hermes", None


def artifact_smoke(engine_ref, artifact_path, params):
    """Return None when the artifact passes the engine contract, else a reason."""
    try:
        proc = subprocess.run(
            [sys.executable, "-c", ARTIFACT_SMOKE, str(engine_ref), str(artifact_path),
             json.dumps(params or {}, sort_keys=True)],
            capture_output=True, text=True, timeout=SMOKE_TIMEOUT,
        )
    except (OSError, subprocess.SubprocessError):
        return "the artifact smoke did not complete"
    try:
        report = json.loads((proc.stdout or "").strip().splitlines()[-1])
    except (ValueError, IndexError):
        report = {"ok": False, "error": (proc.stderr or "").strip()[-400:] or "no smoke report"}
    if not isinstance(report, dict) or not report.get("ok"):
        return str((report or {}).get("error") or "the artifact smoke failed")
    return None


def cell_config(request, cell_ref, artifact_sha256, generator):
    """Return effective_config.json for one run-scoped cell."""
    strategy = dict(request["strategy"])
    strategy["params"] = dict(strategy.get("params") or {})
    strategy["warmup_days"] = strategy.get("warmup_days", 0)
    strategy["artifact"] = {"ref": cell_ref + "/" + SIGNAL_ARTIFACT_NAME, "sha256": artifact_sha256}
    return {
        "schema": "qlib-formal-research-cell-v1",
        "scope": "run-scoped materialized research cell; not Survivor/HB Certified",
        "candidate": {
            "path": request["candidate_path"],
            "source_commit": request["source_commit"],
            "git_blob_sha": request["source_blob_sha"],
            "sha256": hashlib.sha256(request["record_text"].encode("utf-8")).hexdigest(),
        },
        "runtime": dict(request["runtime"]),
        "data": dict(request["data"]),
        "execution": {
            "engine": "qlib.backtest.research_cell (shared shell via the frozen qlib runtime)",
            "entrypoint": cell_ref + "/" + ENGINE_ENTRYPOINT_NAME,
        },
        "research_leverage": request["research_leverage"],
        "strategy": strategy,
        "house_overlay": dict(request["house_overlay"]),
        "research_cost_model": dict(request["research_cost_model"]),
        "materialization": {"generator": generator, "engine_ref": request["engine_ref"]},
        "economics_boundary": {
            "research_leverage_is_exposure_multiplier": True,
            "isolated_margin_funding_slippage": "not modeled here; Node13 Hummingbot owns canonical economics",
        },
    }


def cell_handoff(request, cell_ref, artifact_sha256, engine_sha256, config_sha256):
    """Return the executable handoff one materialized cell publishes."""
    config_ref = cell_ref + "/" + CONFIG_NAME
    return {
        "source_commit": request["source_commit"],
        "candidate_path": request["candidate_path"],
        "source_blob_sha": request["source_blob_sha"],
        "entrypoint_ref": cell_ref + "/" + ENGINE_ENTRYPOINT_NAME,
        "entrypoint_sha256": engine_sha256,
        "effective_config_ref": config_ref,
        "effective_config_sha256": config_sha256,
        "qlib_runtime_commit": request["runtime"]["commit"],
        "capabilities": {key: list(values) for key, values in VERIFIED_PRIMITIVES.items()},
        "evidence_refs": {
            "materialization": cell_ref + "/" + RECEIPT_NAME,
            "effective_config": config_ref,
            "strategy_artifact": cell_ref + "/" + SIGNAL_ARTIFACT_NAME,
        },
        "research_cost_model": dict(request["research_cost_model"]),
        "run_inputs": {
            "symbol": request["strategy"]["symbol"],
            "timeframe": request["strategy"]["timeframe"],
            "research_leverage": request["research_leverage"],
            "strategy_artifact_sha256": artifact_sha256,
        },
    }


def engine_coverage(engine_ref):
    """Return the engine's own frozen coverage tuples, or None when it declares none.

    The engine owns the research domain. This file reads it instead of keeping a
    second copy, so materialization cannot widen the domain on its own.
    """
    spec = importlib.util.spec_from_file_location("cell_engine_coverage", str(engine_ref))
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return (getattr(module, "CELL_SYMBOLS", None), getattr(module, "CELL_TIMEFRAMES", None),
            getattr(module, "CELL_LEVERAGES", None))


def cmd_materialize(payload_b64):
    """Resolve or materialize one run-scoped executable handoff. No shell."""
    request, reason = decode_handoff(payload_b64)
    if request is None:
        return fail(reason)
    problems = materialize_problems(request)
    if problems:
        return fail("; ".join(problems))
    root = os.environ.get("RESEARCH_MATERIALIZE_ROOT", MATERIALIZE_ROOT_DEFAULT)
    if not check_abs_path(root):
        return fail("the materialize root is not an absolute path")
    cell = Path(root) / materialize_name(request)
    cell_ref = root + "/" + cell.name
    engine_ref = Path(request["engine_ref"])
    if not engine_ref.is_file():
        return fail("engine_ref is not readable")
    symbols, timeframes, leverages = engine_coverage(engine_ref) or (None, None, None)
    if symbols:
        identity = (request["strategy"]["symbol"], request["strategy"]["timeframe"],
                    request["research_leverage"])
        if identity[0] not in symbols or identity[1] not in timeframes or identity[2] not in leverages:
            return fail("the strategy identity is outside the engine's frozen coverage")
    if cell.is_dir():
        # ponytail: a retry must not overwrite evidence. An existing cell is
        # resolved only while its own bytes still match the declared hashes.
        try:
            config = json.loads((cell / CONFIG_NAME).read_text(encoding="utf-8"))
        except (OSError, ValueError, UnicodeDecodeError):
            return fail("the existing cell config is not readable")
        declared = ((config.get("strategy") or {}).get("artifact") or {}).get("sha256")
        if file_sha256(cell / SIGNAL_ARTIFACT_NAME) != declared:
            return fail("the existing cell artifact does not match its declared hash")
        handoff = cell_handoff(request, cell_ref, declared,
                               file_sha256(cell / ENGINE_ENTRYPOINT_NAME), file_sha256(cell / CONFIG_NAME))
        reason = check_handoff(handoff)
        if reason:
            return fail("the existing cell handoff is not executable: " + reason)
        print(json.dumps({"ok": True, "generator": "existing", "handoff": handoff}, sort_keys=True))
        return 0
    if cell.exists():
        return fail("the materialize path exists and is not a cell directory")
    source, generator, reason = artifact_source(request)
    if source is None:
        return fail(reason)
    try:
        cell.mkdir(parents=True)
    except OSError:
        return fail("the cell directory could not be created")
    artifact_path = cell / SIGNAL_ARTIFACT_NAME
    artifact_path.write_text(source, encoding="utf-8")
    smoke = artifact_smoke(engine_ref, artifact_path, request["strategy"].get("params"))
    if smoke is not None:
        shutil.rmtree(cell, ignore_errors=True)
        return fail("the materialized artifact is not runnable: " + smoke)
    shutil.copyfile(engine_ref, cell / ENGINE_ENTRYPOINT_NAME)
    config = cell_config(request, cell_ref, file_sha256(artifact_path), generator)
    (cell / CONFIG_NAME).write_text(json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    handoff = cell_handoff(request, cell_ref, config["strategy"]["artifact"]["sha256"],
                           file_sha256(cell / ENGINE_ENTRYPOINT_NAME), file_sha256(cell / CONFIG_NAME))
    reason = check_handoff(handoff)
    if reason:
        return fail("the materialized handoff is not executable: " + reason)
    (cell / RECEIPT_NAME).write_text(json.dumps({
        "schema": "qlib-strategy-materialization-v1",
        "generator": generator,
        "record_sha256": config["candidate"]["sha256"],
        "engine_ref": request["engine_ref"],
        "strategy_artifact_sha256": handoff["run_inputs"]["strategy_artifact_sha256"],
        "effective_config_sha256": handoff["effective_config_sha256"],
        "smoke": "engine loader plus engine row contract on the built-in bar fixture",
        "handoff": handoff,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"ok": True, "generator": generator, "handoff": handoff}, sort_keys=True))
    return 0


def parse_forced_command(value, hermes=False):
    """Parse SSH_ORIGINAL_COMMAND for the fixed launch shape.

    The Qlib key runs this file with no argv. The Hermes key uses hermes-forced.
    The command text lives in SSH_ORIGINAL_COMMAND. Accept one allowed verb plus one
    argument, with one optional leading "cd / ;". Anything else fails
    closed. Return (verb, arg) or (None, reason). Never launches a shell.
    """
    limit = HERMES_PAYLOAD_LIMIT + 128 if hermes else 8192
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        return None, "forced-command input is missing or invalid"
    text = value.strip()
    if ";" in text:
        prefix, _, rest = text.partition(";")
        if prefix.strip() != "cd /" or ";" in rest:
            return None, "forced-command input is missing or invalid"
        text = rest
    tokens = text.strip().split()
    if len(tokens) != 2:
        return None, "forced-command input is missing or invalid"
    verb, arg = tokens
    if verb not in (HERMES_VERBS if hermes else FORCED_VERBS):
        return None, "forced-command input is missing or invalid"
    if verb == "research-readback":
        if not RUNID.match(arg):
            return None, "forced-command input is missing or invalid"
    else:
        if len(arg) > HERMES_PAYLOAD_LIMIT or re.fullmatch(r"[A-Za-z0-9+/=]+", arg) is None:
            return None, "forced-command input is missing or invalid"
    return (verb, arg), None


def resolve_container_cli():
    """Return the fixed container CLI path, or None when unavailable."""
    override = os.environ.get("RESEARCH_CONTAINER_CLI")
    if override:
        try:
            p = Path(override)
            if p.is_file() and os.access(p, os.X_OK):
                return str(p)
        except OSError:
            pass
        return None
    for cand in ("/usr/local/bin/container",):
        try:
            if Path(cand).is_file() and os.access(cand, os.X_OK):
                return cand
        except OSError:
            continue
    return shutil.which("container")


def host_results_source():
    """Return the host dir backing guest /results, or None when absent."""
    override = os.environ.get("RESEARCH_HOST_RESULTS_SOURCE")
    if override:
        try:
            if Path(override).is_dir():
                return override
        except OSError:
            pass
        return None
    try:
        if Path(HOST_RESULTS_SOURCE).is_dir():
            return HOST_RESULTS_SOURCE
    except OSError:
        pass
    return None


def should_forward_host():
    """True when a no-argv host launch should use the fixed runtime.

    Only for the default guest root missing on the host. Temp-root tests
    stay local; inside the fixed runtime /results exists so no forwarding.
    """
    if "RESEARCH_RESULTS_ROOT" in os.environ:
        return False
    if os.environ.get("RESEARCH_FORWARDED") == "1":
        return False
    try:
        if Path("/results/_validation").is_dir():
            return False
    except OSError:
        pass
    if resolve_container_cli() is None:
        return False
    if host_results_source() is None:
        return False
    return True


def build_forward_command(verb, arg):
    """Build the bounded fixed-runtime command, or None when invalid.

    Fixed image/python/mounts only; the sole variables are the already
    validated verb and one bounded payload/run id. No shell is used.
    """
    if verb not in FORCED_VERBS:
        return None
    if verb == "research-readback":
        if not RUNID.match(arg or ""):
            return None
    else:
        if not isinstance(arg, str) or len(arg) > 65536:
            return None
        if re.fullmatch(r"[A-Za-z0-9+/=]+", arg) is None:
            return None
    cli = resolve_container_cli()
    src = host_results_source()
    if cli is None or src is None:
        return None
    audit_src = str(Path(__file__).resolve().parent)
    if verb == "research-readback":
        return [
            cli, "run", "--read-only",
            "--mount", "type=bind,source=" + src + ",target=/results,readonly",
            "--mount", "type=bind,source=" + audit_src + ",target=/audit,readonly",
            FIXED_IMAGE, FIXED_GUEST_PYTHON,
            "/audit/research-transport.py", verb, arg,
        ]
    return [
        cli, "run",
        "--mount", "type=bind,source=" + src + ",target=/results",
        "--mount", "type=bind,source=" + audit_src + ",target=/audit,readonly",
        FIXED_IMAGE, FIXED_GUEST_PYTHON,
        "/audit/research-transport.py", verb, arg,
    ]


def forward_via_container(verb, arg):
    """Forward one bounded host command to the fixed runtime. No shell."""
    cmd = build_forward_command(verb, arg)
    if cmd is None:
        return fail("forced-command input is missing or invalid")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=SUBMIT_TIMEOUT)
    except (OSError, subprocess.SubprocessError) as exc:
        return fail("fixed runtime is not reachable: " + str(exc)[:200])
    if proc.stdout:
        print(proc.stdout, end="" if proc.stdout.endswith("\n") else "\n")
    if proc.stderr:
        print(proc.stderr, end="" if proc.stderr.endswith("\n") else "\n", file=sys.stderr)
    if proc.returncode == 0:
        return 0
    if proc.returncode == 2:
        return 2
    return fail("fixed runtime execution failed")


def main(argv):
    """Parse args and dispatch to one subcommand."""
    if not argv or argv == ["hermes-forced"]:
        forced = os.environ.get("SSH_ORIGINAL_COMMAND")
        parsed, reason = parse_forced_command(forced, hermes=bool(argv))
        if parsed is None:
            return fail(reason or "forced-command input is missing or invalid")
        verb, arg = parsed
        # ponytail: a separate restricted key enables only this host verb.
        # Keep the Qlib key and container forwarding unchanged.
        if argv:
            if verb == MATERIALIZE_VERB:
                return cmd_materialize(arg)
            return cmd_hermes(arg)
        # ponytail: host launches with no /results use the fixed runtime.
        if should_forward_host():
            return forward_via_container(verb, arg)
        if verb == "research-submit":
            return cmd_submit(arg)
        return cmd_readback(arg)
    parser = argparse.ArgumentParser(description="Bridge a handoff to the native Qlib path.")
    parser.add_argument(
        "cmd",
        choices=["research-submit", "research-readback"],
        help="research-submit takes a base64 handoff; research-readback takes a run id",
    )
    parser.add_argument("arg", help="base64 handoff JSON or 32-hex run id")
    args = parser.parse_args(argv)
    if args.cmd == "research-submit":
        return cmd_submit(args.arg)
    return cmd_readback(args.arg)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
