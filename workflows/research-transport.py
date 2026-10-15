#!/usr/bin/env python3
"""Thin SSH-side transport: validated handoff -> existing Qlib native path -> MLflow readback.

submit: check one base64 handoff, verify file hashes, run the existing native
entrypoint, print one Node04 receipt. readback: find one run id under the fixed
results root, verify its manifest, print one Node05 receipt. Exit 0 means valid,
exit 2 means invalid. This file never fabricates a PASS receipt: every receipt
field comes from hashes checked here or files the native run wrote.

ponytail: single-file bridge on purpose. Synchronous subprocess only, one fixed
results root, one out_dir per frozen executable (a re-submit refuses instead of
clobbering evidence), single-candidate coverage only. Submit binds the caller
hashes to the frozen config formal fields and the exact consumed file before
executing; readback verifies every manifest entry plus the native run
metadata/params/metrics/artifact bytes and keeps run/experiment identity
across stdout, disk, receipt, and native. No-argv runs only dispatch a strict
SSH_ORIGINAL_COMMAND (one verb, one arg), forwarding host launches with no
/results to the fixed container runtime. Ceilings:
RESULTS_ROOT holds at most a few hundred run dirs (readback scans one filename
per dir); SUBMIT_TIMEOUT bounds one native run; MAX_ARTIFACTS bounds one native
inventory walk; run_inputs/cost ride along as declared facts and never steer
the frozen entrypoint.
"""

import argparse
import base64
import binascii
import hashlib
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
MAX_ARTIFACTS = 500

# ponytail: the forced-command entry accepts exactly these verbs, one arg each.
FORCED_VERBS = ("submit", "research-submit", "readback", "research-readback")

# ponytail: readback actually reads these four files, so the manifest must
# cover them. Other manifest entries are verified when listed, never assumed.
REQUIRED_MANIFEST = ("mlflow_readback.json", "summary.json", "signals.csv", "events.csv")

# ponytail: bounded host-to-fixed-runtime forwarding. The host key runs this
# file with no argv; when the guest /results root is missing on the host but
# the fixed container runtime exists, forward the same bounded verb/arg to
# that fixed runtime. Never accept arbitrary shell/image/argv here.
FIXED_CONTAINER = "qlib-run"
FIXED_GUEST_PYTHON = "/opt/venv/bin/python"
FIXED_IMAGE = "qlib:main-bee09f23-arm64"
FIXED_IMAGE_DIGEST = "sha256:8bee2a8beed672b17096ad44db5064dbaadcafe124c2ee989cd03b47683355b9"
HOST_RESULTS_SOURCE = "/Volumes/ExpansionDrive/qlib-results"

# ponytail: native backtest copies must equal the verified root evidence
# bytes. Production entry logs these root files under artifacts/backtest.
REQUIRED_BACKTEST_COPY = ("events.csv", "signals.csv", "summary.json", "portfolio_report.csv")


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


def check_frozen_binding(obj):
    """Prove the verified config is the frozen config the entrypoint uses.

    The native entrypoint reads its sibling effective_config.json, so bind
    the caller hashes to that file's formal identity fields before running
    anything. A substring or note mention never counts. No execution here.
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
    # ponytail: bind the exact consumed file, not any sibling with matching
    # fields. The native entry reads <entry_dir>/effective_config.json.
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
    # ponytail: a matching declaration must not authorize a program that
    # never consumes the config. Require the entry to reference the frozen
    # config contract and the fixed out dir before any execution.
    try:
        entry_bytes = Path(obj["entrypoint_ref"]).read_bytes()
    except OSError:
        return "entrypoint is not readable"
    if b"effective_config.json" not in entry_bytes or b"QLIB_OUT_DIR" not in entry_bytes:
        return "config/execution identity mismatch"
    return None


def check_submit_native(out_dir, run_id, experiment_id, disk):
    """Share readback native identity checks before submit reports PASS.

    A child that deletes meta.yaml or drifts params/metrics must fail here,
    not only on later readback. Return None when clean, else a reason.
    """
    run_ref = out_dir / "mlruns" / experiment_id / run_id
    try:
        if not contained(str(out_dir), str(run_ref)) or not run_ref.is_dir():
            return "mlflow run is missing"
    except OSError:
        return "mlflow run is missing"
    meta_bytes = read_contained(run_ref, "meta.yaml")
    if meta_bytes is None:
        return "native run metadata is missing"
    try:
        native_run, native_exp, native_status = parse_run_meta(meta_bytes.decode("utf-8"))
    except UnicodeDecodeError:
        return "native run metadata is missing"
    if native_run != run_id or native_exp != experiment_id:
        return "native run identity mismatch"
    if native_status != "3":
        return "native run is not FINISHED"
    native_params = read_native_params(run_ref)
    disk_params = disk.get("params") or {}
    if native_params is None or native_params != disk_params:
        return "native params mismatch"
    native_metrics = read_native_metrics(run_ref)
    disk_metrics = disk.get("metrics") or {}
    if native_metrics is None or set(native_metrics) != set(disk_metrics):
        return "native metrics mismatch"
    for key, claimed in disk_metrics.items():
        try:
            same = float(native_metrics[key]) == float(claimed)
        except (TypeError, ValueError, KeyError):
            same = False
        if not same:
            return "native metrics mismatch"
    inventory = artifact_inventory(run_ref)
    disk_artifacts = disk.get("artifact_names") or []
    if inventory is None or not isinstance(disk_artifacts, list):
        return "native artifact inventory mismatch"
    if set(disk_artifacts) != set(inventory):
        return "native artifact inventory mismatch"
    return None


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
    reason = check_submit_native(out_dir, run_id, experiment_id, disk)
    if reason is not None:
        return fail(reason)
    native_hashes = native_artifact_hashes(out_dir / "mlruns" / experiment_id / run_id)
    if native_hashes is None:
        return fail("native artifact inventory mismatch")
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
        "native_artifact_sha256": native_hashes,
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


def parse_run_meta(text):
    """Parse file-store meta.yaml run identity without a YAML library."""
    run_id = experiment_id = status = None
    for line in text.splitlines():
        if line.startswith("run_id:"):
            run_id = line.split(":", 1)[1].strip()
        elif line.startswith("experiment_id:"):
            experiment_id = line.split(":", 1)[1].strip().strip("'\"")
        elif line.startswith("status:"):
            status = line.split(":", 1)[1].strip()
    return run_id, experiment_id, status


def read_native_params(run_ref):
    """Read native params files, or None when the layout is not verifiable."""
    params = {}
    pdir = run_ref / "params"
    try:
        if not pdir.is_dir():
            return None
        for child in sorted(pdir.iterdir()):
            if child.is_symlink() or not child.is_file():
                return None
            if not contained(str(run_ref), str(child)):
                return None
            params[child.name] = child.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return params


def read_native_metrics(run_ref):
    """Read latest native metric values, or None when not verifiable."""
    metrics = {}
    mdir = run_ref / "metrics"
    try:
        if not mdir.is_dir():
            return None
        for child in sorted(mdir.iterdir()):
            if child.is_symlink() or not child.is_file():
                return None
            if not contained(str(run_ref), str(child)):
                return None
            lines = child.read_text(encoding="utf-8").strip().splitlines()
            if not lines:
                return None
            try:
                metrics[child.name] = float(lines[-1].split()[1])
            except (IndexError, ValueError):
                return None
    except OSError:
        return None
    return metrics


def artifact_inventory(run_ref):
    """List native artifact paths, or None on any symlink/escape/overflow."""
    adir = run_ref / "artifacts"
    # ponytail: anchor the artifact directory root itself. Descendant checks
    # alone resolve a relocated directory as a new trusted base.
    try:
        if adir.is_symlink():
            return None
        if not contained(str(run_ref), str(adir)):
            return None
        if not adir.is_dir():
            return None
    except OSError:
        return None
    names = []
    try:
        paths = sorted(adir.rglob("*"))
    except OSError:
        return None
    for path in paths:
        if path.is_symlink():
            return None
        if path.is_file():
            if not contained(str(adir), str(path)):
                return None
            try:
                names.append(path.relative_to(adir).as_posix())
            except ValueError:
                return None
            if len(names) > MAX_ARTIFACTS:
                return None
    return names


def native_artifact_hashes(run_ref):
    """Map each native artifact path to its sha256, or None when unverifiable."""
    adir = run_ref / "artifacts"
    try:
        if adir.is_symlink() or not contained(str(run_ref), str(adir)):
            return None
    except OSError:
        return None
    out = {}
    try:
        paths = sorted(adir.rglob("*"))
    except OSError:
        return None
    for path in paths:
        if path.is_symlink():
            return None
        if path.is_file():
            if not contained(str(adir), str(path)):
                return None
            try:
                rel = path.relative_to(adir).as_posix()
            except ValueError:
                return None
            digest = file_sha256(str(path))
            if digest is None:
                return None
            out[rel] = digest
            if len(out) > MAX_ARTIFACTS:
                return None
    return out


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
    if not isinstance(artifacts, list) or not all(safe_rel(a) for a in artifacts):
        return fail("artifact inventory has an unsafe path")
    for name in REQUIRED_MANIFEST:
        if name not in manifest:
            return fail("required evidence is missing from the manifest: " + name)
    for name, entry in manifest.items():
        if not safe_rel(name):
            return fail("manifest entry escapes the run: " + str(name))
        if not isinstance(entry, dict):
            return fail("manifest/content mismatch: " + str(name))
        claimed_bytes = entry.get("bytes")
        claimed_sha = entry.get("sha256")
        if not isinstance(claimed_bytes, int) or claimed_bytes < 0:
            return fail("manifest/content mismatch: " + str(name))
        if not isinstance(claimed_sha, str) or not HEX64.match(claimed_sha):
            return fail("manifest/content mismatch: " + str(name))
        actual = read_contained(real_out, name)
        if actual is None or len(actual) != claimed_bytes:
            return fail("manifest/content mismatch: " + str(name))
        if hashlib.sha256(actual).hexdigest() != claimed_sha:
            return fail("manifest/content mismatch: " + str(name))
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
    run_ref = real_out / "mlruns" / experiment_id / run_id
    if not contained(str(real_out), str(run_ref)) or not run_ref.is_dir():
        return fail("mlflow run is missing")
    meta_bytes = read_contained(run_ref, "meta.yaml")
    if meta_bytes is None:
        return fail("native run metadata is missing")
    try:
        native_run, native_exp, native_status = parse_run_meta(
            meta_bytes.decode("utf-8")
        )
    except UnicodeDecodeError:
        return fail("native run metadata is missing")
    if native_run != run_id or native_exp != experiment_id:
        return fail("native run identity mismatch")
    if native_status != "3":
        return fail("native run is not FINISHED")
    native_params = read_native_params(run_ref)
    if native_params is None or native_params != params:
        return fail("native params mismatch")
    native_metrics = read_native_metrics(run_ref)
    if native_metrics is None or set(native_metrics) != set(metrics):
        return fail("native metrics mismatch")
    for key, claimed in metrics.items():
        try:
            same = float(native_metrics[key]) == float(claimed)
        except (TypeError, ValueError):
            same = False
        if not same:
            return fail("native metrics mismatch")
    inventory = artifact_inventory(run_ref)
    if inventory is None or set(artifacts) != set(inventory):
        return fail("native artifact inventory mismatch")
    repro = [a for a in artifacts if isinstance(a, str) and a.startswith("repro/")]
    configs = [a for a in repro if a.endswith("/effective_config.json")]
    entries = [a for a in repro if a.endswith(".py")]
    providers = [a for a in repro if a.endswith("provider-manifest.json")]
    if len(configs) != 1 or len(entries) != 1 or len(providers) > 1:
        return fail("repro artifacts are ambiguous")
    repro_cfg_bytes = read_contained(run_ref / "artifacts", configs[0])
    if repro_cfg_bytes is None:
        return fail("repro/config identity mismatch")
    try:
        repro_cfg = json.loads(repro_cfg_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return fail("repro/config identity mismatch")
    if not isinstance(repro_cfg, dict):
        return fail("repro/config identity mismatch")
    repro_cand = repro_cfg.get("candidate")
    if not isinstance(repro_cand, dict):
        return fail("repro/candidate identity mismatch")
    if repro_cand.get("path") != submit.get("candidate_path"):
        return fail("repro/candidate identity mismatch")
    if repro_cand.get("git_blob_sha") != submit.get("candidate_blob_sha"):
        return fail("repro/candidate identity mismatch")
    if "qlib_runtime_commit" in submit:
        repro_runtime = repro_cfg.get("runtime")
        if not isinstance(repro_runtime, dict):
            return fail("repro/runtime identity mismatch")
        if repro_runtime.get("commit") != submit.get("qlib_runtime_commit"):
            return fail("repro/runtime identity mismatch")
    repro_entry = run_ref / "artifacts" / entries[0]
    if not contained(str(run_ref / "artifacts"), str(repro_entry)):
        return fail("repro/executable identity mismatch")
    entry_digest = file_sha256(str(repro_entry))
    if entry_digest is None or entry_digest != submit.get("entrypoint_sha256"):
        return fail("repro/executable identity mismatch")
    repro_cfg_path = run_ref / "artifacts" / configs[0]
    if not contained(str(run_ref / "artifacts"), str(repro_cfg_path)):
        return fail("repro/config identity mismatch")
    cfg_digest = file_sha256(str(repro_cfg_path))
    if cfg_digest is None or cfg_digest != submit.get("effective_config_sha256"):
        return fail("repro/config identity mismatch")
    # ponytail: verify native artifact bytes, not only inventory names. New
    # submits record hashes; legacy receipts without the field still verify
    # via root-copy equality and provider binding below.
    recorded = submit.get("native_artifact_sha256")
    if isinstance(recorded, dict):
        current = native_artifact_hashes(run_ref)
        if current is None or current != recorded:
            return fail("native artifact bytes mismatch")
    # ponytail: each live native backtest copy must equal its verified root
    # file. Stubs carry no data/strategy section and skip this; their bytes
    # are still bound by the recorded hashes above.
    if isinstance(repro_cfg, dict) and ("data" in repro_cfg or "strategy" in repro_cfg):
        for name in REQUIRED_BACKTEST_COPY:
            root_bytes = read_contained(real_out, name)
            native_bytes = read_contained(run_ref / "artifacts" / "backtest", name)
            if root_bytes is None and native_bytes is None:
                continue
            if root_bytes is None or native_bytes is None:
                return fail("native backtest bytes mismatch: " + name)
            if root_bytes != native_bytes:
                return fail("native backtest bytes mismatch: " + name)
    # ponytail: bind the provider manifest to the frozen config digest.
    data = repro_cfg.get("data") if isinstance(repro_cfg, dict) else None
    if isinstance(data, dict) and "provider_manifest_sha256" in data:
        if len(providers) != 1:
            return fail("repro/provider identity mismatch")
        pm_bytes = read_contained(run_ref / "artifacts", providers[0])
        if pm_bytes is None:
            return fail("repro/provider identity mismatch")
        try:
            pm_obj = json.loads(pm_bytes.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return fail("repro/provider identity mismatch")
        try:
            compact = json.dumps(pm_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError):
            return fail("repro/provider identity mismatch")
        if hashlib.sha256(compact).hexdigest() != data.get("provider_manifest_sha256"):
            return fail("repro/provider identity mismatch")
        want_count = data.get("provider_file_count")
        if not isinstance(want_count, int):
            return fail("repro/provider identity mismatch")
        if not isinstance(pm_obj, list) or len(pm_obj) != want_count:
            return fail("repro/provider identity mismatch")
    # ponytail: live runs must keep portfolio and trade evidence. Stubs have
    # no data/strategy section and skip this; live configs carry it.
    if isinstance(repro_cfg, dict) and ("data" in repro_cfg or "strategy" in repro_cfg):
        for name in ("portfolio_report.csv", "trade_indicators.csv"):
            if name not in manifest:
                return fail("required evidence is missing from the manifest: " + name)
    refs = {
        "candidate": CANDIDATE_BLOB_API + str(submit["candidate_blob_sha"]),
        "mlflow_run": str(run_ref),
        "mlflow_readback": str(real_out / "mlflow_readback.json"),
        "manifest": str(real_out / "manifest.json"),
        "effective_config": str(run_ref / "artifacts" / configs[0]),
        "entrypoint": str(run_ref / "artifacts" / entries[0]),
    }
    if providers:
        refs["provider_manifest"] = str(run_ref / "artifacts" / providers[0])
    for key, ref in refs.items():
        if key == "candidate":
            continue
        # ponytail: native refs must stay inside the native run, not merely
        # inside the outer out_dir. A symlinked artifacts dir stays inside
        # out_dir while leaving its native run.
        want_base = (
            str(run_ref)
            if key in ("mlflow_run", "effective_config", "entrypoint", "provider_manifest")
            else str(real_out)
        )
        if not contained(want_base, ref) or not Path(ref).exists():
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


def parse_forced_command(value):
    """Strictly parse SSH_ORIGINAL_COMMAND for the fixed launch shape.

    The restricted key runs this file with no argv; the only command text
    lives in SSH_ORIGINAL_COMMAND. Accept exactly one known verb plus one
    argument, with one optional leading "cd / ;". Anything else fails
    closed. Return (verb, arg) or (None, reason). Never launches a shell.
    """
    if not isinstance(value, str) or not value.strip() or len(value) > 8192:
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
    if verb not in FORCED_VERBS:
        return None, "forced-command input is missing or invalid"
    if verb in ("readback", "research-readback"):
        if not RUNID.match(arg):
            return None, "forced-command input is missing or invalid"
    else:
        if len(arg) > 65536 or re.fullmatch(r"[A-Za-z0-9+/=]+", arg) is None:
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
    if verb in ("readback", "research-readback"):
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
    if verb in ("readback", "research-readback"):
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
    if not argv:
        forced = os.environ.get("SSH_ORIGINAL_COMMAND")
        parsed, reason = parse_forced_command(forced)
        if parsed is None:
            return fail(reason or "forced-command input is missing or invalid")
        verb, arg = parsed
        # ponytail: host launches with no /results use the fixed runtime.
        if should_forward_host():
            return forward_via_container(verb, arg)
        if verb in ("submit", "research-submit"):
            return cmd_submit(arg)
        return cmd_readback(arg)
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
