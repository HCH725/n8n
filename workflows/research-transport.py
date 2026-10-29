#!/usr/bin/env python3
"""Thin SSH-side transport: validated handoff -> existing Qlib native path -> MLflow readback.

submit: check one base64 handoff, verify file hashes, run the existing native
entrypoint, print one Node04 receipt. readback: find one run id under the fixed
results root, verify its manifest, print one Node05 receipt. Exit 0 means valid,
exit 2 means invalid. This file never fabricates a PASS receipt: every receipt
field comes from hashes checked here or files the native run wrote.

materialize: verify one base64 materialize request, then run ONLY the existing
Qlib ``research_cell.py materialize --spec ... --root ...`` in the pinned
runtime. No arbitrary argv, no shell, no ``--force``. It writes the frozen cell
dirs the existing engineering flow declares, verifies the campaign manifest the
Qlib run wrote, and prints one receipt. A request whose spec does not exist is
a typed ``implementation_needed`` answer, never an invented strategy: this file
carries no strategy semantics and never compiles Markdown into Qlib code.

hermes-forced: a separate restricted key sends one base64 UTF-8 task to the
fixed host Hermes argv. This mode accepts no Qlib verb and starts no shell. The
same key serves ``research-handoff``: it resolves one already-frozen engineering
cell against its own manifest, verifies every byte against the frozen digests and
prints the executable handoff. It generates nothing, writes nothing, imports no
strategy artifact and starts no subprocess. The engineering cell itself is
produced by the existing Hermes/Kanban flow. The workflow's readiness gate still
decides admission.

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
- Zero-trade is valid completed execution, not performance evidence. readback
  cross-checks summary.cycles_replayed, metrics.total_trades and the events.csv
  header and row count. It never invents a trade.
"""

import argparse
import base64
import binascii
import csv
import hashlib
import io
import json
import math
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
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
    #: The shared shell opens one long leg. A declared short side is a genuine
    #: capability gap and routes ENGINEERING_HOLD instead of being accepted.
    "sides": ["long"],
}

CANDIDATE_BLOB_API = "https://api.github.com/repos/HCH725/alpha-strategy-research/git/blobs/"

RESULTS_ROOT_DEFAULT = "/results/production"
OUT_PREFIX = "n8n-live-"
SUBMIT_TIMEOUT = 1800
MAX_SCAN_DIRS = 500

# ponytail: the forced-command entry accepts exactly these three verbs, one arg
# each. The short aliases (submit/readback) are gone on purpose: production
# Node04/Node05 already use the research- prefix, and one spelling keeps the
# SSH trust boundary auditable. ``research-materialize`` is the third Qlib verb:
# it runs the existing Qlib materializer in this same pinned runtime, so it
# belongs to the Qlib key rather than to the restricted Hermes key.
MATERIALIZE_VERB = "research-materialize"
FORCED_VERBS = ("research-submit", "research-readback", MATERIALIZE_VERB)
HERMES_VERB = "research-hermes"
#: Second host verb on the same restricted key: resolve one frozen engineering
#: cell and print its executable handoff. It never generates, writes or imports.
HANDOFF_VERB = "research-handoff"
HERMES_VERBS = (HERMES_VERB, HANDOFF_VERB)
HERMES_PAYLOAD_LIMIT = 65536

# ponytail: readback actually reads these five files, so the manifest must
# cover them. Only existence plus the readback sha correspondence is checked;
# per-file byte attestation lives with the native run, not here.
REQUIRED_MANIFEST = ("mlflow_readback.json", "summary.json", "metrics.json",
                     "signals.csv", "events.csv")

#: The runtime writes this exact minimum header, then one row per replayed
#: stage. A zero-cycle run writes the header only.
EVENT_FIELDS = ("cycle", "stage", "stage_price", "stage_quote_amount", "filled_quote")

# ponytail: bounded host-to-fixed-runtime forwarding. The host key runs this
# file with no argv; when the guest /results root is missing on the host but
# the fixed container runtime exists, forward the same bounded verb/arg to
# that fixed runtime. Never accept arbitrary shell/image/argv here.
FIXED_CONTAINER = "qlib-run"
FIXED_GUEST_PYTHON = "/opt/venv/bin/python"
FIXED_IMAGE = "qlib:main-f92320c1-arm64"
FIXED_IMAGE_DIGEST = "sha256:6081534f5b223c7ee53b28a05670b3351cfe0878cc0c05cf81790bf86d48efc8"
FIXED_RUNTIME_COMMIT = "f92320c176521b269f5dee361a2172b8e6cde25c"
HOST_RESULTS_SOURCE = "/Volumes/ExpansionDrive/qlib-results"


def fail(reason):
    """Print a rejection report and return exit code 2."""
    print(json.dumps({"ok": False, "error": reason}))
    return 2


def implementation_needed(reason):
    """Print one expected ``implementation_needed`` answer. Exit 0, like the handoff.

    A missing approved spec is an expected state, not corrupt transport: the
    caller must be able to parse the typed payload and route it to the bounded
    engineering lane. Every malformed, mismatched or unsafe request still fails
    closed with exit 2, so this answer can never be read as a pass.
    """
    print(json.dumps({"ok": True, "status": "implementation_needed",
                      "source": "none", "reason": reason}, sort_keys=True))
    return 0


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


def is_count(value):
    """True when value is one integer count. A bool is never a count."""
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def count_events(events_bytes):
    """Return (data rows, None) or (None, reason) for one events.csv payload.

    The runtime writes the five minimum header fields, then one row per
    replayed stage. A zero-cycle run writes the header only.
    """
    try:
        rows = [row for row in csv.reader(io.StringIO(events_bytes.decode("utf-8"), newline=""),
                                          strict=True)
                if row]
    except (UnicodeDecodeError, csv.Error):
        return None, "event evidence is not readable CSV"
    if not rows or tuple(rows[0]) != EVENT_FIELDS:
        return None, "event evidence has a bad header"
    if any(len(row) != len(EVENT_FIELDS) for row in rows[1:]):
        return None, "event evidence has a bad row"
    return len(rows) - 1, None


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
        run_metrics_bytes = read_contained(real_out, "metrics.json")
        signals_bytes = read_contained(real_out, "signals.csv")
        events_bytes = read_contained(real_out, "events.csv")
        if (summary_bytes is None or run_metrics_bytes is None
                or signals_bytes is None or events_bytes is None):
            return fail("run evidence is not readable")
        summary = json.loads(summary_bytes.decode("utf-8"))
        run_metrics = json.loads(run_metrics_bytes.decode("utf-8"))
        signals = signals_bytes.decode("utf-8").splitlines()
    except (ValueError, UnicodeDecodeError, OSError):
        return fail("run evidence is not readable")
    # ponytail: the runtime writes both counts. Zero trades is a valid
    # completed execution, so the two counts must agree instead of being
    # guessed from a non-empty events file.
    if not isinstance(summary, dict) or not is_count(summary.get("cycles_replayed")):
        return fail("run evidence has no usable cycle count")
    if not isinstance(run_metrics, dict) or not is_count(run_metrics.get("total_trades")):
        return fail("run evidence has no usable trade count")
    cycles = summary["cycles_replayed"]
    if run_metrics["total_trades"] != cycles:
        return fail("run evidence cycle/trade mismatch")
    event_rows, reason = count_events(events_bytes)
    if event_rows is None:
        return fail(reason)
    if (cycles == 0) != (event_rows == 0):
        return fail("event evidence does not match the replayed cycle count")
    data_ok = (
        isinstance(params.get("symbol"), str) and len(params["symbol"]) > 0
        and isinstance(params.get("frequency"), str) and len(params["frequency"]) > 0
        and isinstance(summary, dict) and is_count(summary.get("cycles_replayed"))
        and len(signals) >= 2
    )
    execution_ok = (cycles == 0 and event_rows == 0) or (cycles > 0 and event_rows > 0)
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
    # ponytail: additive, whitelisted native evidence. Every PR #19 check above
    # already ran; this block only re-exposes what they verified, and it never
    # fills in a field the native run did not write. A missing phase stays null
    # so the caller holds on the absence instead of reading a guessed phase.
    config, _why = _read_json(submit["effective_config_ref"])
    if not isinstance(config, dict):
        return fail("the verified effective config is not readable JSON")
    binding, reason = _phase_binding_for_run(submit)
    if reason is not None:
        return fail(reason)
    native, reason = _native_evidence(summary, run_metrics, config, submit,
                                      manifest_sha256, binding)
    if native is None:
        return fail(reason)
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
                "native_evidence": native,
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


# ---------------------------------------------------------------------------
# One frozen-cell handoff verb: fixed request in, fixed reply out.
#
# The strategy artifact is produced by the existing engineering flow. A Qlib
# ``materialize()`` run writes one frozen cell directory per identity plus the
# campaign manifest that binds every digest. This file never generates code,
# never writes a file, never imports the strategy artifact and never starts a
# subprocess. It verifies one existing cell against its own frozen evidence and
# prints the executable handoff the readiness gate already expects.
# ---------------------------------------------------------------------------

HANDOFF_KIND_RESOLVE = "handoff-resolve-v1"
HANDOFF_KIND_VERIFY = "handoff-verify-v1"
MANIFEST_NAME = "campaign-manifest.json"
MANIFEST_SCHEMA = "qlib-formal-campaign-manifest-v1"
STRATEGY_KEYS = ("symbol", "timeframe", "family", "sides", "params", "warmup_days",
                 "window_start_utc", "window_end_utc_inclusive", "force_flat_bar_utc")
STRATEGY_REQUIRED = ("symbol", "timeframe", "window_start_utc", "window_end_utc_inclusive")
OVERLAY_KEYS = ("base_order_quote_pct", "safety_order_quote_pct", "safety_order_levels",
                "so_spacing_pct", "take_profit_pct", "stop_loss_pct", "trade_cost",
                "initial_capital_quote")
OVERLAY_NUMERIC_KEYS = ("base_order_quote_pct", "safety_order_quote_pct", "safety_order_levels",
                        "so_spacing_pct", "trade_cost", "initial_capital_quote")
COST_MODEL_KEYS = ("fees_per_side", "slippage", "funding", "approved")
#: Every cell digest pair the manifest binds. Bytes are hashed only to be
#: compared with the frozen declaration; this file never re-signs them.
CELL_EVIDENCE = (("effective_config_ref", "effective_config_sha256"),
                 ("entrypoint_ref", "entrypoint_sha256"),
                 ("strategy_artifact_ref", "strategy_artifact_sha256"))
HANDOFF_MATCH_KEYS = ("source_commit", "candidate_path", "source_blob_sha", "entrypoint_ref",
                      "entrypoint_sha256", "effective_config_sha256", "qlib_runtime_commit")

# ---------------------------------------------------------------------------
# Three narrow additions on the already-fixed surface. None of them adds a
# service, queue, registry, scheduler or compiler.
#
# - ``campaign-manifest-read-v1`` reads one frozen campaign manifest (zero
#   writes, no child process) on the existing handoff verb.
# - ``native_evidence`` is one additive, whitelisted object inside the existing
#   Node05 receipt, built only from bytes this file already verified.
# - ``research-materialize`` runs ONLY the existing Qlib
#   ``materialize --spec ... --root ...``, never ``--force``, never a shell.
# ---------------------------------------------------------------------------

HANDOFF_KIND_CAMPAIGN = "campaign-manifest-read-v1"
MATERIALIZE_KIND = "materialize-v1"
MATERIALIZE_RECEIPT = "materialize-receipt.json"
MATERIALIZE_RECEIPT_SCHEMA = "qlib-n8n-materialize-receipt-v1"
MATERIALIZE_LOCK = ".materialize.lock"
#: Bounded wait for one concurrent identical request to converge. A longer wait
#: is not a retry policy: the caller sees a typed refuse and can ask again.
MATERIALIZE_LOCK_WAIT = 30.0
MATERIALIZE_LOCK_POLL = 0.1
#: A phase is a research decision the caller already made. This file never
#: derives one: an absent phase stays null and unbound, never guessed.
PHASES = ("IS_BASELINE", "IS_RETEST", "OOS")
OOS_PHASE = "OOS"
WINDOW_STAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}$")
#: Whitelisted campaign-manifest cell fields. Only these are returned, so a field
#: a later Qlib build adds cannot leak into the n8n reply by accident.
CAMPAIGN_CELL_KEYS = (
    "cell_id", "symbol", "timeframe", "research_leverage", "source_commit",
    "candidate_path", "source_blob_sha", "entrypoint_ref", "entrypoint_sha256",
    "effective_config_ref", "effective_config_sha256", "strategy_artifact_ref",
    "strategy_artifact_sha256", "qlib_runtime_commit", "capabilities",
    "evidence_refs", "run_inputs", "research_cost_model",
)
#: Native metrics the campaign/OOS decision needs. ``total_trades`` is required;
#: every other value is null when the native run omitted it, never filled in.
NATIVE_METRIC_KEYS = ("net_return_pct", "cagr_pct", "sharpe", "max_drawdown_pct",
                      "win_rate_pct", "profit_factor", "net_profit_usdt",
                      "evaluation_bars", "funding_paid_quote")
#: Native applied-economics fields, verbatim. The modeled-mark file inventory is
#: deliberately excluded: it names host paths and adds no decision value.
APPLIED_ECONOMICS_KEYS = (
    "applied", "slippage_applied", "funding_applied", "funding_declaration",
    "funding_total_payment_quote", "funding_charged_event_count", "funding_reconciled",
    "funding_truth_status_counts", "funding_charged_truth_status_counts",
    "funding_basis", "funding_source_ref", "funding_source_sha256",
    "funding_modeled_mark_basis", "funding_modeled_mark_snapshot_sha256",
    "declared_model_matches_applied", "declared_model_match_reason",
)


def _read_json(path_value):
    """Return (object, None) or (None, reason) for one JSON file. Never writes."""
    try:
        return json.loads(Path(path_value).read_bytes().decode("utf-8")), None
    except (OSError, ValueError, UnicodeDecodeError):
        return None, "not readable JSON"


def _identity_digest(identity):
    """Return a stable 12-hex digest of one full effective identity."""
    return hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:12]


def _identity_problems(identity):
    """Return the fail-closed problems in one full effective identity."""
    if not isinstance(identity, dict):
        return ["identity is not a JSON object"]
    unknown = [key for key in identity
               if key not in ("strategy", "research_leverage", "runtime", "data",
                              "house_overlay", "research_cost_model")]
    if unknown:
        return ["unknown identity field: " + str(unknown[0])]
    strategy = identity.get("strategy")
    if not isinstance(strategy, dict):
        return ["identity.strategy is not a JSON object"]
    extra = [key for key in strategy if key not in STRATEGY_KEYS]
    if extra:
        return ["unknown strategy field: " + str(extra[0])]
    for key in STRATEGY_REQUIRED:
        if not isinstance(strategy.get(key), str) or not strategy[key]:
            return ["strategy %s is missing" % key]
    # A strategy must state which execution sides it implements. The shell only
    # executes one long leg, so a two-sided strategy cannot be accepted here.
    sides = strategy.get("sides")
    if not isinstance(sides, list) or not sides or [s for s in sides if not isinstance(s, str)]:
        return ["strategy execution sides are not declared"]
    if strategy.get("params") is not None and not isinstance(strategy["params"], dict):
        return ["strategy params is not a JSON object"]
    warmup = strategy.get("warmup_days", 0)
    if not isinstance(warmup, (int, float)) or isinstance(warmup, bool) or warmup < 0:
        return ["strategy warmup_days is not a non-negative number"]
    leverage = identity.get("research_leverage")
    if not isinstance(leverage, int) or isinstance(leverage, bool) or leverage <= 0:
        return ["research_leverage is not a positive integer"]
    runtime = identity.get("runtime")
    if not isinstance(runtime, dict) or not HEX40.match(str(runtime.get("commit"))):
        return ["runtime commit is missing or invalid"]
    data = identity.get("data")
    if not isinstance(data, dict) or not check_abs_path(data.get("provider_ref")):
        return ["data provider_ref is missing or invalid"]
    overlay = identity.get("house_overlay")
    if not isinstance(overlay, dict):
        return ["house_overlay is not a JSON object"]
    for key in OVERLAY_KEYS:
        if key not in overlay:
            return ["house_overlay has no approved value for " + key]
    for key in OVERLAY_NUMERIC_KEYS:
        value = overlay.get(key)
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            return ["house_overlay.%s is not a usable number" % key]
    cost = identity.get("research_cost_model")
    if not isinstance(cost, dict) or [key for key in COST_MODEL_KEYS if key not in cost]:
        return ["research_cost_model does not declare every field"]
    if not isinstance(cost.get("approved"), bool):
        return ["research_cost_model.approved is not a boolean"]
    return []


def _request_problems(request):
    """Return the fail-closed problems in one handoff request."""
    if not isinstance(request, dict):
        return ["handoff request is not a JSON object"]
    kind = request.get("request")
    if kind not in (HANDOFF_KIND_RESOLVE, HANDOFF_KIND_VERIFY, HANDOFF_KIND_CAMPAIGN):
        return ["handoff request kind is not supported"]
    allowed = {"request", "source_commit", "candidate_path", "source_blob_sha"}
    if kind == HANDOFF_KIND_RESOLVE:
        allowed |= {"identity", "evidence_root"}
    elif kind == HANDOFF_KIND_CAMPAIGN:
        allowed |= {"evidence_root"}
    else:
        allowed |= {"handoff"}
    unknown = [key for key in request if key not in allowed]
    if unknown:
        return ["unknown field: " + str(unknown[0])]
    for key in ("source_commit", "candidate_path", "source_blob_sha"):
        if request.get(key) is None:
            return ["missing field: " + key]
    if not HEX40.match(str(request["source_commit"])):
        return ["source_commit has a bad shape"]
    name = request["candidate_path"]
    if (not isinstance(name, str) or "/" in name or ".." in name
            or not name.endswith(".md") or len(name) > 256):
        return ["candidate_path has a bad shape"]
    if not HEX40.match(str(request["source_blob_sha"])):
        return ["source_blob_sha has a bad shape"]
    if kind in (HANDOFF_KIND_RESOLVE, HANDOFF_KIND_CAMPAIGN):
        if not check_abs_path(request.get("evidence_root")):
            return ["evidence_root is not an absolute path"]
    if kind == HANDOFF_KIND_RESOLVE:
        return _identity_problems(request.get("identity"))
    if kind == HANDOFF_KIND_CAMPAIGN:
        return []
    reason = check_handoff(request.get("handoff"))
    return [reason] if reason else []


def _manifest_cells(evidence_root):
    """Return (cells, None) or (None, reason) from one frozen evidence root."""
    manifest, why = _read_json(str(Path(evidence_root) / MANIFEST_NAME))
    if manifest is None:
        return None, "the evidence root has no readable " + MANIFEST_NAME
    if not isinstance(manifest, dict) or manifest.get("schema") != MANIFEST_SCHEMA:
        return None, "the evidence manifest schema is not " + MANIFEST_SCHEMA
    cells = manifest.get("cells")
    if not isinstance(cells, list) or not cells:
        return None, "the evidence manifest carries no cell"
    return [cell for cell in cells if isinstance(cell, dict)], None


def _evidence_root_for(config_ref):
    """Walk up from one frozen config to the manifest that binds it."""
    path = Path(config_ref)
    for _ in range(4):
        path = path.parent
        if (path / MANIFEST_NAME).is_file():
            return str(path)
    return None


def _cell_byte_problems(cell, evidence_root):
    """Compare the bytes on disk with the digests the manifest already froze."""
    problems = []
    for ref_key, sha_key in CELL_EVIDENCE:
        ref, want = cell.get(ref_key), cell.get(sha_key)
        if not isinstance(ref, str) or not HEX64.match(str(want or "")):
            problems.append("cell evidence is incomplete: " + ref_key)
            continue
        if not check_abs_path(ref) or not contained(evidence_root, ref):
            problems.append("cell evidence is outside the evidence root: " + ref_key)
            continue
        if not Path(ref).is_file():
            problems.append("cell evidence is missing on disk: " + ref_key)
            continue
        if file_sha256(ref) != want:
            problems.append("cell evidence bytes do not match the frozen manifest digest: " + ref_key)
    return problems


def _identity_gap(cell, config, identity, request):
    """List every effective-identity field that differs from the frozen config.

    A cell is reusable only for exactly the identity it was frozen with. A
    changed policy, runtime, data or engine identity is a different identity,
    never the same cell with a new label.
    """
    gap = []

    def differ(name, got, want):
        if got != want:
            gap.append("%s: %r != %r" % (name, got, want))

    candidate = config.get("candidate") if isinstance(config.get("candidate"), dict) else {}
    differ("candidate.path", candidate.get("path"), request["candidate_path"])
    differ("candidate.source_commit", candidate.get("source_commit"), request["source_commit"])
    differ("candidate.git_blob_sha", candidate.get("git_blob_sha"), request["source_blob_sha"])
    runtime = config.get("runtime") if isinstance(config.get("runtime"), dict) else {}
    differ("runtime.commit", runtime.get("commit"), identity["runtime"]["commit"])
    data = config.get("data") if isinstance(config.get("data"), dict) else {}
    differ("data.provider_ref", data.get("provider_ref"), identity["data"]["provider_ref"])
    execution = config.get("execution") if isinstance(config.get("execution"), dict) else {}
    differ("execution.entrypoint", execution.get("entrypoint"), cell.get("entrypoint_ref"))
    differ("research_leverage", config.get("research_leverage"), identity["research_leverage"])
    strategy = config.get("strategy") if isinstance(config.get("strategy"), dict) else {}
    for key in STRATEGY_KEYS:
        differ("strategy." + key, strategy.get(key), identity["strategy"].get(key))
    overlay = config.get("house_overlay") if isinstance(config.get("house_overlay"), dict) else {}
    for key in OVERLAY_KEYS:
        differ("house_overlay." + key, overlay.get(key), identity["house_overlay"].get(key))
    cost = config.get("research_cost_model") if isinstance(config.get("research_cost_model"), dict) else {}
    for key in COST_MODEL_KEYS:
        differ("research_cost_model." + key, cost.get(key), identity["research_cost_model"].get(key))
    return gap


def _handoff_from_cell(cell, config, evidence_root):
    """Build the executable handoff from the verified evidence, never the request."""
    refs = {"manifest": str(Path(evidence_root) / MANIFEST_NAME),
            "effective_config": cell["effective_config_ref"],
            "strategy_artifact": cell["strategy_artifact_ref"]}
    extra = cell.get("evidence_refs")
    if isinstance(extra, dict):
        for key, value in extra.items():
            if isinstance(value, str) and value and key not in refs:
                refs[key] = value
    return {
        "source_commit": cell.get("source_commit"),
        "candidate_path": cell.get("candidate_path"),
        "source_blob_sha": cell.get("source_blob_sha"),
        "entrypoint_ref": cell.get("entrypoint_ref"),
        "entrypoint_sha256": cell.get("entrypoint_sha256"),
        "effective_config_ref": cell.get("effective_config_ref"),
        "effective_config_sha256": cell.get("effective_config_sha256"),
        "qlib_runtime_commit": cell.get("qlib_runtime_commit"),
        "capabilities": config["capabilities"],
        "evidence_refs": refs,
        "research_cost_model": dict(config.get("research_cost_model") or {}),
        "run_inputs": {
            "symbol": cell.get("symbol"),
            "timeframe": cell.get("timeframe"),
            "research_leverage": cell.get("research_leverage"),
            "strategy_artifact_sha256": cell.get("strategy_artifact_sha256"),
        },
    }


def _ready_report(cell, config, evidence_root):
    """Return (report, None) or (None, reason) for one fully verified cell."""
    # ponytail: bind declarations to the evidence already checked by both paths.
    # Strategy semantics stay with engineering review. Do not import code here.
    strategy = config.get("strategy") if isinstance(config.get("strategy"), dict) else {}
    sides = strategy.get("sides")
    if (not isinstance(sides, list) or not sides
            or any(not isinstance(side, str) or not side for side in sides)):
        return None, "the frozen strategy.sides must be a non-empty list of side names"
    capabilities = config.get("capabilities")
    declared = capabilities.get("sides") if isinstance(capabilities, dict) else None
    if (not isinstance(declared, list) or any(not isinstance(side, str) for side in declared)
            or set(sides) != set(declared)):
        return None, "the frozen capabilities.sides do not match strategy.sides"
    artifact = strategy.get("artifact")
    if not isinstance(artifact, dict):
        return None, "the frozen strategy.artifact declaration is missing"
    ref = artifact.get("ref")
    if (not isinstance(ref, str) or not check_abs_path(ref) or not contained(evidence_root, ref)
            or os.path.realpath(ref) != os.path.realpath(cell["strategy_artifact_ref"])):
        return None, "the frozen strategy.artifact.ref does not match the manifest artifact"
    if artifact.get("sha256") != cell["strategy_artifact_sha256"]:
        return None, "the frozen strategy.artifact.sha256 does not match the manifest digest"
    handoff = _handoff_from_cell(cell, config, evidence_root)
    reason = check_handoff(handoff)
    if reason:
        return None, "the frozen handoff is not executable: " + reason
    return {"ok": True, "status": "ready", "source": "frozen-cell", "handoff": handoff}, None


def resolve_frozen_handoff(request):
    """Return (report, None) or (None, reason) for one resolve request.

    Zero writes. A missing cell is an expected answer (implementation_needed),
    not an error; a present cell that does not carry the requested identity, or
    whose bytes no longer match the frozen manifest, fails closed.
    """
    evidence_root = request["evidence_root"]
    cells, reason = _manifest_cells(evidence_root)
    if cells is None:
        return None, reason
    matched = [cell for cell in cells
               if cell.get("candidate_path") == request["candidate_path"]
               and cell.get("source_commit") == request["source_commit"]
               and cell.get("source_blob_sha") == request["source_blob_sha"]]
    if not matched:
        return {"ok": True, "status": "implementation_needed", "source": "none",
                "identity_digest": _identity_digest(request["identity"]),
                "reason": ("no frozen engineering cell exists for this candidate; "
                           "the existing engineering flow must produce one")}, None
    conflicts, broken = [], []
    for cell in matched:
        problems = _cell_byte_problems(cell, evidence_root)
        if problems:
            broken.extend(problems)
            continue
        config, why = _read_json(cell["effective_config_ref"])
        if config is None:
            broken.append("the frozen effective config is " + str(why))
            continue
        gap = _identity_gap(cell, config, request["identity"], request)
        if gap:
            conflicts.extend(gap)
            continue
        return _ready_report(cell, config, evidence_root)
    # Byte integrity beats an identity mismatch: a rewritten file is evidence
    # corruption, not a different (and possibly acceptable) identity.
    if broken:
        return None, "the frozen cell evidence is not intact: " + "; ".join(
            sorted(set(broken))[:4])
    if conflicts:
        return None, ("the frozen cell does not carry the requested effective identity: "
                      + "; ".join(sorted(set(conflicts))[:4]))


def verify_frozen_handoff(request):
    """Verify one supplied handoff against the frozen evidence. Zero writes.

    The reply is always rebuilt from the evidence, so a caller cannot hand in a
    handoff whose cost model, approved flag or capabilities differ from the
    config the cell was frozen with.
    """
    handoff = request["handoff"]
    evidence_root = _evidence_root_for(handoff["effective_config_ref"])
    if evidence_root is None:
        return None, "the handoff does not point at a frozen evidence root"
    cells, reason = _manifest_cells(evidence_root)
    if cells is None:
        return None, reason
    matched = [cell for cell in cells
               if cell.get("effective_config_ref") == handoff["effective_config_ref"]]
    if not matched:
        return None, "no frozen cell matches the supplied handoff"
    for cell in matched:
        problems = _cell_byte_problems(cell, evidence_root)
        if problems:
            return None, "; ".join(problems[:4])
        config, why = _read_json(cell["effective_config_ref"])
        if config is None:
            return None, "the frozen effective config is " + str(why)
        gap = [key for key in HANDOFF_MATCH_KEYS if handoff.get(key) != cell.get(key)]
        gap += ["pinned:" + key for key in ("source_commit", "candidate_path", "source_blob_sha")
                if request.get(key) != cell.get(key)]
        run_inputs = handoff.get("run_inputs") if isinstance(handoff.get("run_inputs"), dict) else {}
        declared_artifact = run_inputs.get("strategy_artifact_sha256")
        if declared_artifact is not None and declared_artifact != cell.get("strategy_artifact_sha256"):
            gap.append("run_inputs.strategy_artifact_sha256")
        if gap:
            return None, "the handoff does not match the frozen cell: " + ", ".join(gap)
        return _ready_report(cell, config, evidence_root)
    return None, "no frozen cell matches the supplied handoff"


def cmd_handoff(payload_b64):
    """Verify, resolve or read one frozen cell/campaign and print the report.

    Every kind but ``campaign-manifest-read-v1`` answers for one cell; the
    campaign read answers for the whole frozen manifest. All three are
    zero-write and start no child process.
    """
    request, reason = decode_handoff(payload_b64)
    if request is None:
        return fail(reason)
    problems = _request_problems(request)
    if problems:
        return fail("; ".join(problems))
    if request["request"] == HANDOFF_KIND_RESOLVE:
        report, reason = resolve_frozen_handoff(request)
    elif request["request"] == HANDOFF_KIND_CAMPAIGN:
        report, reason = read_campaign_manifest(request)
    else:
        report, reason = verify_frozen_handoff(request)
    if report is None:
        return fail(reason)
    print(json.dumps(report, sort_keys=True))
    return 0


# ---------------------------------------------------------------------------
# Phase/window binding. The transport never invents a calendar window: it
# validates and binds the window the caller's approved run spec already carries.
# ---------------------------------------------------------------------------


def _window_problems(window):
    """Return the problems in one approved phase window. Bounds are never invented."""
    if not isinstance(window, dict):
        return ["window is not a JSON object"]
    unknown = [key for key in window if key not in ("start_utc", "end_utc_inclusive")]
    if unknown:
        return ["unknown window field: " + str(unknown[0])]
    for key in ("start_utc", "end_utc_inclusive"):
        value = window.get(key)
        if not isinstance(value, str) or WINDOW_STAMP.match(value) is None:
            return ["window.%s is not a naive UTC timestamp" % key]
    if window["start_utc"] >= window["end_utc_inclusive"]:
        return ["window bounds are not ordered"]
    return []


def _window_identity(window):
    """Return the stable digest of one already validated approved window."""
    return hashlib.sha256(
        json.dumps({"start_utc": window["start_utc"],
                    "end_utc_inclusive": window["end_utc_inclusive"]},
                   sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _as_utc(value):
    """Return one naive-UTC datetime from the two evidence spellings, or None."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        moment = datetime.fromisoformat(value.strip().replace(" ", "T", 1))
    except ValueError:
        return None
    if moment.tzinfo is not None:
        moment = moment.astimezone(timezone.utc).replace(tzinfo=None)
    return moment


# ---------------------------------------------------------------------------
# Campaign manifest readback: one zero-write verified read of the frozen
# campaign manifest. Every cell digest is recomputed from the bytes on disk.
# ---------------------------------------------------------------------------


def _cell_config_problems(cell, config, request=None):
    """Bind one cell config to its manifest declaration and the caller identity."""
    if not isinstance(config, dict):
        return ["a frozen cell config is not readable JSON"]
    problems = []
    candidate = config.get("candidate") if isinstance(config.get("candidate"), dict) else {}
    for key, want in (("path", cell.get("candidate_path")),
                      ("source_commit", cell.get("source_commit")),
                      ("git_blob_sha", cell.get("source_blob_sha"))):
        if candidate.get(key) != want:
            problems.append("cell config candidate.%s does not match the manifest" % key)
    runtime = config.get("runtime") if isinstance(config.get("runtime"), dict) else {}
    if runtime.get("commit") != cell.get("qlib_runtime_commit"):
        problems.append("cell config runtime.commit does not match the manifest")
    strategy = config.get("strategy") if isinstance(config.get("strategy"), dict) else {}
    artifact = strategy.get("artifact") if isinstance(strategy.get("artifact"), dict) else {}
    if artifact.get("sha256") != cell.get("strategy_artifact_sha256"):
        problems.append("cell config strategy.artifact.sha256 does not match the manifest")
    if request is not None:
        for key, want in (("path", request["candidate_path"]),
                          ("source_commit", request["source_commit"]),
                          ("git_blob_sha", request["source_blob_sha"])):
            if candidate.get(key) != want:
                problems.append("cell config candidate.%s does not match the request" % key)
        wanted_runtime = request.get("qlib_runtime_commit")
        if wanted_runtime is not None and runtime.get("commit") != wanted_runtime:
            problems.append("cell config runtime.commit does not match the request")
    return problems


def _phase_binding_for_manifest(evidence_root, manifest_sha256, config_ref=None):
    """Return (binding, None) or (None, reason) for one evidence root.

    The chain is: a campaign manifest whose bytes and cell digests are verified,
    a materialize receipt that binds that exact manifest sha256, and the approved
    phase plus window the receipt recorded. A missing receipt is an unbound
    answer (never an invented phase); a present but inconsistent receipt is
    contradictory evidence and fails closed.
    """
    receipt, _why = _read_json(str(Path(evidence_root) / MATERIALIZE_RECEIPT))
    if receipt is None:
        return None, None
    if not isinstance(receipt, dict) or receipt.get("schema") != MATERIALIZE_RECEIPT_SCHEMA:
        return None, "the materialize receipt in the evidence root is not readable"
    bound = receipt.get("campaign_manifest") if isinstance(receipt.get("campaign_manifest"), dict) else {}
    if bound.get("sha256") != manifest_sha256:
        return None, "the materialize receipt does not bind this campaign manifest"
    phase = receipt.get("phase")
    window = receipt.get("window")
    problems = _window_problems(window)
    if phase not in PHASES or problems:
        return None, ("the materialize receipt carries no usable phase/window: "
                      + "; ".join(problems or ["phase is not an approved phase"]))
    if receipt.get("window_identity_sha256") != _window_identity(window):
        return None, "the materialize receipt window identity does not match its window"
    if config_ref is not None:
        cells, reason = _manifest_cells(evidence_root)
        if cells is None:
            return None, reason
        hit = [cell for cell in cells
               if isinstance(cell.get("effective_config_ref"), str)
               and os.path.realpath(cell["effective_config_ref"]) == os.path.realpath(config_ref)]
        if not hit:
            return None, "the frozen campaign manifest does not carry this run's effective config"
    return {"phase": phase, "window": dict(window),
            "window_identity_sha256": receipt["window_identity_sha256"],
            "campaign_manifest_sha256": manifest_sha256,
            "campaign_manifest_ref": str(Path(evidence_root) / MANIFEST_NAME),
            "materialize_spec_sha256": receipt.get("spec_sha256")
            if isinstance(receipt.get("spec_sha256"), str) else None,
            "source": MATERIALIZE_RECEIPT}, None


def _phase_binding_for_run(submit):
    """Return (binding, None) or (None, reason) for one submitted run.

    The evidence root is discovered from the already hash-verified effective
    config, so the caller cannot point a run at someone else's phase.
    """
    config_ref = submit.get("effective_config_ref")
    if not isinstance(config_ref, str):
        return None, None
    evidence_root = _evidence_root_for(config_ref)
    if evidence_root is None:
        return None, None
    manifest_sha256 = file_sha256(str(Path(evidence_root) / MANIFEST_NAME))
    if manifest_sha256 is None or not HEX64.match(manifest_sha256):
        return None, "the evidence root campaign manifest is not readable"
    return _phase_binding_for_manifest(evidence_root, manifest_sha256, config_ref)


def read_campaign_manifest(request):
    """Return (report, None) or (None, reason) for one verified campaign manifest.

    The manifest is read from the evidence root the request names, never from the
    request body. Every cell ref must resolve inside that root and every declared
    digest must equal the bytes on disk. A per-run ``manifest.json`` (a sha map
    with no schema) is not a campaign manifest and never passes here.
    """
    evidence_root = request["evidence_root"]
    try:
        if not Path(evidence_root).is_dir():
            return None, "the evidence root is not a directory"
    except OSError:
        return None, "the evidence root is not a directory"
    ref = Path(evidence_root) / MANIFEST_NAME
    if not contained(evidence_root, str(ref)):
        return None, "the campaign manifest is outside the evidence root"
    manifest, _why = _read_json(str(ref))
    if manifest is None:
        return None, "the evidence root has no readable " + MANIFEST_NAME
    if not isinstance(manifest, dict) or manifest.get("schema") != MANIFEST_SCHEMA:
        return None, "the evidence manifest schema is not " + MANIFEST_SCHEMA
    cells = manifest.get("cells")
    if not isinstance(cells, list) or not cells:
        return None, "the evidence manifest carries no cell"
    if manifest.get("cell_count") != len(cells):
        return None, "the evidence manifest cell_count does not match its cells"
    if [cell for cell in cells if not isinstance(cell, dict)]:
        return None, "the evidence manifest carries a malformed cell"
    windows = set()
    seen = set()
    for cell in cells:
        for key in ("source_commit", "candidate_path", "source_blob_sha"):
            if cell.get(key) != request[key]:
                return None, "the evidence manifest does not carry the requested candidate: " + key
        if cell.get("cell_id") in seen:
            return None, "the evidence manifest repeats a cell id"
        seen.add(cell.get("cell_id"))
        problems = _cell_byte_problems(cell, evidence_root)
        if problems:
            return None, "; ".join(sorted(set(problems))[:4])
        config, _why = _read_json(cell.get("effective_config_ref"))
        problems = _cell_config_problems(cell, config, request)
        if problems:
            return None, "; ".join(sorted(set(problems))[:4])
        strategy = config.get("strategy") if isinstance(config.get("strategy"), dict) else {}
        windows.add((strategy.get("window_start_utc"), strategy.get("window_end_utc_inclusive")))
    if len(windows) != 1 or _window_problems({"start_utc": list(windows)[0][0],
                                              "end_utc_inclusive": list(windows)[0][1]}):
        return None, "the evidence manifest cells do not share one approved window"
    manifest_sha256 = file_sha256(str(ref))
    if manifest_sha256 is None or not HEX64.match(manifest_sha256):
        return None, "the campaign manifest identity is invalid"
    binding, reason = _phase_binding_for_manifest(evidence_root, manifest_sha256)
    if reason is not None:
        return None, reason
    window_start, window_end = list(windows)[0]
    return {
        "ok": True, "status": "ready", "source": "frozen-campaign-manifest",
        "manifest_kind": "campaign", "schema": manifest["schema"],
        "manifest_ref": str(ref), "manifest_sha256": manifest_sha256,
        "cell_count": len(cells),
        "window": {"start_utc": window_start, "end_utc_inclusive": window_end,
                   "identity_sha256": _window_identity({"start_utc": window_start,
                                                        "end_utc_inclusive": window_end})},
        "cells": [{key: cell[key] for key in CAMPAIGN_CELL_KEYS if key in cell} for cell in cells],
        "phase_binding": binding,
        "phase_bound": binding is not None,
        "generated_from": manifest.get("generated_from")
        if isinstance(manifest.get("generated_from"), str) else None,
    }, None


# ---------------------------------------------------------------------------
# Native readback enrichment. Additive only: the PR #19 receipt fields and every
# PR #19 check above stay exactly as they are.
# ---------------------------------------------------------------------------


def _native_metrics(run_metrics):
    """Return (metrics, None) or (None, reason) for the whitelisted native metrics."""
    total = run_metrics.get("total_trades")
    if not is_count(total):
        return None, "native metrics carry no usable total_trades"
    out = {"total_trades": total}
    for key in NATIVE_METRIC_KEYS:
        if key not in run_metrics or run_metrics[key] is None:
            out[key] = None
            continue
        value = run_metrics[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None, "native metric %s is not a JSON number" % key
        if not math.isfinite(float(value)):
            return None, "native metric %s is not finite" % key
        if key == "evaluation_bars":
            if not is_count(value):
                return None, "native metric evaluation_bars is not an integer count"
            out[key] = value
            continue
        out[key] = float(value)
    return out, None


def _native_applied_economics(summary):
    """Return (applied, None) or (None, reason) for the native economics block."""
    applied = summary.get("applied_economics")
    if applied is None:
        return None, None
    if not isinstance(applied, dict):
        return None, "native applied economics is not a JSON object"
    for key in ("funding_applied", "funding_reconciled", "slippage_applied",
                "declared_model_matches_applied"):
        if key in applied and not isinstance(applied[key], bool):
            return None, "native applied economics %s is not a boolean" % key
    for key in ("funding_total_payment_quote", "funding_charged_event_count"):
        value = applied.get(key)
        if value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None, "native applied economics %s is not a JSON number" % key
        if not math.isfinite(float(value)):
            return None, "native applied economics %s is not finite" % key
    for key in ("funding_truth_status_counts", "funding_charged_truth_status_counts"):
        if key in applied and applied[key] is not None and not isinstance(applied[key], dict):
            return None, "native applied economics %s is not a JSON object" % key
    for key in ("funding_basis", "funding_source_ref", "funding_source_sha256",
                "funding_modeled_mark_basis", "funding_modeled_mark_snapshot_sha256",
                "funding_declaration", "declared_model_match_reason", "applied"):
        value = applied.get(key)
        if value is not None and not isinstance(value, str):
            return None, "native applied economics %s is not a string" % key
    return {key: applied[key] for key in APPLIED_ECONOMICS_KEYS if key in applied}, None


def _native_claim(summary):
    """Return (claimable, cost_approved, None) or (None, None, reason) from summary."""
    boundary = summary.get("economics_boundary")
    if boundary is None:
        return None, None, None
    if not isinstance(boundary, dict):
        return None, None, "native economics boundary is not a JSON object"
    claimable = boundary.get("performance_claimable")
    approved = boundary.get("cost_model_approved")
    for name, value in (("performance_claimable", claimable), ("cost_model_approved", approved)):
        if value is not None and not isinstance(value, bool):
            return None, None, "native economics boundary %s is not a boolean" % name
    return claimable, approved, None


def _native_evidence(summary, run_metrics, config, submit, manifest_sha256, binding):
    """Return (native, None) or (None, reason) for the additive Node05 block.

    Only fields this file already verified reach the reply, and nothing is filled
    in: a field the native run did not write stays null so the caller can hold on
    the absence. Contradictory native claims are evidence corruption, not a
    smaller claim, and fail closed.
    """
    metrics, reason = _native_metrics(run_metrics)
    if metrics is None:
        return None, reason
    applied, reason = _native_applied_economics(summary)
    if reason is not None:
        return None, reason
    claimable, cost_approved, reason = _native_claim(summary)
    if reason is not None:
        return None, reason
    omitted = summary.get("mlflow_metrics_omitted")
    if omitted is not None:
        if not isinstance(omitted, list) or any(not isinstance(key, str) for key in omitted):
            return None, "native omitted metric list is not a list of names"
        omitted = list(omitted)
    else:
        omitted = []
    strategy = config.get("strategy") if isinstance(config.get("strategy"), dict) else {}
    window = {"start_utc": strategy.get("window_start_utc"),
              "end_utc_inclusive": strategy.get("window_end_utc_inclusive")}
    approved = isinstance(window["start_utc"], str) and isinstance(window["end_utc_inclusive"], str)
    window_identity = None
    if approved:
        problems = _window_problems(window)
        if problems:
            return None, "the verified effective config window is not usable: " + "; ".join(problems)
        window_identity = _window_identity(window)
    native_start_raw = summary.get("evaluation_window_start_utc")
    native_end_raw = summary.get("evaluation_window_end_utc")
    native_start = native_end = None
    inside = None
    if native_start_raw is not None or native_end_raw is not None:
        native_start, native_end = _as_utc(native_start_raw), _as_utc(native_end_raw)
        if native_start is None or native_end is None:
            return None, "native evaluation window is not readable UTC evidence"
        if native_start > native_end:
            return None, "native evaluation window bounds are not ordered"
        if not approved:
            return None, "native evaluation window cannot be bound without a frozen config window"
        bound_start, bound_end = _as_utc(window["start_utc"]), _as_utc(window["end_utc_inclusive"])
        if bound_start is None or bound_end is None:
            return None, "the verified effective config window is not readable UTC"
        inside = bound_start <= native_start and native_end <= bound_end
        if not inside:
            return None, "native evaluation window escapes the approved window"
    phase = phase_source = None
    if binding is not None:
        if window_identity is None or binding.get("window_identity_sha256") != window_identity:
            return None, "the verified materialize receipt binds a different window"
        phase = binding.get("phase")
        phase_source = binding.get("source")
    zero_trade = metrics["total_trades"] == 0
    if zero_trade and claimable is True:
        return None, "native evidence claims performance claimability for a zero-trade run"
    if claimable is True and cost_approved is not True:
        return None, "native evidence claims performance claimability without an approved cost model"
    limits = []
    if applied is None:
        limits.append("native applied economics are absent")
    else:
        if applied.get("funding_applied") is not True:
            limits.append("funding is not applied to PnL")
        if applied.get("slippage_applied") is True:
            limits.append("slippage is applied to fills")
        match_reason = applied.get("declared_model_match_reason")
        if applied.get("declared_model_matches_applied") is not True and isinstance(match_reason, str):
            limits.append(match_reason)
    if cost_approved is not True:
        limits.append("the research cost model is not approved")
    for key in omitted:
        limits.append("native metric is undefined: " + key)
    if zero_trade:
        limits.append("zero-trade run: completed execution, not performance evidence")
    if not approved:
        limits.append("the verified effective config carries no frozen window")
    if phase is None:
        limits.append("no verified materialize receipt binds an approved phase/window")
    params = strategy.get("params") if isinstance(strategy.get("params"), dict) else None
    native_params = summary.get("strategy_params")
    if native_params is not None and not isinstance(native_params, dict):
        return None, "native strategy params are not a JSON object"
    if isinstance(native_params, dict) and params is not None and native_params != params:
        return None, "native strategy params do not match the verified run config"
    artifact = strategy.get("artifact") if isinstance(strategy.get("artifact"), dict) else {}
    return {
        "phase": phase,
        "phase_source": phase_source,
        "phase_bound": phase is not None,
        "feeds_research": None if phase is None else phase != OOS_PHASE,
        "oos_isolated": None if phase is None else phase == OOS_PHASE,
        "window": {
            "approved_start_utc": window["start_utc"],
            "approved_end_utc_inclusive": window["end_utc_inclusive"],
            "native_evaluation_start_utc": native_start_raw if native_start is not None else None,
            "native_evaluation_end_utc": native_end_raw if native_end is not None else None,
            "native_inside_approved": inside,
            "identity_sha256": window_identity,
        },
        "metrics": metrics,
        "metrics_omitted": omitted,
        "applied_economics": applied,
        "performance_claimable": claimable,
        "cost_model_approved": cost_approved,
        "limitations": limits,
        "identity": {
            "candidate_blob_sha": submit.get("candidate_blob_sha"),
            "source_commit": submit.get("source_commit"),
            "effective_config_sha256": submit.get("effective_config_sha256"),
            "entrypoint_ref": submit.get("entrypoint_ref"),
            "entrypoint_sha256": submit.get("entrypoint_sha256"),
            "qlib_runtime_commit": submit.get("qlib_runtime_commit"),
            "strategy_artifact_ref": artifact.get("ref") if isinstance(artifact.get("ref"), str) else None,
            "strategy_artifact_sha256": artifact.get("sha256")
            if isinstance(artifact.get("sha256"), str) else None,
            "strategy_params": params,
            "run_manifest_sha256": manifest_sha256,
            "campaign_manifest_sha256": (binding or {}).get("campaign_manifest_sha256"),
            "campaign_manifest_ref": (binding or {}).get("campaign_manifest_ref"),
            "materialize_spec_sha256": (binding or {}).get("materialize_spec_sha256"),
        },
    }, None


# ---------------------------------------------------------------------------
# Bounded materialize: one fixed request, one fixed Qlib command, no shell.
# ---------------------------------------------------------------------------


def _materialize_problems(request):
    """Return the fail-closed problems in one materialize request."""
    if not isinstance(request, dict):
        return ["materialize request is not a JSON object"]
    if request.get("request") != MATERIALIZE_KIND:
        return ["materialize request kind is not supported"]
    allowed = {"request", "spec_ref", "root", "phase", "window", "source_commit",
               "candidate_path", "source_blob_sha", "strategy_artifact_sha256",
               "qlib_runtime_commit"}
    unknown = [key for key in request if key not in allowed]
    if unknown:
        return ["unknown field: " + str(unknown[0])]
    for key in ("spec_ref", "root", "phase", "window", "source_commit", "candidate_path",
                "source_blob_sha", "strategy_artifact_sha256", "qlib_runtime_commit"):
        if request.get(key) is None:
            return ["missing field: " + key]
    if not check_abs_path(request["spec_ref"]):
        return ["spec_ref is not an absolute path"]
    if not check_abs_path(request["root"]):
        return ["root is not an absolute path"]
    if request["phase"] not in PHASES:
        return ["phase is not one of " + ", ".join(PHASES)]
    problems = _window_problems(request["window"])
    if problems:
        return problems
    if not HEX40.match(str(request["source_commit"])):
        return ["source_commit has a bad shape"]
    name = request["candidate_path"]
    if (not isinstance(name, str) or "/" in name or ".." in name
            or not name.endswith(".md") or len(name) > 256):
        return ["candidate_path has a bad shape"]
    if not HEX40.match(str(request["source_blob_sha"])):
        return ["source_blob_sha has a bad shape"]
    if not HEX64.match(str(request["strategy_artifact_sha256"])):
        return ["strategy_artifact_sha256 has a bad shape"]
    if not HEX40.match(str(request["qlib_runtime_commit"])):
        return ["qlib_runtime_commit has a bad shape"]
    return []


def _materialize_spec_problems(spec, request):
    """Bind one materialize spec to the request. Strategy semantics stay outside."""
    if not isinstance(spec, dict):
        return ["the materialize spec is not a JSON object"]
    problems = []
    materialize = spec.get("materialize")
    if not isinstance(materialize, dict):
        return ["the materialize spec has no materialize block"]
    cells_dir = materialize.get("cells_dir")
    if not check_abs_path(cells_dir):
        problems.append("materialize.cells_dir is not an absolute path")
    elif os.path.realpath(cells_dir) != os.path.realpath(request["root"]):
        problems.append("materialize.cells_dir does not match the requested root")
    if not check_abs_path(materialize.get("results_root")):
        problems.append("materialize.results_root is not an absolute path")
    candidate = spec.get("candidate") if isinstance(spec.get("candidate"), dict) else {}
    for key, want in (("path", request["candidate_path"]),
                      ("source_commit", request["source_commit"]),
                      ("git_blob_sha", request["source_blob_sha"])):
        if candidate.get(key) != want:
            problems.append("spec candidate.%s does not match the request" % key)
    runtime = spec.get("runtime") if isinstance(spec.get("runtime"), dict) else {}
    if runtime.get("commit") != request["qlib_runtime_commit"]:
        problems.append("spec runtime.commit does not match the request")
    strategy = spec.get("strategy") if isinstance(spec.get("strategy"), dict) else {}
    window = request["window"]
    if strategy.get("window_start_utc") != window["start_utc"]:
        problems.append("spec strategy.window_start_utc does not match the approved window")
    if strategy.get("window_end_utc_inclusive") != window["end_utc_inclusive"]:
        problems.append("spec strategy.window_end_utc_inclusive does not match the approved window")
    sides = strategy.get("sides")
    if not isinstance(sides, list) or not sides or [s for s in sides if not isinstance(s, str) or not s]:
        problems.append("spec strategy.sides is not a declared side list")
    else:
        outside = [side for side in sides if side not in VERIFIED_PRIMITIVES["sides"]]
        if outside:
            problems.append("ENGINEERING_HOLD: the engine has no execution primitive for side: "
                            + ", ".join(map(str, outside)))
    artifact = spec.get("strategy_artifact") if isinstance(spec.get("strategy_artifact"), dict) else {}
    source = artifact.get("source")
    if not check_abs_path(source):
        problems.append("spec strategy_artifact.source is not an absolute path")
    elif file_sha256(source) != request["strategy_artifact_sha256"]:
        problems.append("spec strategy_artifact.source does not match the requested sha256")
    return problems


def _verify_materialized(root, request, window):
    """Return (manifest, None) or (None, reason) for the manifest Qlib just wrote."""
    manifest, _why = _read_json(str(Path(root) / MANIFEST_NAME))
    if not isinstance(manifest, dict) or manifest.get("schema") != MANIFEST_SCHEMA:
        return None, "the materialized campaign manifest is not " + MANIFEST_SCHEMA
    cells = manifest.get("cells")
    if not isinstance(cells, list) or not cells:
        return None, "the materialized campaign manifest carries no cell"
    if manifest.get("cell_count") != len(cells):
        return None, "the materialized campaign manifest cell_count does not match its cells"
    seen = set()
    windows = set()
    for cell in cells:
        if not isinstance(cell, dict):
            return None, "the materialized campaign manifest carries a malformed cell"
        for key, want in (("source_commit", request["source_commit"]),
                          ("candidate_path", request["candidate_path"]),
                          ("source_blob_sha", request["source_blob_sha"]),
                          ("qlib_runtime_commit", request["qlib_runtime_commit"]),
                          ("strategy_artifact_sha256", request["strategy_artifact_sha256"])):
            if cell.get(key) != want:
                return None, "a materialized cell does not carry the requested identity: " + key
        if cell.get("cell_id") in seen:
            return None, "the materialized campaign manifest repeats a cell id"
        seen.add(cell.get("cell_id"))
        problems = _cell_byte_problems(cell, str(root))
        if problems:
            return None, "; ".join(sorted(set(problems))[:4])
        config, _why = _read_json(cell.get("effective_config_ref"))
        problems = _cell_config_problems(cell, config, request)
        if problems:
            return None, "; ".join(sorted(set(problems))[:4])
        strategy = config.get("strategy") if isinstance(config.get("strategy"), dict) else {}
        windows.add((strategy.get("window_start_utc"), strategy.get("window_end_utc_inclusive")))
    if windows != {(window["start_utc"], window["end_utc_inclusive"])}:
        return None, "the materialized cells do not all carry the approved window"
    return manifest, None


def _receipt_runtime(request, spec):
    """Return the runtime provenance one receipt binds, truthfully.

    The spec usually declares only ``runtime.commit``. Inside the fixed runtime
    the transport itself knows the image and digest it is executing, so it binds
    those constants instead of persisting null; on the host it never invents an
    image the spec did not declare.
    """
    declared = spec.get("runtime") if isinstance(spec.get("runtime"), dict) else {}
    commit = request["qlib_runtime_commit"]
    image = declared.get("image") if isinstance(declared.get("image"), str) else None
    digest = declared.get("image_digest") if isinstance(declared.get("image_digest"), str) else None
    if is_fixed_runtime():
        commit = FIXED_RUNTIME_COMMIT
        image = image or FIXED_IMAGE
        digest = digest or FIXED_IMAGE_DIGEST
    return {"commit": commit, "image": image, "image_digest": digest}


def _materialize_receipt(request, spec, spec_sha256, manifest, manifest_sha256):
    """Return the deterministic receipt one verified materialization binds."""
    cells = [cell for cell in manifest["cells"] if isinstance(cell, dict)]
    ordered = sorted(cells, key=lambda cell: str(cell.get("cell_id")))
    ids = [str(cell.get("cell_id")) for cell in ordered]
    evidence = "\n".join("%s:%s:%s:%s" % (cell.get("cell_id"), cell.get("effective_config_sha256"),
                                          cell.get("entrypoint_sha256"),
                                          cell.get("strategy_artifact_sha256"))
                         for cell in ordered)
    window = {"start_utc": request["window"]["start_utc"],
              "end_utc_inclusive": request["window"]["end_utc_inclusive"]}
    return {
        "schema": MATERIALIZE_RECEIPT_SCHEMA,
        "request": MATERIALIZE_KIND,
        "phase": request["phase"],
        "window": window,
        "window_identity_sha256": _window_identity(window),
        "source_commit": request["source_commit"],
        "candidate_path": request["candidate_path"],
        "source_blob_sha": request["source_blob_sha"],
        "qlib_runtime_commit": request["qlib_runtime_commit"],
        "runtime": _receipt_runtime(request, spec),
        "spec_ref": request["spec_ref"],
        "spec_sha256": spec_sha256,
        "strategy_artifact": {"source": spec["strategy_artifact"]["source"],
                              "sha256": request["strategy_artifact_sha256"]},
        "root": request["root"],
        "cells_root": spec["materialize"]["cells_dir"],
        "results_root": spec["materialize"]["results_root"],
        "campaign_manifest": {"schema": manifest.get("schema"),
                              "ref": str(Path(request["root"]) / MANIFEST_NAME),
                              "sha256": manifest_sha256,
                              "cell_count": manifest.get("cell_count")},
        "cell_ids": ids,
        "cell_ids_sha256": hashlib.sha256("\n".join(ids).encode("utf-8")).hexdigest(),
        "cell_evidence_sha256": hashlib.sha256(evidence.encode("utf-8")).hexdigest(),
    }


def _write_receipt(root, receipt):
    """Write one receipt deterministically. Return True on success."""
    try:
        (Path(root) / MATERIALIZE_RECEIPT).write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError:
        return False
    return True


def _acquire_lock(lock_path):
    """Take the one materialization lock. Return (handle, None) or (None, reason)."""
    deadline = time.monotonic() + MATERIALIZE_LOCK_WAIT
    while True:
        try:
            return os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), None
        except FileExistsError:
            if time.monotonic() >= deadline:
                return None, ("another materialization holds " + MATERIALIZE_LOCK
                              + "; retry after it finishes")
            time.sleep(MATERIALIZE_LOCK_POLL)
        except OSError:
            return None, "the materialization lock is not usable"


def _release_lock(handle, lock_path):
    """Release one materialization lock. Never raises."""
    try:
        os.close(handle)
    except OSError:
        pass
    try:
        os.unlink(str(lock_path))
    except OSError:
        pass


def _materialize_existing(request, spec, spec_sha256):
    """Converge on one receipt-bound materialization, or refuse.

    An existing campaign manifest alone is NOT proof: it records the cells, not
    the spec economics/params that produced them. Writing a fresh receipt for a
    root that has none would let a different spec be bound to someone else's
    cells, so an existing root must already carry a receipt, and that receipt
    must match this request and spec byte for byte. A receipt is never
    reconstructed after the fact, and production never uses ``--force``.
    """
    manifest, reason = _verify_materialized(request["root"], request, request["window"])
    if manifest is None:
        return fail("refuse overwrite: " + str(reason))
    manifest_sha256 = file_sha256(str(Path(request["root"]) / MANIFEST_NAME))
    if manifest_sha256 is None or not HEX64.match(manifest_sha256):
        return fail("materialized campaign manifest identity is invalid")
    receipt = _materialize_receipt(request, spec, spec_sha256, manifest, manifest_sha256)
    payload = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("utf-8")
    try:
        stored = (Path(request["root"]) / MATERIALIZE_RECEIPT).read_bytes()
    except OSError:
        return fail("refuse overwrite: the existing materialization carries no receipt, and a "
                    "receipt is never reconstructed from a later spec")
    if stored != payload:
        return fail("refuse overwrite: the stored materialize receipt binds a different request")
    print(json.dumps(dict(receipt, ok=True, status="materialized", state="existing"),
                     sort_keys=True))
    return 0


def cmd_materialize(payload_b64):
    """Run ONLY the existing Qlib materializer for one validated request."""
    request, reason = decode_handoff(payload_b64)
    if request is None:
        return fail(reason)
    problems = _materialize_problems(request)
    if problems:
        return fail("; ".join(problems))
    root = resolve_root()
    if root is None:
        return fail("results root is not usable")
    for key in ("spec_ref", "root"):
        if not under_root(request[key], root):
            return fail(key + " escapes the results root")
    try:
        spec_bytes = Path(request["spec_ref"]).read_bytes()
    except OSError:
        return implementation_needed(
            "MATERIALIZE_SPEC_MISSING: no approved materialize spec exists at the requested "
            "path; the existing engineering flow must produce it")
    try:
        spec = json.loads(spec_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return fail("the materialize spec is not readable JSON")
    problems = _materialize_spec_problems(spec, request)
    if problems:
        return fail("; ".join(problems))
    for key in ("strategy_artifact.source", "materialize.results_root"):
        block, _, name = key.rpartition(".")
        value = spec[block][name]
        if not under_root(value, root):
            return fail(key + " escapes the results root")
    if is_fixed_runtime():
        if request["qlib_runtime_commit"] != FIXED_RUNTIME_COMMIT:
            return fail("config/runtime identity mismatch")
        runtime = spec.get("runtime") if isinstance(spec.get("runtime"), dict) else {}
        if runtime.get("commit") != FIXED_RUNTIME_COMMIT:
            return fail("config/runtime identity mismatch")
        if runtime.get("image") is not None and runtime.get("image") != FIXED_IMAGE:
            return fail("config/runtime identity mismatch")
        if runtime.get("image_digest") is not None and runtime.get("image_digest") != FIXED_IMAGE_DIGEST:
            return fail("config/runtime identity mismatch")
    spec_sha256 = hashlib.sha256(spec_bytes).hexdigest()
    cells_root = Path(request["root"])
    manifest_path = cells_root / MANIFEST_NAME
    if manifest_path.exists():
        return _materialize_existing(request, spec, spec_sha256)
    try:
        cells_root.mkdir(parents=True, exist_ok=True)
    except OSError:
        return fail("the materialization root is not writable")
    try:
        leftovers = [entry.name for entry in cells_root.iterdir()
                     if entry.name not in (MATERIALIZE_LOCK, MATERIALIZE_RECEIPT)]
    except OSError:
        return fail("the materialization root is not readable")
    if leftovers:
        return fail("refuse overwrite: the materialization root is not empty: " + leftovers[0])
    handle, why = _acquire_lock(cells_root / MATERIALIZE_LOCK)
    if handle is None:
        return fail(str(why))
    try:
        if manifest_path.exists():  # a concurrent identical request converged first
            return _materialize_existing(request, spec, spec_sha256)
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "qlib.backtest.research_cell", "materialize",
                 "--spec", request["spec_ref"], "--root", request["root"]],
                cwd="/", capture_output=True, text=True, timeout=SUBMIT_TIMEOUT,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return fail("native materialize did not start: " + str(exc)[:200])
        if proc.returncode != 0:
            return fail("native materialize failed: " + (proc.stderr or "")[-2000:])
        manifest, reason = _verify_materialized(request["root"], request, request["window"])
        if manifest is None:
            return fail(str(reason))
        manifest_sha256 = file_sha256(str(manifest_path))
        if manifest_sha256 is None or not HEX64.match(manifest_sha256):
            return fail("materialized campaign manifest identity is invalid")
        receipt = _materialize_receipt(request, spec, spec_sha256, manifest, manifest_sha256)
        if not _write_receipt(request["root"], receipt):
            return fail("materialize receipt is not writable")
        print(json.dumps(dict(receipt, ok=True, status="materialized", state="created"),
                         sort_keys=True))
        return 0
    finally:
        _release_lock(handle, cells_root / MATERIALIZE_LOCK)


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

    Only for the configured guest root missing on the host. Temp-root tests
    stay local; inside the fixed runtime /results exists so no forwarding.
    """
    if "RESEARCH_RESULTS_ROOT" in os.environ:
        return False
    if os.environ.get("RESEARCH_FORWARDED") == "1":
        return False
    try:
        if Path(RESULTS_ROOT_DEFAULT).is_dir():
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
            if verb == HANDOFF_VERB:
                return cmd_handoff(arg)
            return cmd_hermes(arg)
        # ponytail: host launches with no /results use the fixed runtime.
        if should_forward_host():
            return forward_via_container(verb, arg)
        if verb == "research-submit":
            return cmd_submit(arg)
        if verb == MATERIALIZE_VERB:
            return cmd_materialize(arg)
        return cmd_readback(arg)
    parser = argparse.ArgumentParser(description="Bridge a handoff to the native Qlib path.")
    parser.add_argument(
        "cmd",
        choices=["research-submit", "research-readback", MATERIALIZE_VERB],
        help=("research-submit takes a base64 handoff, research-readback takes a run id, "
              "research-materialize takes a base64 materialize request"),
    )
    parser.add_argument("arg", help="base64 JSON or 32-hex run id")
    args = parser.parse_args(argv)
    if args.cmd == "research-submit":
        return cmd_submit(args.arg)
    if args.cmd == MATERIALIZE_VERB:
        return cmd_materialize(args.arg)
    return cmd_readback(args.arg)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
