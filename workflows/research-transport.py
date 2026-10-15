#!/usr/bin/env python3
"""Thin SSH-side transport for research handoff payloads.

Read one base64 JSON payload (submit) or one run id (readback).
Check explicit fields, path shape, and hash shape.
Print JSON to stdout. Exit 0 means valid, exit 2 means invalid.

ponytail: validate-only here. A live run needs a separate bounded
deployment decision. This file never fabricates a PASS receipt.
"""

import argparse
import base64
import binascii
import json
import re
import sys

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


def cmd_submit(payload_b64):
    """Validate one base64 payload. Never run a recipe here."""
    try:
        raw = base64.b64decode(payload_b64, validate=True)
    except (binascii.Error, ValueError):
        return fail("payload is not base64")
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return fail("payload is not JSON")
    reason = check_handoff(obj)
    if reason is not None:
        return fail(reason)
    print(
        json.dumps(
            {
                "ok": True,
                "mode": "validate-only",
                "candidate_path": obj["candidate_path"],
                "source_blob_sha": obj["source_blob_sha"],
                "entrypoint_sha256": obj["entrypoint_sha256"],
                "effective_config_sha256": obj["effective_config_sha256"],
            }
        )
    )
    return 0


def cmd_readback(run_id):
    """Validate one run id for a readback request."""
    if not RUNID.match(run_id or ""):
        return fail("run_id has a bad shape")
    print(json.dumps({"ok": True, "mode": "validate-only", "run_id": run_id}))
    return 0


def main(argv):
    """Parse args and dispatch to one subcommand."""
    parser = argparse.ArgumentParser(description="Validate research handoff payloads.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_submit = sub.add_parser("submit", help="validate one base64 handoff payload")
    p_submit.add_argument("payload_b64", help="base64 of the handoff JSON")
    p_read = sub.add_parser("readback", help="validate one run id")
    p_read.add_argument("run_id", help="32 hex chars")
    args = parser.parse_args(argv)
    if args.cmd == "submit":
        return cmd_submit(args.payload_b64)
    return cmd_readback(args.run_id)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
