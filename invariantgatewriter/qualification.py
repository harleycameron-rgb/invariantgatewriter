"""Backend-only orchestration for reviewed module candidates.

This module is not registered with the public node or an MCP/API route.
Qualification policy remains exclusively the trusted backend qualifier's
responsibility; declaration validation and synthetic tests are not admission.
Manifests are used transiently and are never persisted or logged here.
"""

import hashlib
import json
import re

from .writer import FIELDS, GateError


_EVENT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SAFE_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")


def _safe_code(value, fallback):
    return value if type(value) is str and _SAFE_CODE.fullmatch(value) else fallback


def submit_reviewed_modules(items, writer, qualifier, authorize, context):
    """Submit 1–100 reviewed candidates using trusted backend dependencies.

    Each item has exactly ``declaration`` and ``qualificationId``. The event ID
    is explicitly supplied by the reviewing backend: reuse it for retries and
    allocate a NEW ID for a new chronological event, even for an identical
    declaration. Snapshot hashes are content identity, not event identity.

    ``authorize(context, "gate:write")`` must authenticate and authorize using
    trusted backend context; only literal True permits processing. Authentication
    failure and invalid batch sizes raise GateError before qualifier/storage use.

    ``qualifier(declaration, qualification_id)`` is a trusted backend callable,
    not a tool parameter. It returns exactly either:
      {"status": "qualified", "qualification": signed_envelope}
      {"status": "pending" or "rejected", "code": safe_static_code}
    Safe codes are lowercase identifiers of at most 64 ASCII characters.
    No configured qualifier yields per-item pending, never fabricated receipts.

    Returns {"atomic": False, "results": [...]}. Results include index/status,
    validated moduleId/qualificationId/moduleSHA512 when available, and either
    a receipt (qualified) or a safe code (pending/rejected). Successful writes
    remain committed when another item fails. Gate errors become per-item
    rejected results; retry transient storage failures with the original ID.
    """
    try:
        allowed = authorize(context, "gate:write") is True
    except Exception:
        allowed = False
    if not allowed:
        raise GateError("unauthorized")
    if type(items) is not list or not 1 <= len(items) <= 100:
        raise GateError("invalid_batch_size")

    results = []
    for index, item in enumerate(items):
        result = {"index": index, "status": "rejected"}
        results.append(result)
        if type(item) is not dict or set(item) != {"declaration", "qualificationId"}:
            result["code"] = "invalid_candidate_fields"
            continue
        event_id = item["qualificationId"]
        if type(event_id) is not str or not _EVENT_ID.fullmatch(event_id):
            result["code"] = "invalid_qualification_id"
            continue
        result["qualificationId"] = event_id
        try:
            # Resolve at invocation time so the public validator can evolve
            # (including v2 declarations) without a stale bound function.
            from .public_node import _validate

            declaration = item["declaration"]
            _validate(declaration)
            canonical = json.dumps(
                declaration, sort_keys=True, separators=(",", ":"),
                ensure_ascii=False, allow_nan=False,
            ).encode("utf-8")
            declaration_hash = hashlib.sha512(canonical).hexdigest()
            result["moduleId"] = declaration["moduleId"]
            result["moduleSHA512"] = declaration_hash
            # Isolate the caller's declaration from a qualifier that mutates
            # its argument. The binding is to the original validated snapshot.
            reviewed_declaration = json.loads(canonical)
        except Exception:
            result["code"] = "invalid_declaration"
            continue
        if qualifier is None:
            result.update(status="pending", code="qualification_service_unconnected")
            continue
        try:
            decision = qualifier(reviewed_declaration, event_id)
        except Exception:
            result["code"] = "qualifier_error"
            continue
        if type(decision) is not dict:
            result["code"] = "invalid_qualifier_response"
            continue
        status = decision.get("status")
        if status in ("pending", "rejected"):
            if set(decision) != {"status", "code"}:
                result["code"] = "invalid_qualifier_response"
                continue
            code = _safe_code(decision["code"], None)
            if code is None:
                result["code"] = "invalid_qualifier_response"
                continue
            result.update(status=status, code=code)
            continue
        if status != "qualified" or set(decision) != {"status", "qualification"}:
            result["code"] = "invalid_qualifier_response"
            continue
        envelope = decision["qualification"]
        if type(envelope) is not dict or set(envelope) != FIELDS:
            result["code"] = "invalid_qualification_envelope"
            continue
        if envelope["moduleSHA512"] != declaration_hash:
            result["code"] = "qualification_module_mismatch"
            continue
        if envelope["qualificationId"] != event_id:
            result["code"] = "qualification_id_mismatch"
            continue
        try:
            receipt = writer.write(envelope)
        except GateError as error:
            result["code"] = _safe_code(error.code, "writer_error")
            continue
        except Exception:
            result["code"] = "writer_error"
            continue
        result.update(status="qualified", receipt=receipt)
    return {"atomic": False, "results": results}
