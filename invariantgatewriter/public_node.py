"""Transient public declaration checks and synthetic tests; no gate or storage."""

import argparse
import copy
import base64
import hashlib
import json
import math
import os
import re
import threading
import time
from collections import OrderedDict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from html.parser import HTMLParser
from pathlib import Path


MAX_BODY = 65536
MAX_TEST_EVENTS = 4096
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z", re.ASCII)
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z", re.ASCII)
EVENT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
TYPES = ("string", "number", "integer", "boolean")
PROTOCOLS = ("2025-06-18", "2025-03-26", "2024-11-05")
INTERFACES = {
    "identity/1": ({"value": "string"}, {"value": "string"}),
    "numbers.add/1": ({"a": "number", "b": "number"}, {"sum": "number"}),
    "text.concat/1": ({"left": "string", "right": "string"}, {"result": "string"}),
    "boolean.not/1": ({"value": "boolean"}, {"value": "boolean"}),
}


class PublicNodeError(ValueError):
    """Sanitized public error."""


def _require(condition, message):
    if not condition:
        raise PublicNodeError(message)


def _bounded(value):
    count = 0

    def walk(item, depth):
        nonlocal count
        count += 1
        _require(count <= 4096 and depth <= 12, "Declaration complexity limit exceeded.")
        if type(item) is dict:
            _require(len(item) <= 32, "Object property limit exceeded.")
            for key, child in item.items():
                _require(type(key) is str, "Object keys must be strings.")
                walk(key, depth + 1)
                walk(child, depth + 1)
        elif type(item) is list:
            _require(len(item) <= 64, "Array limit exceeded.")
            for child in item:
                walk(child, depth + 1)
        elif type(item) is str:
            _require(len(item) <= 4096, "String limit exceeded.")
        elif type(item) is float:
            _require(math.isfinite(item), "Numbers must be finite.")
        else:
            _require(item is None or type(item) in (bool, int), "Only JSON values are accepted.")
    walk(value, 0)
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                             allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, UnicodeError, OverflowError):
        raise PublicNodeError("Invalid JSON declaration.") from None
    _require(len(encoded) <= MAX_BODY, "Declaration size limit exceeded.")
    return encoded


def _object(value, keys):
    _require(type(value) is dict and set(value) == set(keys), "Invalid object fields.")


def _string(value, maximum=128, pattern=None):
    _require(type(value) is str and 1 <= len(value) <= maximum, "Invalid string field.")
    if pattern:
        valid = (_is_name(value) if pattern is NAME else
                 _is_version(value) if pattern is VERSION else False)
        _require(valid, "Invalid identifier or version.")


def _is_name(value):
    return (bool(value) and value.isascii() and value[0].isalnum()
            and all(character.isalnum() or character in "._-" for character in value))


def _is_version(value):
    parts = value.split(".")
    return len(parts) == 3 and all(part and part.isascii() and part.isdecimal() for part in parts)


def _array(value, maximum):
    _require(type(value) is list and len(value) <= maximum, "Invalid array field.")


def _ports(value):
    _array(value, 32)
    result = {}
    for port in value:
        _object(port, ("name", "type"))
        _string(port["name"], pattern=NAME)
        _require(type(port["type"]) is str and port["type"] in TYPES, "Invalid port type.")
        _require(port["name"] not in result, "Duplicate port name.")
        result[port["name"]] = port["type"]
    return result


def _matches(value, kind):
    if kind == "string":
        return type(value) is str
    if kind == "boolean":
        return type(value) is bool
    if kind == "integer":
        return type(value) is int
    return type(value) in (int, float)


def _values(values, ports):
    _require(type(values) is dict and set(values) == set(ports), "Test port names do not match.")
    for name, kind in ports.items():
        _require(_matches(values[name], kind), "Test port types do not match.")


def _validate(manifest):
    if type(manifest) is dict and manifest.get("schema") == "module-manifest/2":
        from .topology import validate_declaration
        return validate_declaration(manifest)
    return _validate_v1(manifest)


def _validate_v1(manifest):
    canonical = _bounded(manifest)
    _object(manifest, ("schema", "moduleId", "version", "purpose", "inputs", "outputs",
                       "constraints", "engineConnections", "syntheticTests"))
    _require(manifest["schema"] == "module-manifest/1", "Unsupported manifest schema.")
    _string(manifest["moduleId"], pattern=NAME)
    _string(manifest["version"], maximum=64, pattern=VERSION)
    _string(manifest["purpose"], maximum=4096)
    _ports(manifest["inputs"])
    _ports(manifest["outputs"])
    _array(manifest["constraints"], 32)
    for constraint in manifest["constraints"]:
        _object(constraint, ("kind", "value"))
        _string(constraint["kind"])
        value = constraint["value"]
        _require(value is None or type(value) in (str, int, float, bool), "Invalid constraint value.")
        if constraint["kind"] in ("maxStringLength", "maxArrayLength"):
            _require(type(value) is int and 0 <= value <= 4096, "Invalid structural constraint.")
        elif constraint["kind"] == "nonNegativeNumbers":
            _require(value is True, "Invalid structural constraint.")
    _array(manifest["engineConnections"], 32)
    connections = {}
    for connection in manifest["engineConnections"]:
        _object(connection, ("name", "interface", "required", "inputs", "outputs"))
        _string(connection["name"], pattern=NAME)
        _string(connection["interface"])
        _require(type(connection["required"]) is bool, "Invalid required flag.")
        _require(connection["name"] not in connections, "Duplicate connection name.")
        connections[connection["name"]] = (_ports(connection["inputs"]), _ports(connection["outputs"]))
    _array(manifest["syntheticTests"], 64)
    names = set()
    for test in manifest["syntheticTests"]:
        _object(test, ("name", "connection", "inputs", "expectedOutputs"))
        _string(test["name"], pattern=NAME)
        _string(test["connection"], pattern=NAME)
        _require(test["name"] not in names, "Duplicate test name.")
        names.add(test["name"])
        _require(test["connection"] in connections, "Test connection is not declared.")
        inputs, outputs = connections[test["connection"]]
        _values(test["inputs"], inputs)
        _values(test["expectedOutputs"], outputs)
    return hashlib.sha512(canonical).hexdigest()


def _constraint_findings(manifest, actual=None):
    values = [value for test in manifest["syntheticTests"]
              for field in ("inputs", "expectedOutputs") for value in test[field].values()]
    if actual:
        values.extend(actual.values())
    findings = []
    for constraint in manifest["constraints"]:
        kind, limit = constraint["kind"], constraint["value"]
        if kind == "maxStringLength":
            relevant = [v for v in values if type(v) is str]
            if not relevant:
                findings.append({"kind": kind, "status": "unresolved"})
                continue
            passed = all(len(v) <= limit for v in relevant)
        elif kind == "maxArrayLength":
            arrays = [manifest[field] for field in
                      ("inputs", "outputs", "engineConnections", "syntheticTests")]
            arrays.extend(connection[field] for connection in manifest["engineConnections"]
                          for field in ("inputs", "outputs"))
            passed = all(len(array) <= limit for array in arrays)
        elif kind == "nonNegativeNumbers":
            relevant = [v for v in values if type(v) in (int, float)]
            if not relevant:
                findings.append({"kind": kind, "status": "unresolved"})
                continue
            passed = all(v >= 0 for v in relevant)
        elif kind in ("includeEngine", "excludeEngine") and manifest["schema"] == "module-manifest/2":
            findings.append({"kind": kind, "status": "deferred"})
            continue
        else:
            findings.append({"kind": kind, "status": "unresolved"})
            continue
        findings.append({"kind": kind, "status": "satisfied" if passed else "violated"})
    return findings


def _connection_findings(manifest):
    findings = []
    for connection in manifest["engineConnections"]:
        interface = INTERFACES.get(connection["interface"])
        signature = (_ports(connection["inputs"]), _ports(connection["outputs"]))
        status = "unresolved" if interface is None else "compatible" if signature == interface else "incompatible"
        findings.append({"name": connection["name"], "interface": connection["interface"],
                         "required": connection["required"], "status": status})
    return findings


class RateLimiter:
    """Fixed rolling budgets, bounded by at most global_limit active identities."""

    def __init__(self, client_limit=60, global_limit=300, clock=time.monotonic):
        self.client_limit = client_limit
        self.global_limit = global_limit
        self.clock = clock
        self.global_events = deque()
        self.clients = {}
        self.lock = threading.Lock()

    def allow(self, identity):
        with self.lock:
            now = self.clock()
            while self.global_events and self.global_events[0][0] <= now - 60:
                timestamp, old_identity = self.global_events.popleft()
                events = self.clients[old_identity]
                events.popleft()
                if not events:
                    del self.clients[old_identity]
            events = self.clients.get(identity, ())
            if len(self.global_events) >= self.global_limit or len(events) >= self.client_limit:
                return False
            self.global_events.append((now, identity))
            self.clients.setdefault(identity, deque()).append(now)
            return True


class PublicModuleNode:
    """Identity is supplied by trusted transport context, never manifest arguments."""

    def __init__(self, limiter=None, client_identity=None, *,
                 available_dependencies=None, engine_catalog=None):
        self.limiter = limiter if limiter is not None else RateLimiter()
        self.client_identity = client_identity
        self._event_records = OrderedDict()
        self._event_lock = threading.Lock()
        if available_dependencies is not None:
            _require(type(available_dependencies) is dict, "Invalid backend dependency configuration.")
            self.available_dependencies = copy.deepcopy(available_dependencies)
        if engine_catalog is not None:
            _require(type(engine_catalog) is dict, "Invalid backend engine configuration.")
            self.engine_catalog = copy.deepcopy(engine_catalog)

    def _charge(self, identity=None):
        if identity is None:
            identity = self.client_identity() if self.client_identity else "global-default"
        _require(type(identity) is str and 1 <= len(identity) <= 256, "Invalid trusted client identity.")
        _require(self.limiter.allow(identity), "Rate limit exceeded.")

    def _run(self, action, manifest, event_id=None):
        if event_id is not None and (action != "test" or type(event_id) is not str
                                     or EVENT_ID.fullmatch(event_id) is None):
            return {"valid": False, "errors": ["Invalid synthetic event ID."],
                    "liveAdmission": False, "syntheticReceipt": {
                        "schema": "module-synthetic-receipt/2", "synthetic": True,
                        "signed": False, "liveAdmission": False, "status": "invalid",
                        "tests": [], "scope": {"execution": "not_run"}}}
        try:
            digest = _validate(manifest)
        except (PublicNodeError, RecursionError) as error:
            reason = str(error) if isinstance(error, PublicNodeError) else "Declaration complexity limit exceeded."
            return {
                "valid": False, "errors": [reason], "constraints": [], "connections": [],
                "unresolvedConstraints": [], "liveAdmission": False,
                "syntheticReceipt": {
                    "schema": "module-synthetic-receipt/2", "synthetic": True,
                    "signed": False,
                    "liveAdmission": False, "status": "invalid", "tests": [],
                    "scope": {"execution": "not_run", "moduleImplementationExecuted": False,
                              "moduleDeclaredIOExecuted": False, "testedConnections": [],
                              "syntheticAssertions": [], "checkedConstraints": [],
                              "unresolvedConstraints": []},
                },
            }
        if event_id is not None:
            with self._event_lock:
                prior = self._event_records.get(event_id)
                if prior is not None and prior[0] != digest:
                    return {"valid": False, "errors": ["Synthetic event ID content conflict."],
                            "errorCode": "event_id_conflict", "declarationSha512": digest,
                            "liveAdmission": False, "syntheticReceipt": {
                                "schema": "module-synthetic-receipt/2", "synthetic": True,
                                "signed": False, "liveAdmission": False, "status": "rejected",
                                "eventId": event_id, "tests": [],
                                "scope": {"execution": "not_run"}}}
        constraints = _constraint_findings(manifest)
        findings = _connection_findings(manifest)
        result = {"valid": True, "schema": manifest["schema"], "declarationSha512": digest,
                  "constraints": constraints, "connections": findings,
                  "unresolvedConstraints": [f for f in constraints if f["status"] == "unresolved"],
                  "liveAdmission": False}
        scope = {
            "execution": "not_run", "moduleImplementationExecuted": False,
            "moduleDeclaredIOExecuted": False, "testedConnections": [],
            "syntheticAssertions": [],
            "checkedConstraints": [f["kind"] for f in constraints
                                   if f["status"] in ("satisfied", "violated")],
            "unresolvedConstraints": [f["kind"] for f in constraints if f["status"] == "unresolved"],
        }
        if manifest["schema"] == "module-manifest/2":
            scope["placementAssessmentIncluded"] = False
            scope["placementConstraints"] = "Evaluated separately in top-level status and topology evidence."
        result["syntheticReceipt"] = {
            "schema": "module-synthetic-receipt/2", "declarationSha512": digest,
            "eventId": event_id, "synthetic": True, "signed": False,
            "liveAdmission": False, "status": "not_run",
            "scope": scope, "tests": [],
        }
        if action != "test":
            self._assessment(manifest, digest, result)
            return result

        by_name = {c["name"]: c for c in manifest["engineConnections"]}
        statuses = {c["name"]: c["status"] for c in findings}
        tests = []
        for test in manifest["syntheticTests"]:
            status = statuses[test["connection"]]
            if status != "compatible":
                tests.append({"name": test["name"], "status": "unresolved" if status == "unresolved" else "failed"})
                continue
            interface = by_name[test["connection"]]["interface"]
            inputs = test["inputs"]
            try:
                if interface == "identity/1":
                    output = {"value": inputs["value"]}
                elif interface == "numbers.add/1":
                    output = {"sum": inputs["a"] + inputs["b"]}
                elif interface == "text.concat/1":
                    output = {"result": inputs["left"] + inputs["right"]}
                else:
                    output = {"value": not inputs["value"]}
                _bounded(output)
                if manifest["schema"] == "module-manifest/2":
                    from .topology import SAFE_INTEGER
                    _require(all(type(value) not in (int, float) or
                                 type(value) is int and abs(value) <= SAFE_INTEGER
                                 for value in output.values()), "Unsafe synthetic output number.")
                passed = output == test["expectedOutputs"]
                actual_constraints = _constraint_findings(manifest, output)
                passed = passed and all(f["status"] != "violated" for f in actual_constraints)
                for aggregate, actual_finding in zip(constraints, actual_constraints):
                    if actual_finding["status"] == "violated":
                        aggregate["status"] = "violated"
                tests.append({"name": test["name"], "status": "passed" if passed else "failed",
                              "actualOutputs": output})
            except (PublicNodeError, OverflowError):
                tests.append({"name": test["name"], "status": "failed"})
        failed = any(t["status"] == "failed" for t in tests) or any(c["status"] == "violated" for c in constraints)
        incomplete = (not tests or any(t["status"] == "unresolved" for t in tests)
                      or any(c["status"] == "unresolved" for c in constraints)
                      or any(c["status"] != "compatible" for c in findings))
        scope["execution"] = "backend-defined builtin connection interfaces only"
        scope["testedConnections"] = sorted({test["connection"] for test in manifest["syntheticTests"]
                                             if statuses[test["connection"]] == "compatible"})
        scope["syntheticAssertions"] = ["connection port signatures", "expected output equality"]
        result["syntheticReceipt"]["status"] = "failed" if failed else "incomplete" if incomplete else "passed"
        result["syntheticReceipt"]["tests"] = tests
        self._assessment(manifest, digest, result)
        self._bind_synthetic_receipt(manifest, digest, event_id, result)
        if event_id is not None:
            receipt = result["syntheticReceipt"]
            with self._event_lock:
                prior = self._event_records.get(event_id)
                if prior is not None:
                    if prior != (digest, receipt["receiptSha512"]):
                        return {"valid": False, "errors": ["Synthetic event ID content conflict."],
                                "errorCode": "event_id_conflict", "declarationSha512": digest,
                                "liveAdmission": False, "syntheticReceipt": {
                                    "schema": "module-synthetic-receipt/2", "synthetic": True,
                                    "signed": False, "liveAdmission": False, "status": "rejected",
                                    "eventId": event_id, "tests": [],
                                    "scope": {"execution": "not_run"}}}
                    self._event_records.move_to_end(event_id)
                    receipt["duplicate"] = True
                else:
                    if len(self._event_records) >= MAX_TEST_EVENTS:
                        self._event_records.popitem(last=False)
                    self._event_records[event_id] = (digest, receipt["receiptSha512"])
                    receipt["duplicate"] = False
        return result

    @staticmethod
    def _bind_synthetic_receipt(manifest, digest, event_id, result):
        receipt = result["syntheticReceipt"]
        requirements = manifest.get("businessRequirements", {
            "function": manifest["purpose"],
            "inputs": manifest["inputs"],
            "outputs": manifest["outputs"],
            "acceptanceCases": [test["name"] for test in manifest["syntheticTests"]],
        })
        body = {
            "schema": receipt["schema"], "eventId": event_id,
            "moduleId": manifest["moduleId"], "declarationSha512": digest,
            "requirements": requirements, "evidence": manifest.get("evidence", []),
            "resolvedTopology": {
                "status": result.get("status"),
                "identityRing": result.get("identityRing"),
                "placementRing": result.get("placementRing"),
                "assessmentEvidence": result.get("evidence"),
            },
            "status": receipt["status"], "tests": receipt["tests"],
            "scope": receipt["scope"], "synthetic": True, "signed": False,
            "liveAdmission": False,
        }
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False, allow_nan=False).encode("utf-8")
        receipt.update(body)
        receipt["receiptSha512"] = hashlib.sha512(canonical).hexdigest()

    def _assessment(self, manifest, digest, result):
        if manifest["schema"] == "module-manifest/2":
            from .topology import assess_declaration
            assessment = assess_declaration(
                manifest, digest, test_receipt=result["syntheticReceipt"],
                available_dependencies=getattr(self, "available_dependencies", None),
                engine_catalog=getattr(self, "engine_catalog", None))
            placement_checks = iter(check for check in assessment["evidence"]
                                    if check["kind"] == "constraint"
                                    and check["evidence"].get("kind") in ("includeEngine", "excludeEngine"))
            for finding in result["constraints"]:
                if finding["status"] == "deferred":
                    checked = next(placement_checks)
                    finding["status"] = "violated" if checked["status"] == "incompatible" else "satisfied"
            result.update(assessment)
        return result

    def droppoint_module_validate(self, manifest):
        self._charge()
        return self._run("validate", manifest)

    def droppoint_module_test(self, manifest, event_id=None):
        self._charge()
        return self._run("test", manifest, event_id)

    def droppoint_module_connections(self, manifest):
        self._charge()
        return self._run("connections", manifest)


def register_module_tools(host, node):
    """Register public tools during serialized startup, preserving existing names.

    The host must expose every registered name through tool_names() and reject
    duplicates itself. No authentication context parameter is exposed or needed.
    """
    try:
        existing_names = set(host.tool_names())
    except Exception:
        raise PublicNodeError("Host registry inspection is required.") from None
    if existing_names.intersection(TOOL_NAMES):
        raise PublicNodeError("Public tool name collision.")
    tools = tuple(getattr(node, name) for name in TOOL_NAMES)
    for tool in tools:
        host.tool(name=tool.__name__, description=TOOL_DESCRIPTIONS[tool.__name__])(tool)
    return tools


TOOL_NAMES = ("droppoint_module_validate", "droppoint_module_test", "droppoint_module_connections")
TOOL_DESCRIPTIONS = {
    "droppoint_module_validate": "Validate a transient public module declaration; never authorize live admission.",
    "droppoint_module_test": "Run builtin acceptance tests; optional eventId enables process-local retry deduplication.",
    "droppoint_module_connections": "Check declared builtin engine signatures; unknown interfaces remain unresolved.",
}
_default_node = PublicModuleNode()


def droppoint_module_validate(manifest):
    return _default_node.droppoint_module_validate(manifest)


def droppoint_module_test(manifest, event_id=None):
    return _default_node.droppoint_module_test(manifest, event_id)


def droppoint_module_connections(manifest):
    return _default_node.droppoint_module_connections(manifest)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "Duplicate JSON field.")
        result[key] = value
    return result


def _parse(raw):
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(PublicNodeError("Invalid number.")))
    except (ValueError, UnicodeError, RecursionError):
        raise PublicNodeError("Invalid JSON request.") from None


class BoundedHTTPServer(ThreadingHTTPServer):
    """Limit active connections before spawning request-handler threads."""

    daemon_threads = True

    def __init__(self, address, handler, max_connections):
        _require(type(max_connections) is int and 1 <= max_connections <= 300,
                 "Invalid active connection budget.")
        self.connection_slots = threading.BoundedSemaphore(max_connections)
        super().__init__(address, handler)

    def process_request(self, request, client_address):
        if not self.connection_slots.acquire(blocking=False):
            try:
                request.settimeout(1)
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n"
                                b"Connection: close\r\nRetry-After: 5\r\n\r\n")
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.connection_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.connection_slots.release()

    def handle_error(self, request, client_address):
        # Public declarations and transport details must not enter server logs.
        pass


def _manifest_input_schema(*, event_id=False):
    definitions = {}
    for version, filename in (("v1", "module_manifest.schema.json"),
                              ("v2", "module_manifest_v2.schema.json")):
        schema = json.loads(Path(__file__).with_name(filename).read_text("utf-8"))
        schema.pop("$id", None)
        schema.pop("$schema", None)

        def relocate(value):
            if type(value) is dict:
                return {key: ("#/$defs/" + version + child[1:]
                              if key == "$ref" and child.startswith("#/") else relocate(child))
                        for key, child in value.items()}
            if type(value) is list:
                return [relocate(child) for child in value]
            return value

        definitions[version] = relocate(schema)
    properties = {"manifest": {"oneOf": [
        {"$ref": "#/$defs/v1"}, {"$ref": "#/$defs/v2"}]}}
    if event_id:
        properties["eventId"] = {
            "type": "string", "maxLength": 128,
            "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}(?![\\s\\S])",
        }
    return {"type": "object", "required": ["manifest"], "additionalProperties": False,
            "$defs": definitions, "properties": properties}


class _InlineAssetParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.chunks = {"script": [], "style": []}
        self.active = None
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag in self.chunks:
            self.active = tag
            self.parts = []

    def handle_data(self, data):
        if self.active is not None:
            self.parts.append(data)

    def handle_endtag(self, tag):
        if tag == self.active:
            self.chunks[tag].append("".join(self.parts).encode("utf-8"))
            self.active = None
            self.parts = []


def _page_policy(page, *, modules=False):
    parser = _InlineAssetParser()
    parser.feed(page.decode("utf-8"))
    parser.close()
    _require(parser.active is None, "Invalid static asset.")
    hashes = {tag: " ".join("'sha256-" + base64.b64encode(
        hashlib.sha256(chunk).digest()).decode("ascii") + "'" for chunk in chunks)
        for tag, chunks in parser.chunks.items()}
    scripts = ("'self' " if modules else "") + hashes["script"]
    return (f"default-src 'self'; script-src {scripts}; style-src {hashes['style']}; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
            "object-src 'none'; form-action 'self'")


def create_server(host="127.0.0.1", port=8080, node=None, source_identity=None,
                  allowed_hosts=None, allowed_origins=None, max_connections=32):
    """Create a bounded public server with explicit transport trust boundaries.

    source_identity(handler) must be trusted deployment code; XFF is ignored.
    allowed_hosts contains exact Host authorities, including non-default ports.
    allowed_origins contains exact browser origins; neither permits wildcards.
    Defaults allow only bound-host authorities and their HTTP origins.
    """
    node = node if node is not None else PublicModuleNode()
    page = Path(__file__).with_name("public_node.html").read_bytes()
    zip_page = Path(__file__).with_name("zip_node.html").read_bytes()
    content_policy = _page_policy(page)
    zip_policy = _page_policy(zip_page, modules=True)
    assets = {
        "/": (page, "text/html; charset=utf-8", content_policy),
        "/zip": (zip_page, "text/html; charset=utf-8", zip_policy),
        "/zip_intake.mjs": (Path(__file__).with_name("zip_intake.mjs").read_bytes(),
                            "text/javascript; charset=utf-8", zip_policy),
    }
    hosts = set()
    origins = set()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def log_message(self, *args):
            pass

        def _send(self, status, payload=None, asset=None):
            raw = asset[0] if asset is not None else b"" if payload is None else json.dumps(
                payload, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", asset[1] if asset is not None else "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", asset[2] if asset is not None else content_policy)
            self.send_header("Connection", "close")
            if status == 429:
                self.send_header("Retry-After", "60")
            self.end_headers()
            self.close_connection = True
            self.wfile.write(raw)

        def _charge(self):
            try:
                identity = source_identity(self) if source_identity else self.client_address[0]
                node._charge(identity)
                return True
            except PublicNodeError:
                self._send(429, {"error": "Rate limit exceeded."})
                return False
            except Exception:
                self._send(500, {"error": "Transport configuration error."})
                return False

        def _anonymous(self):
            if any(self.headers.get(name) is not None for name in
                   ("Authorization", "Proxy-Authorization", "Cookie")):
                self._send(400, {"error": "Credentials are not accepted."})
                return False
            return True

        def _trusted_target(self):
            host_headers = self.headers.get_all("Host", [])
            if len(host_headers) != 1 or host_headers[0].lower() not in hosts:
                self._send(403, {"error": "Host is not allowed."})
                return False
            origin_headers = self.headers.get_all("Origin", [])
            if origin_headers and (len(origin_headers) != 1 or origin_headers[0] not in origins):
                self._send(403, {"error": "Origin is not allowed."})
                return False
            return True

        def do_GET(self):
            if self._charge() and self._trusted_target() and self._anonymous():
                asset = assets.get(self.path)
                if asset is None:
                    self._send(404, {"error": "Not found."})
                else:
                    self._send(200, asset=asset)

        def do_POST(self):
            if not self._charge() or not self._trusted_target() or not self._anonymous():
                return
            if self.path not in ("/mcp", "/api/validate", "/api/test", "/api/connections"):
                self._send(404, {"error": "Not found."})
                return
            protocol_headers = self.headers.get_all("MCP-Protocol-Version", [])
            if self.path == "/mcp" and protocol_headers and (
                    len(protocol_headers) != 1 or protocol_headers[0] not in PROTOCOLS):
                self._send(400, {"error": "Unsupported MCP protocol version."})
                return
            lengths = self.headers.get_all("Content-Length", [])
            if self.headers.get("Transfer-Encoding") is not None or len(lengths) != 1 or not re.fullmatch(r"[0-9]+", lengths[0]):
                self._send(400, {"error": "A single valid Content-Length is required."})
                return
            if len(lengths[0]) > 10 or int(lengths[0]) > MAX_BODY:
                self._send(413, {"error": "Request size limit exceeded."})
                return
            if (len(self.headers.get_all("Content-Type", [])) != 1
                    or self.headers.get_content_type() != "application/json"):
                self._send(415, {"error": "JSON content type required."})
                return
            try:
                raw = self.rfile.read(int(lengths[0]))
                _require(len(raw) == int(lengths[0]), "Incomplete body.")
                request = _parse(raw)
                _bounded(request)
            except (PublicNodeError, TimeoutError, OSError, RecursionError):
                self._send(400, {"error": "Invalid or oversized JSON request."})
                return
            if self.path == "/mcp":
                self._mcp(request)
            else:
                event_id = None
                manifest = request
                if self.path == "/api/test" and type(request) is dict and "manifest" in request:
                    if set(request) - {"manifest", "eventId"}:
                        self._send(400, {"error": "Invalid synthetic test request."})
                        return
                    manifest = request["manifest"]
                    event_id = request.get("eventId")
                self._send(200, node._run(self.path.rsplit("/", 1)[1], manifest, event_id))

        def _mcp(self, request):
            request_id = request.get("id") if type(request) is dict else None
            valid_id = request_id is None or type(request_id) in (str, int)
            if not valid_id:
                request_id = None

            def error(code, message):
                self._send(200, {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}})

            if (type(request) is not dict or request.get("jsonrpc") != "2.0"
                    or type(request.get("method")) is not str or not valid_id
                    or set(request) - {"jsonrpc", "id", "method", "params"}):
                error(-32600, "Invalid Request")
                return
            method = request["method"]
            params = request.get("params", {})
            if type(params) is not dict:
                error(-32602, "Invalid params")
                return
            if method == "notifications/initialized" and "id" not in request and not params:
                self._send(202)
                return
            if "id" not in request:
                self._send(202)
                return
            if method == "initialize":
                if (set(params) != {"protocolVersion", "capabilities", "clientInfo"}
                        or type(params["protocolVersion"]) is not str
                        or type(params["capabilities"]) is not dict
                        or type(params["clientInfo"]) is not dict
                        or set(params["clientInfo"]) != {"name", "version"}
                        or any(type(v) is not str for v in params["clientInfo"].values())):
                    error(-32602, "Invalid params")
                    return
                version = params["protocolVersion"] if params["protocolVersion"] in PROTOCOLS else PROTOCOLS[0]
                result = {"protocolVersion": version, "capabilities": {"tools": {"listChanged": False}},
                          "serverInfo": {"name": "invariantgatewriter-public", "version": "1.0.0"}}
            elif method == "ping" and not params:
                result = {}
            elif method == "tools/list" and not params:
                result = {"tools": [{"name": name, "description": TOOL_DESCRIPTIONS[name],
                                    "inputSchema": _manifest_input_schema(event_id=name == "droppoint_module_test")}
                                   for name in TOOL_NAMES]}
            elif method == "tools/call":
                if (set(params) != {"name", "arguments"} or params["name"] not in TOOL_NAMES
                        or type(params["arguments"]) is not dict
                        or "manifest" not in params["arguments"]
                        or set(params["arguments"]) - ({"manifest", "eventId"}
                            if params["name"] == "droppoint_module_test" else {"manifest"})):
                    error(-32602, "Invalid params")
                    return
                value = node._run(params["name"].removeprefix("droppoint_module_"),
                                  params["arguments"]["manifest"], params["arguments"].get("eventId"))
                result = {"content": [{"type": "text", "text": json.dumps(value, ensure_ascii=False, allow_nan=False)}],
                          "structuredContent": value, "isError": not value["valid"]}
            else:
                error(-32601, "Method not found")
                return
            self._send(200, {"jsonrpc": "2.0", "id": request_id, "result": result})

    server = BoundedHTTPServer((host, port), Handler, max_connections)
    actual_port = server.server_address[1]
    default_hosts = {host, server.server_address[0]}
    if host in ("127.0.0.1", "localhost"):
        default_hosts.update(("127.0.0.1", "localhost"))
    authorities = {name if actual_port == 80 else f"{name}:{actual_port}" for name in default_hosts}
    try:
        _require(not isinstance(allowed_hosts, str) and not isinstance(allowed_origins, str),
                 "Allowlists must be collections of exact values.")
        configured_hosts = authorities if allowed_hosts is None else set(allowed_hosts)
        _require(bool(configured_hosts) and all(type(value) is str and value and "*" not in value
                                               and "/" not in value and "@" not in value
                                               for value in configured_hosts), "Invalid Host allowlist.")
        hosts.update(value.lower() for value in configured_hosts)
        configured_origins = {"http://" + value for value in hosts} if allowed_origins is None else set(allowed_origins)
        _require(all(type(value) is str and value.startswith(("http://", "https://"))
                     and "*" not in value and "@" not in value for value in configured_origins),
                 "Invalid Origin allowlist.")
        origins.update(configured_origins)
    except (PublicNodeError, TypeError):
        server.server_close()
        raise PublicNodeError("Invalid transport allowlist configuration.") from None
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=os.environ.get("PUBLIC_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8080")))
    parser.add_argument("--allowed-host", action="append", help="Allowed Host authority; repeat for multiple values.")
    parser.add_argument("--allowed-origin", action="append", help="Allowed browser origin; repeat for multiple values.")
    parser.add_argument("--max-connections", type=int, default=32)
    args = parser.parse_args()
    hosts = args.allowed_host
    origins = args.allowed_origin
    if hosts is None and "PUBLIC_ALLOWED_HOSTS" in os.environ:
        hosts = os.environ["PUBLIC_ALLOWED_HOSTS"].split(",")
    if origins is None and "PUBLIC_ALLOWED_ORIGINS" in os.environ:
        origins = os.environ["PUBLIC_ALLOWED_ORIGINS"].split(",")
    server = create_server(args.host, args.port, allowed_hosts=hosts,
                           allowed_origins=origins, max_connections=args.max_connections)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
