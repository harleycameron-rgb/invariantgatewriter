import copy
import base64
import hashlib
import http.client
import json
import re
import socket
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from invariantgatewriter.public_node import (
    MAX_BODY, PublicModuleNode, PublicNodeError, RateLimiter, create_server,
    main, register_module_tools,
    _validate, _page_policy,
)
from invariantgatewriter.topology import SAFE_INTEGER, builtin_engine_catalog, validate_declaration


def manifest():
    inputs = [{"name": "a", "type": "number"}, {"name": "b", "type": "number"}]
    outputs = [{"name": "sum", "type": "number"}]
    return {
        "schema": "module-manifest/1", "moduleId": "example.add", "version": "1.0.0",
        "purpose": "Synthetic addition ☀", "inputs": inputs, "outputs": outputs,
        "constraints": [{"kind": "nonNegativeNumbers", "value": True}],
        "engineConnections": [{"name": "add", "interface": "numbers.add/1",
                               "required": True, "inputs": copy.deepcopy(inputs),
                               "outputs": copy.deepcopy(outputs)}],
        "syntheticTests": [{"name": "basic", "connection": "add",
                            "inputs": {"a": 2, "b": 3}, "expectedOutputs": {"sum": 5}}],
    }


def manifest_v2():
    value = manifest()
    value.update(schema="module-manifest/2", dependencies=[],
                 proposedPlacements=["numbers", "local-sandbox"],
                 evidence=[{"reference": "module.json", "method": "explicit-declaration"}],
                 extractionMethod="explicit-declaration", unresolvedQuestions=[])
    return value


class V2ModuleTests(unittest.TestCase):
    def test_csp_parser_preserves_literal_script_and_style_content(self):
        script = 'const value = "<div>&amp;<!-- literal -->";\r\n'
        style = 'body::after{content:"<script>&amp;"}\n'
        page = ('<style>' + style + '</style><script\n type="module">' +
                script + '</script>').encode()
        policy = _page_policy(page, modules=True)
        for content in (script, style):
            digest = base64.b64encode(hashlib.sha256(content.encode()).digest()).decode()
            self.assertIn("'sha256-" + digest + "'", policy)
        self.assertNotIn("unsafe-inline", policy)

    def test_validator_entrypoint_hashes_all_v2_fields_without_charge(self):
        value = manifest_v2()
        self.assertEqual(_validate(value), validate_declaration(value))
        self.assertEqual(_validate(value), hashlib.sha512(json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest())
        value["purpose"] += " changed"
        self.assertEqual(_validate(value), validate_declaration(value))

    def test_all_operations_attach_rings_but_only_executed_tests_complete(self):
        node = PublicModuleNode()
        for action in ("validate", "connections", "test"):
            value = manifest_v2()
            result = getattr(node, "droppoint_module_" + action)(value)
            self.assertTrue(result["valid"])
            self.assertEqual(result["schema"], "module-manifest/2")
            self.assertEqual(result["identityRing"]["declarationSha512"], result["declarationSha512"])
            self.assertEqual(result["placementRing"]["feasible"], ["local-sandbox", "numbers"])
            self.assertFalse(result["liveAdmission"])
            self.assertEqual(result["status"], "complete" if action == "test" else "pending")
            self.assertEqual(result["syntheticReceipt"]["status"], "passed" if action == "test" else "not_run")
            self.assertEqual(result["topology"]["completionPoint"], [0, 0] if action == "test" else None)
            self.assertFalse(result["syntheticReceipt"]["scope"]["moduleImplementationExecuted"])
            self.assertFalse(result["syntheticReceipt"]["scope"]["placementAssessmentIncluded"])

    def test_backend_dependencies_and_catalog_are_not_client_claims(self):
        value = manifest_v2()
        value["dependencies"] = [{"moduleId": "@scope/pkg", "version": "1.2.3"}]
        self.assertEqual(PublicModuleNode().droppoint_module_test(value)["status"], "pending")
        config = {"@scope/pkg": "1.2.3"}
        node = PublicModuleNode(available_dependencies=config)
        config["@scope/pkg"] = "2.0.0"
        self.assertEqual(node.droppoint_module_test(value)["status"], "complete")
        self.assertEqual(PublicModuleNode(available_dependencies=config).droppoint_module_test(value)["status"],
                         "incompatible")
        self.assertEqual(PublicModuleNode(engine_catalog={}).droppoint_module_test(manifest_v2())["status"],
                         "incompatible")
        catalog = builtin_engine_catalog()
        node = PublicModuleNode(engine_catalog=catalog)
        catalog.clear()
        self.assertEqual(node.droppoint_module_test(manifest_v2())["status"], "complete")
        value["availableDependencies"] = {"@scope/pkg": "1.2.3"}
        self.assertFalse(node.droppoint_module_test(value)["valid"])

    def test_placement_constraints_resolve_only_in_v2(self):
        value = manifest_v2()
        value["constraints"].append({"kind": "includeEngine", "value": "numbers"})
        result = PublicModuleNode().droppoint_module_test(value)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["placementRing"]["feasible"], ["numbers"])
        self.assertEqual(result["constraints"][-1]["status"], "satisfied")
        self.assertEqual(result["syntheticReceipt"]["status"], "passed")
        self.assertNotIn("includeEngine", result["syntheticReceipt"]["scope"]["checkedConstraints"])
        value["constraints"].append({"kind": "excludeEngine", "value": "numbers"})
        result = PublicModuleNode().droppoint_module_test(value)
        self.assertEqual(result["status"], "incompatible")
        self.assertEqual(result["constraints"][-1]["status"], "violated")
        self.assertEqual(result["syntheticReceipt"]["status"], "passed")
        self.assertFalse(result["syntheticReceipt"]["scope"]["placementAssessmentIncluded"])
        value["constraints"] = [{"kind": "includeEngine", "value": "unavailable"}]
        result = PublicModuleNode().droppoint_module_validate(value)
        self.assertEqual(result["constraints"][-1]["status"], "violated")
        self.assertEqual(result["status"], "incompatible")
        old = manifest()
        old["constraints"].append({"kind": "includeEngine", "value": "numbers"})
        old_result = PublicModuleNode().droppoint_module_test(old)
        self.assertEqual(old_result["constraints"][-1]["status"], "unresolved")
        self.assertNotIn("topology", old_result)

    def test_v2_safe_output_numbers_and_sanitized_invalid_manifests(self):
        value = manifest_v2()
        value["syntheticTests"][0]["inputs"] = {"a": SAFE_INTEGER, "b": 1}
        value["syntheticTests"][0]["expectedOutputs"] = {"sum": SAFE_INTEGER}
        result = PublicModuleNode().droppoint_module_test(value)
        self.assertEqual(result["status"], "incompatible")
        self.assertEqual(result["syntheticReceipt"]["status"], "failed")
        self.assertNotIn("actualOutputs", result["syntheticReceipt"]["tests"][0])
        for invalid in (1.0, SAFE_INTEGER + 1, True):
            value = manifest_v2()
            value["syntheticTests"][0]["inputs"]["a"] = invalid
            result = PublicModuleNode().droppoint_module_validate(value)
            self.assertFalse(result["valid"])
            self.assertEqual(result["syntheticReceipt"]["status"], "invalid")
            self.assertNotIn("identityRing", result)
        value = manifest_v2()
        value["evidence"][0]["reference"] = "../private-credential"
        result = PublicModuleNode().droppoint_module_validate(value)
        self.assertFalse(result["valid"])
        self.assertNotIn("private-credential", json.dumps(result))

    def test_partial_and_incompatible_candidates_stay_independent(self):
        node = PublicModuleNode()
        value = manifest_v2()
        value["extractionMethod"] = "static-interface"
        self.assertEqual(node.droppoint_module_test(value)["status"], "pending")
        value = manifest_v2()
        value["proposedPlacements"] = ["text"]
        self.assertEqual(node.droppoint_module_test(value)["status"], "incompatible")
        self.assertEqual(node.droppoint_module_test(manifest_v2())["status"], "complete")


class ModuleTests(unittest.TestCase):
    def setUp(self):
        self.node = PublicModuleNode()

    def test_hash_all_fields_canonical(self):
        value = manifest()
        before = copy.deepcopy(value)
        result = self.node.droppoint_module_validate(value)
        canonical = json.dumps(value, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False, allow_nan=False).encode()
        self.assertTrue(result["valid"])
        self.assertEqual(result["declarationSha512"], hashlib.sha512(canonical).hexdigest())
        self.assertFalse(result["liveAdmission"])
        self.assertEqual(value, before)
        value["purpose"] += " changed"
        self.assertNotEqual(self.node.droppoint_module_validate(value)["declarationSha512"],
                            result["declarationSha512"])
        self.assertNotIn("manifests", self.node.__dict__)
        self.assertEqual(result["syntheticReceipt"]["status"], "not_run")
        self.assertEqual(result["syntheticReceipt"]["declarationSha512"], result["declarationSha512"])

    def test_expected_outputs_are_asserted(self):
        value = manifest()
        receipt = self.node.droppoint_module_test(value)["syntheticReceipt"]
        self.assertEqual(receipt["status"], "passed")
        self.assertEqual(receipt["tests"][0]["actualOutputs"], {"sum": 5})
        self.assertTrue(receipt["synthetic"])
        self.assertFalse(receipt["liveAdmission"])
        self.assertFalse(receipt["scope"]["moduleImplementationExecuted"])
        self.assertFalse(receipt["scope"]["moduleDeclaredIOExecuted"])
        self.assertEqual(receipt["scope"]["testedConnections"], ["add"])
        self.assertEqual(receipt["scope"]["checkedConstraints"], ["nonNegativeNumbers"])
        value["syntheticTests"][0]["expectedOutputs"]["sum"] = 6
        self.assertEqual(self.node.droppoint_module_test(value)["syntheticReceipt"]["status"], "failed")

    def test_constraints_fail_or_remain_unresolved(self):
        value = manifest()
        value["syntheticTests"][0]["inputs"]["a"] = -2
        value["syntheticTests"][0]["expectedOutputs"]["sum"] = 1
        result = self.node.droppoint_module_test(value)
        self.assertEqual(result["constraints"][0]["status"], "violated")
        self.assertEqual(result["syntheticReceipt"]["status"], "failed")
        value = manifest()
        value["constraints"].append({"kind": "externalSafetyProof", "value": "claimed"})
        result = self.node.droppoint_module_test(value)
        self.assertEqual(result["constraints"][1]["status"], "unresolved")
        self.assertEqual(result["syntheticReceipt"]["status"], "incomplete")
        value = manifest()
        value["constraints"] = [{"kind": "maxArrayLength", "value": 1}]
        result = self.node.droppoint_module_test(value)
        self.assertEqual(result["constraints"][0]["status"], "violated")
        self.assertEqual(result["syntheticReceipt"]["status"], "failed")

    def test_connection_signature_and_unknown_optional(self):
        value = manifest()
        value["engineConnections"][0]["inputs"][0]["type"] = "integer"
        self.assertTrue(self.node.droppoint_module_validate(value)["valid"])
        result = self.node.droppoint_module_test(value)
        self.assertEqual(result["connections"][0]["status"], "incompatible")
        self.assertEqual(result["syntheticReceipt"]["status"], "failed")
        value = manifest()
        value["engineConnections"][0]["interface"] = "future.engine/1"
        value["engineConnections"][0]["required"] = False
        result = self.node.droppoint_module_test(value)
        self.assertEqual(result["connections"][0]["status"], "unresolved")
        self.assertEqual(result["syntheticReceipt"]["status"], "incomplete")

    def test_all_builtin_operations(self):
        for interface, inputs, expected, kind in [
            ("identity/1", {"value": "héllo"}, {"value": "héllo"}, "string"),
            ("text.concat/1", {"left": "<script>", "right": "safe"}, {"result": "<script>safe"}, "string"),
            ("boolean.not/1", {"value": True}, {"value": False}, "boolean"),
        ]:
            with self.subTest(interface=interface):
                value = manifest()
                value["constraints"] = [{"kind": "maxStringLength", "value": 100}] if kind == "string" else []
                connection = value["engineConnections"][0]
                connection["interface"] = interface
                connection["inputs"] = [{"name": name, "type": kind} for name in inputs]
                connection["outputs"] = [{"name": name, "type": kind} for name in expected]
                test = value["syntheticTests"][0]
                test["inputs"], test["expectedOutputs"] = inputs, expected
                self.assertEqual(self.node.droppoint_module_test(value)["syntheticReceipt"]["status"], "passed")
                if kind == "string":
                    value["constraints"][0]["value"] = 1
                    self.assertEqual(self.node.droppoint_module_test(value)["syntheticReceipt"]["status"], "failed")

    def test_constraints_without_relevant_values_are_unresolved(self):
        value = manifest()
        value["constraints"] = [{"kind": "maxStringLength", "value": 100}]
        result = self.node.droppoint_module_test(value)
        self.assertEqual(result["constraints"][0]["status"], "unresolved")
        self.assertEqual(result["unresolvedConstraints"], [{"kind": "maxStringLength", "status": "unresolved"}])
        self.assertEqual(result["syntheticReceipt"]["status"], "incomplete")
        self.assertEqual(result["syntheticReceipt"]["scope"]["checkedConstraints"], [])
        self.assertEqual(result["syntheticReceipt"]["scope"]["unresolvedConstraints"], ["maxStringLength"])
        value = manifest()
        value["syntheticTests"] = []
        result = self.node.droppoint_module_test(value)
        self.assertEqual(result["constraints"][0]["status"], "unresolved")
        self.assertEqual(result["syntheticReceipt"]["scope"]["testedConnections"], [])

    def test_module_io_is_only_metadata_not_executed(self):
        value = manifest()
        value["inputs"] = [{"name": "unexecuted", "type": "boolean"}]
        value["outputs"] = []
        result = self.node.droppoint_module_test(value)
        self.assertEqual(result["syntheticReceipt"]["status"], "passed")
        self.assertFalse(result["syntheticReceipt"]["scope"]["moduleDeclaredIOExecuted"])

    def test_every_operation_has_consistent_analysis_and_receipt(self):
        value = manifest()
        value["constraints"].append({"kind": "externalClaim", "value": True})
        for action in ("validate", "connections", "test"):
            result = getattr(self.node, "droppoint_module_" + action)(value)
            self.assertEqual(result["connections"][0]["status"], "compatible")
            self.assertEqual(result["unresolvedConstraints"], [{"kind": "externalClaim", "status": "unresolved"}])
            receipt = result["syntheticReceipt"]
            self.assertEqual(receipt["declarationSha512"], result["declarationSha512"])
            self.assertEqual(receipt["status"], "incomplete" if action == "test" else "not_run")
            if action != "test":
                self.assertEqual(receipt["tests"], [])
                self.assertEqual(receipt["scope"]["execution"], "not_run")
            invalid = getattr(self.node, "droppoint_module_" + action)({})
            self.assertEqual(invalid["errors"], ["Invalid object fields."])
            self.assertEqual(invalid["syntheticReceipt"]["status"], "invalid")
            self.assertNotIn("declarationSha512", invalid["syntheticReceipt"])
            self.assertFalse(invalid["liveAdmission"])

    def test_empty_tests_never_pass(self):
        value = manifest()
        value["syntheticTests"] = []
        self.assertEqual(self.node.droppoint_module_test(value)["syntheticReceipt"]["status"], "incomplete")

    def test_strict_invalid_manifests(self):
        mutations = [
            lambda m: m.update(extra="field"),
            lambda m: m.update(schema="module-manifest/2"),
            lambda m: m.update(moduleId="invalid\n"),
            lambda m: m.update(version="1.0"),
            lambda m: m.update(purpose=""),
            lambda m: m["inputs"].append(m["inputs"][0]),
            lambda m: m["engineConnections"].append(m["engineConnections"][0]),
            lambda m: m["syntheticTests"].append(m["syntheticTests"][0]),
            lambda m: m["syntheticTests"][0].update(connection="undeclared"),
            lambda m: m["syntheticTests"][0]["inputs"].update(a=True),
            lambda m: m["syntheticTests"][0]["inputs"].update(a=float("nan")),
            lambda m: m["syntheticTests"][0]["inputs"].update(a=float("inf")),
            lambda m: m["syntheticTests"][0]["inputs"].update(a=[1]),
            lambda m: m["syntheticTests"][0]["inputs"].update(other=1),
            lambda m: m["syntheticTests"][0]["expectedOutputs"].update(sum=False),
            lambda m: m["engineConnections"][0].update(required=1),
            lambda m: m["constraints"][0].update(value=1),
            lambda m: m.update(constraints=[{"kind": "maxArrayLength", "value": True}]),
            lambda m: m.update(purpose="x" * 4097),
            lambda m: m.update(syntheticTests=[m["syntheticTests"][0]] * 65),
            lambda m: m.update(constraints=[{"kind": "unknown", "value": {}}]),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                value = manifest()
                mutation(value)
                result = self.node.droppoint_module_test(value)
                self.assertFalse(result["valid"])
                self.assertNotIn("declarationSha512", result)
                self.assertFalse(result["liveAdmission"])

    def test_limits_and_no_recursion_or_execution(self):
        nested = "private payload"
        for _ in range(14):
            nested = [nested]
        values = [nested, {"x": object()}, {"x": "\ud800"}, {"x": "x" * MAX_BODY}]
        for value in values:
            self.assertFalse(self.node.droppoint_module_validate(value)["valid"])
        value = manifest()
        value["constraints"] = [{"kind": "unknown", "value": "x" * 4096} for _ in range(20)]
        self.assertFalse(self.node.droppoint_module_validate(value)["valid"])
        cyclic = []
        cyclic.append(cyclic)
        self.assertFalse(self.node.droppoint_module_validate(cyclic)["valid"])
        value = manifest()
        value["engineConnections"][0]["interface"] = "__import__('os').system('anything')"
        self.assertEqual(self.node.droppoint_module_test(value)["connections"][0]["status"], "unresolved")
        value = manifest()
        value["syntheticTests"][0]["inputs"] = {"a": 1e308, "b": 1e308}
        value["syntheticTests"][0]["expectedOutputs"] = {"sum": 0}
        self.assertEqual(self.node.droppoint_module_test(value)["syntheticReceipt"]["status"], "failed")

    def test_integer_boolean_distinction(self):
        value = manifest()
        value["engineConnections"][0]["inputs"][0]["type"] = "integer"
        value["syntheticTests"][0]["inputs"]["a"] = 2.0
        self.assertFalse(self.node.droppoint_module_validate(value)["valid"])

    def test_registered_tools_rate_limit_trusted_context(self):
        class Host:
            def __init__(self):
                self.functions = {"legacy": object(), "droppoint_gate_status": object()}
                self.descriptions = {}

            def tool_names(self):
                return tuple(self.functions)

            def tool(self, *, name, description):
                def register(function):
                    if name in self.functions:
                        raise AssertionError("Unexpected duplicate")
                    self.functions[name] = function
                    self.descriptions[name] = description
                    return function
                return register
        host = Host()
        existing = dict(host.functions)
        identity = ["trusted-a"]
        node = PublicModuleNode(RateLimiter(client_limit=1), lambda: identity[0])
        tools = register_module_tools(host, node)
        self.assertEqual(len(tools), 3)
        self.assertEqual(set(host.functions), {
            "legacy", "droppoint_gate_status", "droppoint_module_validate",
            "droppoint_module_test", "droppoint_module_connections"})
        self.assertTrue(all(host.functions[name] is function for name, function in existing.items()))
        self.assertTrue(all(host.descriptions.values()))
        host.functions["droppoint_module_validate"](manifest())
        with self.assertRaises(PublicNodeError):
            host.functions["droppoint_module_test"](manifest())
        identity[0] = "trusted-b"
        self.assertTrue(host.functions["droppoint_module_validate"](manifest())["valid"])
        with self.assertRaises(TypeError):
            host.functions["droppoint_module_validate"](manifest(), client_id="arbitrary")

    def test_registration_preflights_every_collision(self):
        class Host:
            def __init__(self, collision):
                self.names = {"legacy", collision}
                self.registrations = []

            def tool_names(self):
                return self.names

            def tool(self, **kwargs):
                self.registrations.append(kwargs)
                return lambda function: function
        for name in ("droppoint_module_validate", "droppoint_module_test", "droppoint_module_connections"):
            host = Host(name)
            with self.assertRaises(PublicNodeError):
                register_module_tools(host, self.node)
            self.assertEqual(host.registrations, [])

    def test_registration_without_inspection_fails_closed(self):
        class Host:
            def tool(self, **kwargs):
                raise AssertionError("Must not register without inspecting")
        with self.assertRaises(PublicNodeError):
            register_module_tools(Host(), self.node)

    def test_default_registered_identity_is_rate_limited(self):
        node = PublicModuleNode(RateLimiter(client_limit=1))
        node.droppoint_module_validate(manifest())
        with self.assertRaises(PublicNodeError):
            node.droppoint_module_connections(manifest())

    def test_rolling_limits_and_bounded_bookkeeping(self):
        now = [100.0]
        limiter = RateLimiter(client_limit=2, global_limit=3, clock=lambda: now[0])
        self.assertTrue(limiter.allow("a"))
        self.assertTrue(limiter.allow("a"))
        self.assertFalse(limiter.allow("a"))
        self.assertTrue(limiter.allow("b"))
        for i in range(1000):
            self.assertFalse(limiter.allow(str(i)))
        self.assertEqual(len(limiter.clients), 2)
        now[0] += 60
        self.assertTrue(limiter.allow("new"))
        self.assertEqual(set(limiter.clients), {"new"})
        self.assertEqual(len(limiter.global_events), 1)

    def test_schema_file_is_valid_json_and_matches_example(self):
        schema = json.loads(Path("invariantgatewriter/module_manifest.schema.json").read_text())
        self.assertEqual(schema["properties"]["schema"]["const"], "module-manifest/1")
        self.assertEqual(set(schema["required"]), set(manifest()))
        self.assertFalse(schema["additionalProperties"])
        for property_name in ("moduleId", "version"):
            expression = schema["properties"][property_name]["pattern"]
            valid = manifest()[property_name]
            self.assertIsNotNone(re.search(expression, valid))
            self.assertIsNone(re.search(expression, valid + "\n"))

    def test_no_live_writer_or_storage_is_initialized(self):
        with patch("invariantgatewriter.writer.GateWriter", side_effect=AssertionError("live writer")), \
                patch("invariantgatewriter.writer.SQLiteStore", side_effect=AssertionError("live store")):
            node = PublicModuleNode()
            self.assertTrue(node.droppoint_module_test(manifest())["valid"])
            server = create_server(port=0, node=node)
            server.server_close()

    def test_cli_passes_explicit_transport_settings(self):
        arguments = [
            "public_node", "--host", "127.0.0.1", "--port", "8080",
            "--allowed-host", "public.example", "--allowed-host", "other.example",
            "--allowed-origin", "https://public.example", "--max-connections", "16",
        ]
        with patch("sys.argv", arguments), patch("invariantgatewriter.public_node.create_server") as factory:
            factory.return_value.serve_forever.side_effect = KeyboardInterrupt
            main()
            factory.assert_called_once_with(
                "127.0.0.1", 8080, allowed_hosts=["public.example", "other.example"],
                allowed_origins=["https://public.example"], max_connections=16)
            factory.return_value.server_close.assert_called_once()


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.node = PublicModuleNode()
        self.server = create_server(port=0, node=self.node)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def request(self, path, value=None, method="POST", headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            body = None if value is None else json.dumps(value).encode()
            connection.request(method, path, body, headers or {"Content-Type": "application/json"})
            response = connection.getresponse()
            raw = response.read()
            content_type = response.getheader("Content-Type")
            parsed = json.loads(raw) if raw and content_type == "application/json" else raw.decode()
            return response.status, dict(response.getheaders()), parsed
        finally:
            connection.close()

    def rpc(self, method, params=None, request_id=1):
        value = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            value["params"] = params
        return self.request("/mcp", value)

    def test_browser_and_api_no_retention(self):
        status, headers, page = self.request("/", method="GET")
        self.assertEqual(status, 200)
        self.assertIn("textContent", page)
        self.assertNotIn("innerHTML", page)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertNotIn("Access-Control-Allow-Origin", headers)
        for action in ("validate", "test", "connections"):
            status, _, result = self.request("/api/" + action, manifest())
            self.assertEqual(status, 200)
            self.assertTrue(result["valid"])
            self.assertFalse(result["liveAdmission"])
        self.assertEqual(set(self.node.__dict__), {"limiter", "client_identity"})
        self.assertEqual(set(self.node.limiter.clients), {"127.0.0.1"})

    def test_mcp_flow(self):
        for version in ("2024-11-05", "2025-03-26", "2025-06-18", "future"):
            status, _, reply = self.rpc("initialize", {
                "protocolVersion": version, "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}})
            self.assertEqual(status, 200)
            self.assertEqual(reply["result"]["protocolVersion"], version if version != "future" else "2025-06-18")
        status, _, reply = self.request("/mcp", {"jsonrpc": "2.0", "method": "notifications/initialized"})
        self.assertEqual(status, 202)
        self.assertEqual(reply, "")
        self.assertEqual(self.rpc("ping")[2]["result"], {})
        tools = self.rpc("tools/list")[2]["result"]["tools"]
        self.assertEqual(len(tools), 3)
        self.assertTrue(all(tool["name"].startswith("droppoint_module_") for tool in tools))
        reply = self.rpc("tools/call", {"name": "droppoint_module_test", "arguments": {"manifest": manifest()}})[2]
        result = reply["result"]
        self.assertEqual(json.loads(result["content"][0]["text"]), result["structuredContent"])
        self.assertFalse(result["isError"])
        self.assertEqual(result["structuredContent"]["syntheticReceipt"]["status"], "passed")
        invalid = self.rpc("tools/call", {"name": "droppoint_module_test", "arguments": {"manifest": {}}})[2]
        self.assertTrue(invalid["result"]["isError"])

    def test_v2_rest_mcp_and_advertised_local_schema_references(self):
        value = manifest_v2()
        for action in ("validate", "connections", "test"):
            status, _, result = self.request("/api/" + action, value)
            self.assertEqual(status, 200)
            self.assertTrue(result["valid"])
            self.assertEqual(result["status"], "complete" if action == "test" else "pending")
        reply = self.rpc("tools/call", {
            "name": "droppoint_module_test", "arguments": {"manifest": value}})[2]["result"]
        self.assertEqual(reply["structuredContent"]["status"], "complete")
        self.assertFalse(reply["structuredContent"]["liveAdmission"])
        for tool in self.rpc("tools/list")[2]["result"]["tools"]:
            schema = tool["inputSchema"]
            self.assertEqual(set(schema["$defs"]), {"v1", "v2"})
            self.assertEqual(schema["$defs"]["v2"]["properties"]["schema"]["const"], "module-manifest/2")

            def check_refs(item):
                if type(item) is dict:
                    if "$ref" in item:
                        target = schema
                        for component in item["$ref"].removeprefix("#/").split("/"):
                            target = target[component]
                    for child in item.values():
                        check_refs(child)
                elif type(item) is list:
                    for child in item:
                        check_refs(child)
            check_refs(schema)

    def test_zip_assets_are_whitelisted_with_module_csp_and_no_store(self):
        self.assertIn('href="/zip"', self.request("/", method="GET")[2])
        for path, mime in (("/zip", "text/html"), ("/zip_intake.mjs", "text/javascript")):
            status, headers, text = self.request(path, method="GET")
            self.assertEqual(status, 200)
            self.assertTrue(headers["Content-Type"].startswith(mime))
            self.assertEqual(headers["Cache-Control"], "no-store")
            self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
            policy = headers["Content-Security-Policy"]
            self.assertIn("script-src 'self' 'sha256-", policy)
            self.assertNotIn("unsafe-inline", policy)
            self.assertIn("connect-src 'self'", policy)
            if path == "/zip":
                code = re.search(r'<script type="module">(.*?)</script>', text, re.DOTALL)[1]
                hashed = base64.b64encode(hashlib.sha256(code.encode()).digest()).decode()
                self.assertIn("'sha256-" + hashed + "'", policy)
                self.assertIn('from "/zip_intake.mjs"', text)
        for path in ("/zip?upload=x", "/zip_node.html", "/topology.py", "/module_manifest_v2.schema.json",
                     "/../README.md", "/%2e%2e/README.md", "/zip_intake.mjs/../README.md"):
            self.assertEqual(self.request(path, method="GET")[0], 404)
        self.assertEqual(self.request("/api/write", {}, method="POST")[0], 404)

    def test_zip_assets_preserve_host_origin_credentials_and_rate_checks(self):
        for path in ("/zip", "/zip_intake.mjs"):
            for headers, expected in (({"Host": "rebinding.example"}, 403),
                                      ({"Origin": "https://untrusted.example"}, 403),
                                      ({"Authorization": "private-credential"}, 400),
                                      ({"Cookie": "private-credential"}, 400)):
                status, _, result = self.request(path, method="GET", headers=headers)
                self.assertEqual(status, expected)
                self.assertNotIn("private-credential", json.dumps(result))
        self.node.limiter.client_limit = 1
        self.assertEqual(self.request("/zip", method="GET")[0], 429)

    def test_mcp_rejects_live_tools_and_extra_arguments(self):
        for params in [
            {"name": "tap_gate_submit", "arguments": {}},
            {"name": "droppoint_module_test", "arguments": {"manifest": manifest(), "client_id": "fake"}},
            {"name": [], "arguments": {}},
        ]:
            self.assertEqual(self.rpc("tools/call", params)[2]["error"]["code"], -32602)
        self.assertEqual(self.rpc("initialize", {})[2]["error"]["code"], -32602)
        self.assertEqual(self.rpc("unknown")[2]["error"]["code"], -32601)
        self.assertEqual(self.request("/mcp", [1, 2])[2]["error"]["code"], -32600)
        self.assertEqual(self.request("/mcp", {"jsonrpc": "2.0", "method": "ping", "id": True})[2]["error"]["code"], -32600)

    def raw_request(self, request):
        request = request.replace(b"Host: localhost\r\n",
                                  f"Host: localhost:{self.port}\r\n".encode())
        with socket.create_connection(("127.0.0.1", self.port), timeout=3) as connection:
            connection.sendall(request)
            try:
                connection.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            chunks = []
            while True:
                data = connection.recv(65536)
                if not data:
                    break
                chunks.append(data)
        return b"".join(chunks)

    def test_body_limits_before_read_and_header_rejections(self):
        prefix = b"POST /api/validate HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n"
        for headers, expected in [
            (b"Content-Length: 65537\r\n", 413),
            (b"Content-Length: -1\r\n", 400),
            (b"Content-Length: abc\r\n", 400),
            (b"", 400),
            (b"Content-Length: 2\r\nContent-Length: 2\r\n", 400),
            (b"Transfer-Encoding: chunked\r\nContent-Length: 2\r\n", 400),
            (b"Content-Length: " + b"9" * 100 + b"\r\n", 413),
        ]:
            with self.subTest(headers=headers):
                response = self.raw_request(prefix + headers + b"\r\n")
                self.assertIn(f" {expected} ".encode(), response.split(b"\r\n", 1)[0])
        status, _, _ = self.request("/api/test", manifest(), headers={"Content-Type": "text/plain"})
        self.assertEqual(status, 415)
        status, _, _ = self.request("/api/test", manifest(), headers={
            "Content-Type": "application/json", "Origin": "https://untrusted.example"})
        self.assertEqual(status, 403)

    def test_credentials_are_rejected_and_browser_never_sends_them(self):
        page = self.request("/", method="GET")[2]
        self.assertIn('credentials: "omit"', page)
        for name in ("Authorization", "Proxy-Authorization", "Cookie"):
            with self.subTest(name=name):
                headers = {"Content-Type": "application/json", name: "private credential"}
                status, _, result = self.request("/api/test", manifest(), headers=headers)
                self.assertEqual(status, 400)
                self.assertNotIn("private credential", json.dumps(result))
                self.assertEqual(self.request("/", method="GET", headers=headers)[0], 400)

    def test_host_and_origin_prevent_rebinding(self):
        valid_host = f"127.0.0.1:{self.port}"
        self.assertEqual(self.request("/api/test", manifest(), headers={
            "Content-Type": "application/json", "Origin": "http://" + valid_host})[0], 200)
        for path, value, method in (("/", None, "GET"), ("/api/test", manifest(), "POST"),
                                    ("/mcp", {"jsonrpc": "2.0", "method": "ping", "id": 1}, "POST")):
            for headers in ({"Host": "rebinding.example"},
                            {"Origin": "http://rebinding.example"},
                            {"Host": "rebinding.example", "Origin": "http://rebinding.example"},
                            {"Origin": "null"}):
                headers["Content-Type"] = "application/json"
                self.assertEqual(self.request(path, value, method, headers)[0], 403)
        status, headers, _ = self.request("/", method="GET")
        self.assertEqual(status, 200)
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertNotIn("unsafe-inline", headers["Content-Security-Policy"])
        self.assertIn("sha256-", headers["Content-Security-Policy"])

    def test_mcp_protocol_header_versions(self):
        request = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
        headers = {"Content-Type": "application/json", "MCP-Protocol-Version": "unsupported"}
        self.assertEqual(self.request("/mcp", request, headers=headers)[0], 400)
        headers["MCP-Protocol-Version"] = "2025-06-18"
        self.assertEqual(self.request("/mcp", request, headers=headers)[0], 200)

    def test_configurable_allowlists_and_connection_budget(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.server = create_server(
            port=0, node=self.node, allowed_hosts={"public.example"},
            allowed_origins={"https://public.example"}, max_connections=2)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]
        headers = {"Host": "public.example", "Origin": "https://public.example",
                   "Content-Type": "application/json"}
        self.assertEqual(self.request("/api/test", manifest(), headers=headers)[0], 200)
        self.assertEqual(self.request("/api/test", manifest())[0], 403)
        held = []
        try:
            for _ in range(2):
                connection = socket.create_connection(("127.0.0.1", self.port), timeout=3)
                held.append(connection)
                connection.sendall(b"GET / HTTP/1.1\r\nHost: public.example\r\n")
            deadline = time.monotonic() + 2
            while self.server.connection_slots._value and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual(self.server.connection_slots._value, 0)
            response = self.raw_request(b"GET / HTTP/1.1\r\nHost: public.example\r\n\r\n")
            self.assertIn(b" 503 ", response.split(b"\r\n", 1)[0])
        finally:
            for connection in held:
                connection.close()
        deadline = time.monotonic() + 2
        while self.server.connection_slots._value != 2 and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(self.server.connection_slots._value, 2)
        self.assertEqual(self.request("/", method="GET", headers=headers)[0], 200)

    def test_malformed_duplicate_nonfinite_sanitized(self):
        for body in (b'{"secret":', b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}', b"\xff"):
            response = self.raw_request(
                b"POST /api/test HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: "
                + str(len(body)).encode() + b"\r\n\r\n" + body)
            self.assertIn(b" 400 ", response.split(b"\r\n", 1)[0])
            self.assertNotIn(b"secret", response)
        status, _, result = self.request("/api/test", {"private": "not echoed"})
        self.assertEqual(status, 200)
        self.assertNotIn("not echoed", json.dumps(result))

    def test_rate_limits_cover_get_api_and_mcp_ignore_xff(self):
        self.node.limiter = RateLimiter(client_limit=3)
        self.assertEqual(self.request("/", method="GET")[0], 200)
        self.assertEqual(self.request("/api/test", manifest())[0], 200)
        self.assertEqual(self.rpc("ping")[0], 200)
        status, headers, _ = self.request("/", method="GET", headers={"X-Forwarded-For": "different-client"})
        self.assertEqual(status, 429)
        self.assertEqual(headers["Retry-After"], "60")
        self.assertEqual(self.rpc("ping")[0], 429)
        self.assertEqual(self.request("/api/test", manifest())[0], 429)
        self.assertEqual(len(self.node.limiter.clients), 1)

    def test_global_budget_with_trusted_identity_callback(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        counter = [0]

        def trusted_identity(handler):
            counter[0] += 1
            return "trusted-" + str(counter[0])
        self.node.limiter = RateLimiter(client_limit=60, global_limit=2)
        self.server = create_server(port=0, node=self.node, source_identity=trusted_identity)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]
        self.assertEqual(self.request("/", method="GET")[0], 200)
        self.assertEqual(self.request("/", method="GET")[0], 200)
        self.assertEqual(self.request("/", method="GET")[0], 429)
        self.assertEqual(len(self.node.limiter.clients), 2)


if __name__ == "__main__":
    unittest.main()
