import copy
import hashlib
import json
import math
import unittest
from pathlib import Path

from invariantgatewriter.public_node import PublicModuleNode, PublicNodeError
from invariantgatewriter.topology import (
    EXTRA_FIELDS, MAPPING_VERSION, SAFE_INTEGER, assess_declaration,
    builtin_engine_catalog, declaration_topology, validate_declaration,
)


def manifest():
    inputs = [{"name": "a", "type": "number"}, {"name": "b", "type": "number"}]
    outputs = [{"name": "sum", "type": "number"}]
    return {
        "schema": "module-manifest/2", "moduleId": "example.add", "version": "1.0.0",
        "purpose": "Local synthetic addition ☀", "inputs": inputs, "outputs": outputs,
        "constraints": [],
        "engineConnections": [{"name": "add", "interface": "numbers.add/1",
                               "required": True, "inputs": copy.deepcopy(inputs),
                               "outputs": copy.deepcopy(outputs)}],
        "syntheticTests": [{"name": "basic", "connection": "add",
                            "inputs": {"a": 2, "b": 3}, "expectedOutputs": {"sum": 5}}],
        "dependencies": [], "proposedPlacements": ["numbers", "local-sandbox"],
        "evidence": [{"reference": "module.json", "method": "explicit-declaration"}],
        "extractionMethod": "explicit-declaration", "unresolvedQuestions": [],
    }


def receipt(value):
    base = {key: item for key, item in value.items() if key not in EXTRA_FIELDS}
    base["schema"] = "module-manifest/1"
    result = PublicModuleNode().droppoint_module_test(base)["syntheticReceipt"]
    result["declarationSha512"] = validate_declaration(value)
    return result


def assess(value, tested=False, **kwargs):
    return assess_declaration(value, validate_declaration(value),
                              test_receipt=receipt(value) if tested else None, **kwargs)


class TopologyTests(unittest.TestCase):
    def test_canonical_full_v2_hash_and_no_mutation(self):
        value = manifest()
        original = copy.deepcopy(value)
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertEqual(validate_declaration(value), hashlib.sha512(encoded).hexdigest())
        self.assertEqual(value, original)
        digest = validate_declaration(value)
        for field in ("evidence", "proposedPlacements", "dependencies", "unresolvedQuestions"):
            changed = copy.deepcopy(value)
            changed[field] = []
            if changed[field] == value[field]:
                changed[field] = ([{"moduleId": "dep", "version": "^1.0.0"}]
                                  if field == "dependencies" else ["question"])
            self.assertNotEqual(validate_declaration(changed), digest)

    def test_model_extremes_and_digest_byte_order(self):
        for first, second in [(0, 0), (65535, 65535), (0, 65535), (65535, 0), (258, 772)]:
            digest = first.to_bytes(2, "big").hex() + second.to_bytes(2, "big").hex() + "00" * 60
            result = declaration_topology(digest)
            self.assertEqual(result["mappingVersion"], MAPPING_VERSION)
            self.assertEqual(result["alpha"], first / 65535)
            self.assertEqual(result["beta"], second / 65535)
            self.assertEqual(result["vertex"], [0, 0])
            self.assertEqual(result["orientation"], "upward")
            for suffix in ("A", "B"):
                coefficient = result["a" if suffix == "A" else "b"]
                focus = result["focus" + suffix]
                self.assertEqual(focus, [0, 1 / (4 * coefficient)])
                self.assertEqual(result["directrix" + suffix], -focus[1])
            bound = result["sandbox"]["xMax"]
            self.assertEqual(result["sandbox"]["xMin"], -bound)
            self.assertAlmostEqual(max(result["a"], result["b"]) * bound**2, 1)
            self.assertEqual(result["intersection"], "coincident" if first == second else "common-vertex")
            self.assertIsNone(result["completionPoint"])
            self.assertEqual(declaration_topology(digest, complete=True)["completionPoint"], [0, 0])

    def test_fingerprint_stability(self):
        result = declaration_topology("01234567" + "ab" * 60)
        self.assertEqual(result["alpha"], 291 / 65535)
        self.assertEqual(result["beta"], 17767 / 65535)
        self.assertEqual(result, declaration_topology("01234567" + "ab" * 60))
        self.assertAlmostEqual(result["sandbox"]["xMax"], math.sqrt(1 / result["b"]))

    def test_invalid_digest_sanitized(self):
        for digest in ("bad", "A" * 128, "", None):
            with self.assertRaisesRegex(PublicNodeError, "Invalid declaration digest"):
                declaration_topology(digest)
        with self.assertRaisesRegex(PublicNodeError, "Declaration digest mismatch"):
            assess_declaration(manifest(), "0" * 128)

    def test_two_rings_are_distinct_and_hash_does_not_complete(self):
        value = manifest()
        result = assess(value)
        self.assertEqual(result["identityRing"]["moduleId"], value["moduleId"])
        self.assertEqual(result["identityRing"]["declarationSha512"], validate_declaration(value))
        self.assertEqual(result["placementRing"]["proposed"], value["proposedPlacements"])
        self.assertEqual(result["status"], "pending")
        self.assertIsNone(result["topology"]["completionPoint"])
        self.assertFalse(result["liveAdmission"])
        self.assertIn("local synthetic", result["completionScope"])

    def test_completion_needs_backend_tests_and_explicit_declaration(self):
        value = manifest()
        self.assertEqual(assess(value, tested=True)["status"], "complete")
        self.assertEqual(assess(value, tested=True)["topology"]["completionPoint"], [0, 0])
        for method in ("package-boundary", "static-interface"):
            value["extractionMethod"] = method
            self.assertEqual(assess(value, tested=True)["status"], "pending")
        value["extractionMethod"] = "explicit-declaration"
        value["unresolvedQuestions"] = ["What is the deployment boundary?"]
        self.assertEqual(assess(value, tested=True)["status"], "pending")

    def test_receipts_must_match_and_prove_execution(self):
        value = manifest()
        digest = validate_declaration(value)
        for field, invalid in [("declarationSha512", "0" * 128), ("synthetic", False),
                               ("liveAdmission", True), ("tests", []),
                               ("scope", {"execution": "not_run"})]:
            proof = receipt(value)
            proof[field] = invalid
            result = assess_declaration(value, digest, test_receipt=proof)
            self.assertEqual(result["status"], "pending")
        value["syntheticTests"] = []
        self.assertEqual(assess(value, tested=True)["status"], "pending")
        value = manifest()
        value["syntheticTests"][0]["expectedOutputs"]["sum"] = 7
        self.assertEqual(assess(value, tested=True)["status"], "incompatible")

    def test_required_interfaces_narrow_engine_choices(self):
        value = manifest()
        value["proposedPlacements"] = ["numbers", "text", "identity", "boolean", "local-sandbox"]
        result = assess(value)
        self.assertEqual(result["placementRing"]["feasible"], ["local-sandbox", "numbers"])
        checks = [item for item in result["evidence"] if item["kind"] == "interface"]
        self.assertEqual(checks[0]["before"], sorted(value["proposedPlacements"]))
        self.assertEqual(checks[0]["after"], ["local-sandbox", "numbers"])
        for item in result["evidence"]:
            self.assertLessEqual(set(item["after"]), set(item["before"]))
            self.assertIn("reason", item)
            self.assertIn("evidence", item)

    def test_unknown_placements_empty_proposals_and_unknown_interfaces(self):
        value = manifest()
        value["proposedPlacements"] = ["remote-engine"]
        self.assertEqual(assess(value)["status"], "incompatible")
        value["proposedPlacements"] = ["remote-engine", "numbers"]
        result = assess(value, tested=True)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["placementRing"]["feasible"], ["numbers"])
        self.assertEqual(result["evidence"][0]["before"], ["numbers", "remote-engine"])
        self.assertEqual(result["evidence"][0]["after"], ["numbers"])
        value["proposedPlacements"] = []
        result = assess(value, tested=True)
        self.assertEqual(result["status"], "pending")
        self.assertEqual(result["placementRing"]["feasible"], ["local-sandbox", "numbers"])
        for required in (True, False):
            value["engineConnections"][0]["interface"] = "future/1"
            value["engineConnections"][0]["required"] = required
            self.assertEqual(assess(value)["status"], "pending")
        self.assertEqual(assess(manifest(), engine_catalog={})["status"], "incompatible")

    def test_multiple_required_interfaces_intersect_engine_candidates(self):
        value = manifest()
        value["engineConnections"].append({
            "name": "not", "interface": "boolean.not/1", "required": True,
            "inputs": [{"name": "value", "type": "boolean"}],
            "outputs": [{"name": "value", "type": "boolean"}],
        })
        value["syntheticTests"].append({
            "name": "negate", "connection": "not",
            "inputs": {"value": True}, "expectedOutputs": {"value": False},
        })
        self.assertEqual(assess(value, tested=True)["placementRing"]["feasible"], ["local-sandbox"])
        value["proposedPlacements"] = ["numbers", "boolean"]
        self.assertEqual(assess(value, tested=True)["status"], "incompatible")

    def test_port_mismatch_is_incompatible_not_hash_based(self):
        value = manifest()
        value["engineConnections"][0]["inputs"][0]["type"] = "integer"
        result = assess(value)
        self.assertEqual(result["status"], "incompatible")
        self.assertEqual(result["placementRing"]["feasible"], [])
        self.assertEqual(len(result["identityRing"]["declarationSha512"]), 128)

    def test_include_exclude_constraints(self):
        value = manifest()
        value["constraints"] = [{"kind": "includeEngine", "value": "numbers"}]
        result = assess(value)
        self.assertEqual(result["placementRing"]["feasible"], ["numbers"])
        value["constraints"].append({"kind": "excludeEngine", "value": "numbers"})
        self.assertEqual(assess(value)["status"], "incompatible")
        value["constraints"] = [{"kind": "excludeEngine", "value": "local-sandbox"}]
        self.assertEqual(assess(value)["placementRing"]["feasible"], ["numbers"])
        value["constraints"] = [{"kind": "includeEngine", "value": "unknown"}]
        self.assertEqual(assess(value)["status"], "incompatible")

    def test_structural_constraints_and_partial_resolution(self):
        value = manifest()
        value["constraints"] = [{"kind": "nonNegativeNumbers", "value": True},
                                {"kind": "futureProof", "value": "unverified"}]
        result = assess(value)
        self.assertEqual(result["status"], "pending")
        self.assertEqual(result["placementRing"]["feasible"], ["local-sandbox", "numbers"])
        value["constraints"] = [{"kind": "maxArrayLength", "value": 1}]
        self.assertEqual(assess(value)["status"], "incompatible")
        value["constraints"] = [{"kind": "maxStringLength", "value": 10}]
        self.assertEqual(assess(value)["status"], "pending")
        value["constraints"] = [{"kind": "nonNegativeNumbers", "value": True}]
        value["syntheticTests"][0]["inputs"]["a"] = -2
        self.assertEqual(assess(value)["status"], "incompatible")

    def test_dependency_config_never_client_claims(self):
        value = manifest()
        value["dependencies"] = [{"moduleId": "@scope/pkg", "version": "1.2.3"}]
        self.assertEqual(assess(value, tested=True)["status"], "pending")
        self.assertEqual(assess(value, tested=True,
                                available_dependencies={"@scope/pkg": "1.2.3"})["status"], "complete")
        self.assertEqual(assess(value, tested=True,
                                available_dependencies={"@scope/pkg": "1.2.4"})["status"], "incompatible")
        value["dependencies"][0]["version"] = "^1.2.3"
        self.assertEqual(assess(value, tested=True,
                                available_dependencies={"@scope/pkg": "1.2.3"})["status"], "pending")
        value["dependencies"][0]["version"] = "1.2.3-beta.1+build.2"
        self.assertEqual(assess(value, tested=True,
                                available_dependencies={"@scope/pkg": "1.2.3-beta.1+build.2"})["status"], "complete")
        for version in ("01.2.3", "1.2", "*", "~1.2.3", "1.2.3-01"):
            value["dependencies"][0]["version"] = version
            self.assertEqual(assess(value, tested=True,
                                    available_dependencies={"@scope/pkg": version})["status"], "pending")

    def test_multiple_candidates_independent(self):
        first, second = manifest(), manifest()
        second["moduleId"] = "other.module"
        second["proposedPlacements"] = ["text"]
        first_result = assess(first, tested=True)
        second_result = assess(second, tested=True)
        self.assertEqual(first_result["status"], "complete")
        self.assertEqual(second_result["status"], "incompatible")
        self.assertNotEqual(first_result["identityRing"], second_result["identityRing"])
        self.assertEqual(assess(first, tested=True), first_result)


class V2ValidationTests(unittest.TestCase):
    def test_safe_integer_limits_and_booleans_not_integers(self):
        for number in (-SAFE_INTEGER, SAFE_INTEGER):
            value = manifest()
            value["syntheticTests"][0]["inputs"]["a"] = number
            validate_declaration(value)
        for number in (SAFE_INTEGER + 1, -SAFE_INTEGER - 1, 1.0, 0.5, float("inf")):
            value = manifest()
            value["syntheticTests"][0]["inputs"]["a"] = number
            with self.assertRaises(PublicNodeError):
                validate_declaration(value)
        value = manifest()
        value["syntheticTests"][0]["inputs"]["a"] = True
        with self.assertRaisesRegex(PublicNodeError, "Test port types"):
            validate_declaration(value)

    def test_unsafe_unicode_and_nonascii_keys(self):
        for character in ("\x00", "\n", "\u200b", "\u202e", "\ud800", "\U000e0001"):
            value = manifest()
            value["purpose"] += character
            with self.assertRaises(PublicNodeError):
                validate_declaration(value)
        value = manifest()
        value["syntheticTests"][0]["inputs"]["☀"] = 2
        with self.assertRaisesRegex(PublicNodeError, "Invalid object field"):
            validate_declaration(value)
        value = manifest()
        value["purpose"] += " 日本語 😀"
        validate_declaration(value)

    def test_evidence_is_safe_metadata_only(self):
        for path in ("/etc/passwd", "../module.json", "a/../module.json", "a//b", "./module.json",
                     "C:\\file", "https://host/file", ".env", "src/.env.local", ".git/config",
                     ".ssh/config", ".aws/config", "credentials.json", "secrets.txt",
                     "key.pem", "x%2fy"):
            value = manifest()
            value["evidence"][0]["reference"] = path
            with self.assertRaisesRegex(PublicNodeError, "Unsafe evidence reference"):
                validate_declaration(value)
        value = manifest()
        value["evidence"][0]["reference"] = "nested/package.json"
        validate_declaration(value)

    def test_v2_exact_fields_and_metadata_limits(self):
        value = manifest()
        value["availableDependencies"] = {}
        with self.assertRaisesRegex(PublicNodeError, "Invalid object fields"):
            validate_declaration(value)
        value = manifest()
        value["proposedPlacements"] *= 2
        with self.assertRaisesRegex(PublicNodeError, "Duplicate proposed"):
            validate_declaration(value)
        value = manifest()
        value["dependencies"] = [{"moduleId": "../bad", "version": "1.0.0"}]
        with self.assertRaises(PublicNodeError):
            validate_declaration(value)
        value = manifest()
        value["dependencies"] = [{"moduleId": "dep", "version": "1.0.0"}] * 2
        with self.assertRaisesRegex(PublicNodeError, "Duplicate dependency"):
            validate_declaration(value)
        value = manifest()
        value["unresolvedQuestions"] = ["a"] * 33
        with self.assertRaises(PublicNodeError):
            validate_declaration(value)

    def test_schema_is_json_and_exact_fields(self):
        path = Path(__file__).resolve().parents[1] / "invariantgatewriter/module_manifest_v2.schema.json"
        schema = json.loads(path.read_text())
        self.assertEqual(schema["properties"]["schema"]["const"], "module-manifest/2")
        self.assertEqual(set(schema["required"]), set(manifest()))
        self.assertEqual(schema["$defs"]["integer"]["maximum"], SAFE_INTEGER)


if __name__ == "__main__":
    unittest.main()
