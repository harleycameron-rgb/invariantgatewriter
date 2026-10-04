"""Synthetic fixtures exercise backend orchestration, not live admission."""

import hashlib
import hmac
import json
import unittest
from unittest.mock import Mock, patch

from invariantgatewriter import GateError, GateWriter, QualificationVerifier, SQLiteStore
from invariantgatewriter.qualification import submit_reviewed_modules


NOW = 1800000000
TEST_KEY = b"synthetic-review-qualification-key-never-production" * 2


def declaration(module_id="reviewed-module"):
    return {
        "schema": "module-manifest/1",
        "moduleId": module_id,
        "version": "1.0.0",
        "purpose": "Synthetic unit-test declaration; not a live admission.",
        "inputs": [{"name": "value", "type": "string"}],
        "outputs": [{"name": "value", "type": "string"}],
        "constraints": [],
        "engineConnections": [{
            "name": "echo", "interface": "identity/1", "required": True,
            "inputs": [{"name": "value", "type": "string"}],
            "outputs": [{"name": "value", "type": "string"}],
        }],
        "syntheticTests": [{
            "name": "echo-test", "connection": "echo", "inputs": {"value": "synthetic"},
            "expectedOutputs": {"value": "synthetic"},
        }],
    }


def candidate(event_id="review-event-1", module=None):
    return {"declaration": declaration() if module is None else module, "qualificationId": event_id}


def signed_test_decision(module, event_id, **changes):
    """Private unit-test signing fixture; no production signing entry point."""
    canonical = json.dumps(
        module, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False,
    ).encode()
    envelope = {
        "schema": "gate-qualification/1",
        "gateId": "invarianttap-gate-1",
        "qualificationId": event_id,
        "source": "qualified-submission",
        "accepted": True,
        "policyVersion": "review-policy-1",
        "moduleSHA512": hashlib.sha512(canonical).hexdigest(),
        "issuedAt": NOW - 1,
        "expiresAt": NOW + 100,
    }
    envelope.update(changes)
    body = json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    envelope["signature"] = hmac.new(TEST_KEY, body, hashlib.sha512).hexdigest()
    return {"status": "qualified", "qualification": envelope}


class ReviewedQualificationTests(unittest.TestCase):
    def setUp(self):
        self.store = SQLiteStore(":memory:")
        self.addCleanup(self.store.close)
        self.writer = GateWriter(
            self.store, QualificationVerifier(TEST_KEY, {"review-policy-1"}, clock=lambda: NOW),
            trusted_service_connected=True, clock=lambda: NOW,
        )
        self.context = object()
        self.authorize = Mock(return_value=True)

    def submit(self, items, qualifier=signed_test_decision, writer=None):
        return submit_reviewed_modules(
            items, self.writer if writer is None else writer, qualifier,
            self.authorize, self.context,
        )

    def assert_error(self, code, operation):
        with self.assertRaises(GateError) as caught:
            operation()
        self.assertEqual(caught.exception.code, code)

    def test_authorize_before_validation_qualifier_or_storage(self):
        qualifier = Mock(side_effect=AssertionError)
        writer = Mock()
        for allowed in [False, None, 1, "true", {}]:
            self.authorize.return_value = allowed
            with patch("invariantgatewriter.public_node._validate", side_effect=AssertionError) as validate:
                self.assert_error("unauthorized", lambda: self.submit(None, qualifier, writer))
                validate.assert_not_called()
        self.authorize.side_effect = RuntimeError(TEST_KEY.decode())
        self.assert_error("unauthorized", lambda: self.submit([candidate()], qualifier, writer))
        qualifier.assert_not_called()
        writer.write.assert_not_called()
        self.authorize.assert_called_with(self.context, "gate:write")

    def test_multiple_candidates_have_independent_outcomes(self):
        items = [
            candidate("event-1", declaration("accepted")),
            candidate("event-2", declaration("rejected")),
            candidate("event-3", declaration("pending")),
            candidate("event-4", declaration("accepted-again")),
        ]

        def qualifier(module, event_id):
            if module["moduleId"] in ("rejected", "pending"):
                return {"status": module["moduleId"], "code": "review_required"}
            return signed_test_decision(module, event_id)

        result = self.submit(items, qualifier)
        self.assertFalse(result["atomic"])
        self.assertEqual([r["status"] for r in result["results"]], ["qualified", "rejected", "pending", "qualified"])
        self.assertEqual([r["index"] for r in result["results"]], list(range(4)))
        self.assertEqual(self.writer.status()["occupiedReceipts"], 2)
        self.assertEqual(result["results"][1]["code"], "review_required")
        self.assertNotIn("declaration", json.dumps(result))

    def test_missing_service_pending_never_signs_or_writes(self):
        writer = Mock()
        result = self.submit([candidate(), candidate("event-2")], None, writer)
        writer.write.assert_not_called()
        for item in result["results"]:
            self.assertEqual(item["status"], "pending")
            self.assertEqual(item["code"], "qualification_service_unconnected")
            self.assertNotIn("receipt", item)
        self.assertEqual(self.writer.status()["occupiedReceipts"], 0)

    def test_retry_deduplicates_and_new_event_is_independent(self):
        item = candidate()
        first = self.submit([item])["results"][0]
        retry = self.submit([item])["results"][0]
        self.assertEqual(first["status"], "qualified")
        self.assertFalse(first["receipt"]["duplicate"])
        self.assertEqual(retry["receipt"], dict(first["receipt"], duplicate=True))
        self.assertEqual(self.writer.status()["occupiedReceipts"], 1)
        next_event = self.submit([candidate("review-event-2")])["results"][0]
        self.assertEqual(first["moduleSHA512"], next_event["moduleSHA512"])
        self.assertNotEqual(first["qualificationId"], next_event["qualificationId"])
        self.assertFalse(next_event["receipt"]["duplicate"])
        self.assertEqual(self.writer.status()["occupiedReceipts"], 2)

    def test_changed_snapshot_same_event_rejected(self):
        self.submit([candidate()])
        changed = declaration()
        changed["version"] = "1.0.1"
        result = self.submit([candidate(module=changed)])["results"][0]
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["code"], "qualification_id_conflict")
        self.assertEqual(self.writer.status()["occupiedReceipts"], 1)

    def test_signature_and_source_verified_by_existing_writer(self):
        def forged(module, event_id):
            decision = signed_test_decision(module, event_id)
            decision["qualification"]["signature"] = "f" * 128
            return decision

        for qualifier, code in [
            (forged, "invalid_signature"),
            (lambda module, event: signed_test_decision(module, event, source="synthetic-test"), "invalid_source"),
            (lambda module, event: signed_test_decision(module, event, expiresAt=NOW), "expired_receipt"),
            (lambda module, event: signed_test_decision(module, event, policyVersion="unknown"), "unsupported_policy"),
        ]:
            with self.subTest(code=code):
                result = self.submit([candidate()], qualifier)["results"][0]
                self.assertEqual((result["status"], result["code"]), ("rejected", code))
        self.assertEqual(self.writer.status()["occupiedReceipts"], 0)

    def test_envelope_bound_to_requested_event_and_snapshot(self):
        writer = Mock()
        cases = [
            ({"qualificationId": "another-event"}, "qualification_id_mismatch"),
            ({"moduleSHA512": "0" * 128}, "qualification_module_mismatch"),
            ({"extra": "private"}, "invalid_qualification_envelope"),
        ]
        for changes, code in cases:
            result = self.submit(
                [candidate()], lambda module, event: signed_test_decision(module, event, **changes),
                writer,
            )["results"][0]
            self.assertEqual(result["code"], code)
        writer.write.assert_not_called()

    def test_default_live_disabled_unchanged(self):
        disabled = GateWriter(self.store, self.writer._verifier)
        result = self.submit([candidate()], writer=disabled)["results"][0]
        self.assertEqual((result["status"], result["code"]), ("rejected", "live_writes_disabled"))
        self.assertFalse(disabled.status()["liveWritesEnabled"])
        self.assertEqual(disabled.status()["occupiedReceipts"], 0)

    def test_strict_candidate_fields_and_invalid_declarations(self):
        invalid_manifest = declaration()
        invalid_manifest["rawMedia"] = "private-input"
        bad_identity = declaration()
        bad_identity["moduleId"] = "personal name"
        qualifier = Mock()
        writer = Mock()
        invalid_items = [
            None, {}, {"declaration": declaration(), "qualificationId": "event", "signature": "private"},
            candidate(event_id="personal name"), candidate(module=invalid_manifest),
            candidate(module=bad_identity), candidate(module={"moduleId": "looks-valid"}),
        ]
        result = self.submit(invalid_items, qualifier, writer)
        self.assertTrue(all(item["status"] == "rejected" for item in result["results"]))
        self.assertNotIn("private", json.dumps(result))
        qualifier.assert_not_called()
        writer.write.assert_not_called()

    def test_batch_bounds_before_qualifier(self):
        qualifier = Mock()
        for items in [[], [candidate()] * 101, (), None, {}]:
            self.assert_error("invalid_batch_size", lambda: self.submit(items, qualifier))
        qualifier.assert_not_called()
        result = self.submit([candidate("event-" + str(i)) for i in range(100)], None)
        self.assertEqual(len(result["results"]), 100)
        self.assertTrue(all(r["status"] == "pending" for r in result["results"]))

    def test_qualifier_protocol_and_errors_sanitized(self):
        invalid_decisions = [
            None, [], {}, {"status": "accepted", "qualification": {}},
            {"status": "qualified", "qualification": {}, "key": TEST_KEY.decode()},
            {"status": "pending", "code": "private error with spaces"},
            {"status": "pending", "code": []},
            {"status": "pending", "code": "a" * 65},
            {"status": "rejected", "code": "policy_rejected", "extra": "private"},
        ]
        writer = Mock()
        for decision in invalid_decisions:
            result = self.submit([candidate()], lambda module, event: decision, writer)["results"][0]
            self.assertEqual(result["status"], "rejected")
            self.assertIn(result["code"], {"invalid_qualifier_response", "invalid_qualification_envelope"})
            self.assertNotIn(TEST_KEY.decode(), json.dumps(result))
        error = Mock(side_effect=RuntimeError(TEST_KEY.decode()))
        result = self.submit([candidate()], error, writer)["results"][0]
        self.assertEqual(result["code"], "qualifier_error")
        writer.write.assert_not_called()

    def test_writer_transient_error_safely_rejected_and_retryable(self):
        writer = Mock()
        writer.write.side_effect = GateError("storage_error")
        result = self.submit([candidate()], writer=writer)["results"][0]
        self.assertEqual((result["status"], result["code"]), ("rejected", "storage_error"))
        result = self.submit([candidate()])["results"][0]
        self.assertEqual(result["status"], "qualified")
        self.assertFalse(result["receipt"]["duplicate"])
        writer.write.side_effect = RuntimeError(TEST_KEY.decode())
        result = self.submit([candidate()], writer=writer)["results"][0]
        self.assertEqual(result["code"], "writer_error")
        self.assertNotIn(TEST_KEY.decode(), json.dumps(result))

    def test_qualifier_cannot_mutate_original_or_change_binding(self):
        item = candidate()
        original = json.loads(json.dumps(item))

        def mutate(module, event_id):
            module["purpose"] = "Mutated trusted qualifier input"
            return signed_test_decision(module, event_id)

        result = self.submit([item], mutate)["results"][0]
        self.assertEqual(result["code"], "qualification_module_mismatch")
        self.assertEqual(item, original)
        self.assertEqual(self.writer.status()["occupiedReceipts"], 0)

    def test_validator_late_bound_no_synthetic_admission_assumption(self):
        module = declaration()
        # A synthetically failing declaration can still be reviewed; only the
        # trusted qualifier determines policy. The helper never runs tests.
        module["syntheticTests"][0]["expectedOutputs"]["value"] = "different"
        with patch("invariantgatewriter.public_node._validate", wraps=__import__(
            "invariantgatewriter.public_node", fromlist=["_validate"],
        )._validate) as validate:
            result = self.submit([candidate(module=module)])["results"][0]
            validate.assert_called_once()
        self.assertEqual(result["status"], "qualified")

    def test_canonical_snapshot_hash_not_changed_by_key_order(self):
        original = declaration()
        reversed_keys = dict(reversed(list(original.items())))
        first = self.submit([candidate(module=original)])["results"][0]
        second = self.submit([candidate(module=reversed_keys)])["results"][0]
        self.assertEqual(first["moduleSHA512"], second["moduleSHA512"])
        self.assertTrue(second["receipt"]["duplicate"])


if __name__ == "__main__":
    unittest.main()
