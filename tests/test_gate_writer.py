import concurrent.futures
import hashlib
import hmac
import json
import pathlib
import unittest
import uuid
from unittest.mock import patch

from invariantgatewriter import (
    GateError, GateWriter, HostContext, QualificationVerifier, SQLiteStore, register_gate_tools,
)


NOW = 1800000000
TEST_KEY = b"synthetic-unit-test-key-not-a-production-secret" * 2


def qualification(event="event-1", **changes):
    body = {
        "schema": "gate-qualification/1",
        "gateId": "invarianttap-gate-1",
        "qualificationId": event,
        "source": "qualified-submission",
        "accepted": True,
        "policyVersion": "policy-1",
        "moduleSHA512": hashlib.sha512(b"synthetic-unit-test-module").hexdigest(),
        "issuedAt": NOW - 10,
        "expiresAt": NOW + 100,
    }
    body.update(changes)
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    body["signature"] = hmac.new(TEST_KEY, canonical, hashlib.sha512).hexdigest()
    return body


class WriterTests(unittest.TestCase):
    def setUp(self):
        self.store = SQLiteStore(":memory:")
        self.addCleanup(self.store.close)
        self.verifier = QualificationVerifier(TEST_KEY, {"policy-1"}, clock=lambda: NOW)
        self.writer = GateWriter(
            self.store, self.verifier, trusted_service_connected=True, clock=lambda: NOW,
        )

    def assert_error(self, code, operation, *args):
        with self.assertRaises(GateError) as caught:
            operation(*args)
        self.assertEqual(caught.exception.code, code)

    def test_write_lookup_retry_and_conflict(self):
        envelope = qualification()
        first = self.writer.write(envelope)
        self.assertEqual(first["layer"], 0)
        self.assertEqual(first["writtenAt"], NOW)
        self.assertFalse(first["duplicate"])
        self.assertEqual(self.writer.lookup("event-1")["receipt"], first)
        self.assertEqual(self.writer.write(envelope), dict(first, duplicate=True))
        self.assertEqual(self.writer.status()["occupiedReceipts"], 1)
        self.assert_error(
            "qualification_id_conflict", self.writer.write,
            qualification(moduleSHA512="f" * 128),
        )
        self.assertEqual(self.writer.status()["occupiedReceipts"], 1)

    def test_canonical_hash_coordinate_and_signature_not_hashed(self):
        envelope = qualification()
        body = {key: value for key, value in envelope.items() if key != "signature"}
        digest = hashlib.sha512(json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode()).digest()
        result = self.writer.dry_run(dict(reversed(list(envelope.items()))))
        self.assertEqual(result["receiptSHA512"], digest.hex())
        self.assertEqual(result["x"], int.from_bytes(digest[:2], "big") % 2048)
        self.assertEqual(result["y"], int.from_bytes(digest[2:4], "big") % 2048)

    def test_dry_run_does_not_access_database(self):
        disabled = GateWriter(self.store, self.verifier)
        with patch.object(self.store, "write", side_effect=AssertionError), \
                patch.object(self.store, "counts", side_effect=AssertionError), \
                patch.object(self.store, "lookup", side_effect=AssertionError):
            result = disabled.dry_run(qualification())
        self.assertTrue(result["dryRun"])
        self.assertTrue(result["test"])
        self.assertFalse(result["synthetic"])
        self.assertFalse(result["liveSubmission"])
        self.assertNotIn("layer", result)
        self.assertNotIn("writtenAt", result)
        self.assertEqual(self.writer.status()["occupiedReceipts"], 0)
        self.assert_error("live_writes_disabled", disabled.write, qualification())

    def test_default_disabled_even_with_key_and_policy(self):
        disabled = GateWriter(self.store, self.verifier)
        self.assertFalse(disabled.status()["liveWritesEnabled"])
        self.assert_error("live_writes_disabled", disabled.write, qualification())
        self.assert_error(
            "qualification_verifier_unconfigured", GateWriter(self.store).dry_run, qualification(),
        )
        self.assert_error(
            "qualification_verifier_unconfigured",
            GateWriter(self.store, trusted_service_connected=True).write, qualification(),
        )
        self.assert_error(
            "invalid_writer_configuration",
            lambda: GateWriter(self.store, self.verifier, trusted_service_connected="true"),
        )

    def test_forgery_and_hash_only_rejected(self):
        envelope = qualification()
        envelope["signature"] = "f" * 128
        self.assert_error("invalid_signature", self.writer.write, envelope)
        envelope = qualification()
        envelope["moduleSHA512"] = "f" * 128
        self.assert_error("invalid_signature", self.writer.write, envelope)
        self.assert_error("invalid_envelope_fields", self.writer.write, {"moduleSHA512": "a" * 128})
        self.assertEqual(self.writer.status()["occupiedReceipts"], 0)

    def test_validation_cases(self):
        cases = [
            ("invalid_source", {"source": "synthetic-test"}),
            ("invalid_source", {"source": "browser-accepted"}),
            ("unsupported_policy", {"policyVersion": "policy-2"}),
            ("unsupported_policy", {"policyVersion": []}),
            ("expired_receipt", {"expiresAt": NOW}),
            ("not_yet_valid", {"issuedAt": NOW + 1}),
            ("invalid_timestamps", {"issuedAt": True}),
            ("invalid_timestamps", {"expiresAt": float(NOW + 100)}),
            ("invalid_timestamps", {"issuedAt": NOW + 100}),
            ("invalid_timestamps", {"expiresAt": 2**64}),
            ("not_accepted", {"accepted": 1}),
            ("not_accepted", {"accepted": False}),
            ("invalid_envelope", {"schema": "other"}),
            ("invalid_envelope", {"gateId": "other"}),
            ("invalid_module_hash", {"moduleSHA512": "abc"}),
            ("invalid_module_hash", {"moduleSHA512": "F" * 128}),
            ("invalid_qualification_id", {"qualificationId": "personal name"}),
            ("invalid_envelope_fields", {"filename": "private-file.wav"}),
        ]
        for code, changes in cases:
            with self.subTest(code=code, changes=changes):
                self.assert_error(code, self.writer.write, qualification(**changes))
        for value in [None, [], "private raw input", {}]:
            self.assert_error("invalid_envelope_fields", self.writer.write, value)

    def test_missing_fields_and_malformed_signature(self):
        for field in qualification():
            envelope = qualification()
            del envelope[field]
            self.assert_error("invalid_envelope_fields", self.writer.write, envelope)
        for signature in [None, [], "0" * 127, "F" * 128]:
            envelope = qualification()
            envelope["signature"] = signature
            self.assert_error("invalid_signature", self.writer.write, envelope)

    def test_expired_retry_still_rejected(self):
        envelope = qualification()
        self.writer.write(envelope)
        expired = GateWriter(
            self.store, QualificationVerifier(TEST_KEY, {"policy-1"}, clock=lambda: NOW + 100),
            trusted_service_connected=True,
        )
        self.assert_error("expired_receipt", expired.write, envelope)
        self.assertEqual(self.writer.status()["occupiedReceipts"], 1)

    def test_stack_limit_and_duplicate_at_full_coordinate(self):
        with patch("invariantgatewriter.writer._coordinate", return_value=(17, 29)):
            for layer in range(512):
                self.assertEqual(self.writer.write(qualification("stack-" + str(layer)))["layer"], layer)
            self.assert_error("coordinate_full", self.writer.write, qualification("overflow"))
            self.assertTrue(self.writer.write(qualification("stack-511"))["duplicate"])
        self.assertEqual(self.writer.status()["occupiedReceipts"], 512)
        self.assertEqual(self.writer.status()["occupiedCoordinates"], 1)
        self.assertIsNone(self.writer.lookup("overflow")["receipt"])

    def test_batch_partial_completion_and_size(self):
        invalid = qualification("bad")
        invalid["signature"] = "f" * 128
        result = self.writer.write_batch([qualification(), invalid, qualification(), qualification("second")])
        self.assertFalse(result["atomic"])
        self.assertEqual([item["ok"] for item in result["results"]], [True, False, True, True])
        self.assertEqual(result["results"][1], {"index": 1, "ok": False, "error": {"code": "invalid_signature"}})
        self.assertTrue(result["results"][2]["receipt"]["duplicate"])
        self.assertEqual(self.writer.status()["occupiedReceipts"], 2)
        for invalid_batch in [[], [qualification()] * 101, {}, "private", None]:
            self.assert_error("invalid_batch_size", self.writer.write_batch, invalid_batch)
        self.assertEqual(len(self.writer.write_batch([qualification()] * 100)["results"]), 100)

    def test_disabled_batch_explicit_per_item_errors(self):
        result = GateWriter(self.store, self.verifier).write_batch([qualification()] * 2)
        self.assertEqual(
            [item["error"]["code"] for item in result["results"]],
            ["live_writes_disabled", "live_writes_disabled"],
        )

    def test_self_test_isolated_with_explicit_labels(self):
        self.writer.write(qualification())
        before = self.writer.status()
        with patch.object(self.store, "write", side_effect=AssertionError), \
                patch.object(self.store, "counts", side_effect=AssertionError), \
                patch.object(self.store, "lookup", side_effect=AssertionError), \
                patch.object(self.verifier, "verify", side_effect=AssertionError):
            result = self.writer.self_test()
        self.assertTrue(result["passed"])
        self.assertTrue(result["isolated"])
        self.assertTrue(result["synthetic"])
        self.assertTrue(result["test"])
        self.assertFalse(result["liveSubmission"])
        self.assertEqual(len(result["checks"]), 7)
        for check in result["checks"]:
            self.assertTrue(check["synthetic"])
            self.assertTrue(check["test"])
            self.assertTrue(check["passed"])
        self.assertEqual(self.writer.status(), before)
        disabled = GateWriter(self.store)
        self.assertTrue(disabled.self_test()["passed"])
        self.assertFalse(disabled.status()["liveWritesEnabled"])
        self.assertNotIn("occupiedReceipts", result)

    def test_lookup_validates_identifier(self):
        self.assertIsNone(self.writer.lookup("missing")["receipt"])
        self.assert_error("invalid_qualification_id", self.writer.lookup, "'; DROP TABLE gate_receipts;")

    def test_self_test_setup_failure_has_explicit_safe_checks(self):
        with patch("invariantgatewriter.writer.SQLiteStore", side_effect=RuntimeError(TEST_KEY.decode())):
            result = self.writer.self_test()
        self.assertFalse(result["passed"])
        self.assertFalse(result["liveSubmission"])
        self.assertEqual(len(result["checks"]), 7)
        for check in result["checks"]:
            self.assertTrue(check["synthetic"])
            self.assertTrue(check["test"])
            self.assertFalse(check["passed"])
            self.assertEqual(check["error"]["code"], "self_test_setup_failed")
        self.assertNotIn(TEST_KEY.decode(), json.dumps(result))

    def test_self_test_check_failure_has_explicit_safe_result(self):
        with patch("invariantgatewriter.writer.SQLiteStore.lookup", side_effect=RuntimeError(TEST_KEY.decode())):
            result = self.writer.self_test()
        self.assertFalse(result["passed"])
        self.assertFalse(result["liveSubmission"])
        for check in result["checks"]:
            if not check["passed"]:
                self.assertEqual(check["error"]["code"], "self_test_check_failed")
        self.assertNotIn(TEST_KEY.decode(), json.dumps(result))

    def test_privacy_metadata_only(self):
        self.writer.write(qualification())
        columns = [row[1] for row in self.store._connection.execute("PRAGMA table_info(gate_receipts)")]
        self.assertEqual(columns, ["qualification_id", "receipt_sha512", "x", "y", "layer", "written_at"])
        self.assertEqual(self.writer.status()["privacy"], "No raw media retained; receipt metadata retained.")
        self.assertNotIn(TEST_KEY.decode(), repr(self.verifier))


class PersistenceTests(unittest.TestCase):
    def setUp(self):
        # Project-local scratch database, deleted after each test.
        self.path = pathlib.Path.cwd() / ("gate-test-" + uuid.uuid4().hex + ".sqlite")
        self.addCleanup(self.remove_database)

    def remove_database(self):
        for suffix in ["", "-journal", "-wal", "-shm"]:
            pathlib.Path(str(self.path) + suffix).unlink(missing_ok=True)

    def writer(self, store):
        return GateWriter(
            store, QualificationVerifier(TEST_KEY, {"policy-1"}, clock=lambda: NOW),
            trusted_service_connected=True, clock=lambda: NOW,
        )

    def test_restart_persistence(self):
        store = SQLiteStore(self.path)
        try:
            first = self.writer(store).write(qualification())
        finally:
            store.close()
        restarted = SQLiteStore(self.path)
        try:
            writer = self.writer(restarted)
            self.assertEqual(writer.lookup("event-1")["receipt"], first)
            self.assertEqual(writer.write(qualification()), dict(first, duplicate=True))
            self.assertEqual(writer.status()["occupiedReceipts"], 1)
        finally:
            restarted.close()

    def test_concurrent_duplicate_writes_across_connections(self):
        stores = [SQLiteStore(self.path) for _ in range(8)]
        try:
            writers = [self.writer(store) for store in stores]
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                receipts = list(pool.map(lambda w: w.write(qualification()), writers))
            self.assertEqual(sum(not result["duplicate"] for result in receipts), 1)
            self.assertEqual(len({(r["x"], r["y"], r["layer"]) for r in receipts}), 1)
            self.assertEqual(writers[0].status()["occupiedReceipts"], 1)
        finally:
            for store in stores:
                store.close()

    def test_concurrent_distinct_colliding_receipts(self):
        stores = [SQLiteStore(self.path) for _ in range(8)]
        try:
            writers = [self.writer(store) for store in stores]
            with patch("invariantgatewriter.writer._coordinate", return_value=(0, 0)):
                with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                    results = list(pool.map(
                        lambda pair: pair[1].write(qualification("concurrent-" + str(pair[0]))),
                        enumerate(writers),
                    ))
            self.assertEqual(sorted(r["layer"] for r in results), list(range(8)))
        finally:
            for store in stores:
                store.close()


class Host:
    def __init__(self):
        self.tools = {
            name: object() for name in [
                "droppoint_status", "droppoint_modules", "droppoint_test", "droppoint_verify",
            ]
        }

    def tool_names(self):
        return tuple(self.tools)

    def tool(self, *, name, description):
        def register(function):
            if name in self.tools:
                raise ValueError("duplicate tool")
            self.tools[name] = function
            if not description:
                raise ValueError("missing description")
            return function
        return register


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.host = Host()
        self.store = SQLiteStore(":memory:")
        self.addCleanup(self.store.close)
        self.writer = GateWriter(
            self.store, QualificationVerifier(TEST_KEY, {"policy-1"}, clock=lambda: NOW),
            trusted_service_connected=True, clock=lambda: NOW,
        )
        self.allowed = False
        self.calls = []
        self.native_context = object()
        self.context = HostContext(self.native_context)

        def authorize(context, permission):
            self.assertIs(context, self.native_context)
            self.calls.append(permission)
            return self.allowed

        self.legacy = dict(self.host.tools)
        register_gate_tools(self.host, self.writer, authorize)

    def tool_arguments(self):
        return {
            "droppoint_gate_status": (),
            "droppoint_gate_write": (qualification(),),
            "droppoint_gate_write_batch": ([qualification()],),
            "droppoint_gate_lookup": ("event-1",),
            "droppoint_gate_dry_run": (qualification(),),
            "droppoint_gate_self_test": (),
        }

    def test_registration_preserves_legacy_tools(self):
        self.assertEqual(len(self.host.tools), 10)
        for name, original in self.legacy.items():
            self.assertIs(self.host.tools[name], original)

    def test_collision_preflight_registers_nothing(self):
        host = Host()
        existing_gate_tool = object()
        host.tools["droppoint_gate_self_test"] = existing_gate_tool
        before = dict(host.tools)
        with self.assertRaises(GateError) as caught:
            register_gate_tools(host, self.writer, lambda context, permission: True)
        self.assertEqual(caught.exception.code, "tool_name_collision")
        self.assertEqual(host.tools, before)

    def test_registration_without_registry_inspection_fails_closed(self):
        host = Host()
        host.tool_names = None
        before = dict(host.tools)
        with self.assertRaises(GateError) as caught:
            register_gate_tools(host, self.writer, lambda context, permission: True)
        self.assertEqual(caught.exception.code, "host_registration_unsupported")
        self.assertEqual(host.tools, before)

    def test_authorization_required_for_all_six_tools(self):
        for name, arguments in self.tool_arguments().items():
            with self.subTest(name=name):
                self.assertEqual(
                    self.host.tools[name](*arguments, context=self.context), {"error": {"code": "unauthorized"}},
                )
        self.assertEqual(set(self.calls), {"gate:read", "gate:write", "gate:self_test"})
        self.assertEqual(self.writer.status()["occupiedReceipts"], 0)
        self.allowed = True
        for name, arguments in self.tool_arguments().items():
            self.assertNotIn("error", self.host.tools[name](*arguments, context=self.context))

    def test_fail_closed_nonboolean_and_exception(self):
        for allowed in [None, 1, "true", {}, False]:
            self.allowed = allowed
            self.assertEqual(
                self.host.tools["droppoint_gate_status"](context=self.context), {"error": {"code": "unauthorized"}},
            )
        other_host = Host()

        def failing_authorizer(context, permission):
            raise RuntimeError(TEST_KEY.decode())

        register_gate_tools(other_host, self.writer, failing_authorizer)
        self.assertEqual(
            other_host.tools["droppoint_gate_status"](context=self.context), {"error": {"code": "unauthorized"}},
        )

    def test_caller_cannot_supply_auth_context(self):
        with self.assertRaises(TypeError):
            self.host.tools["droppoint_gate_status"](authorized=True)
        self.allowed = True
        self.assertEqual(
            self.host.tools["droppoint_gate_status"](context={"authorized": True}),
            {"error": {"code": "unauthorized"}},
        )
        self.allowed = False
        envelope = qualification()
        envelope["authorized"] = True
        self.assertEqual(
            self.host.tools["droppoint_gate_write"](envelope, context=self.context), {"error": {"code": "unauthorized"}},
        )
        self.allowed = True
        self.assertEqual(
            self.host.tools["droppoint_gate_write"](envelope, context=self.context),
            {"error": {"code": "invalid_envelope_fields"}},
        )

    def test_errors_do_not_echo_private_values(self):
        self.allowed = True
        envelope = qualification()
        envelope["filename"] = "private-filename"
        result = self.host.tools["droppoint_gate_write_batch"]([envelope], context=self.context)
        self.assertNotIn("private-filename", json.dumps(result))
        with patch.object(self.writer, "status", side_effect=RuntimeError(TEST_KEY.decode())):
            self.assertEqual(
                self.host.tools["droppoint_gate_status"](context=self.context), {"error": {"code": "internal_error"}},
            )


if __name__ == "__main__":
    unittest.main()
