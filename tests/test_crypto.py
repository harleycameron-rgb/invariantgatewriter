"""Cryptographic properties of qualification envelopes (/1 HMAC and /2 keyring)."""

import hashlib
import hmac
import json
import unittest

from invariantgatewriter import (
    Ed25519PublicKey, GateError, GateWriter, HmacSha512Key, KeyringVerifier,
    QualificationVerifier, SQLiteStore,
)
from invariantgatewriter.qualification import submit_reviewed_modules
from invariantgatewriter.writer import MAX_CLOCK_SKEW, _canonical, _coordinate

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
except ImportError:  # pragma: no cover - optional dependency
    ed25519 = None

NOW = 1800000000
HMAC_KEY = b"synthetic-unit-test-key-not-a-production-secret" * 2
OTHER_HMAC_KEY = b"another-synthetic-unit-test-key-not-a-secret!!" * 2
POLICIES = {"policy-1"}
MODULE = hashlib.sha512(b"synthetic-unit-test-module").hexdigest()


def body(schema="gate-qualification/1", event="event-1", **changes):
    value = {
        "schema": schema, "gateId": "invarianttap-gate-1", "qualificationId": event,
        "source": "qualified-submission", "accepted": True, "policyVersion": "policy-1",
        "moduleSHA512": MODULE, "issuedAt": NOW - 10, "expiresAt": NOW + 100,
    }
    value.update(changes)
    return value


def hmac_sign(value, key=HMAC_KEY):
    return dict(value, signature=hmac.new(key, _canonical(value), hashlib.sha512).hexdigest())


def raw_public(private):
    return private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def ed_sign(value, private):
    return dict(value, signature=private.sign(_canonical(value)).hex())


class HmacV1Tests(unittest.TestCase):
    def verifier(self, **kwargs):
        return QualificationVerifier(HMAC_KEY, POLICIES, clock=lambda: NOW, **kwargs)

    def test_valid_tag_and_receipt_hash_excludes_signature(self):
        envelope = hmac_sign(body())
        event, receipt, x, y = self.verifier().verify(envelope)
        self.assertEqual(event, "event-1")
        self.assertEqual(receipt, hashlib.sha512(_canonical(body())).hexdigest())
        self.assertEqual((x, y), _coordinate(receipt))

    def test_every_signed_field_is_bound(self):
        envelope = hmac_sign(body())
        for field, value in [("qualificationId", "event-2"), ("policyVersion", "policy-1"),
                             ("moduleSHA512", "e" * 128), ("issuedAt", NOW - 11),
                             ("expiresAt", NOW + 101)]:
            tampered = dict(envelope, **{field: value})
            if tampered == envelope:
                continue
            with self.subTest(field=field):
                with self.assertRaises(GateError) as caught:
                    self.verifier().verify(tampered)
                self.assertEqual(caught.exception.code, "invalid_signature")

    def test_wrong_key_and_bit_flip_rejected(self):
        for envelope in (hmac_sign(body(), OTHER_HMAC_KEY),):
            with self.assertRaises(GateError):
                self.verifier().verify(envelope)
        envelope = hmac_sign(body())
        flipped = format(int(envelope["signature"][0], 16) ^ 1, "x") + envelope["signature"][1:]
        with self.assertRaises(GateError) as caught:
            self.verifier().verify(dict(envelope, signature=flipped))
        self.assertEqual(caught.exception.code, "invalid_signature")

    def test_uses_constant_time_comparison(self):
        calls = []
        original = hmac.compare_digest

        def spy(a, b):
            calls.append(1)
            return original(a, b)

        hmac.compare_digest = spy
        try:
            self.verifier().verify(hmac_sign(body()))
        finally:
            hmac.compare_digest = original
        self.assertEqual(len(calls), 1)

    def test_v1_rejects_key_id_field(self):
        envelope = hmac_sign(body(keyId="k1"))
        with self.assertRaises(GateError) as caught:
            self.verifier().verify(envelope)
        self.assertEqual(caught.exception.code, "invalid_envelope_fields")

    def test_default_has_no_clock_tolerance(self):
        with self.assertRaises(GateError) as caught:
            self.verifier().verify(hmac_sign(body(issuedAt=NOW + 1, expiresAt=NOW + 100)))
        self.assertEqual(caught.exception.code, "not_yet_valid")
        with self.assertRaises(GateError) as caught:
            self.verifier().verify(hmac_sign(body(issuedAt=NOW - 100, expiresAt=NOW)))
        self.assertEqual(caught.exception.code, "expired_receipt")

    def test_clock_skew_widens_both_edges_exactly(self):
        verifier = self.verifier(max_clock_skew=30)
        verifier.verify(hmac_sign(body(issuedAt=NOW + 30, expiresAt=NOW + 100)))
        verifier.verify(hmac_sign(body(event="e2", issuedAt=NOW - 100, expiresAt=NOW - 29)))
        with self.assertRaises(GateError) as caught:
            verifier.verify(hmac_sign(body(issuedAt=NOW + 31, expiresAt=NOW + 100)))
        self.assertEqual(caught.exception.code, "not_yet_valid")
        with self.assertRaises(GateError) as caught:
            verifier.verify(hmac_sign(body(issuedAt=NOW - 100, expiresAt=NOW - 30)))
        self.assertEqual(caught.exception.code, "expired_receipt")

    def test_clock_skew_is_bounded(self):
        for skew in (-1, MAX_CLOCK_SKEW + 1, 1.5, True, "30"):
            with self.subTest(skew=skew):
                with self.assertRaises(GateError):
                    self.verifier(max_clock_skew=skew)
        self.verifier(max_clock_skew=MAX_CLOCK_SKEW)


@unittest.skipIf(ed25519 is None, "cryptography not installed")
class KeyringV2Tests(unittest.TestCase):
    def setUp(self):
        self.private = ed25519.Ed25519PrivateKey.generate()
        self.public = Ed25519PublicKey(raw_public(self.private))

    def keyring(self, keys=None, **kwargs):
        keys = {"ed-2026-10": self.public} if keys is None else keys
        return KeyringVerifier(keys, POLICIES, clock=lambda: NOW, **kwargs)

    def v2(self, key_id="ed-2026-10", **changes):
        return body("gate-qualification/2", keyId=key_id, **changes)

    def test_rfc8032_test_vector_1(self):
        key = Ed25519PublicKey.from_hex(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        signature = ("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                     "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
        self.assertTrue(key.verify(signature, b""))
        self.assertFalse(key.verify(signature, b"\x00"))

    def test_ed25519_round_trip_and_receipt_binds_key_id(self):
        envelope = ed_sign(self.v2(), self.private)
        event, receipt, x, y = self.keyring().verify(envelope)
        self.assertEqual(receipt, hashlib.sha512(_canonical(self.v2())).hexdigest())
        self.assertEqual((x, y), _coordinate(receipt))
        self.assertNotIn(envelope["signature"].encode(), _canonical(self.v2()))

    def test_every_signed_field_including_key_id_is_bound(self):
        other = ed25519.Ed25519PrivateKey.generate()
        keyring = self.keyring({"ed-2026-10": self.public,
                                "ed-2027-01": Ed25519PublicKey(raw_public(other))})
        envelope = ed_sign(self.v2(), self.private)
        for field, value in [("qualificationId", "event-2"), ("moduleSHA512", "e" * 128),
                             ("issuedAt", NOW - 11), ("expiresAt", NOW + 101),
                             ("keyId", "ed-2027-01")]:
            with self.subTest(field=field):
                with self.assertRaises(GateError) as caught:
                    keyring.verify(dict(envelope, **{field: value}))
                self.assertEqual(caught.exception.code, "invalid_signature")

    def test_wrong_private_key_rejected(self):
        intruder = ed25519.Ed25519PrivateKey.generate()
        with self.assertRaises(GateError) as caught:
            self.keyring().verify(ed_sign(self.v2(), intruder))
        self.assertEqual(caught.exception.code, "invalid_signature")

    def test_unknown_and_malformed_key_ids(self):
        envelope = ed_sign(self.v2(key_id="ed-retired"), self.private)
        with self.assertRaises(GateError) as caught:
            self.keyring().verify(envelope)
        self.assertEqual(caught.exception.code, "unknown_key_id")
        for key_id in ("", "../x", "k" * 129, 7, None):
            with self.subTest(key_id=key_id):
                with self.assertRaises(GateError) as caught:
                    self.keyring().verify(dict(envelope, keyId=key_id))
                self.assertEqual(caught.exception.code, "invalid_key_id")

    def test_registry_fixes_algorithm_no_confusion(self):
        # An HMAC tag computed with the Ed25519 public bytes as "secret" must
        # not verify against the Ed25519 entry, and vice versa.
        raw = raw_public(self.private)
        forged = dict(self.v2(), signature=hmac.new(raw * 2, _canonical(self.v2()),
                                                    hashlib.sha512).hexdigest())
        with self.assertRaises(GateError) as caught:
            self.keyring().verify(forged)
        self.assertEqual(caught.exception.code, "invalid_signature")
        hmac_ring = self.keyring({"ed-2026-10": HmacSha512Key(HMAC_KEY)})
        with self.assertRaises(GateError) as caught:
            hmac_ring.verify(ed_sign(self.v2(), self.private))
        self.assertEqual(caught.exception.code, "invalid_signature")

    def test_hmac_keyring_entry_verifies_v2(self):
        ring = self.keyring({"hmac-1": HmacSha512Key(HMAC_KEY)})
        ring.verify(hmac_sign(self.v2(key_id="hmac-1")))
        self.assertFalse(ring.publicly_verifiable)
        self.assertEqual(ring.public_keys(), {})
        self.assertNotIn(HMAC_KEY.hex(), repr(HmacSha512Key(HMAC_KEY)))

    def test_rotation_two_live_keys_then_retirement(self):
        new_private = ed25519.Ed25519PrivateKey.generate()
        new_public = Ed25519PublicKey(raw_public(new_private))
        both = self.keyring({"ed-2026-10": self.public, "ed-2027-01": new_public})
        old_envelope = ed_sign(self.v2(event="old"), self.private)
        new_envelope = ed_sign(self.v2(key_id="ed-2027-01", event="new"), new_private)
        both.verify(old_envelope)
        both.verify(new_envelope)
        retired = self.keyring({"ed-2027-01": new_public})
        retired.verify(new_envelope)
        with self.assertRaises(GateError) as caught:
            retired.verify(old_envelope)
        self.assertEqual(caught.exception.code, "unknown_key_id")

    def test_public_keyring_holds_no_secrets(self):
        ring = self.keyring()
        self.assertTrue(ring.publicly_verifiable)
        self.assertEqual(ring.public_keys(), {"ed-2026-10": raw_public(self.private).hex()})
        self.assertEqual(Ed25519PublicKey.from_hex(raw_public(self.private).hex()).raw,
                         raw_public(self.private))

    def test_legacy_v1_only_when_enabled(self):
        v1 = hmac_sign(body())
        with self.assertRaises(GateError) as caught:
            self.keyring().verify(v1)
        self.assertEqual(caught.exception.code, "legacy_schema_disabled")
        ring = self.keyring(legacy_hmac_key=HMAC_KEY)
        ring.verify(v1)
        self.assertFalse(ring.publicly_verifiable)

    def test_schema_and_field_set_must_agree(self):
        signed_v1_schema_with_key = ed_sign(body(keyId="ed-2026-10"), self.private)
        with self.assertRaises(GateError) as caught:
            self.keyring().verify(signed_v1_schema_with_key)
        self.assertEqual(caught.exception.code, "invalid_envelope")
        missing = ed_sign(self.v2(), self.private)
        del missing["keyId"]
        with self.assertRaises(GateError) as caught:
            self.keyring().verify(missing)
        self.assertEqual(caught.exception.code, "legacy_schema_disabled")
        extra = dict(ed_sign(self.v2(), self.private), alg="none")
        with self.assertRaises(GateError) as caught:
            self.keyring().verify(extra)
        self.assertEqual(caught.exception.code, "invalid_envelope_fields")

    def test_signature_encoding_strict(self):
        envelope = ed_sign(self.v2(), self.private)
        for signature in (envelope["signature"].upper(), envelope["signature"][:-2],
                          envelope["signature"] + "00", None, 0):
            with self.subTest(signature=str(signature)[:8]):
                with self.assertRaises(GateError) as caught:
                    self.keyring().verify(dict(envelope, signature=signature))
                self.assertEqual(caught.exception.code, "invalid_signature")

    def test_non_canonical_s_rejected(self):
        # RFC 8032 requires S < L; S + L is a malleated encoding of a valid signature.
        L = 2**252 + 27742317777372353535851937790883648493
        envelope = ed_sign(self.v2(), self.private)
        sig = bytes.fromhex(envelope["signature"])
        s = int.from_bytes(sig[32:], "little") + L
        if s < 2**256:
            malleated = sig[:32] + s.to_bytes(32, "little")
            with self.assertRaises(GateError) as caught:
                self.keyring().verify(dict(envelope, signature=malleated.hex()))
            self.assertEqual(caught.exception.code, "invalid_signature")

    def test_invalid_key_configuration(self):
        for keys in ({}, [], {"bad id": self.public}, {"k": b"x" * 32}, {"k": "abc"}):
            with self.subTest(keys=str(keys)[:20]):
                with self.assertRaises(GateError):
                    KeyringVerifier(keys, POLICIES)
        for raw in (b"x" * 31, b"x" * 33, "x" * 32):
            with self.assertRaises(GateError):
                Ed25519PublicKey(raw)
        for value in ("A" * 64, "a" * 63, None):
            with self.assertRaises(GateError):
                Ed25519PublicKey.from_hex(value)
        with self.assertRaises(GateError):
            HmacSha512Key(b"short")

    def test_skew_applies_to_v2(self):
        ring = self.keyring(max_clock_skew=5)
        ring.verify(ed_sign(self.v2(issuedAt=NOW + 5), self.private))
        with self.assertRaises(GateError) as caught:
            ring.verify(ed_sign(self.v2(issuedAt=NOW + 6), self.private))
        self.assertEqual(caught.exception.code, "not_yet_valid")

    def test_gate_writer_and_reviewed_submission_accept_v2(self):
        store = SQLiteStore(":memory:")
        writer = GateWriter(store, self.keyring(), trusted_service_connected=True,
                            clock=lambda: NOW)
        envelope = ed_sign(self.v2(), self.private)
        first = writer.write(envelope)
        self.assertEqual(writer.write(envelope), dict(first, duplicate=True))
        self.assertEqual(writer.dry_run(envelope)["receiptSHA512"], first["receiptSHA512"])

        declaration_hash = {}

        def qualifier(declaration, event_id):
            canonical = json.dumps(declaration, sort_keys=True, separators=(",", ":"),
                                   ensure_ascii=False, allow_nan=False).encode()
            declaration_hash["h"] = hashlib.sha512(canonical).hexdigest()
            return {"status": "qualified", "qualification": ed_sign(
                self.v2(event=event_id, moduleSHA512=declaration_hash["h"]), self.private)}

        from tests.test_qualification import declaration as reviewed_declaration
        result = submit_reviewed_modules(
            [{"declaration": reviewed_declaration(), "qualificationId": "reviewed-v2"}],
            writer, qualifier, lambda context, scope: True, object())
        item = result["results"][0]
        self.assertEqual(item["status"], "success", item)
        self.assertEqual(item["moduleSHA512"], declaration_hash["h"])
        store.close()


if __name__ == "__main__":
    unittest.main()
