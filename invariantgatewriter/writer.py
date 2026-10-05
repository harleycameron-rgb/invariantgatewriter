"""Qualification verification and sparse transactional receipt storage."""

import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import threading
import time

GATE_ID = "invarianttap-gate-1"
PRIVACY = "No raw media retained; receipt metadata retained."
FIELDS = frozenset({
    "schema", "gateId", "qualificationId", "source", "accepted",
    "policyVersion", "moduleSHA512", "issuedAt", "expiresAt", "signature",
})
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
FIELDS_V2 = FIELDS | {"keyId"}
SCHEMA_V1 = "gate-qualification/1"
SCHEMA_V2 = "gate-qualification/2"
HEX512 = re.compile(r"[0-9a-f]{128}\Z")
MAX_CLOCK_SKEW = 300


class GateError(Exception):
    """Safe public error: neither input nor credentials are included."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _identifier(value):
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise GateError("invalid_qualification_id")
    return value


def _canonical(body):
    return json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _coordinate(receipt_hash):
    digest = bytes.fromhex(receipt_hash)
    return int.from_bytes(digest[:2], "big") % 2048, int.from_bytes(digest[2:4], "big") % 2048


def _skew(value):
    if type(value) is not int or not 0 <= value <= MAX_CLOCK_SKEW:
        raise GateError("invalid_verifier_configuration")
    return value


def _policies(supported_policies):
    if isinstance(supported_policies, (str, bytes)):
        raise GateError("invalid_verifier_configuration")
    try:
        policies = frozenset(supported_policies)
    except TypeError:
        raise GateError("invalid_verifier_configuration") from None
    if not policies or any(not isinstance(p, str) or not IDENTIFIER.fullmatch(p) for p in policies):
        raise GateError("invalid_verifier_configuration")
    return policies


def _check_body(body, expected_source, policies, now, skew):
    """Validate every signed field except the signature itself.

    ``skew`` widens both edges of the validity window by at most
    MAX_CLOCK_SKEW seconds to tolerate clock drift between issuer and gate.
    """
    if body["gateId"] != GATE_ID:
        raise GateError("invalid_envelope")
    _identifier(body["qualificationId"])
    if body["source"] != expected_source:
        raise GateError("invalid_source")
    if body["accepted"] is not True:
        raise GateError("not_accepted")
    if not isinstance(body["policyVersion"], str) or body["policyVersion"] not in policies:
        raise GateError("unsupported_policy")
    if not isinstance(body["moduleSHA512"], str) or not HEX512.fullmatch(body["moduleSHA512"]):
        raise GateError("invalid_module_hash")
    issued, expires = body["issuedAt"], body["expiresAt"]
    if type(issued) is not int or type(expires) is not int or not 0 <= issued < expires <= 2**63 - 1:
        raise GateError("invalid_timestamps")
    if issued > now + skew:
        raise GateError("not_yet_valid")
    if expires <= now - skew:
        raise GateError("expired_receipt")


def _signature_hex(envelope):
    signature = envelope["signature"]
    if not isinstance(signature, str) or not HEX512.fullmatch(signature):
        raise GateError("invalid_signature")
    return signature


def _receipt(body, canonical):
    receipt_hash = hashlib.sha512(canonical).hexdigest()
    x, y = _coordinate(receipt_hash)
    return body["qualificationId"], receipt_hash, x, y


class QualificationVerifier:
    """Verify ``gate-qualification/1`` HMAC-SHA512 envelopes.

    The signature is lowercase hex HMAC over UTF-8 canonical JSON of all
    envelope fields except signature. Provision keys out of band; this API
    exposes no signing function. HMAC is symmetric: whoever can verify can
    also sign, so /1 receipts are verifiable only by the key holder. Use
    KeyringVerifier with Ed25519 keys for publicly verifiable /2 envelopes.
    """

    def __init__(self, key, supported_policies, clock=time.time, *, max_clock_skew=0):
        if not isinstance(key, bytes) or len(key) < 32:
            raise GateError("invalid_verifier_configuration")
        self._key = key
        self._policies = _policies(supported_policies)
        self._clock = clock
        self._skew = _skew(max_clock_skew)

    def verify(self, envelope):
        return self._verify(envelope, "qualified-submission")

    def _verify(self, envelope, expected_source):
        if not isinstance(envelope, dict) or set(envelope) != FIELDS:
            raise GateError("invalid_envelope_fields")
        body = {name: envelope[name] for name in FIELDS if name != "signature"}
        if body["schema"] != SCHEMA_V1:
            raise GateError("invalid_envelope")
        _check_body(body, expected_source, self._policies, int(self._clock()), self._skew)
        signature = _signature_hex(envelope)
        canonical = _canonical(body)
        expected = hmac.new(self._key, canonical, hashlib.sha512).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise GateError("invalid_signature")
        return _receipt(body, canonical)


class HmacSha512Key:
    """Shared secret (>= 32 bytes) for a keyring entry. Private: backend only."""

    algorithm = "hmac-sha512"
    public = False

    def __init__(self, secret):
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise GateError("invalid_verifier_configuration")
        self._secret = secret

    def verify(self, signature_hex, message):
        expected = hmac.new(self._secret, message, hashlib.sha512).hexdigest()
        return hmac.compare_digest(signature_hex, expected)

    def __repr__(self):
        return "HmacSha512Key(<redacted>)"


class Ed25519PublicKey:
    """Ed25519 (RFC 8032) verification key: 32 raw bytes, safe to publish.

    Requires the optional ``cryptography`` package. Signatures are 64 bytes,
    carried as 128 lowercase hex characters like HMAC-SHA512 tags.
    """

    algorithm = "ed25519"
    public = True

    def __init__(self, raw):
        if not isinstance(raw, bytes) or len(raw) != 32:
            raise GateError("invalid_verifier_configuration")
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519
        except ImportError:
            raise GateError("ed25519_unavailable") from None
        try:
            self._key = ed25519.Ed25519PublicKey.from_public_bytes(raw)
        except Exception:
            raise GateError("invalid_verifier_configuration") from None
        self.raw = raw

    @classmethod
    def from_hex(cls, value):
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise GateError("invalid_verifier_configuration")
        return cls(bytes.fromhex(value))

    def verify(self, signature_hex, message):
        from cryptography.exceptions import InvalidSignature
        try:
            self._key.verify(bytes.fromhex(signature_hex), message)
        except (InvalidSignature, ValueError):
            return False
        return True

    def __repr__(self):
        return "Ed25519PublicKey(" + self.raw.hex() + ")"


class KeyringVerifier:
    """Verify ``gate-qualification/2`` envelopes against a key registry.

    /2 adds a signed ``keyId``. The registry, not the envelope, fixes each
    key's algorithm, so a sender cannot choose the algorithm (no algorithm
    confusion). Several keys may be live at once for rotation; retiring a
    key is removing its entry. The receipt hash covers keyId but never the
    signature. ``legacy_hmac_key`` optionally keeps accepting /1 envelopes
    during migration. A keyring holding only Ed25519PublicKey entries holds
    no secrets and can be run by anyone to check receipts independently.
    """

    def __init__(self, keys, supported_policies, clock=time.time, *,
                 max_clock_skew=0, legacy_hmac_key=None):
        if not isinstance(keys, dict) or not keys:
            raise GateError("invalid_verifier_configuration")
        for key_id, key in keys.items():
            if not isinstance(key_id, str) or not IDENTIFIER.fullmatch(key_id):
                raise GateError("invalid_verifier_configuration")
            if not isinstance(key, (HmacSha512Key, Ed25519PublicKey)):
                raise GateError("invalid_verifier_configuration")
        self._keys = dict(keys)
        self._policies = _policies(supported_policies)
        self._clock = clock
        self._skew = _skew(max_clock_skew)
        self._legacy = None if legacy_hmac_key is None else QualificationVerifier(
            legacy_hmac_key, self._policies, clock, max_clock_skew=max_clock_skew)

    @property
    def publicly_verifiable(self):
        return all(key.public for key in self._keys.values()) and self._legacy is None

    def public_keys(self):
        """keyId -> hex for publishable keys only; secrets are never listed."""
        return {key_id: key.raw.hex() for key_id, key in sorted(self._keys.items()) if key.public}

    def verify(self, envelope):
        return self._verify(envelope, "qualified-submission")

    def _verify(self, envelope, expected_source):
        if isinstance(envelope, dict) and set(envelope) == FIELDS:
            if self._legacy is None:
                raise GateError("legacy_schema_disabled")
            return self._legacy._verify(envelope, expected_source)
        if not isinstance(envelope, dict) or set(envelope) != FIELDS_V2:
            raise GateError("invalid_envelope_fields")
        body = {name: envelope[name] for name in FIELDS_V2 if name != "signature"}
        if body["schema"] != SCHEMA_V2:
            raise GateError("invalid_envelope")
        key_id = body["keyId"]
        if not isinstance(key_id, str) or not IDENTIFIER.fullmatch(key_id):
            raise GateError("invalid_key_id")
        key = self._keys.get(key_id)
        if key is None:
            raise GateError("unknown_key_id")
        _check_body(body, expected_source, self._policies, int(self._clock()), self._skew)
        signature = _signature_hex(envelope)
        canonical = _canonical(body)
        if not key.verify(signature, canonical):
            raise GateError("invalid_signature")
        return _receipt(body, canonical)


class SQLiteStore:
    """SQLite persistence with cross-process locking and unique placements."""

    def __init__(self, path):
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            path, timeout=30, isolation_level=None, check_same_thread=False,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA busy_timeout = 30000")
        self._connection.execute("""
            CREATE TABLE IF NOT EXISTS gate_receipts (
                qualification_id TEXT PRIMARY KEY NOT NULL,
                receipt_sha512 TEXT NOT NULL,
                x INTEGER NOT NULL CHECK (x BETWEEN 0 AND 2047),
                y INTEGER NOT NULL CHECK (y BETWEEN 0 AND 2047),
                layer INTEGER NOT NULL CHECK (layer BETWEEN 0 AND 511),
                written_at INTEGER NOT NULL,
                UNIQUE (x, y, layer)
            )
        """)

    @staticmethod
    def _placement(row, duplicate):
        return {
            "gateId": GATE_ID, "receiptSHA512": row["receipt_sha512"],
            "x": row["x"], "y": row["y"], "layer": row["layer"],
            "writtenAt": row["written_at"], "duplicate": duplicate,
        }

    def write(self, qualification_id, receipt_hash, x, y, written_at):
        with self._lock:
            connection = self._connection
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT * FROM gate_receipts WHERE qualification_id = ?",
                    (qualification_id,),
                ).fetchone()
                if row is not None:
                    if row["receipt_sha512"] != receipt_hash:
                        raise GateError("qualification_id_conflict")
                    result = self._placement(row, True)
                else:
                    layer = connection.execute(
                        "SELECT COALESCE(MAX(layer), -1) + 1 FROM gate_receipts WHERE x = ? AND y = ?",
                        (x, y),
                    ).fetchone()[0]
                    if layer >= 512:
                        raise GateError("coordinate_full")
                    connection.execute(
                        "INSERT INTO gate_receipts VALUES (?, ?, ?, ?, ?, ?)",
                        (qualification_id, receipt_hash, x, y, layer, written_at),
                    )
                    row = connection.execute(
                        "SELECT * FROM gate_receipts WHERE qualification_id = ?",
                        (qualification_id,),
                    ).fetchone()
                    result = self._placement(row, False)
                connection.execute("COMMIT")
                return result
            except GateError:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
            except sqlite3.Error:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise GateError("storage_error") from None

    def lookup(self, qualification_id):
        _identifier(qualification_id)
        with self._lock:
            try:
                row = self._connection.execute(
                    "SELECT * FROM gate_receipts WHERE qualification_id = ?",
                    (qualification_id,),
                ).fetchone()
                return None if row is None else self._placement(row, False)
            except sqlite3.Error:
                raise GateError("storage_error") from None

    def counts(self):
        with self._lock:
            try:
                return self._connection.execute("""
                    SELECT COUNT(*), COUNT(DISTINCT x * 2048 + y)
                    FROM gate_receipts
                """).fetchone()
            except sqlite3.Error:
                raise GateError("storage_error") from None

    def close(self):
        with self._lock:
            self._connection.close()


class GateWriter:
    """Backend service; invoke through an authenticated host adapter.

    trusted_service_connected must be explicitly enabled only after the
    deployment has established a trusted qualification-service connection.
    Merely configuring a verifier never enables live writes.
    """

    def __init__(self, store, verifier=None, *, trusted_service_connected=False, clock=time.time):
        if type(trusted_service_connected) is not bool:
            raise GateError("invalid_writer_configuration")
        self._store = store
        self._verifier = verifier
        self._connected = trusted_service_connected
        self._clock = clock

    def status(self):
        receipts, coordinates = self._store.counts()
        return {
            "gateId": GATE_ID, "width": 2048, "height": 2048,
            "layersPerCoordinate": 512, "theoreticalCapacity": 2147483648,
            "occupiedReceipts": receipts, "occupiedCoordinates": coordinates,
            "liveWritesEnabled": self._connected and self._verifier is not None,
            "qualificationVerifierConfigured": self._verifier is not None,
            "privacy": PRIVACY,
        }

    def _verify(self, qualification):
        if self._verifier is None:
            raise GateError("qualification_verifier_unconfigured")
        return self._verifier.verify(qualification)

    def dry_run(self, qualification):
        _, receipt_hash, x, y = self._verify(qualification)
        return {
            "gateId": GATE_ID, "receiptSHA512": receipt_hash, "x": x, "y": y,
            "dryRun": True, "test": True, "synthetic": False, "liveSubmission": False,
        }

    def write(self, qualification):
        if not self._connected:
            raise GateError("live_writes_disabled")
        verified = self._verify(qualification)
        return self._store.write(*verified, int(self._clock()))

    def write_batch(self, qualifications):
        if not isinstance(qualifications, list) or not 1 <= len(qualifications) <= 100:
            raise GateError("invalid_batch_size")
        results = []
        for index, qualification in enumerate(qualifications):
            try:
                results.append({"index": index, "ok": True, "receipt": self.write(qualification)})
            except GateError as error:
                results.append({"index": index, "ok": False, "error": {"code": error.code}})
        return {"results": results, "atomic": False}

    def lookup(self, qualification_id):
        return {"gateId": GATE_ID, "receipt": self._store.lookup(qualification_id)}

    def self_test(self):
        """Exercise only private in-memory storage and synthetic receipts."""
        check_names = (
            "write", "lookup", "retry", "dedup", "event_content_conflict",
            "layer_stack_0_through_511_and_overflow", "synthetic_live_rejection",
        )
        try:
            key = secrets.token_bytes(64)
            now = int(time.time())
            verifier = QualificationVerifier(key, {"synthetic-test-policy"}, clock=lambda: now)
            store = SQLiteStore(":memory:")
        except Exception:
            return {
                "synthetic": True, "test": True, "isolated": True, "passed": False,
                "liveSubmission": False,
                "checks": [
                    {
                        "name": name, "synthetic": True, "test": True, "passed": False,
                        "error": {"code": "self_test_setup_failed"},
                    }
                    for name in check_names
                ],
            }
        checks = []

        def check(name, operation):
            try:
                passed = operation() is True
            except Exception:
                passed = False
            result = {"name": name, "synthetic": True, "test": True, "passed": passed}
            if not passed:
                result["error"] = {"code": "self_test_check_failed"}
            checks.append(result)

        def synthetic(event):
            body = {
                "schema": "gate-qualification/1", "gateId": GATE_ID,
                "qualificationId": event, "source": "synthetic-test", "accepted": True,
                "policyVersion": "synthetic-test-policy", "moduleSHA512": "0" * 128,
                "issuedAt": now - 1, "expiresAt": now + 60,
            }
            body["signature"] = hmac.new(key, _canonical(body), hashlib.sha512).hexdigest()
            return body

        def write_test():
            receipt = verifier._verify(synthetic("synthetic-write"), "synthetic-test")
            result = store.write(*receipt, now)
            return result["layer"] == 0 and result["duplicate"] is False

        def lookup_test():
            return store.lookup("synthetic-write") is not None

        def retry_test():
            receipt = verifier._verify(synthetic("synthetic-write"), "synthetic-test")
            first = store.lookup("synthetic-write")
            second = store.write(*receipt, now + 1)
            return second == dict(first, duplicate=True)

        def dedup_test():
            receipt = verifier._verify(synthetic("synthetic-write"), "synthetic-test")
            before = tuple(store.counts())
            result = store.write(*receipt, now + 2)
            return result["duplicate"] is True and tuple(store.counts()) == before

        def conflict_test():
            try:
                store.write("synthetic-write", "f" * 128, 0, 0, now)
            except GateError as error:
                return error.code == "qualification_id_conflict"
            return False

        def stack_test():
            # Force a collision at the allocation boundary, not in the hash mapper.
            first = store.lookup("synthetic-write")
            x, y = (0, 0) if (first["x"], first["y"]) == (2047, 2047) else (2047, 2047)
            for layer in range(512):
                result = store.write("synthetic-stack-" + str(layer), "a" * 128, x, y, now)
                if result["layer"] != layer:
                    return False
            try:
                store.write("synthetic-overflow", "b" * 128, x, y, now)
            except GateError as error:
                return error.code == "coordinate_full" and store.lookup("synthetic-overflow") is None
            return False

        def live_rejection_test():
            try:
                verifier.verify(synthetic("synthetic-live-rejection"))
            except GateError as error:
                return error.code == "invalid_source"
            return False

        try:
            check("write", write_test)
            check("lookup", lookup_test)
            check("retry", retry_test)
            check("dedup", dedup_test)
            check("event_content_conflict", conflict_test)
            check("layer_stack_0_through_511_and_overflow", stack_test)
            check("synthetic_live_rejection", live_rejection_test)
        finally:
            try:
                store.close()
            except Exception:
                checks.append({
                    "name": "cleanup", "synthetic": True, "test": True, "passed": False,
                    "error": {"code": "self_test_cleanup_failed"},
                })
        return {
            "synthetic": True, "test": True, "isolated": True,
            "liveSubmission": False,
            "passed": all(check["passed"] for check in checks), "checks": checks,
        }
