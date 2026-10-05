"""Transport-independent, backend-only InvariantTap gate connector."""

from .adapter import HostContext, register_gate_tools
from .writer import (
    Ed25519PublicKey, GateError, GateWriter, HmacSha512Key, KeyringVerifier,
    QualificationVerifier, SQLiteStore,
)

__all__ = [
    "Ed25519PublicKey",
    "GateError",
    "GateWriter",
    "HmacSha512Key",
    "HostContext",
    "KeyringVerifier",
    "QualificationVerifier",
    "SQLiteStore",
    "register_gate_tools",
]
