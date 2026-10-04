"""Transport-independent, backend-only InvariantTap gate connector."""

from .adapter import HostContext, register_gate_tools
from .writer import GateError, GateWriter, QualificationVerifier, SQLiteStore

__all__ = [
    "GateError",
    "GateWriter",
    "HostContext",
    "QualificationVerifier",
    "SQLiteStore",
    "register_gate_tools",
]
