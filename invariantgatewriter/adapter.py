"""Host adapter; no transport or authentication implementation is fabricated."""

from .writer import GateError


class HostContext:
    """Backend-only injection marker wrapping the native trusted host context.

    The host must exclude this parameter from its public tool schema and
    construct this wrapper from its authenticated request context, never JSON.
    """

    def __init__(self, native_context):
        self._native_context = native_context


def register_gate_tools(host, writer, authorize):
    """Register six additional tools using host.tool(name=..., description=...).

    authorize(native_context, permission) MUST authenticate and authorize
    using trusted injected host request context. Only literal True allows access.
    HostContext parameters must be injected backend-side, never caller supplied.
    This marker is NOT a FastMCP Context annotation: supply an explicit host
    wrapper that hides it from the client schema and injects native context.
    host.tool_names() must return every registered name. Run this adapter during
    serialized startup, with no concurrent registry modifications. All names
    are checked before registration; the host must also reject duplicates.
    Returns the registered callables for host-side testing.
    """
    def invoke(context, permission, operation, *args):
        try:
            try:
                allowed = (
                    isinstance(context, HostContext)
                    and authorize(context._native_context, permission) is True
                )
            except Exception:
                allowed = False
            if not allowed:
                raise GateError("unauthorized")
            return operation(*args)
        except GateError as error:
            return {"error": {"code": error.code}}
        except Exception:
            # Hosts may log errors themselves; never propagate input or secrets.
            return {"error": {"code": "internal_error"}}

    def droppoint_gate_status(*, context: HostContext):
        return invoke(context, "gate:read", writer.status)

    def droppoint_gate_write(qualification: dict, *, context: HostContext):
        return invoke(context, "gate:write", writer.write, qualification)

    def droppoint_gate_write_batch(qualifications: list, *, context: HostContext):
        return invoke(context, "gate:write", writer.write_batch, qualifications)

    def droppoint_gate_lookup(qualification_id: str, *, context: HostContext):
        return invoke(context, "gate:read", writer.lookup, qualification_id)

    def droppoint_gate_dry_run(qualification: dict, *, context: HostContext):
        return invoke(context, "gate:read", writer.dry_run, qualification)

    def droppoint_gate_self_test(*, context: HostContext):
        return invoke(context, "gate:self_test", writer.self_test)

    tools = (
        (droppoint_gate_status, "Read gate capacity, occupancy and backend connection status."),
        (droppoint_gate_write, "Write one trusted backend-qualified receipt."),
        (droppoint_gate_write_batch, "Write 1–100 qualifications with per-item results."),
        (droppoint_gate_lookup, "Look up receipt metadata by qualification ID."),
        (droppoint_gate_dry_run, "Validate qualification and compute coordinate without storage access."),
        (droppoint_gate_self_test, "Run isolated synthetic checks without accessing live receipts."),
    )
    try:
        existing_names = set(host.tool_names())
    except Exception:
        raise GateError("host_registration_unsupported") from None
    if existing_names.intersection(tool.__name__ for tool, _ in tools):
        raise GateError("tool_name_collision")
    for tool, description in tools:
        host.tool(name=tool.__name__, description=description)(tool)
    return tuple(tool for tool, _ in tools)
