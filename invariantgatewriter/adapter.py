"""Host adapter; no transport or authentication implementation is fabricated."""

from .writer import GateError


def register_gate_tools(host, writer, authorize):
    """Register six additional tools using host.tool()(callable).

    authorize(tool_name) MUST authenticate the current caller and authorize
    this operation using trusted host request context (for example a ContextVar).
    Only literal True allows access. Tool parameters are never auth context.
    The host must reject duplicate tool names instead of replacing old tools.
    Returns the registered callables for host-side testing.
    """
    def invoke(name, operation, *args):
        try:
            try:
                allowed = authorize(name) is True
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

    def droppoint_gate_status():
        return invoke("droppoint_gate_status", writer.status)

    def droppoint_gate_write(qualification: dict):
        return invoke("droppoint_gate_write", writer.write, qualification)

    def droppoint_gate_write_batch(qualifications: list):
        return invoke("droppoint_gate_write_batch", writer.write_batch, qualifications)

    def droppoint_gate_lookup(qualification_id: str):
        return invoke("droppoint_gate_lookup", writer.lookup, qualification_id)

    def droppoint_gate_dry_run(qualification: dict):
        return invoke("droppoint_gate_dry_run", writer.dry_run, qualification)

    def droppoint_gate_self_test():
        return invoke("droppoint_gate_self_test", writer.self_test)

    tools = (
        droppoint_gate_status, droppoint_gate_write, droppoint_gate_write_batch,
        droppoint_gate_lookup, droppoint_gate_dry_run, droppoint_gate_self_test,
    )
    for tool in tools:
        host.tool()(tool)
    return tools
