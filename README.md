# InvariantTap gate writer

Backend receipt storage and a host-registration adapter for the InvariantTap /
DROPPOINT gate. Only trusted, backend-qualified submissions belong in the live
gate; a module hash or browser-reported acceptance is not qualification.

The public module test node is a separate entry point for declarative manifests.
It validates declarations and runs predefined synthetic operations, not uploaded
code. A passing public test establishes only the properties actually tested:
**live admission still requires the gate's qualification policy**.

## Connection status

This repository did not contain the existing InvariantTap MCP host or a trusted
qualification service. The connector is therefore **not a deployed or connected
InvariantTap plugin**. Host coupling and qualification-service integration are
separate steps, described below. Live writes are disabled by default.

Burn Harness is an optional future qualification route. Its interface has not
been verified here; it is not connected and no Burn Harness run is claimed.

## Gate model

- Gate ID: `invarianttap-gate-1`.
- Coordinates: 2048 × 2048.
- Each coordinate has up to 512 receipt layers, numbered 0–511.
- Theoretical capacity: 2,147,483,648 receipts, **not tested throughput**.
- Sparse SQLite storage allocates only occupied positions.
- Unique event IDs and coordinate/layer pairs are enforced transactionally.
- Retrying an event returns its existing placement without allocating a layer.
  Reusing the event ID with different content fails.
- Full coordinates fail without relocation or overflow.

## Tools

| Tool | Purpose |
| --- | --- |
| `droppoint_gate_status` | Report live storage and connection state. |
| `droppoint_gate_write` | Verify a qualification and persist one receipt. |
| `droppoint_gate_write_batch` | Process up to 100 qualifications with per-item results. |
| `droppoint_gate_lookup` | Retrieve an existing placement. |
| `droppoint_gate_dry_run` | Validate a qualification and calculate its coordinate without writing or allocating a layer. |
| `droppoint_gate_self_test` | Run explicitly synthetic checks in a separate temporary store. |

Batches allow partial completion: successful items remain committed when other
items fail. Retry individual events using their original qualifications.

Dry runs are labelled test/non-live results, not submission receipts. Self-tests
check write, lookup, retry deduplication and stack limits, returning a result for
each check. They use a temporary database and test-only credentials; neither test
tool contributes to live submission counts or changes live placements.

## Qualification contract

Envelopes contain only the following body fields and a backend signature:

| Field | Requirement |
| --- | --- |
| `schema` | `gate-qualification/1` |
| `gateId` | `invarianttap-gate-1` |
| `qualificationId` | Stable unique opaque event ID; no personal information |
| `source` | `qualified-submission` |
| `accepted` | Boolean `true` |
| `policyVersion` | An explicitly supported backend qualification policy |
| `moduleSHA512` | SHA-512 digest of the module declaration |
| `issuedAt`, `expiresAt` | Integer Unix seconds |

Verification rejects unknown fields, unsupported policies, invalid signatures,
expired receipts and synthetic sources. The canonical qualification body is
hashed with SHA-512 to determine the coordinate. Successful live writes return
`gateId`, `receiptSHA512`, `x`, `y`, `layer`, `writtenAt` and `duplicate`.

### Canonicalization and signatures

Serialize the body (without `signature`) as UTF-8 JSON with sorted keys, compact
separators, unescaped Unicode and no non-finite numbers. In Python this is
`json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
allow_nan=False).encode("utf-8")`.

`signature` is lowercase hexadecimal HMAC-SHA512 over those bytes. Verification
uses a backend-provisioned shared key of at least 32 bytes. The receipt hash is
SHA-512 of the same bytes; `x` and `y` are the first and second two-byte big-endian
digest integers respectively, each modulo 2048.

IDs and policy versions use `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`. Module hashes and
signatures must be 128 lowercase hexadecimal characters. Future-issued receipts
and invalid timestamp ranges are rejected too.

## Privacy and credentials

**No raw media retained; receipt metadata retained.**

Do not send raw audio, video, images, filenames, dates of birth or personal
details. Event identifiers must be opaque: the writer cannot determine whether
an arbitrary identifier embeds personal information.

Keep signing credentials in backend secret configuration, outside Git, browser
code, MCP arguments and logs. No MCP tool exposes a signing function. The
qualification service, not the browser or the coupler, decides acceptance.

## Setup and local tests

Use Python 3.10 or newer with its standard library; no third-party dependencies
are required. Run the regression suite from the repository root:

```sh
cd /home/runner/work/invariantgatewriter/invariantgatewriter
python -m unittest discover -s tests -v
```

For deployment, choose a persistent SQLite database path writable only by the
backend service account. Protect the database and its backups as receipt
metadata. Configure the verifier, supported policy versions and authorization
adapter on the backend; never obtain those settings from tool arguments.

The package exports `SQLiteStore`, `QualificationVerifier`, `GateWriter` and
`register_gate_tools`. Construct a store with its database path and a verifier
with backend key bytes and an iterable of supported policy versions. Construct
`GateWriter(store, verifier)` to leave live writing disabled, or explicitly set
`trusted_service_connected=True` only after the service connection is verified.
Close the store during backend shutdown.

## Existing host connection

The existing host must supply its own MCP transport, authenticated caller
context and backend permission checks. Add the six gate tools without replacing
`droppoint_status`, `droppoint_modules`, `droppoint_test` or `droppoint_verify`.
Existing tool behavior remains the responsibility of the original host, whose
source is not present here.

Call `register_gate_tools(host, writer, authorize)` during serialized host
startup. The adapter uses
`host.tool(name=tool_name, description=description)(callable)` and requires
`host.tool_names()` to enumerate existing registrations. It checks for name
collisions before registering anything; the host must also reject duplicates.
Adapt this registration boundary if the real host uses another language or
registrar.

The backend wrapper must inject keyword-only `context: HostContext` around its
native trusted request context, **excluding it from the public tool schema**.
`HostContext` is not FastMCP's native context annotation; passing this adapter
directly to an unadapted FastMCP registrar is not a working integration.
`authorize(native_context, permission)` authenticates and checks the caller.
Only literal `True` permits access; exceptions deny access. Permissions are
`gate:read` for status/lookup/dry-run, `gate:write` for write/batch, and
`gate:self_test` for self-test. Callers cannot supply identities or permissions.

Tool inputs are `qualification` for write/dry-run, `qualifications` for batch,
and `qualification_id` for lookup; status/self-test take no arguments. Errors
return a safe `error.code`. Batch results contain `index`, `ok` and either a
`receipt` or `error`; `atomic` is `false`.

Before deployment, verify that the host injects caller context rather than
accepting identity or permissions from user-supplied tool arguments. Exercise
unauthenticated and unauthorized calls through the real transport, confirm the
legacy tools still work, and expose the new tools in the existing plugin's tool
discovery configuration.

## Qualification-service connection

This is independent of registering the MCP tools:

1. Inspect the actual qualification-service interface and acceptance policy.
2. Agree on the envelope, canonicalization, signature and policy version.
3. Provision verification credentials only on the backend and securely provision
   the corresponding signing credentials to the trusted qualification service.
4. Connect the real service and verify genuine accepted, rejected, forged and
   expired events end to end.
5. Enable live writes only after this connection is operational. Merely
   registering tools or configuring credentials does not establish qualification.

Do not fabricate live receipts to populate the gate. Synthetic checks prove
local connector behavior, not service connectivity, deployment or capacity.

## Public module test node

The public node accepts declarative manifests describing a module's ID, version,
purpose, inputs, outputs, constraints, engine connections and synthetic cases.
It returns validation results, a canonical SHA-512 declaration fingerprint,
compatibility findings, unresolved constraints and a labelled synthetic receipt
to the caller. Manifest contents are processed transiently, not stored by
default. Receipts are not gate qualifications or proof of live acceptance.

The public tools are separate from all gate tools:

| Tool | Purpose |
| --- | --- |
| `droppoint_module_validate` | Validate a versioned declaration. |
| `droppoint_module_test` | Run only predefined synthetic operations. |
| `droppoint_module_connections` | Compare declarations against known engine interfaces. |

Unknown engine interfaces and unsupported constraints remain unresolved rather
than being treated as verified. The node never executes uploaded code or imports
user-selected programs. Declaring an engine connection does not connect an
external engine or demonstrate its operational availability.

### Manifest schema and test scope

The versioned contract is
[`module_manifest.schema.json`](invariantgatewriter/module_manifest.schema.json).
The browser form includes an editable example. Every manifest contains:

| Field | Shape |
| --- | --- |
| `schema` | `module-manifest/1` |
| `moduleId` | Opaque module identifier |
| `version` | Three numeric components, such as `1.0.0` |
| `purpose` | Nonempty description |
| `inputs`, `outputs` | Lists of `{name, type}` ports |
| `constraints` | List of `{kind, value}` declarations |
| `engineConnections` | List of `{name, interface, required, inputs, outputs}` declarations |
| `syntheticTests` | List of `{name, connection, inputs, expectedOutputs}` cases |

Port types are `string`, `number`, `integer` and `boolean`; booleans are not
numbers. Test values must match the named connection's ports. Unknown fields,
duplicate names and undeclared test connections are rejected. Fingerprints use
SHA-512 of canonical UTF-8 JSON of the entire manifest, including its test cases,
with the same sorted-key compact serialization described above. Changing any
declaration or test changes the fingerprint; object key order does not.

The built-in interface catalog supports `identity/1` (string identity),
`numbers.add/1`, `text.concat/1` and `boolean.not/1`. Tests use only these
predefined implementations. They check declared **connection** signatures and
synthetic expected outputs, not the behavior of an uploaded module
implementation. Structural constraints apply only to synthetic values; they
cannot establish universal guarantees for real-world inputs.

| Interface | Inputs | Outputs |
| --- | --- | --- |
| `identity/1` | `value: string` | `value: string` |
| `numbers.add/1` | `a: number`, `b: number` | `sum: number` |
| `text.concat/1` | `left: string`, `right: string` | `result: string` |
| `boolean.not/1` | `value: boolean` | `value: boolean` |

Supported constraint kinds are `maxStringLength`, `maxArrayLength` and
`nonNegativeNumbers`. Unrecognized or non-applicable constraints remain
unresolved. A receipt is a caller-returned, unsigned report of local checks,
not a trusted qualification signature.

### Public deployment

**Publishing the GitHub repository does not run the test node.** A backend
process must be started and maintained separately. The public service must not
expose the gate writer or signing credentials. Keep gate authentication and
qualification behind their separate trusted backend boundaries.

For Internet access, deploy behind a TLS reverse proxy, restrict backend network
access to that proxy and apply additional edge rate/concurrency limits. The
in-process limits are per process, not a distributed anti-abuse system. Do not
trust arbitrary forwarded client-IP headers; only configure a trusted proxy
integration after verifying its behavior. Disable body logging, analytics and
request capture at the proxy as well as the application to preserve transient
processing.

Start the local browser/API service from the repository root:

```sh
python -m invariantgatewriter.public_node --host 127.0.0.1 --port 8080
```

Open `http://127.0.0.1:8080/` for the manifest form. JSON requests use
`POST /api/validate`, `POST /api/test` or `POST /api/connections`; MCP clients use
`POST /mcp`. This public process does not initialize live gate storage.

The REST request body is the manifest itself, with `Content-Type:
application/json`. MCP `tools/call` accepts `arguments: {"manifest": ...}`.
The MCP endpoint supports initialization, tool discovery and tool calls; it
does not register or dispatch live gate tools.
This anonymous service rejects authorization and cookie headers. Use a separate
public hostname or remove unrelated cookies at the trusted reverse proxy; never
forward gate credentials to the public node.

Python callers can import `PublicModuleNode`, `RateLimiter` and
`register_module_tools` from `invariantgatewriter.public_node`. Register public
tools separately from `register_gate_tools`. If a trusted client-identity
callback is unavailable, callable public tools share a rate-limit identity;
never extract trusted caller identity from a submitted manifest.
Public registration uses the same `tool_names()` preflight and
`tool(name=..., description=...)` registrar contract; it does not require gate
authorization context.

Requests are limited to 64 KiB. Default limits are 60 requests per client per
minute and 300 globally per minute. Client identification uses the peer address,
not untrusted `X-Forwarded-For`. Clients behind one proxy may share a quota.