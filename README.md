# InvariantTap gate writer

Backend receipt storage and a host-registration adapter for the InvariantTap /
DROPPOINT gate. Only trusted, backend-qualified submissions belong in the live
gate; a module hash or browser-reported acceptance is not qualification.

The public module test node is a separate entry point for declarative manifests.
It validates declarations and runs predefined synthetic operations, not uploaded
code. A passing public test establishes only the properties actually tested:
**live admission still requires the gate's qualification policy**.

### Contents

- [Connection status](#connection-status)
- [Gate model and tools](#gate-model)
- [Qualification contract](#qualification-contract)
- [Privacy and credentials](#privacy-and-credentials)
- [Setup and local tests](#setup-and-local-tests)
- [Existing host connection](#existing-host-connection)
- [Qualification-service connection](#qualification-service-connection)
- [Public module test node](#public-module-test-node)
- [Local ZIP inspection and module extraction](#local-zip-inspection-and-module-extraction)
- [Identity, placement and convergence](#identity-placement-and-convergence)
- [Multiple qualification events](#multiple-qualification-events)

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

“ZIP inspection happens locally. Reviewed module declarations may be sent for
qualification. No raw media or repository files are retained by the gate;
receipt metadata is retained.”

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

For browser-local ZIP logic, use Node.js 22 or newer and its built-in test runner:

```sh
node --test tests/test_zip_intake.mjs
```

No uploaded repository code is run by either test node. Regression tests cover
authentication, forged/expired qualifications, isolated test stores, concurrent
deduplication, full stacks, partial batches and persistence; public-node tests
cover schema/compatibility, limits and API/MCP transport; ZIP/model tests cover
unsafe archives, multiple candidates, fingerprint determinism, feasible-set
narrowing and upward-opening focus geometry.

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
implementation. String/numeric constraints apply only to synthetic values;
`maxArrayLength` checks declaration port, connection and test lists, not runtime
array behavior. These checks cannot establish universal guarantees for real-world
inputs.

| Interface | Inputs | Outputs |
| --- | --- | --- |
| `identity/1` | `value: string` | `value: string` |
| `numbers.add/1` | `a: number`, `b: number` | `sum: number` |
| `text.concat/1` | `left: string`, `right: string` | `result: string` |
| `boolean.not/1` | `value: boolean` | `value: boolean` |

Supported constraint kinds are `maxStringLength`, `maxArrayLength` and
`nonNegativeNumbers`; version 2 also supports placement constraints
`includeEngine` and `excludeEngine`. Unrecognized or non-applicable constraints remain
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
The original InvariantTap host is unavailable here: its logging and retention
have not been inspected. No broader host-wide zero-retention guarantee is made.

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

The HTTP server caps active connections at 32 and uses five-second socket
timeouts. Configure `--allowed-host` and `--allowed-origin` (repeatable) for a
reverse-proxied deployment, including any nondefault port in the host authority.
Use `--max-connections` to change the connection cap. Defaults permit local
addresses; the allowlist is not inferred from arbitrary incoming headers.

## Local ZIP inspection and module extraction

Open `/zip` on the local public-node server. The browser reads the ZIP locally;
it sends neither the archive nor extracted repository files to the backend.
Repository code is never executed, and the original archive/files are unchanged.
Clear/end inspection to discard working buffers and UI state.

The archive inspector bounds archive bytes, streamed expansion and entry counts,
and rejects unsafe paths, symlinks, unsupported encrypted/ZIP64/multidisk
archives, duplicate/conflicting names, malformed metadata, bad checksums and
oversized expansions. Nested archive entries are excluded; they are never
recursively expanded.

| Resource | Limit |
| --- | --- |
| ZIP archive | 8 MiB |
| Total expanded files | 16 MiB |
| Individual file | 1 MiB |
| Archive entry count (including directories) | 256 |
| Expansion ratio | 100:1 |

Extraction prefers explicit module declarations; otherwise it identifies
documented interfaces and package boundaries using static metadata. It does not split every file into a
module, invent missing contracts or inflate receipt counts. Inferred candidates
carry unresolved questions; unknown contracts stay unknown. Evidence references
and extraction methods distinguish declarations from inference.

Use `droppoint.module.json` for explicit declarations (one manifest, or a
`modules` list). Static package metadata provides inferred candidates when no
explicit declaration covers that boundary. A bounded `droppoint-module` JSON
fence in `README.md`, or `droppoint.interface.json`, supplies an unconfirmed
documented-interface candidate with explicit evidence and open confirmation
questions. Conflicting candidate identities are rejected instead of silently
choosing one. The small
[`synthetic_modules.zip`](tests/fixtures/synthetic_modules.zip) fixture exercises
multiple local candidates; its declarations and synthetic cases are test
material, not live qualifications.

Credentials, private keys, environment files and personal material are excluded
from outgoing declarations where detected. **Detection is fallible.** Inspect
and edit each outgoing declaration, then explicitly approve it before sending.
Do not include secrets or personal information in descriptions, contracts or
evidence paths. Only reviewed declaration JSON is sent to the public test API.

Version `module-manifest/2` adds `dependencies`, `proposedPlacements`, `evidence`,
`extractionMethod` and `unresolvedQuestions` to the original declaration.
Version 1 remains supported for existing callers. The version 2 contract is
[`module_manifest_v2.schema.json`](invariantgatewriter/module_manifest_v2.schema.json).
Version 2 numeric values are safe JSON integers to keep browser and backend
canonicalization identical. The fingerprint identifies the reviewed declaration
snapshot; it neither proves behavior nor independently describes the constraint
architecture.

## Identity, placement and convergence

Two separate reports prevent confusing declaration identity with compatibility:

- **H:** module ID → canonical declaration SHA-512.
- **P:** module ID → proposed engine placements and remaining feasible choices.

These rings are not the gate coordinate allocator. A declaration fingerprint
identifies a snapshot; `receiptSHA512` hashes a signed qualification body for a
particular event and determines its gate coordinate. Different chronological
events for the same declaration may therefore have different gate coordinates.

Placement checks compare declared connection interfaces, backend-known
dependency availability, and inclusion/exclusion constraints. Results record
evidence, unresolved conditions and each narrowing of the feasible set **K**.
A hash alone never establishes physical contact, orbital compatibility or
technology compatibility. Built-in engine interfaces are local synthetic
implementations, not verified remote deployments.

### Versioned parabola mapping

`parabola-sha512/1` reads the first and second two-byte big-endian unsigned
integers from the declaration digest and divides each by 65535 to obtain
`alpha` and `beta`. Thus both coefficients are in [0, 1]:

- `P_A(x) = (1 + alpha) * x²`
- `P_B(x) = (1 + beta) * x²`

Both curves open **upward**, with vertex (0, 0). Writing `a = 1 + alpha` and
`b = 1 + beta`, their foci are (0, 1/(4a)) and (0, 1/(4b)); directrices are
`y = -1/(4a)` and `y = -1/(4b)`. These are abstract topology coordinates, not
physical measurements.

The sandbox is `-1 ≤ x ≤ 1` and `max(a*x², b*x²) ≤ y ≤ 1`.
Its feasible horizontal range is `|x| ≤ sqrt(1/max(a,b))`.
Equal coefficients produce coincident curves, not a unique convergence point.
The UI draws only candidate curves, points and known receipts; it never allocates
the gate's theoretical capacity.

Empty K means **incompatible**. Remaining unresolved conditions mean **pending**.
A completion point is reported only after compatible interfaces, resolved
dependencies/constraints, an explicit reviewed declaration and successful
nonempty synthetic tests satisfy the documented resolution conditions.
The common vertex may then represent completion; plotting it by itself proves
nothing. Partial resolution is a legitimate result, and even local completion
does not authorize a live gate write.

In version 2 responses, top-level `status` is the placement/model assessment.
`syntheticReceipt.status` describes the predefined test execution only. Successful
builtin tests do not override a pending dependency or an incompatible placement.
Configure dependency availability and engine catalogs only in backend node
configuration; manifest claims are not proof that a dependency is deployed.

## Multiple qualification events

Several candidates from one ZIP are assessed independently. A backend trusted
qualification service must decide live admission per candidate; the browser and
public node cannot issue live qualifications. No fixture or synthetic-test
receipt is promoted to a live qualification.

Use one stable opaque qualification event ID per module/event and reuse it for
retries. A new chronological event needs a new ID; declaration identity is its
fingerprint, not its event ID. Retry deduplication and event-content conflicts
remain enforced by the existing transactional gate writer.
The qualifier must return the same qualification body for an event retry,
including its timestamps; changing the body under an existing event ID is a
conflict. Expired qualifications remain invalid, even for duplicates. A genuinely
new qualification event uses a new event ID rather than silently rewriting one.

For a connected backend, import `submit_reviewed_modules` from
`invariantgatewriter.qualification`. Supply 1–100 items containing `declaration`
and `qualificationId`, plus the writer, backend-only qualifier, authorization
callback and trusted caller context. The callback must authenticate and grant
`gate:write`. The qualifier returns a signed qualification or a pending/rejected
decision; the helper binds its event ID and module hash to the reviewed snapshot
before invoking the gate writer. Missing qualifiers return pending, not invented
acceptance. Each item returns success with a placement, pending, or rejection;
successful items remain committed if others fail.

This helper is not exposed by the public API/MCP process. Integrating it into the
real host requires the host's authenticated transport and the actual trusted
qualification-service interface. Its credentials, policy decisions and signing
remain backend-only.

The local UI can display per-module synthetic success, pending and rejection,
identity/placement rings, constraint evidence and the parabola projection.
Receipt coordinates and stack layers are shown only after an actual successful
write through a connected authenticated host bridge. Neither the trusted
qualifier nor that live browser-to-host bridge is connected in this repository.

A deployment can inject the ZIP module's `configureTrustedHostBridge` with
`qualify_reviewed_module(item)`, `droppoint_gate_dry_run(qualification)` and
`submit_reviewed_modules(items)` callbacks.
Each item contains the reviewed `declaration` and stable `qualificationId`.
The qualifier callback calls the actual trusted backend policy service and
returns a qualified envelope or a pending/rejected decision; it is not a
browser signing function. Only a real qualified envelope reaches
`droppoint_gate_dry_run(qualification)`. The public service does not implement
these callbacks or carry signing credentials. New-event/retry controls and
receipt rendering stay disconnected until a trusted host integration supplies
them.