# Standalone module test surface and optional gate writer

The public module test node runs independently. The repository also contains an
optional backend gate writer; it is not required by the standalone module or
business-test surface.

The public module test node is a separate entry point for declarative manifests.
It validates declarations and runs predefined synthetic operations, not uploaded
code. Its receipts are synthetic, unsigned and never enable live gate admission.

To collaborate on this repository with ChatGPT, open
[ChatGPT Codex](https://chatgpt.com/codex) and connect this GitHub repository.

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
- [Business requirements and candidate matching](#business-requirements-and-candidate-matching)
- [Synthetic receipts and deployment status](#synthetic-receipts-and-deployment-status)

## Connection status

The public module node is a standalone service and does not depend on an
InvariantTap host or qualification service. The optional gate writer remains a
separate library; live writes are disabled by default.

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

The standalone surface is `python -m invariantgatewriter.public_node`. It serves
the declaration form at `/`, browser-local ZIP inspection at `/zip`, REST routes
at `/api/validate`, `/api/connections` and `/api/test`, and the public test MCP
tools at `/mcp`. It does not initialize live gate storage or expose live
admission. InvariantTap is not a required host or qualification dependency.

For Internet access, deploy behind a TLS reverse proxy, restrict backend network
access to that proxy and apply additional edge rate/concurrency limits. The
in-process limits are per process, not a distributed anti-abuse system. Do not
trust arbitrary forwarded client-IP headers; only configure a trusted proxy
integration after verifying its behavior. Disable body logging, analytics and
request capture at the proxy as well as the application to preserve transient
processing.

No hosting target or deployment configuration is present in this repository.
The included Dockerfile runs the actual public-node entrypoint:

```sh
docker build -t invariantgatewriter .
docker run --rm -p 8080:8080 \
  -e PUBLIC_ALLOWED_HOSTS=localhost:8080 \
  -e PUBLIC_ALLOWED_ORIGINS=http://localhost:8080 \
  invariantgatewriter
```

Hosting platforms may supply `PORT`, `PUBLIC_ALLOWED_HOSTS` and
`PUBLIC_ALLOWED_ORIGINS` as environment variables. The allowlists are exact,
comma-separated values; they do not trust forwarded headers. For a public
deployment, configure the actual public authority and HTTPS origin, terminate
TLS at a trusted edge, and do not enable body capture. The container has no
third-party runtime dependencies and runs as an unprivileged user.

Or start the local browser/API service from the repository root:

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
forward gate credentials to the public node. ZIP archives and source files are
read in the browser and are never uploaded.

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

Synthetic test event IDs are deduplicated within one running process (up to 4096
recent IDs); retries of retained events return the same receipt hash, while
changed content under a retained event ID is rejected. When full, the least
recently used ID is evicted. The registry retains only declaration and receipt
hashes, not manifests, and is cleared on restart. It is not a cross-process or
durable idempotency service.

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
`extractionMethod`, `unresolvedQuestions` and `businessRequirements` to the
original declaration. Business requirements declare a function and name each
acceptance case; those names must match synthetic test cases. The standalone
form and ZIP review populate typed business inputs and outputs. Legacy v2 API
declarations without this object remain supported by deriving it from the
existing purpose, ports and synthetic tests.
Version 1 remains supported for existing callers. The version 2 contract is
[`module_manifest_v2.schema.json`](invariantgatewriter/module_manifest_v2.schema.json).
Version 2 numeric values are safe JSON integers to keep browser and backend
canonicalization identical. The fingerprint identifies the reviewed declaration
snapshot; it neither proves behavior nor independently describes the constraint
architecture.

## Business requirements and candidate matching

Version 2 declarations bind a stable `moduleId` and full canonical declaration
SHA-512 in `identityRing`. `businessRequirements` declares the function, typed
inputs and outputs, and acceptance-case names; those ports must match the module
contract, and case names must match declared synthetic tests. Connection
signatures and test values are explicitly typed. Booleans are not integers.

Candidate placements are matched against the backend's local predefined interface
catalog by exact input/output port names and types. Synthetic acceptance results
and declared constraints narrow the finite feasible candidate set; response
evidence records each before/after set. These built-ins are not remote deployments
and do not establish production behavior. `pending` means required evidence or
configuration is unresolved; `incompatible` means no candidate remains.

No continuous parabola convergence is calculated or claimed. The standalone
surface reports discrete candidate and evidence sets only. InvariantTap may be
an optional upstream source of snapshots/history for a surrounding application;
the public-node service neither requires that host nor changes its history.

## Synthetic receipts and deployment status

Running acceptance tests returns an unsigned synthetic receipt labeled
`module-synthetic-receipt/2`. Its SHA-512 binds the module identity, business
requirements, declaration evidence, executed test results and resolved discrete
topology. It is a content fingerprint, not a signature, qualification, live
admission, stored gate receipt or proof that uploaded code ran. Only predefined
synthetic operations run.

Each test event accepts an opaque `eventId`. Repeating the same retained ID and
declaration returns the same receipt hash with `duplicate: true`; reusing it for
changed content is rejected. The bounded least-recently-used index is
process-local and retains only hashes. It is not durable across restart or shared
across service replicas; oldest IDs may be evicted after 4096 unique events.

| Status | Result |
| --- | --- |
| Implemented | Standalone declaration form, business requirements, typed synthetic acceptance tests, browser-local ZIP inspection, candidate assessment and unsigned event receipts. |
| Tested | Python regression suite and Node ZIP-intake suite (run from the repository root as documented above). |
| Publicly deployed | No hosting target is configured in this repository and no hosting credentials/access were supplied. |
| Live-admitted | No. Live gate admission remains disabled; no qualification service is invented or required for the standalone test surface. |

The Dockerfile packages the actual `public_node` entrypoint. The only remaining
deployment prerequisite is access to a configured public hosting target (or a
target selected by the repository owner) to build and run that container. Neither
an InvariantTap integration nor qualification credentials are needed to host or
use this service.