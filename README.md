# InvariantTap gate writer

Backend receipt storage and a host-registration adapter for the InvariantTap /
DROPPOINT gate. Only trusted, backend-qualified submissions belong in the live
gate; a module hash or browser-reported acceptance is not qualification.

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

## Existing host connection

The existing host must supply its own MCP transport, authenticated caller
context and backend permission checks. Add the six gate tools without replacing
`droppoint_status`, `droppoint_modules`, `droppoint_test` or `droppoint_verify`.
Existing tool behavior remains the responsibility of the original host, whose
source is not present here.

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