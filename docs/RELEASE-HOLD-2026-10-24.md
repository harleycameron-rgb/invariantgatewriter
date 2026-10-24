# Gate writer release hold — 2026-10-24

**Decision: HOLD. Live DROPPOINT writes must remain disabled.**

This file records release conditions only. It does not activate the gate, connect a trusted qualification service, or establish production readiness.

## Verified from the repository's published interface description

- Standalone module tests use predefined synthetic operations and issue synthetic, unsigned receipts.
- The optional gate writer has a six-tool interface and an independently required trusted qualification service.
- Live writes are disabled by default. The README does not establish a connection to the InvariantTap host or qualification service.
- Coordinates are 2048 x 2048, with up to 512 layers per coordinate. A full coordinate must reject a write without relocation.
- Retry of an identical event must not allocate a second layer; conflicting event-ID reuse must fail.

## Mandatory pre-release negative checks

- Reject unsigned, expired, malformed, untrusted and mismatched qualifications.
- Reject replay, conflicting event IDs, full stacks and invalid coordinates.
- Prove dry runs and self-tests cannot mutate live placement counts.
- Verify no live credentials, private records or user media enter a public release artifact.
- Confirm that the host, trusted qualification service and transactional storage are connected and independently audited before any live activation.
- Record the exact tested commit, commands, outcomes, and reviewer approval; historical or synthetic tests are not live execution evidence.

## Release handling

Prepare source changes on a review branch only. Do not merge, deploy, enable live writes or advertise a verified gate on the basis of this checklist. Any future activation requires separate explicit approval.
