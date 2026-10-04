# invariantgatewriter

Create a repository named invarianttap-gate-writer under harleycameron-rgb, then paste this into its Copilot coding task:

Build the InvariantTap / DROPPOINT gate-writing connector in this repository.
One gate symbol has:
- 2048 × 2048 coordinates.
- Up to 512 receipt layers per coordinate, numbered 0–511.
- Total theoretical capacity: 2,147,483,648 receipts.
- Sparse storage: allocate only occupied positions.
Implement these MCP tools:
1. droppoint_gate_status
2. droppoint_gate_write
3. droppoint_gate_write_batch
4. droppoint_gate_lookup
Find the existing InvariantTap host that exposes droppoint_status,
droppoint_modules, droppoint_test and droppoint_verify. Preserve those
tools. If its source is unavailable, build a standalone connector and
document the exact remaining host integration steps.
Use the host’s existing language, MCP transport and authentication.
Authenticate callers and authorize gate writes on the backend.
Accept only trusted, backend-qualified submission receipts.
A plain SHA-512 hash or browser-reported acceptance is insufficient.
Keep synthetic tests separate from live gate submissions.
Qualification envelopes must contain:
- schema: gate-qualification/1
- gateId: invarianttap-gate-1
- qualificationId: stable unique event ID
- source: qualified-submission
- accepted: true
- policyVersion: supported qualification policy
- moduleSHA512: hash of the module declaration
- issuedAt and expiresAt: integer Unix seconds
Require a backend signature, verify it before writing, and reject
unknown fields, unsupported policies, expired receipts and invalid
signatures. Never expose the signing key or signing function through
the browser or MCP tools.
Hash the canonical qualification body with SHA-512. Map that digest
deterministically to a gate coordinate. Allocate its next layer in
a database transaction. Enforce unique event IDs and unique
coordinate/layer pairs.
Repeated submissions of the same event must return the existing
placement without consuming another layer. Reject reuse of an event
ID with different content. Reject full coordinates without silent
relocation or overflow.
Return:
- gateId
- receiptSHA512
- x and y
- layer
- writtenAt
- duplicate
Support batches of up to 100 qualifications. Return explicit
per-item successes and failures; document partial completion.
Persist receipt hashes, event IDs, placements and timestamps.
Do not accept or retain raw audio, video, images, filenames,
dates of birth or personal details through these tools.
Use this privacy wording:
“No raw media retained; receipt metadata retained.”
Burn Harness is an optional qualification route. Inspect its actual
interface before integrating it. Do not claim it is connected or ran
unless verified. If no trusted qualification service is available,
leave live writes disabled and explain the missing connection.
Add tests for authorization, forged receipts, synthetic rejection,
expiry, concurrent duplicate writes, stack limits, batch failures
and persistence after restart.
Provide a README with setup, secret configuration, test commands
and exact instructions for exposing the tools to the existing
InvariantTap plugin. Keep secrets out of Git and logs.
Do not fabricate receipts to fill the gate. Do not claim theoretical
capacity is tested throughput. Report what was implemented, tested,
connected and still requires deployment.