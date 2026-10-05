import test from "node:test";
import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import {deflateRawSync} from "node:zlib";
import {inspectZip, crc32, LIMITS, canonicalJSON, declarationHash, validateReviewedManifest, safePath, renderConfirmedReceipt, configureTrustedHostBridge, getTrustedHostBridge, onTrustedHostBridgeChange, hostGatePreview} from "../invariantgatewriter/zip_intake.mjs";

function zip(files) {
  const local = [], central = []; let offset = 0;
  for (const f of files) {
    const name = Buffer.from(f.name), data = Buffer.from(f.text ?? ""), payload = f.deflate ? deflateRawSync(data) : data;
    const crc = f.crc ?? crc32(data), size = f.size ?? data.length;
    const l = Buffer.alloc(30); l.writeUInt32LE(0x04034b50); l.writeUInt16LE(20, 4); l.writeUInt16LE(0x800, 6); l.writeUInt16LE(f.deflate ? 8 : 0, 8);
    l.writeUInt32LE(crc, 14); l.writeUInt32LE(payload.length, 18); l.writeUInt32LE(size, 22); l.writeUInt16LE(name.length, 26);
    const c = Buffer.alloc(46); c.writeUInt32LE(0x02014b50); c.writeUInt16LE(0x314, 4); c.writeUInt16LE(20, 6); c.writeUInt16LE(0x800, 8); c.writeUInt16LE(f.deflate ? 8 : 0, 10);
    c.writeUInt32LE(crc, 16); c.writeUInt32LE(payload.length, 20); c.writeUInt32LE(size, 24); c.writeUInt16LE(name.length, 28);
    c.writeUInt32LE(((f.mode ?? 0x81a4) * 65536) >>> 0, 38); c.writeUInt32LE(f.offset ?? offset, 42);
    local.push(l, name, payload); central.push(c, name); offset += l.length + name.length + payload.length;
  }
  const end = Buffer.alloc(22), cd = Buffer.concat(central);
  end.writeUInt32LE(0x06054b50); end.writeUInt16LE(files.length, 8); end.writeUInt16LE(files.length, 10); end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(offset, 16);
  return new Blob([Buffer.concat([...local, cd, end])]);
}
const declaration = {schema: "module-manifest/1", moduleId: "synthetic.number", version: "1.0.0", purpose: "Synthetic addition", inputs: [], outputs: [], constraints: [], engineConnections: [], syntheticTests: []};
const explicitFile = {name: "droppoint.module.json", text: JSON.stringify(declaration)};
test("fixture extracts two explicit declarations and one unresolved package", async () => {
  const result = await inspectZip(new Blob([await readFile(new URL("fixtures/synthetic_modules.zip", import.meta.url))]));
  assert.equal(result.candidates.length, 3);
  assert.deepEqual(result.candidates.map(c => c.moduleId), ["synthetic.add", "synthetic.concat", "synthetic.inferred"]);
  assert.deepEqual(result.candidates[0].proposedPlacements, ["numbers"]);
  assert.deepEqual(result.candidates[1].proposedPlacements, ["text"]);
  assert.deepEqual(result.candidates[2].proposedPlacements, []);
  assert.equal(result.candidates[2].version, "0.0.0");
  assert.match(result.candidates[2].unresolvedQuestions.join(" "), /purpose.*inputs.*outputs.*version.*dependencies/i);
});
test("stored and deflated declarations, Unicode paths, suppression, multiple declarations", async () => {
  const r = await inspectZip(zip([{name: "unicode-λ/droppoint.module.json", text: JSON.stringify({modules: [declaration, {...declaration, moduleId: "other"}]}), deflate: true}, {name: "unicode-λ/package.json", text: '{"name":"suppressed"}'}]));
  assert.equal(r.candidates.length, 2); assert.deepEqual(r.candidates[0].evidence, []);
});
test("path traversal, absolute, drive, backslash, NUL and symlinks reject", async () => {
  for (const name of ["../a", "/a", "C:a", "x\\a", "a\0b", "a/../b", "a//b", "a/./b"]) await assert.rejects(inspectZip(zip([{name}])));
  await assert.rejects(inspectZip(zip([{name: "link", mode: 0xa1ff}])));
  await assert.rejects(inspectZip(zip([{name: "fifo", mode: 0x11ff}])));
  const disguised = Buffer.from(await zip([{name: "link", mode: 0xa1ff}]).arrayBuffer());
  const central = disguised.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
  disguised[central + 5] = 0;
  await assert.rejects(inspectZip(new Blob([disguised])));
});
test("duplicate names, casefold conflicts and file ancestors reject", async () => {
  for (const names of [["a", "a"], ["a", "A"], ["a", "a/b"], ["a/b", "a"], ["ss", "ß"]]) await assert.rejects(inspectZip(zip(names.map(name => ({name})))));
});
test("CRC, lying sizes, ratio bombs and declared limits reject", async () => {
  await assert.rejects(inspectZip(zip([{...explicitFile, crc: 1}])));
  await assert.rejects(inspectZip(zip([{...explicitFile, deflate: true, size: 1}])));
  await assert.rejects(inspectZip(zip([{name: "bomb", text: "x".repeat(30000), deflate: true}])));
  await assert.rejects(inspectZip(zip([{name: "big", text: "x".repeat(LIMITS.file + 1)}])));
  await assert.rejects(inspectZip(zip(Array.from({length: 257}, (_, i) => ({name: `f${i}`})))));
  await assert.rejects(inspectZip(new Blob([new Uint8Array(LIMITS.archive + 1)])));
  await assert.rejects(inspectZip(zip([{name: "one", text: "abc"}, {name: "two", text: "abc"}]), {limits: {...LIMITS, expanded: 5}}));
});
test("overlap and huge offsets, local mismatch, encryption, multidisk and zip64 reject", async () => {
  await assert.rejects(inspectZip(zip([{name: "same", text: "x"}, {name: "same", offset: 0}])));
  await assert.rejects(inspectZip(zip([{name: "x", offset: 0xffffff00}])));
  const original = Buffer.from(await zip([explicitFile]).arrayBuffer());
  const cd = original.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
  for (const mutate of [
    b => b.writeUInt16LE(1, 6), b => b.writeUInt16LE(1, cd + 8), b => b.writeUInt16LE(1, b.length - 18),
    b => b.writeUInt32LE(0xffffffff, cd + 24), b => b.writeUInt32LE(0, 14),
    b => { b[30] ^= 1; }, b => b.writeUInt16LE(8, cd + 10)
  ]) { const b = Buffer.from(original); mutate(b); await assert.rejects(inspectZip(new Blob([b]))); }
  // Embed a valid local file in another stored file and point its central record inside.
  const inner = Buffer.from(await zip([{name: "inner", text: "abc"}]).arrayBuffer()).subarray(0, 38);
  const overlap = Buffer.from(await zip([{name: "outer", text: inner}, {name: "inner", text: "abc"}]).arrayBuffer());
  const firstCentral = overlap.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
  overlap.writeUInt32LE(35, firstCentral + 46 + 5 + 42);
  await assert.rejects(inspectZip(new Blob([overlap])));
});
test("nested archives and private paths excluded before decoding, privacy never echoed", async () => {
  const r = await inspectZip(zip([explicitFile, {name: ".env", text: "\xff"}, {name: "node_modules/x/package.json", text: '{"name":"ignored"}'}, {name: "personal/photo.jpg", text: "private"}, {name: "inside.zip", text: "not a zip"}, {name: "hidden/package.json", text: '{"name":"hidden","password":"private"}'}, {name: "leak/droppoint.module.json", text: JSON.stringify({...declaration, purpose: "pass" + "word=synthetic-sensitive-example"})}]));
  assert.equal(r.candidates.length, 1); assert.equal(r.exclusions.privatePaths, 3); assert.equal(r.exclusions.nestedArchives, 1);
  assert.ok(r.exclusions.sensitiveContent + r.exclusions.invalidDeclarations >= 2);
  assert.ok(!JSON.stringify(r).includes("synthetic-sensitive-example"));
});
test("inferred dependencies preserve source strings and never invent interface", async () => {
  const r = await inspectZip(zip([{name: "package.json", text: '{"name":"pkg","version":"2.0.0","dependencies":{"other":"^1.2.3"}}'}, {name: "py/pyproject.toml", text: '[project]\nname = "static-py"\nversion = "1.0.0"\n'}]));
  assert.equal(r.candidates.length, 2); assert.deepEqual(r.candidates[0].dependencies, [{moduleId: "other", version: "^1.2.3"}]); assert.deepEqual(r.candidates[0].engineConnections, []);
});
test("unknown explicit keys and recursive secrets never become outgoing", async () => {
  for (const extra of [{privateExtra: "something"}, {syntheticTests: [{name: "t", connection: "c", inputs: {password: "no"}, expectedOutputs: {}}]}, {constraints: [{kind: "x", value: 1.25}]}]) {
    const r = await inspectZip(zip([{...explicitFile, text: JSON.stringify({...declaration, ...extra})}]));
    assert.equal(r.candidates.length, 0);
  }
});
test("bounded documented declarations become unconfirmed static-interface candidates", async () => {
  const readme = "Synthetic interface documentation.\n```droppoint-module\n" + JSON.stringify({...declaration, moduleId: "documented"}) + "\n```\n";
  const result = await inspectZip(zip([{name: "docs/README.md", text: readme}, {name: "contract/droppoint.interface.json", text: JSON.stringify({moduleId: "contract", inputs: [], outputs: []})}]));
  assert.equal(result.candidates.length, 2);
  for (const m of result.candidates) {
    assert.equal(m.extractionMethod, "static-interface");
    assert.equal(m.evidence[0].method, "static-interface");
    assert.match(m.unresolvedQuestions.join(" "), /Confirm.*authoritative/i);
  }
  assert.equal(result.candidates[0].evidence[0].reference, "contract/droppoint.interface.json");
  assert.equal(result.candidates[1].evidence[0].reference, "docs/README.md");
  const bounded = await inspectZip(zip([{name: "README.md", text: "x".repeat(65537)}]));
  assert.equal(bounded.candidates.length, 0); assert.equal(bounded.exclusions.nonDeclarations, 1);
});
test("explicit then interface-file then README precedence never duplicates a package boundary", async () => {
  const docs = "```droppoint-module\n" + JSON.stringify({...declaration, moduleId: "documented"}) + "\n```";
  for (const files of [
    [explicitFile, {name: "droppoint.interface.json", text: JSON.stringify({...declaration, moduleId: "interface"})}, {name: "README.md", text: docs}, {name: "package.json", text: '{"name":"package"}'}],
    [{name: "droppoint.interface.json", text: JSON.stringify({...declaration, moduleId: "interface"})}, {name: "README.md", text: docs}, {name: "package.json", text: '{"name":"package"}'}],
    [{name: "README.md", text: docs}, {name: "package.json", text: '{"name":"package"}'}]
  ]) {
    const result = await inspectZip(zip(files));
    assert.equal(result.candidates.length, 1);
    assert.equal(result.candidates[0].moduleId, files[0] === explicitFile ? declaration.moduleId : files[0].name.endsWith(".json") ? "interface" : "documented");
  }
});
test("conflicting identity groups and ambiguous documented fences are excluded atomically", async () => {
  const result = await inspectZip(zip([
    {name: "one/droppoint.module.json", text: JSON.stringify({modules: [declaration, {...declaration, moduleId: "also-rejected"}]})},
    {name: "two/droppoint.module.json", text: JSON.stringify(declaration)}
  ]));
  assert.equal(result.candidates.length, 0); assert.equal(result.exclusions.invalidDeclarations, 2);
  const duplicate = await inspectZip(zip([{...explicitFile, text: JSON.stringify({modules: [declaration, declaration]})}, {name: "package.json", text: '{"name":"not-fallback"}'}]));
  assert.equal(duplicate.candidates.length, 0); assert.equal(duplicate.exclusions.invalidDeclarations, 1);
  const fence = "```droppoint-module\n" + JSON.stringify(declaration) + "\n```\n";
  const ambiguous = await inspectZip(zip([{name: "README.md", text: fence + fence}, {name: "package.json", text: '{"name":"not-inflated"}'}]));
  assert.equal(ambiguous.candidates.length, 0); assert.equal(ambiguous.exclusions.invalidDeclarations, 1);
});
test("incoming and reviewed module identity/version reject nonstrings before regex coercion", async () => {
  const {candidates: [m]} = await inspectZip(zip([explicitFile]));
  for (const [field, values] of [
    ["moduleId", [["example"], true, false, 123, null]],
    ["version", [["1.0.0"], true, false, 123, null]]
  ]) for (const value of values) {
    assert.throws(() => validateReviewedManifest({...m, [field]: value}));
    const result = await inspectZip(zip([{...explicitFile, text: JSON.stringify({...declaration, [field]: value})}]));
    assert.equal(result.candidates.length, 0);
    assert.equal(result.exclusions.invalidDeclarations, 1);
  }
});
test("scoped package normalization collisions reject both claims independent of archive order", async () => {
  const files = [
    {name: "scoped/package.json", text: '{"name":"@scope/name","version":"1.0.0"}'},
    {name: "dotted/package.json", text: '{"name":"scope.name","version":"1.0.0"}'}
  ];
  for (const ordered of [files, [...files].reverse()]) {
    const result = await inspectZip(zip(ordered));
    assert.equal(result.candidates.length, 0);
    assert.equal(result.exclusions.invalidDeclarations, 2);
  }
});
test("private documentation is not decoded and inspected documentation CRC is mandatory", async () => {
  const doc = "```droppoint-module\n" + JSON.stringify(declaration) + "\n```";
  await assert.rejects(inspectZip(zip([{name: "README.md", text: doc, crc: 1}])));
  const result = await inspectZip(zip([{name: "personal/README.md", text: doc, crc: 1}, {name: "inside.tar", text: doc, crc: 1}]));
  assert.equal(result.candidates.length, 0); assert.equal(result.exclusions.privatePaths, 1); assert.equal(result.exclusions.nestedArchives, 1);
});
test("canonical hash deterministic reordered keys, Python Unicode order and safe numbers", async () => {
  const {candidates: [m]} = await inspectZip(zip([explicitFile]));
  const reordered = Object.fromEntries(Object.entries(m).reverse());
  assert.equal(await declarationHash(m), await declarationHash(reordered));
  assert.equal(canonicalJSON({"\u{10000}": 1, "\ue000": 2}), '{"":2,"𐀀":1}');
  assert.throws(() => canonicalJSON({number: 1.5})); assert.throws(() => canonicalJSON({number: Number.MAX_SAFE_INTEGER + 1}));
  assert.throws(() => validateReviewedManifest({...m, evidence: [{reference: "../secret", method: "explicit"}]}));
  assert.throws(() => validateReviewedManifest({...m, proposedPlacements: ["numbers"]}));
});
test("business requirement ports compare independent of object key order", async () => {
  const {candidates: [m]} = await inspectZip(new Blob([
    await readFile(new URL("fixtures/synthetic_modules.zip", import.meta.url))
  ]));
  const requirements = {
    ...m.businessRequirements,
    inputs: m.businessRequirements.inputs.map(({name, type}) => ({type, name})),
    outputs: m.businessRequirements.outputs.map(({name, type}) => ({type, name}))
  };
  assert.doesNotThrow(() => validateReviewedManifest({...m, businessRequirements: requirements}));
});
test("v2 Unicode accepts emoji, rejects formatting/control characters and non-ASCII object keys", async () => {
  const {candidates: [m]} = await inspectZip(zip([explicitFile]));
  assert.equal(validateReviewedManifest({...m, purpose: "Synthetic emoji 🌱"}).purpose, "Synthetic emoji 🌱");
  for (const value of ["hidden\u202e", "line\u2028break", "paragraph\u2029break", "nul\0", "surrogate\ud800"]) {
    assert.throws(() => validateReviewedManifest({...m, purpose: value}));
  }
  assert.throws(() => validateReviewedManifest({...m, syntheticTests: [{name: "t", connection: "c", inputs: {"λ": 1}, expectedOutputs: {}}]}));
  for (const reference of [".azure/droppoint.module.json", ".npmrc/droppoint.module.json", ".git-private/droppoint.module.json", "secrets-dir/droppoint.module.json", "cert.pem/droppoint.module.json", "a%20b/droppoint.module.json"]) {
    assert.throws(() => validateReviewedManifest({...m, evidence: [{reference, method: "explicit-declaration"}]}));
  }
});
test("known interface names without actual supported IO never propose placement", async () => {
  const r = await inspectZip(zip([{...explicitFile, text: JSON.stringify({...declaration, engineConnections: [{name: "wrong", interface: "numbers.add/1", required: true, inputs: [], outputs: []}]})}]));
  assert.deepEqual(r.candidates[0].proposedPlacements, []);
});
test("working references released on success and failure; original Blob unchanged", async () => {
  const blob = zip([explicitFile]), before = Buffer.from(await blob.arrayBuffer()); let released;
  await inspectZip(blob, {onRelease: state => { released = state; }});
  assert.ok(Object.values(released).every(v => v === null)); assert.deepEqual(Buffer.from(await blob.arrayBuffer()), before);
  await assert.rejects(inspectZip(zip([{name: "../bad"}]), {onRelease: state => { released = state; }}));
  assert.ok(Object.values(released).every(v => v === null));
  const controller = new AbortController(); controller.abort();
  await assert.rejects(inspectZip(blob, {signal: controller.signal, onRelease: state => { released = state; }}));
  assert.ok(Object.values(released).every(v => v === null));
});
test("live receipt hook rejects absent/untrusted responses", () => {
  assert.throws(() => renderConfirmedReceipt({}, {}));
  assert.throws(() => renderConfirmedReceipt({source: "public-service", liveHostReceipt: {confirmed: true}}, {}));
  assert.equal(safePath("folder/"), "folder/");
});
test("host bridge defaults disconnected, accepts functions not pasted JSON, and renders only real receipt shape", () => {
  assert.equal(getTrustedHostBridge(), null);
  assert.throws(() => configureTrustedHostBridge({status: "success"}));
  const changes = [], unsubscribe = onTrustedHostBridgeChange(bridge => changes.push(bridge));
  const bridge = {submit_reviewed_modules: async () => []};
  configureTrustedHostBridge(bridge);
  const target = {textContent: ""}, expected = {moduleId: "synthetic.add", qualificationId: "opaque-event", moduleSHA512: "b".repeat(128)};
  const response = {...expected, status: "success", receipt: {gateId: "invarianttap-gate-1", receiptSHA512: "a".repeat(128), x: 2047, y: 0, layer: 511, writtenAt: 1720000000, duplicate: false}};
  renderConfirmedReceipt(response, target, expected);
  assert.match(target.textContent, /Coordinate: \(2047, 0\)/);
  for (const altered of [
    {...response, status: "pending"}, {...response, status: "qualified"}, {...response, qualificationId: "different"}, {...response, moduleSHA512: "c".repeat(128)},
    {...response, receipt: {...response.receipt, synthetic: true}},
    {...response, receipt: {...response.receipt, dryRun: true}},
    {...response, receipt: {...response.receipt, layer: 512}},
    {...response, receipt: {...response.receipt, x: -1}}
  ]) assert.throws(() => renderConfirmedReceipt(altered, target, expected));
  configureTrustedHostBridge(null);
  assert.throws(() => renderConfirmedReceipt(response, target, expected));
  unsubscribe(); assert.equal(changes.length, 2);
});
test("host dry-run never passes a manifest as qualification or invents an envelope", async () => {
  const {candidates: [m]} = await inspectZip(zip([explicitFile]));
  const item = {declaration: m, qualificationId: "opaque-event"};
  assert.deepEqual(await hostGatePreview(null, item), {status: "pending", code: "qualification_service_unconnected"});
  let calls = 0;
  const envelope = {schema: "gate-qualification/1", gateId: "invarianttap-gate-1", qualificationId: item.qualificationId, source: "qualified-submission", accepted: true, policyVersion: "test-policy", moduleSHA512: await declarationHash(m), issuedAt: 1720000000, expiresAt: 1720000100, signature: "a".repeat(128)};
  const bridge = {
    qualify_reviewed_module: async received => { assert.equal(received, item); return {status: "qualified", qualification: envelope}; },
    droppoint_gate_dry_run: async qualification => { calls++; assert.equal(qualification, envelope); assert.equal(qualification.schema, "gate-qualification/1"); return {dryRun: true}; }
  };
  configureTrustedHostBridge(bridge);
  assert.deepEqual(await hostGatePreview(bridge, item), {dryRun: true});
  bridge.qualify_reviewed_module = async () => ({status: "pending"});
  assert.deepEqual(await hostGatePreview(bridge, item), {status: "pending"});
  bridge.qualify_reviewed_module = async () => ({status: "qualified", qualification: m});
  await assert.rejects(hostGatePreview(bridge, item));
  assert.equal(calls, 1);
  configureTrustedHostBridge(null);
});
test("host dry-run accepts keyed /2 envelopes and rejects schema/keyId mismatches", async () => {
  const {candidates: [m]} = await inspectZip(zip([explicitFile]));
  const item = {declaration: m, qualificationId: "opaque-event-v2"};
  const base = {gateId: "invarianttap-gate-1", qualificationId: item.qualificationId, source: "qualified-submission", accepted: true, policyVersion: "test-policy", moduleSHA512: await declarationHash(m), issuedAt: 1720000000, expiresAt: 1720000100, signature: "a".repeat(128)};
  let envelope = null, calls = 0;
  const bridge = {
    qualify_reviewed_module: async () => ({status: "qualified", qualification: envelope}),
    droppoint_gate_dry_run: async qualification => { calls++; assert.equal(qualification, envelope); return {dryRun: true}; }
  };
  configureTrustedHostBridge(bridge);
  envelope = {...base, schema: "gate-qualification/2", keyId: "ed-2026-10"};
  assert.deepEqual(await hostGatePreview(bridge, item), {dryRun: true});
  for (const bad of [
    {...base, schema: "gate-qualification/2"},
    {...base, schema: "gate-qualification/1", keyId: "ed-2026-10"},
    {...base, schema: "gate-qualification/2", keyId: "../ed"},
    {...base, schema: "gate-qualification/2", keyId: ""},
    {...base, schema: "gate-qualification/2", keyId: 7},
    {...base, schema: "gate-qualification/2", keyId: "ed-2026-10", alg: "none"},
    {...base, schema: "gate-qualification/2", keyId: "ed-2026-10", signature: "A".repeat(128)}
  ]) { envelope = bad; await assert.rejects(hostGatePreview(bridge, item)); }
  assert.equal(calls, 1);
  configureTrustedHostBridge(null);
});
