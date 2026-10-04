import test from "node:test";
import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import {deflateRawSync} from "node:zlib";
import {inspectZip, crc32, LIMITS, canonicalJSON, declarationHash, validateReviewedManifest, safePath, renderConfirmedReceipt} from "../invariantgatewriter/zip_intake.mjs";

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
test("canonical hash deterministic reordered keys, Python Unicode order and safe numbers", async () => {
  const {candidates: [m]} = await inspectZip(zip([explicitFile]));
  const reordered = Object.fromEntries(Object.entries(m).reverse());
  assert.equal(await declarationHash(m), await declarationHash(reordered));
  assert.equal(canonicalJSON({"\u{10000}": 1, "\ue000": 2}), '{"":2,"𐀀":1}');
  assert.throws(() => canonicalJSON({number: 1.5})); assert.throws(() => canonicalJSON({number: Number.MAX_SAFE_INTEGER + 1}));
  assert.throws(() => validateReviewedManifest({...m, evidence: [{reference: "../secret", method: "explicit"}]}));
  assert.throws(() => validateReviewedManifest({...m, proposedPlacements: ["numbers"]}));
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
});
test("live receipt hook rejects absent/untrusted responses", () => {
  assert.throws(() => renderConfirmedReceipt({}, {}));
  assert.throws(() => renderConfirmedReceipt({source: "public-service", liveHostReceipt: {confirmed: true}}, {}));
  assert.equal(safePath("folder/"), "folder/");
});
