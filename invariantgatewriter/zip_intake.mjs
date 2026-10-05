/* ZIP bytes and source text stay local; only reviewed declarations leave this module. */
export const LIMITS = Object.freeze({archive: 8 * 1024 * 1024, expanded: 16 * 1024 * 1024, files: 256, file: 1024 * 1024, ratio: 100});
const fail = () => { throw new Error("Archive or declaration rejected by local safety checks."); };
const decoder = new TextDecoder("utf-8", {fatal: true});
const sensitive = /(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|(?:password|passwd|secret|api[_-]?key|access[_-]?token|authorization|credential)\s*[:=]\s*\S+|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\bgh[pousr]_[A-Za-z0-9]{20,}|\bsk-[A-Za-z0-9]{20,}|\bBearer\s+[A-Za-z0-9._~-]{12,}|:\/\/[^/\s:@]+:[^/\s@]+@|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|(?:^|\n)\s*(?:export\s+)?[A-Z][A-Z0-9_]*(?:TOKEN|KEY|PASSWORD|SECRET)\s*=)/i;
const secretKey = /(?:password|passwd|secret|api[_-]?key|access[_-]?(?:token|key)|authorization|credentials?|private[_-]?key|(?:^|[_-])token$|^(?:env|environment)$)/i;
const nested = /\.(?:zip|tar|gz|gzip|tgz|bz2|bzip2|xz|lzma|lz|7z|rar|jar|war|whl|zst|cab|iso|dmg|deb|rpm|apk|epub|docx|xlsx|pptx|odt|ods|odp)$/i;
const excludedPath = /(?:^|\/)(?:\.env(?:[./]|$)|\.git(?:\/|$)|node_modules(?:\/|$)|vendor(?:\/|$)|\.ssh(?:\/|$)|\.aws(?:\/|$)|\.config(?:\/|$)|home(?:\/|$)|users?(?:\/|$)|private(?:\/|$)|personal(?:\/|$)|credentials?[^/]*|secrets?[^/]*|keys?(?:\.[^/]*)?|id_rsa[^/]*|id_ed25519[^/]*|[^/]*\.(?:pem|key|p12|pfx|jpg|jpeg|png|gif|mp4|mov|mp3|wav|pdf))$/i;
const keys = ["schema", "moduleId", "version", "purpose", "inputs", "outputs", "constraints", "engineConnections", "syntheticTests", "dependencies", "proposedPlacements", "evidence", "extractionMethod", "unresolvedQuestions", "businessRequirements"];
const interfaces = {"identity/1": "identity", "numbers.add/1": "numbers", "text.concat/1": "text", "boolean.not/1": "boolean"};
const contracts = {
  "identity/1": [{value: "string"}, {value: "string"}],
  "numbers.add/1": [{a: "number", b: "number"}, {sum: "number"}],
  "text.concat/1": [{left: "string", right: "string"}, {result: "string"}],
  "boolean.not/1": [{value: "boolean"}, {value: "boolean"}]
};
function supportedConnection(c) {
  const contract = contracts[c.interface];
  return contract && ["inputs", "outputs"].every((field, i) => Array.isArray(c[field]) && c[field].length === Object.keys(contract[i]).length && c[field].every(p => contract[i][p.name] === p.type) && new Set(c[field].map(p => p.name)).size === c[field].length);
}
export function safePath(name) {
  if (!name || name.includes("\\") || name.includes("\0") || name.startsWith("/") || /^[A-Za-z]:/.test(name) || name.split("/").some((p, i, parts) => p === ".." || p === "." || (!p && i !== parts.length - 1))) fail();
  if (/[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]/u.test(name)) fail();
  if (name.split("/").some(p => /:/.test(p) || ["..", "."].includes(p.normalize("NFKC")))) fail();
  return name;
}
function privatePath(name) {
  return excludedPath.test(name) || name.split("/").some(p => /^(?:\.env|\.git|credentials?|secrets?|id_rsa|id_ed25519)/i.test(p) || /^(?:node_modules|vendor|\.ssh|\.aws|\.azure|\.npmrc|\.netrc|\.pypirc|\.config|home|users?|private|personal)$/i.test(p) || /\.(?:pem|key|p12|pfx|jpg|jpeg|png|gif|mp4|mov|mp3|wav|pdf)$/i.test(p));
}
function evidencePath(name) {
  return !privatePath(name) && /^[A-Za-z0-9._/-]+$/.test(name) && !/(?:@|(?:^|\/)(?:downloads|documents|desktop)(?:\/|$))/i.test(name);
}
export function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
  }
  return (crc ^ 0xffffffff) >>> 0;
}
function zipName(bytes, flags) {
  if (!(flags & 0x800) && bytes.some(b => b > 127)) fail();
  return safePath(decoder.decode(bytes));
}
function extraCheck(bytes) {
  const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  for (let i = 0; i < bytes.length;) {
    if (i + 4 > bytes.length) fail();
    const id = v.getUint16(i, true), len = v.getUint16(i + 2, true);
    if (id === 1 || id === 0x7075 || i + 4 + len > bytes.length) fail();
    i += 4 + len;
  }
}
function parseZip(buffer, limits) {
  const bytes = new Uint8Array(buffer), v = new DataView(buffer);
  const u16 = p => v.getUint16(p, true), u32 = p => v.getUint32(p, true);
  if (bytes.length < 22 || bytes.length > limits.archive) fail();
  let end = -1;
  for (let p = bytes.length - 22; p >= Math.max(0, bytes.length - 65557); p--) {
    if (u32(p) === 0x06054b50 && p + 22 + u16(p + 20) === bytes.length) { end = p; break; }
  }
  if (end < 0 || u16(end + 4) || u16(end + 6) || u16(end + 8) !== u16(end + 10)) fail();
  const count = u16(end + 10), length = u32(end + 12), start = u32(end + 16);
  if (count === 65535 || count > limits.files || start + length !== end || start > end || length === 0xffffffff) fail();
  const entries = [], names = new Set(), ranges = [];
  let p = start, total = 0;
  for (let n = 0; n < count; n++) {
    if (p + 46 > end || u32(p) !== 0x02014b50) fail();
    const flags = u16(p + 8), method = u16(p + 10), crc = u32(p + 16);
    const compressed = u32(p + 20), size = u32(p + 24), nl = u16(p + 28), el = u16(p + 30), cl = u16(p + 32), offset = u32(p + 42);
    if (flags & ~0x808 || ![0, 8].includes(method) || u16(p + 34) || p + 46 + nl + el + cl > end || size === 0xffffffff || compressed === 0xffffffff || offset === 0xffffffff) fail();
    const name = zipName(bytes.subarray(p + 46, p + 46 + nl), flags);
    extraCheck(bytes.subarray(p + 46 + nl, p + 46 + nl + el));
    const mode = u32(p + 38) >>> 16, type = mode & 0xf000;
    if ((type && type !== 0x8000 && type !== 0x4000) || (mode & 0xe00) || (u32(p + 38) & 0x400)) fail();
    if ((type === 0x4000 && !name.endsWith("/")) || (type === 0x8000 && name.endsWith("/")) || (name.endsWith("/") && (size || compressed || crc))) fail();
    const folded = name.normalize("NFKC").toUpperCase().toLowerCase().replace(/\/$/, "");
    if (names.has(folded) || [...names].some(other => other.startsWith(folded + "/") && !name.endsWith("/"))) fail();
    // A file may never also be an ancestor of another entry.
    if (entries.some(e => !e.name.endsWith("/") && folded.startsWith(e.folded + "/"))) fail();
    names.add(folded);
    total += size;
    if (size > limits.file || total > limits.expanded || size > compressed * limits.ratio || (method === 0 && size !== compressed)) fail();
    if (offset + 30 > start || u32(offset) !== 0x04034b50 || u16(offset + 6) !== flags || u16(offset + 8) !== method) fail();
    const lnl = u16(offset + 26), lel = u16(offset + 28), data = offset + 30 + lnl + lel;
    if (data + compressed > start || lnl !== nl || zipName(bytes.subarray(offset + 30, offset + 30 + lnl), flags) !== name) fail();
    extraCheck(bytes.subarray(offset + 30 + lnl, data));
    let stop = data + compressed;
    if (flags & 8) {
      if (![0, crc].includes(u32(offset + 14)) || ![0, compressed].includes(u32(offset + 18)) || ![0, size].includes(u32(offset + 22))) fail();
      if (stop + 12 > start) fail();
      if (u32(stop) === 0x08074b50) stop += 4;
      if (stop + 12 > start || u32(stop) !== crc || u32(stop + 4) !== compressed || u32(stop + 8) !== size) fail();
      stop += 12;
    } else if (u32(offset + 14) !== crc || u32(offset + 18) !== compressed || u32(offset + 22) !== size) fail();
    if (ranges.some(([lo, hi]) => offset < hi && stop > lo)) fail();
    ranges.push([offset, stop]);
    entries.push({name, folded, method, size, compressed, crc, data});
    p += 46 + nl + el + cl;
  }
  if (p !== end) fail();
  return {bytes, entries};
}
async function inflate(entry, bytes, limits, budget, signal) {
  let reader, chunks = [], size = 0;
  const abort = () => { reader?.cancel().catch(() => {}); };
  try {
    signal?.throwIfAborted();
    const source = new Blob([bytes.subarray(entry.data, entry.data + entry.compressed)]).stream();
    reader = (entry.method === 8 ? source.pipeThrough(new DecompressionStream("deflate-raw")) : source).getReader();
    signal?.addEventListener("abort", abort, {once: true});
    for (;;) {
      const {value, done} = await reader.read();
      signal?.throwIfAborted();
      if (done) break;
      size += value.byteLength;
      if (size > entry.size || size > limits.file || size > entry.compressed * limits.ratio || budget.used + size > limits.expanded) fail();
      chunks.push(value);
    }
    if (size !== entry.size) fail();
    const result = new Uint8Array(size);
    let p = 0;
    for (const chunk of chunks) { result.set(chunk, p); p += chunk.length; }
    if (crc32(result) !== entry.crc) fail();
    budget.used += size;
    return result;
  } finally {
    signal?.removeEventListener("abort", abort);
    if (reader) { await reader.cancel().catch(() => {}); reader.releaseLock(); }
    chunks.length = 0;
    reader = null;
  }
}
function object(value, allowed, required = allowed) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).some(k => !allowed.includes(k)) || required.some(k => !Object.hasOwn(value, k))) fail();
}
function scan(value, depth = 0) {
  if (depth > 12) fail();
  if (typeof value === "string" && (sensitive.test(value) || value.length > 4096 || /[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]/u.test(value) || /[\ud800-\udfff]/u.test(value.replace(/[\ud800-\udbff][\udc00-\udfff]/g, "")))) fail();
  if (typeof value === "number" && (!Number.isSafeInteger(value) || Object.is(value, -0))) fail();
  if (Array.isArray(value) && value.length > 256) fail();
  if (value && typeof value === "object") for (const [k, v] of Object.entries(value)) {
    if (secretKey.test(k) || sensitive.test(k)) fail();
    scan(k, depth + 1); scan(v, depth + 1);
  }
}
function list(value, allowed, required = allowed) {
  if (!Array.isArray(value)) fail();
  for (const item of value) object(item, allowed, required);
}
export function validateReviewedManifest(m) {
  object(m, keys);
  scan(m);
  const asciiKeys = value => {
    if (value && typeof value === "object") for (const [key, child] of Object.entries(value)) {
      if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(key)) fail();
      asciiKeys(child);
    }
  };
  asciiKeys(m);
  if (m.schema !== "module-manifest/2" || typeof m.moduleId !== "string" || typeof m.version !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(m.moduleId) || !/^\d+\.\d+\.\d+$/.test(m.version) || typeof m.purpose !== "string" || !m.purpose || !["explicit-declaration", "package-boundary", "static-interface"].includes(m.extractionMethod)) fail();
  object(m.businessRequirements, ["function", "inputs", "outputs", "acceptanceCases"]);
  if (typeof m.businessRequirements.function !== "string" || !m.businessRequirements.function.trim() || canonicalJSON(m.businessRequirements.inputs) !== canonicalJSON(m.inputs) || canonicalJSON(m.businessRequirements.outputs) !== canonicalJSON(m.outputs) || !Array.isArray(m.businessRequirements.acceptanceCases) || m.businessRequirements.acceptanceCases.length > 64 || new Set(m.businessRequirements.acceptanceCases).size !== m.businessRequirements.acceptanceCases.length || m.businessRequirements.acceptanceCases.some(name => typeof name !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(name)) || JSON.stringify(m.businessRequirements.acceptanceCases) !== JSON.stringify(m.syntheticTests.map(test => test.name))) fail();
  for (const field of ["inputs", "outputs"]) list(m[field], ["name", "type"]);
  const ports = values => {
    const names = new Set();
    if (values.length > 32) fail();
    for (const p of values) {
      if (typeof p.name !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(p.name) || names.has(p.name) || !["string", "number", "integer", "boolean"].includes(p.type)) fail();
      names.add(p.name);
    }
  };
  ports(m.inputs); ports(m.outputs);
  list(m.constraints, ["kind", "value"]);
  list(m.engineConnections, ["name", "interface", "required", "inputs", "outputs"]);
  for (const c of m.engineConnections) {
    list(c.inputs, ["name", "type"]); list(c.outputs, ["name", "type"]); ports(c.inputs); ports(c.outputs);
    if (typeof c.name !== "string" || typeof c.interface !== "string" || typeof c.required !== "boolean") fail();
  }
  list(m.syntheticTests, ["name", "connection", "inputs", "expectedOutputs"]);
  list(m.dependencies, ["moduleId", "version"]);
  for (const d of m.dependencies) if (typeof d.moduleId !== "string" || !d.moduleId || typeof d.version !== "string" || !d.version) fail();
  for (const t of m.syntheticTests) {
    if (typeof t.name !== "string" || typeof t.connection !== "string") fail();
    for (const field of ["inputs", "expectedOutputs"]) {
      const v = t[field];
      if (!v || typeof v !== "object" || Array.isArray(v) || Object.values(v).some(x => !["string", "number", "boolean"].includes(typeof x))) fail();
    }
  }
  list(m.evidence, ["reference", "method"]);
  for (const e of m.evidence) if (typeof e.reference !== "string" || !evidencePath(safePath(e.reference)) || typeof e.method !== "string") fail();
  for (const field of ["proposedPlacements", "unresolvedQuestions"]) if (!Array.isArray(m[field]) || m[field].some(x => typeof x !== "string")) fail();
  if (m.proposedPlacements.some(x => !Object.values(interfaces).includes(x) || !m.engineConnections.some(c => supportedConnection(c) && interfaces[c.interface] === x))) fail();
  for (const c of m.constraints) {
    if (typeof c.kind !== "string" || !c.kind || (c.value !== null && !["string", "number", "boolean"].includes(typeof c.value))) fail();
    if (["includeEngine", "excludeEngine"].includes(c.kind) && typeof c.value !== "string") fail();
  }
  if (m.purpose === "Purpose not declared" && !m.unresolvedQuestions.some(q => /purpose/i.test(q))) fail();
  if (new TextEncoder().encode(JSON.stringify(m)).length > 65536) fail();
  return m;
}
function codepointCompare(a, b) {
  const aa = Array.from(a, c => c.codePointAt(0)), bb = Array.from(b, c => c.codePointAt(0));
  for (let i = 0; i < Math.min(aa.length, bb.length); i++) if (aa[i] !== bb[i]) return aa[i] - bb[i];
  return aa.length - bb.length;
}
export function canonicalJSON(value) {
  scan(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalJSON).join(",") + "]";
  if (value && typeof value === "object") return "{" + Object.keys(value).sort(codepointCompare).map(k => JSON.stringify(k) + ":" + canonicalJSON(value[k])).join(",") + "}";
  if (value === null || ["string", "number", "boolean"].includes(typeof value)) return JSON.stringify(value);
  fail();
}
export async function declarationHash(manifest) {
  validateReviewedManifest(manifest);
  return [...new Uint8Array(await crypto.subtle.digest("SHA-512", new TextEncoder().encode(canonicalJSON(manifest))))].map(b => b.toString(16).padStart(2, "0")).join("");
}
function explicit(raw, path) {
  object(raw, keys, ["moduleId"]);
  scan(raw);
  if (typeof raw.moduleId !== "string" || (Object.hasOwn(raw, "version") && typeof raw.version !== "string")) fail();
  if (raw.schema !== undefined && !["module-manifest/1", "module-manifest/2"].includes(raw.schema)) fail();
  const questions = [...(raw.unresolvedQuestions ?? [])];
  if (!raw.purpose) questions.push("What is the module purpose?");
  if (!raw.version) questions.push("What is the module version?");
  for (const field of ["inputs", "outputs", "dependencies"]) if (!Object.hasOwn(raw, field)) questions.push(`What are the ${field}?`);
  const m = {
    schema: "module-manifest/2", moduleId: raw.moduleId, version: raw.version ?? "0.0.0",
    purpose: raw.purpose || "Purpose not declared", inputs: raw.inputs ?? [], outputs: raw.outputs ?? [],
    constraints: raw.constraints ?? [], engineConnections: raw.engineConnections ?? [], syntheticTests: raw.syntheticTests ?? [],
    dependencies: raw.dependencies ?? [], proposedPlacements: [],
    evidence: evidencePath(path) ? [{reference: path, method: "explicit-declaration"}] : [],
    extractionMethod: "explicit-declaration", unresolvedQuestions: questions,
    businessRequirements: raw.businessRequirements ?? {
      function: raw.purpose || "Function not declared",
      inputs: raw.inputs ?? [],
      outputs: raw.outputs ?? [],
      acceptanceCases: (raw.syntheticTests ?? []).map(test => test.name)
    }
  };
  if (!m.businessRequirements.function || m.businessRequirements.function === "Function not declared") questions.push("What business function must this module perform?");
  if (!m.businessRequirements.acceptanceCases.length) questions.push("What business acceptance cases must pass?");
  m.proposedPlacements = [...new Set(m.engineConnections.filter(supportedConnection).map(c => interfaces[c.interface]))];
  return validateReviewedManifest(m);
}
function inferred(raw, path, toml = false) {
  scan(raw);
  const name = raw.name, questions = ["What is the module purpose?", "What are the inputs?", "What are the outputs?", "Which engine interfaces and synthetic tests are declared?"];
  if (typeof name !== "string" || !name) return null;
  const moduleId = name.replace(/^@/, "").replace(/\//g, ".");
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(moduleId)) return null;
  const knownVersion = typeof raw.version === "string" && /^\d+\.\d+\.\d+$/.test(raw.version);
  if (!knownVersion) questions.push("What is the module version? The source version is missing or not a three-part numeric version.");
  const deps = [];
  if (toml || !Object.hasOwn(raw, "dependencies")) questions.push("What are the dependencies?");
  else {
    if (!raw.dependencies || typeof raw.dependencies !== "object" || Array.isArray(raw.dependencies)) fail();
    for (const [moduleId, version] of Object.entries(raw.dependencies)) {
      if (typeof version !== "string") fail();
      deps.push({moduleId, version});
    }
  }
  return validateReviewedManifest({schema: "module-manifest/2", moduleId, version: knownVersion ? raw.version : "0.0.0", purpose: "Purpose not declared", inputs: [], outputs: [], constraints: [], engineConnections: [], syntheticTests: [], dependencies: deps, proposedPlacements: [], evidence: evidencePath(path) ? [{reference: path, method: "package-boundary"}] : [], extractionMethod: "package-boundary", unresolvedQuestions: [...questions, "What business function must this module perform?", "What business acceptance cases must pass?"], businessRequirements: {function: "Function not declared", inputs: [], outputs: [], acceptanceCases: []}});
}
function extract(texts, exclusions) {
  const groups = [], occupied = new Set();
  const directory = path => path.slice(0, path.lastIndexOf("/") + 1);
  const declarations = raw => {
    const items = raw && Object.hasOwn(raw, "modules") ? (object(raw, ["modules"]), raw.modules) : [raw];
    if (!Array.isArray(items) || !items.length || items.length > LIMITS.files) fail();
    return items;
  };
  const group = (items, path, documented = false) => {
    // Ambiguous documentation is never split into extra package candidates.
    if (documented && items.length !== 1) fail();
    const local = items.map(raw => {
      const m = explicit(raw, path);
      if (documented) {
        m.extractionMethod = "static-interface";
        m.evidence = evidencePath(path) ? [{reference: path, method: "static-interface"}] : [];
        m.unresolvedQuestions.push("Confirm this documented interface with an authoritative explicit module declaration.");
        validateReviewedManifest(m);
      }
      return m;
    });
    if (new Set(local.map(m => m.moduleId)).size !== local.length) fail();
    groups.push(local);
  };
  for (const [path, text] of texts) {
    if (!/(?:^|\/)(?:droppoint\.module\.json|module-manifest(?:\.[^/]*)?\.json)$/.test(path)) continue;
    occupied.add(directory(path));
    try {
      group(declarations(JSON.parse(text)), path);
    } catch { exclusions.invalidDeclarations++; }
  }
  // Authoritative declarations win; a documented interface replaces, never duplicates,
  // its package boundary. Interface files take precedence over README fences.
  for (const [path, text] of texts) {
    if (!/(?:^|\/)droppoint\.interface\.json$/.test(path) || occupied.has(directory(path))) continue;
    occupied.add(directory(path));
    try { group(declarations(JSON.parse(text)), path, true); }
    catch { exclusions.invalidDeclarations++; }
  }
  for (const [path, text] of texts) {
    if (!/(?:^|\/)README\.md$/i.test(path) || occupied.has(directory(path))) continue;
    const fences = [...text.matchAll(/^```droppoint-module[ \t]*\r?\n([\s\S]*?)^```[ \t]*\r?$/gm)];
    if (!fences.length) continue;
    occupied.add(directory(path));
    try {
      if (fences.length !== 1) fail();
      group(declarations(JSON.parse(fences[0][1])), path, true);
    } catch { exclusions.invalidDeclarations++; }
  }
  for (const [path, text] of texts) {
    const dir = directory(path);
    if (occupied.has(dir)) continue;
    try {
      if (/(?:^|\/)package\.json$/.test(path)) {
        const m = inferred(JSON.parse(text), path);
        if (m) { groups.push([m]); occupied.add(dir); }
      }
      if (/(?:^|\/)pyproject\.toml$/.test(path) && !texts.has(dir + "package.json")) {
        const section = text.match(/^\[project\]\s*\n([\s\S]*?)(?=^\[|(?![\s\S]))/m)?.[1];
        if (section) {
          const m = inferred({name: section.match(/^name\s*=\s*"([^"\n]*)"\s*$/m)?.[1], version: section.match(/^version\s*=\s*"([^"\n]*)"\s*$/m)?.[1]}, path, true);
          if (m) { groups.push([m]); occupied.add(dir); }
        }
      }
    } catch { exclusions.invalidDeclarations++; }
  }
  const counts = new Map(), candidates = [];
  for (const members of groups) for (const m of members) counts.set(m.moduleId, (counts.get(m.moduleId) ?? 0) + 1);
  for (const members of groups) {
    // Reject both colliding groups; never quietly retain the first identity claim.
    if (members.some(m => counts.get(m.moduleId) > 1)) { exclusions.invalidDeclarations++; continue; }
    candidates.push(...members);
  }
  if (candidates.length > LIMITS.files) fail();
  return candidates;
}
export async function inspectZip(blob, {limits = LIMITS, onRelease, signal} = {}) {
  let buffer = null, bytes = null, entries = [], texts = new Map();
  const exclusions = {privatePaths: 0, nestedArchives: 0, sensitiveContent: 0, nonDeclarations: 0, invalidDeclarations: 0};
  try {
    signal?.throwIfAborted();
    if (!blob || blob.size > limits.archive) fail();
    buffer = await blob.arrayBuffer();
    signal?.throwIfAborted();
    ({bytes, entries} = parseZip(buffer, limits));
    const budget = {used: 0};
    for (const entry of entries) {
      signal?.throwIfAborted();
      // Never decode excluded source paths or nested archives.
      if (privatePath(entry.name)) { exclusions.privatePaths++; continue; }
      if (nested.test(entry.name)) { exclusions.nestedArchives++; continue; }
      if (entry.name.endsWith("/")) continue;
      let expanded = await inflate(entry, bytes, limits, budget, signal);
      try {
        const readme = /(?:^|\/)README\.md$/i.test(entry.name);
        if ((!readme && !/(?:^|\/)(?:droppoint\.module\.json|droppoint\.interface\.json|module-manifest(?:\.[^/]*)?\.json|package\.json|pyproject\.toml)$/.test(entry.name)) || (readme && expanded.length > 65536)) { exclusions.nonDeclarations++; continue; }
        const text = decoder.decode(expanded);
        if (sensitive.test(text)) { exclusions.sensitiveContent++; continue; }
        texts.set(entry.name, text);
      } finally { expanded = null; }
    }
    return {candidates: extract(texts, exclusions), exclusions};
  } finally {
    texts.clear(); texts = null; entries.length = 0; entries = null; bytes = null; buffer = null; blob = null;
    onRelease?.({buffer, bytes, entries, texts, blob});
  }
}

let trustedHostBridge = null;
const hostListeners = new Set();
// A trusted host installs executable adapters, never pasted JSON or public API results.
export function configureTrustedHostBridge(bridge) {
  if (bridge !== null && (!bridge || (typeof bridge.droppoint_gate_dry_run !== "function" && typeof bridge.submit_reviewed_modules !== "function"))) fail();
  trustedHostBridge = bridge;
  for (const listener of hostListeners) listener(bridge);
}
export function getTrustedHostBridge() { return trustedHostBridge; }
export function onTrustedHostBridgeChange(listener) {
  hostListeners.add(listener);
  return () => hostListeners.delete(listener);
}
export async function hostGatePreview(bridge, item) {
  if (bridge !== trustedHostBridge || typeof bridge?.droppoint_gate_dry_run !== "function" || typeof bridge?.qualify_reviewed_module !== "function") return {status: "pending", code: "qualification_service_unconnected"};
  object(item, ["declaration", "qualificationId"]);
  validateReviewedManifest(item.declaration);
  if (typeof item.qualificationId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(item.qualificationId)) fail();
  const digest = await declarationHash(item.declaration);
  let qualification = null;
  try {
    const result = await bridge.qualify_reviewed_module(item);
    if (result?.status !== "qualified") return {status: result?.status === "rejected" ? "rejected" : "pending"};
    qualification = result.qualification;
    const v1 = ["schema", "gateId", "qualificationId", "source", "accepted", "policyVersion", "moduleSHA512", "issuedAt", "expiresAt", "signature"];
    object(qualification, [...v1, "keyId"], v1);
    scan(qualification);
    const keyed = Object.hasOwn(qualification, "keyId");
    // /1 is HMAC-only and never carries keyId; /2 must carry a registry keyId.
    if (qualification.schema !== (keyed ? "gate-qualification/2" : "gate-qualification/1") || (keyed && (typeof qualification.keyId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(qualification.keyId))) || qualification.gateId !== "invarianttap-gate-1" || qualification.source !== "qualified-submission" || qualification.accepted !== true || qualification.qualificationId !== item.qualificationId || qualification.moduleSHA512 !== digest || typeof qualification.policyVersion !== "string" || !Number.isSafeInteger(qualification.issuedAt) || !Number.isSafeInteger(qualification.expiresAt) || !/^[a-f0-9]{128}$/.test(qualification.signature) || bridge !== trustedHostBridge) fail();
    // Only a backend-qualified envelope reaches the gate; the gate verifies its signature.
    return await bridge.droppoint_gate_dry_run(qualification);
  } finally { qualification = null; }
}
// The caller must be the installed trusted adapter; this hook cannot verify signatures.
export function renderConfirmedReceipt(response, target, expected) {
  const receipt = response?.receipt;
  if (!trustedHostBridge || !expected || response.status !== "success" || response.moduleId !== expected.moduleId || response.qualificationId !== expected.qualificationId || !/^[a-f0-9]{128}$/.test(expected.moduleSHA512) || response.moduleSHA512 !== expected.moduleSHA512 || !receipt || receipt.gateId !== "invarianttap-gate-1" || !/^[a-f0-9]{128}$/.test(receipt.receiptSHA512) || !Number.isSafeInteger(receipt.x) || receipt.x < 0 || receipt.x > 2047 || !Number.isSafeInteger(receipt.y) || receipt.y < 0 || receipt.y > 2047 || !Number.isSafeInteger(receipt.layer) || receipt.layer < 0 || receipt.layer > 511 || !Number.isSafeInteger(receipt.writtenAt) || typeof receipt.duplicate !== "boolean" || receipt.synthetic === true || receipt.dryRun === true) fail();
  scan(receipt);
  target.textContent = `Actual host writer receipt (trusted adapter response)\nModule: ${response.moduleId}\nEvent: ${response.qualificationId}\nReceipt hash: ${receipt.receiptSHA512}\nCoordinate: (${receipt.x}, ${receipt.y})\nLayer: ${receipt.layer}\nRetry duplicate: ${receipt.duplicate}`;
}
