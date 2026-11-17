// github-core-clone-01 — a standalone GitHub-compatible git forge.
// One Node 22 process (standard library only) serving git smart HTTP, REST v3,
// GraphQL v4 and MCP from its own in-memory store. No git binary, no network
// beyond the trial env, no wall clock or unseeded randomness in stored state:
// every id and timestamp comes from deterministic counters, so a replay of the
// same requests leaves a byte-identical state.
//
// Lifecycle: bind an ephemeral port, POST {"port": p} to $MAKEFUN_ENV_URL/register,
// long-poll GET $MAKEFUN_ENV_URL/done until {"done": true}, then exit 0.

import http from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

// ---------------------------------------------------------------- constants

const ZERO_OID = '0000000000000000000000000000000000000000';
const VIEWER_LOGIN = 'adaiversen'; // the fixed scenario viewer (kit SCENARIO_SEED is constant)
const VIEWER_ID = 1000;
const VIEWER_NAME = 'ada iversen';
const VIEWER_EMAIL = 'adaiversen@example.invalid';
const DEFAULT_BRANCH = 'main';
const SERVER_AGENT = 'forge/1.0';
const SCENARIO_EPOCH_SEC = 1735689600; // 2025-01-01T00:00:00Z; deterministic timestamps derive from this
const TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
const ENV_URL = (process.env.MAKEFUN_ENV_URL ?? '').replace(/\/+$/, '');

// ---------------------------------------------------------------- small utils

function sha1Hex(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}

function sha1Object(type: string, data: Buffer): string {
  const head = Buffer.from(`${type} ${data.length}\0`, 'utf8');
  return sha1Hex(Buffer.concat([head, data]));
}

function b64encode(buf: Buffer): string {
  return buf.toString('base64');
}

function b64decode(text: string): Buffer {
  return Buffer.from(text.replace(/[\r\n\t ]+/g, ''), 'base64');
}

function isOid(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{40}$/i.test(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isoOf(epochSec: number): string {
  return new Date(epochSec * 1000).toISOString();
}

// Deterministic counters: ids, timestamps and request ids never read a clock.
let tick = SCENARIO_EPOCH_SEC;
function nextTick(): number {
  tick += 1;
  return tick;
}
let reqSeq = 0;
function nextRequestId(): string {
  reqSeq += 1;
  return `req-${reqSeq}`;
}
let globalIdSeq = 0;
function nextDbId(): number {
  globalIdSeq += 1;
  return globalIdSeq;
}
function globalId(kind: string, parts: (string | number)[]): string {
  return Buffer.from(`${kind}:${parts.join(':')}`, 'utf8').toString('base64');
}
function decodeGlobalId(id: string): { kind: string; parts: string[] } | null {
  try {
    const text = Buffer.from(id, 'base64').toString('utf8');
    const [kind, ...parts] = text.split(':');
    if (!kind || parts.length === 0) return null;
    return { kind, parts };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------- pkt-lines

const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');

function pktLine(payload: Buffer | string | null): Buffer {
  if (payload === null) return PKT_FLUSH;
  const body = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const len = body.length + 4;
  const head = Buffer.alloc(4);
  head.write(len.toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([head, body]);
}

function pktFlush(): Buffer {
  return PKT_FLUSH;
}

function pktDelim(): Buffer {
  return PKT_DELIM;
}

type PktKind = 'data' | 'flush' | 'delim';
interface PktPacket {
  kind: PktKind;
  payload: Buffer;
}

/** Parse a whole buffer of pkt-lines into packets. Throws on malformed framing. */
function decodePktLines(buf: Buffer): PktPacket[] {
  const out: PktPacket[] = [];
  let off = 0;
  while (off < buf.length) {
    if (off + 4 > buf.length) throw new Error('truncated pkt-line header');
    const hex = buf.subarray(off, off + 4).toString('ascii');
    const len = parseInt(hex, 16);
    if (Number.isNaN(len) || len < 0 || len > 65520) throw new Error(`bad pkt-line length ${JSON.stringify(hex)}`);
    if (len === 0) {
      out.push({ kind: 'flush', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (len === 1) {
      out.push({ kind: 'delim', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (len < 4 || off + len > buf.length) throw new Error('truncated pkt-line payload');
    out.push({ kind: 'data', payload: buf.subarray(off + 4, off + len) });
    off += len;
  }
  return out;
}

/** Encode a list of text lines (or 'flush'/'delim') as pkt-lines. */
function encodePktLines(lines: Array<string | 'flush' | 'delim'>): Buffer {
  const parts: Buffer[] = [];
  for (const line of lines) {
    if (line === 'flush') parts.push(pktFlush());
    else if (line === 'delim') parts.push(pktDelim());
    else parts.push(pktLine(line));
  }
  return Buffer.concat(parts);
}

// ---------------------------------------------------------------- HTTP helpers

function jsonBody(res: http.ServerResponse, status: number, value: unknown, extraHeaders?: Record<string, string>): void {
  const text = JSON.stringify(value);
  res.writeHead(status, {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(text),
    'x-github-request-id': nextRequestId(),
    ...(extraHeaders ?? {}),
  });
  res.end(text);
}

function jsonError(res: http.ServerResponse, status: number, message: string): void {
  jsonBody(res, status, { message });
}

async function readBody(req: http.IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  return Buffer.concat(chunks);
}

function parseJsonBody(buf: Buffer): { ok: true; value: unknown } | { ok: false } {
  if (buf.length === 0) return { ok: true, value: {} };
  try {
    return { ok: true, value: JSON.parse(buf.toString('utf8')) as unknown };
  } catch {
    return { ok: false };
  }
}

function bearerToken(req: http.IncomingMessage): string | null {
  const auth = req.headers.authorization;
  if (!auth) return null;
  const m = /^Bearer\s+(.+)$/.exec(auth);
  return m ? m[1]!.trim() : null;
}

/** True when the request carries the trial token. With no token configured (local dev) any non-empty bearer passes. */
function authorized(req: http.IncomingMessage): boolean {
  const token = bearerToken(req);
  if (token === null || token === '') return false;
  if (TOKEN === '') return true;
  return token === TOKEN;
}

function userJson(): Record<string, unknown> {
  return {
    login: VIEWER_LOGIN,
    id: VIEWER_ID,
    node_id: globalId('User', [VIEWER_ID]),
    avatar_url: '',
    gravatar_id: '',
    url: `https://api.github.com/users/${VIEWER_LOGIN}`,
    html_url: `https://github.com/${VIEWER_LOGIN}`,
    type: 'User',
    site_admin: false,
    name: VIEWER_NAME,
    email: VIEWER_EMAIL,
  };
}

// ---------------------------------------------------------------- git objects

type GitType = 'commit' | 'tree' | 'blob' | 'tag';
interface GitObject {
  type: GitType;
  data: Buffer;
}

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let off = 0;
  while (off < data.length) {
    const sp = data.indexOf(0x20, off);
    if (sp < 0) throw new Error('bad tree entry');
    const nul = data.indexOf(0x00, sp + 1);
    if (nul < 0 || nul + 21 > data.length) throw new Error('bad tree entry');
    const mode = data.subarray(off, sp).toString('ascii');
    const name = data.subarray(sp + 1, nul).toString('utf8');
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, oid });
    off = nul + 21;
  }
  return entries;
}

/** Git's tree sort: entries order by name, directories as if the name ends with '/'. */
function treeSortKey(entry: TreeEntry): string {
  return entry.mode === '40000' ? `${entry.name}/` : entry.name;
}

function buildTree(entries: TreeEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) => (treeSortKey(a) < treeSortKey(b) ? -1 : treeSortKey(a) > treeSortKey(b) ? 1 : 0));
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

const EMPTY_TREE_OID = '4b825dc642cb6eb9a060e54bf8d69288fbee4904';

interface ParsedCommit {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

function parseCommit(data: Buffer): ParsedCommit {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const head = split < 0 ? text : text.slice(0, split);
  // The stored message ends with a newline (buildCommit adds it); the
  // logical message does not carry it — GitHub's API returns it without.
  const message = split < 0 ? '' : text.slice(split + 2).replace(/\n$/, '');
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) author = line.slice(7);
    else if (line.startsWith('committer ')) committer = line.slice(10);
  }
  return { tree, parents, author, committer, message };
}

function buildCommit(tree: string, parents: string[], message: string, epochSec: number): Buffer {
  const who = `${VIEWER_NAME} <${VIEWER_EMAIL}> ${epochSec} +0000`;
  const lines: string[] = [`tree ${tree}`];
  for (const parent of parents) lines.push(`parent ${parent}`);
  lines.push(`author ${who}`);
  lines.push(`committer ${who}`);
  const msg = message.endsWith('\n') ? message : `${message}\n`;
  return Buffer.from(`${lines.join('\n')}\n\n${msg}`, 'utf8');
}

interface ParsedTag {
  object: string;
  type: string;
  tag: string;
  tagger: string;
}

function parseTag(data: Buffer): ParsedTag {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const head = split < 0 ? text : text.slice(0, split);
  let object = '';
  let type = '';
  let tag = '';
  let tagger = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('object ')) object = line.slice(7).trim();
    else if (line.startsWith('type ')) type = line.slice(5).trim();
    else if (line.startsWith('tag ')) tag = line.slice(4).trim();
    else if (line.startsWith('tagger ')) tagger = line.slice(7);
  }
  return { object, type, tag, tagger };
}

/** The commit a tag object ultimately points at (follows tag->tag chains). */
function peelToCommit(objects: Map<string, GitObject>, oid: string): string | null {
  let current = oid;
  const seen = new Set<string>();
  for (let i = 0; i < 16; i += 1) {
    if (seen.has(current)) return null;
    seen.add(current);
    const obj = objects.get(current);
    if (!obj) return null;
    if (obj.type === 'commit') return current;
    if (obj.type === 'tag') {
      current = parseTag(obj.data).object;
      continue;
    }
    return null;
  }
  return null;
}

/** All ancestors of `tips` (including the tips), tip-first, deduplicated. */
function walkAncestors(objects: Map<string, GitObject>, tips: readonly string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const stack = [...tips].reverse();
  while (stack.length > 0) {
    const oid = stack.pop()!;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = objects.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    out.push(oid);
    const parents = parseCommit(obj.data).parents;
    for (let i = parents.length - 1; i >= 0; i -= 1) stack.push(parents[i]!);
  }
  return out;
}

function isAncestor(objects: Map<string, GitObject>, ancestor: string, descendant: string): boolean {
  if (ancestor === descendant) return true;
  const seen = new Set<string>();
  const stack = [descendant];
  while (stack.length > 0) {
    const oid = stack.pop()!;
    if (oid === ancestor) return true;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = objects.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    for (const parent of parseCommit(obj.data).parents) stack.push(parent);
  }
  return false;
}

/** First common ancestor of two tips (walk head's set, then base's order). */
function mergeBase(objects: Map<string, GitObject>, a: string, b: string): string | null {
  const aAncestors = new Set(walkAncestors(objects, [a]));
  for (const oid of walkAncestors(objects, [b])) {
    if (aAncestors.has(oid)) return oid;
  }
  return null;
}

/** The full object closure reachable from commit tips: commits, their trees (recursive) and blobs. */
function reachableObjects(objects: Map<string, GitObject>, tips: readonly string[]): Map<string, GitObject> {
  const out = new Map<string, GitObject>();
  const commits = walkAncestors(objects, tips);
  const queue: string[] = [...commits];
  while (queue.length > 0) {
    const oid = queue.pop()!;
    if (out.has(oid)) continue;
    const obj = objects.get(oid);
    if (!obj) continue;
    out.set(oid, obj);
    if (obj.type === 'commit') {
      queue.push(parseCommit(obj.data).tree);
    } else if (obj.type === 'tree') {
      for (const entry of parseTree(obj.data)) queue.push(entry.oid);
    } else if (obj.type === 'tag') {
      queue.push(parseTag(obj.data).object);
    }
  }
  return out;
}

/** Flatten a tree into path -> {oid, mode}. */
function flattenTree(objects: Map<string, GitObject>, treeOid: string, prefix = '', out = new Map<string, { oid: string; mode: string }>()): Map<string, { oid: string; mode: string }> {
  const obj = objects.get(treeOid);
  if (!obj || obj.type !== 'tree') return out;
  for (const entry of parseTree(obj.data)) {
    const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
    if (entry.mode === '40000') flattenTree(objects, entry.oid, path, out);
    else out.set(path, { oid: entry.oid, mode: entry.mode });
  }
  return out;
}

interface FileDiff {
  path: string;
  status: 'added' | 'modified' | 'removed';
  baseOid: string | null;
  headOid: string | null;
  additions: number;
  deletions: number;
}

function countLines(text: string): string[] {
  if (text === '') return [];
  const lines = text.split('\n');
  if (lines.length > 0 && lines[lines.length - 1] === '') lines.pop();
  return lines;
}

/** Line diff by multiset difference: additions = lines in new not in old, deletions the reverse. */
function lineDiff(oldText: string, newText: string): { additions: number; deletions: number } {
  const oldLines = countLines(oldText);
  const newLines = countLines(newText);
  const oldCount = new Map<string, number>();
  for (const line of oldLines) oldCount.set(line, (oldCount.get(line) ?? 0) + 1);
  const newCount = new Map<string, number>();
  for (const line of newLines) newCount.set(line, (newCount.get(line) ?? 0) + 1);
  let additions = 0;
  const usedNew = new Map<string, number>();
  for (const line of newLines) {
    const seen = (usedNew.get(line) ?? 0) + 1;
    usedNew.set(line, seen);
    if (seen > (oldCount.get(line) ?? 0)) additions += 1;
  }
  let deletions = 0;
  const usedOld = new Map<string, number>();
  for (const line of oldLines) {
    const seen = (usedOld.get(line) ?? 0) + 1;
    usedOld.set(line, seen);
    if (seen > (newCount.get(line) ?? 0)) deletions += 1;
  }
  return { additions, deletions };
}

function diffTrees(objects: Map<string, GitObject>, baseTreeOid: string | null, headTreeOid: string | null): FileDiff[] {
  const base = baseTreeOid ? flattenTree(objects, baseTreeOid) : new Map<string, { oid: string; mode: string }>();
  const head = headTreeOid ? flattenTree(objects, headTreeOid) : new Map<string, { oid: string; mode: string }>();
  const paths = new Set([...base.keys(), ...head.keys()]);
  const diffs: FileDiff[] = [];
  for (const path of [...paths].sort()) {
    const b = base.get(path);
    const h = head.get(path);
    if (b && h && b.oid === h.oid) continue;
    if (b && !h) {
      diffs.push({ path, status: 'removed', baseOid: b.oid, headOid: null, additions: 0, deletions: countLines(objects.get(b.oid)?.data.toString('utf8') ?? '').length });
    } else if (!b && h) {
      const text = objects.get(h.oid)?.data.toString('utf8') ?? '';
      diffs.push({ path, status: 'added', baseOid: null, headOid: h.oid, additions: countLines(text).length, deletions: 0 });
    } else if (b && h) {
      const oldText = objects.get(b.oid)?.data.toString('utf8') ?? '';
      const newText = objects.get(h.oid)?.data.toString('utf8') ?? '';
      const { additions, deletions } = lineDiff(oldText, newText);
      diffs.push({ path, status: 'modified', baseOid: b.oid, headOid: h.oid, additions, deletions });
    }
  }
  return diffs;
}

/** Set (or replace) a file at `path` in the tree rooted at `rootOid`; returns the new root tree oid. */
function setPathInTree(objects: Map<string, GitObject>, rootOid: string | null, segments: string[], blobOid: string): string {
  if (segments.length === 0) throw new Error('empty path');
  const name = segments[0]!;
  if (segments.length === 1) {
    const entries: TreeEntry[] = [];
    if (rootOid) {
      const root = objects.get(rootOid);
      if (root && root.type === 'tree') {
        for (const entry of parseTree(root.data)) {
          if (entry.name !== name) entries.push(entry);
        }
      }
    }
    entries.push({ mode: '100644', name, oid: blobOid });
    const data = buildTree(entries);
    const oid = sha1Object('tree', data);
    objects.set(oid, { type: 'tree', data });
    return oid;
  }
  let subOid: string | null = null;
  if (rootOid) {
    const root = objects.get(rootOid);
    if (root && root.type === 'tree') {
      const found = parseTree(root.data).find((entry) => entry.name === name && entry.mode === '40000');
      if (found) subOid = found.oid;
    }
  }
  const newSub = setPathInTree(objects, subOid, segments.slice(1), blobOid);
  const entries: TreeEntry[] = [];
  if (rootOid) {
    const root = objects.get(rootOid);
    if (root && root.type === 'tree') {
      for (const entry of parseTree(root.data)) {
        if (entry.name !== name) entries.push(entry);
      }
    }
  }
  entries.push({ mode: '40000', name, oid: newSub });
  const data = buildTree(entries);
  const oid = sha1Object('tree', data);
  objects.set(oid, { type: 'tree', data });
  return oid;
}

/** Remove a file at `path` from the tree rooted at `rootOid`; returns the new root tree oid. */
function removePathFromTree(objects: Map<string, GitObject>, rootOid: string | null, segments: string[]): string {
  if (segments.length === 0 || !rootOid) return EMPTY_TREE_OID;
  const root = objects.get(rootOid);
  if (!root || root.type !== 'tree') return EMPTY_TREE_OID;
  const name = segments[0]!;
  const entries: TreeEntry[] = [];
  let changed = false;
  for (const entry of parseTree(root.data)) {
    if (entry.name !== name) {
      entries.push(entry);
      continue;
    }
    changed = true;
    if (segments.length > 1 && entry.mode === '40000') {
      const newSub = removePathFromTree(objects, entry.oid, segments.slice(1));
      const sub = objects.get(newSub);
      if (sub && sub.type === 'tree' && parseTree(sub.data).length > 0) {
        entries.push({ mode: '40000', name, oid: newSub });
      }
    }
  }
  if (!changed) return rootOid;
  if (entries.length === 0) {
    if (!objects.has(EMPTY_TREE_OID)) objects.set(EMPTY_TREE_OID, { type: 'tree', data: Buffer.alloc(0) });
    return EMPTY_TREE_OID;
  }
  const data = buildTree(entries);
  const oid = sha1Object('tree', data);
  objects.set(oid, { type: 'tree', data });
  return oid;
}

/** Look a path up in a tree: the blob oid and mode, or null. */
function lookupPath(objects: Map<string, GitObject>, rootOid: string | null, segments: string[]): { oid: string; mode: string } | null {
  if (!rootOid || segments.length === 0) return null;
  const root = objects.get(rootOid);
  if (!root || root.type !== 'tree') return null;
  const name = segments[0]!;
  const entry = parseTree(root.data).find((candidate) => candidate.name === name);
  if (!entry) return null;
  if (segments.length === 1) return { oid: entry.oid, mode: entry.mode };
  if (entry.mode !== '40000') return null;
  return lookupPath(objects, entry.oid, segments.slice(1));
}

/** Immediate children of a directory path in a tree (for directory listings). */
function listDirectory(objects: Map<string, GitObject>, rootOid: string | null, segments: string[]): TreeEntry[] | null {
  let current = rootOid;
  for (const segment of segments) {
    if (!current) return null;
    const obj = objects.get(current);
    if (!obj || obj.type !== 'tree') return null;
    const entry = parseTree(obj.data).find((candidate) => candidate.name === segment);
    if (!entry || entry.mode !== '40000') return null;
    current = entry.oid;
  }
  if (!current) return [];
  const obj = objects.get(current);
  if (!obj || obj.type !== 'tree') return null;
  return parseTree(obj.data);
}

// ---------------------------------------------------------------- packfiles

/** Inflate one deflate stream starting at `offset`; returns the bytes and how many input bytes it consumed. */
function inflateAt(buf: Buffer, offset: number, expectedSize: number): { data: Buffer; consumed: number } {
  const rest = buf.subarray(offset);
  // Fast path: the whole remainder inflates to exactly the expected size.
  try {
    const whole = inflateSync(rest);
    if (whole.length === expectedSize) {
      // Binary-search the smallest prefix that still yields the full output.
      let lo = 1;
      let hi = rest.length;
      while (lo < hi) {
        const mid = (lo + hi) >> 1;
        try {
          const out = inflateSync(rest.subarray(0, mid));
          if (out.length === expectedSize) hi = mid;
          else lo = mid + 1;
        } catch {
          lo = mid + 1;
        }
      }
      return { data: inflateSync(rest.subarray(0, lo)), consumed: lo };
    }
  } catch {
    // fall through to the probe below
  }
  // Probe with growing prefixes until one inflates to the expected size.
  let probe = 16;
  while (probe <= rest.length) {
    try {
      const out = inflateSync(rest.subarray(0, probe));
      if (out.length === expectedSize) {
        let lo = 1;
        let hi = probe;
        while (lo < hi) {
          const mid = (lo + hi) >> 1;
          try {
            const o2 = inflateSync(rest.subarray(0, mid));
            if (o2.length === expectedSize) hi = mid;
            else lo = mid + 1;
          } catch {
            lo = mid + 1;
          }
        }
        return { data: inflateSync(rest.subarray(0, lo)), consumed: lo };
      }
    } catch {
      // truncated stream; grow the probe
    }
    probe *= 2;
  }
  throw new Error('deflate stream did not inflate to the expected size');
}

/** Read a git varint: returns [value, bytesConsumed]. */
function readVarint(buf: Buffer, off: number): [number, number] {
  let value = buf[off]! & 0x7f;
  let i = off + 1;
  while (buf[i - 1]! & 0x80) {
    value = ((value + 1) << 7) | (buf[i]! & 0x7f);
    i += 1;
  }
  return [value, i - off];
}

/** Apply a git delta to a base buffer. */
function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let off = 0;
  const [baseSize, n1] = readVarint(delta, off);
  off += n1;
  const [resultSize, n2] = readVarint(delta, off);
  off += n2;
  if (baseSize !== base.length) throw new Error('delta base size mismatch');
  const parts: Buffer[] = [];
  let total = 0;
  while (off < delta.length) {
    const op = delta[off]!;
    off += 1;
    if (op & 0x80) {
      let cpOff = 0;
      let cpSize = 0;
      for (let i = 0; i < 4; i += 1) {
        if (op & (1 << i)) {
          cpOff |= delta[off]! << (8 * i);
          off += 1;
        }
      }
      for (let i = 0; i < 3; i += 1) {
        if (op & (0x10 << i)) {
          cpSize |= delta[off]! << (8 * i);
          off += 1;
        }
      }
      if (cpSize === 0) cpSize = 0x10000;
      if (cpOff + cpSize > base.length) throw new Error('delta copy out of range');
      const chunk = base.subarray(cpOff, cpOff + cpSize);
      parts.push(chunk);
      total += chunk.length;
    } else if (op > 0) {
      const chunk = delta.subarray(off, off + op);
      if (chunk.length !== op) throw new Error('delta insert truncated');
      parts.push(chunk);
      total += chunk.length;
      off += op;
    } else {
      throw new Error('delta opcode 0');
    }
  }
  if (total !== resultSize) throw new Error('delta result size mismatch');
  return Buffer.concat(parts);
}

const PACK_TYPE_NAME: Record<number, GitType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };
const PACK_TYPE_NUM: Record<GitType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };

interface ParsedPack {
  version: number;
  declaredCount: number;
  objects: Map<string, GitObject>;
  deltaCount: number;
}

/** Parse a packfile; deltas resolve against pack entries and, as a fallback, `baseObjects`. */
function readPack(pack: Buffer, baseObjects?: Map<string, GitObject>): ParsedPack {
  if (pack.length < 12 || pack.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('not a packfile');
  const version = pack.readUInt32BE(4);
  const declaredCount = pack.readUInt32BE(8);
  if (version !== 2 && version !== 3) throw new Error(`unsupported pack version ${version}`);
  const byOffset = new Map<number, { type: GitType; data: Buffer }>();
  const objects = new Map<string, GitObject>();
  let deltaCount = 0;
  let off = 12;
  interface PendingDelta {
    at: number;
    baseOid: string | null;
    baseOffset: number | null;
    delta: Buffer;
  }
  const pending: PendingDelta[] = [];
  for (let i = 0; i < declaredCount; i += 1) {
    const entryStart = off;
    let byte = pack[off]!;
    off += 1;
    const typeNum = (byte >> 4) & 0x07;
    let size = byte & 0x0f;
    let shift = 4;
    while (byte & 0x80) {
      byte = pack[off]!;
      off += 1;
      size |= (byte & 0x7f) << shift;
      shift += 7;
    }
    if (typeNum === 6) {
      // OBJ_OFS_DELTA: offset varint (git's offset encoding)
      let b = pack[off]!;
      off += 1;
      let baseOff = b & 0x7f;
      while (b & 0x80) {
        b = pack[off]!;
        off += 1;
        baseOff = ((baseOff + 1) << 7) | (b & 0x7f);
      }
      const baseOffset = entryStart - baseOff;
      const { data, consumed } = inflateAt(pack, off, size);
      off += consumed;
      pending.push({ at: entryStart, baseOid: null, baseOffset, delta: data });
      deltaCount += 1;
    } else if (typeNum === 7) {
      // OBJ_REF_DELTA: 20-byte base oid
      const baseOid = pack.subarray(off, off + 20).toString('hex');
      off += 20;
      const { data, consumed } = inflateAt(pack, off, size);
      off += consumed;
      pending.push({ at: entryStart, baseOid, baseOffset: null, delta: data });
      deltaCount += 1;
    } else {
      const type = PACK_TYPE_NAME[typeNum];
      if (!type) throw new Error(`unknown pack object type ${typeNum}`);
      const { data, consumed } = inflateAt(pack, off, size);
      off += consumed;
      const oid = sha1Object(type, data);
      byOffset.set(entryStart, { type, data });
      objects.set(oid, { type, data });
    }
  }
  // Resolve deltas (a delta's base may itself be a delta: resolve in offset order, retrying).
  let remaining = pending;
  for (let round = 0; round < 64 && remaining.length > 0; round += 1) {
    const next: PendingDelta[] = [];
    for (const item of remaining) {
      let base: { type: GitType; data: Buffer } | undefined;
      if (item.baseOffset !== null) base = byOffset.get(item.baseOffset);
      else if (item.baseOid !== null) {
        const found = objects.get(item.baseOid);
        if (found) base = found;
        else if (baseObjects?.has(item.baseOid)) base = baseObjects.get(item.baseOid);
      }
      if (!base) {
        next.push(item);
        continue;
      }
      const data = applyDelta(base.data, item.delta);
      const oid = sha1Object(base.type, data);
      byOffset.set(item.at, { type: base.type, data });
      objects.set(oid, { type: base.type, data });
    }
    if (next.length === remaining.length) throw new Error('unresolvable pack delta base');
    remaining = next;
  }
  if (remaining.length > 0) throw new Error('unresolvable pack delta base');
  return { version, declaredCount, objects, deltaCount };
}

function verifyPackChecksum(pack: Buffer): { ok: boolean; actual: string; expected: string } {
  if (pack.length < 20) return { ok: false, actual: '', expected: '' };
  const expected = pack.subarray(pack.length - 20).toString('hex');
  const actual = sha1Hex(pack.subarray(0, pack.length - 20));
  return { ok: actual === expected, actual, expected };
}

/** Build a version-2 packfile from plain objects (no deltas), entries sorted by oid. */
function writePack(objects: Map<string, GitObject> | GitObject[]): Buffer {
  const list: Array<{ oid: string; type: GitType; data: Buffer }> = [];
  if (objects instanceof Map) {
    for (const [oid, obj] of objects) list.push({ oid, type: obj.type, data: obj.data });
  } else {
    for (const obj of objects) list.push({ oid: sha1Object(obj.type, obj.data), type: obj.type, data: obj.data });
  }
  list.sort((a, b) => (a.oid < b.oid ? -1 : a.oid > b.oid ? 1 : 0));
  const parts: Buffer[] = [];
  const head = Buffer.alloc(12);
  head.write('PACK', 0, 'ascii');
  head.writeUInt32BE(2, 4);
  head.writeUInt32BE(list.length, 8);
  parts.push(head);
  for (const entry of list) {
    const typeNum = PACK_TYPE_NUM[entry.type];
    const size = entry.data.length;
    const headerBytes: number[] = [];
    let first = (typeNum << 4) | (size & 0x0f);
    let rest = size >> 4;
    if (rest > 0) first |= 0x80;
    headerBytes.push(first);
    while (rest > 0) {
      let b = rest & 0x7f;
      rest >>= 7;
      if (rest > 0) b |= 0x80;
      headerBytes.push(b);
    }
    parts.push(Buffer.from(headerBytes));
    parts.push(deflateSync(entry.data));
  }
  const body = Buffer.concat(parts);
  const trailer = createHash('sha1').update(body).digest();
  return Buffer.concat([body, trailer]);
}

// ---------------------------------------------------------------- store

interface Label {
  id: number;
  name: string;
  color: string;
  description: string;
}

interface Comment {
  id: number;
  body: string;
  createdSeq: number;
}

interface Issue {
  dbId: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  createdSeq: number;
  updatedSeq: number;
  closedSeq: number | null;
  comments: Comment[];
  nextCommentId: number;
}

interface Pull {
  dbId: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  headRef: string;
  baseRef: string;
  headSha: string;
  baseSha: string;
  merged: boolean;
  mergedSeq: number | null;
  mergeCommitSha: string | null;
  createdSeq: number;
  updatedSeq: number;
}

interface Repo {
  dbId: number;
  owner: string;
  name: string;
  description: string;
  isPrivate: boolean;
  defaultBranch: string;
  createdSeq: number;
  updatedSeq: number;
  objects: Map<string, GitObject>;
  refs: Map<string, string>;
  issues: Map<number, Issue>;
  pulls: Map<number, Pull>;
  labels: Map<string, Label>;
  nextIssueNumber: number;
  nextPullNumber: number;
  nextLabelId: number;
}

const repos = new Map<string, Repo>();
let repoCreateSeq = 0;

function repoKey(owner: string, name: string): string {
  return `${owner}/${name}`;
}

function getRepo(owner: string, name: string): Repo | undefined {
  return repos.get(repoKey(owner, name));
}

function createRepoRecord(name: string, description: string, isPrivate: boolean): Repo {
  const dbId = nextDbId();
  const seq = nextTick();
  repoCreateSeq += 1;
  const repo: Repo = {
    dbId,
    owner: VIEWER_LOGIN,
    name,
    description,
    isPrivate,
    defaultBranch: DEFAULT_BRANCH,
    createdSeq: seq,
    updatedSeq: seq,
    objects: new Map<string, GitObject>(),
    refs: new Map<string, string>(),
    issues: new Map<number, Issue>(),
    pulls: new Map<number, Pull>(),
    labels: new Map<string, Label>(),
    nextIssueNumber: 1,
    nextPullNumber: 1,
    nextLabelId: 1,
  };
  repos.set(repoKey(VIEWER_LOGIN, name), repo);
  return repo;
}

function deleteRepoRecord(repo: Repo): void {
  repos.delete(repoKey(repo.owner, repo.name));
}

function listViewerRepos(): Repo[] {
  const out: Repo[] = [];
  for (const repo of repos.values()) {
    if (repo.owner === VIEWER_LOGIN) out.push(repo);
  }
  out.sort((a, b) => a.createdSeq - b.createdSeq || a.dbId - b.dbId);
  return out;
}

function refTip(repo: Repo, ref: string): string | null {
  return repo.refs.get(ref) ?? null;
}

function resolveRef(repo: Repo, ref: string): string | null {
  if (ref.startsWith('refs/')) return repo.refs.get(ref) ?? null;
  const branch = repo.refs.get(`refs/heads/${ref}`);
  if (branch) return branch;
  if (isOid(ref)) return repo.objects.has(ref) ? ref : null;
  return null;
}

function branchNames(repo: Repo): string[] {
  const names: string[] = [];
  for (const ref of repo.refs.keys()) {
    if (ref.startsWith('refs/heads/')) names.push(ref.slice('refs/heads/'.length));
  }
  names.sort();
  return names;
}

/** Commit a new tree on `branch` (creating the branch from the default tip when missing). */
function commitOnBranch(repo: Repo, branch: string, treeOid: string, message: string): string {
  const current = repo.refs.get(`refs/heads/${branch}`);
  const parents = current ? [current] : [];
  const commit = buildCommit(treeOid, parents, message, nextTick());
  const oid = sha1Object('commit', commit);
  repo.objects.set(oid, { type: 'commit', data: commit });
  repo.refs.set(`refs/heads/${branch}`, oid);
  repo.updatedSeq = tick;
  return oid;
}

/** The tip commit's tree oid for a branch (null when the branch is unborn). */
function branchTree(repo: Repo, branch: string): string | null {
  const tip = repo.refs.get(`refs/heads/${branch}`);
  if (!tip) return null;
  const obj = repo.objects.get(tip);
  if (!obj || obj.type !== 'commit') return null;
  return parseCommit(obj.data).tree;
}

function createIssueRecord(repo: Repo, title: string, body: string, labels: string[]): Issue {
  const number = repo.nextIssueNumber;
  repo.nextIssueNumber += 1;
  const seq = nextTick();
  const issue: Issue = {
    dbId: nextDbId(),
    number,
    title,
    body,
    state: 'open',
    labels: [...labels],
    createdSeq: seq,
    updatedSeq: seq,
    closedSeq: null,
    comments: [],
    nextCommentId: 1,
  };
  repo.issues.set(number, issue);
  return issue;
}

function createPullRecord(repo: Repo, title: string, body: string, head: string, base: string): Pull | null {
  const headSha = resolveRef(repo, head);
  const baseSha = resolveRef(repo, base);
  if (!headSha || !baseSha) return null;
  const number = repo.nextPullNumber;
  repo.nextPullNumber += 1;
  const seq = nextTick();
  const pull: Pull = {
    dbId: nextDbId(),
    number,
    title,
    body,
    state: 'open',
    headRef: head,
    baseRef: base,
    headSha,
    baseSha,
    merged: false,
    mergedSeq: null,
    mergeCommitSha: null,
    createdSeq: seq,
    updatedSeq: seq,
  };
  repo.pulls.set(number, pull);
  return pull;
}

/** The merge base commit of a pull request (first common ancestor of head and base tips). */
function pullMergeBase(repo: Repo, pull: Pull): string | null {
  return mergeBase(repo.objects, pull.headSha, pull.baseSha);
}

/** 3-way mergeability: does the head apply cleanly onto the base tip? */
function pullMergeable(repo: Repo, pull: Pull): 'MERGEABLE' | 'CONFLICTING' {
  if (pull.merged || pull.state !== 'open') return 'MERGEABLE';
  const base = pullMergeBase(repo, pull);
  if (!base) return 'CONFLICTING';
  const headTip = resolveRef(repo, pull.headRef) ?? pull.headSha;
  const baseTip = resolveRef(repo, pull.baseRef) ?? pull.baseSha;
  const baseObj = repo.objects.get(base);
  const headObj = repo.objects.get(headTip);
  const tipObj = repo.objects.get(baseTip);
  if (!baseObj || !headObj || !tipObj) return 'CONFLICTING';
  const baseTree = parseCommit(baseObj.data).tree;
  const headTree = parseCommit(headObj.data).tree;
  const tipTree = parseCommit(tipObj.data).tree;
  const headDiff = diffTrees(repo.objects, baseTree, headTree);
  const tipDiff = diffTrees(repo.objects, baseTree, tipTree);
  const tipChanged = new Map(tipDiff.map((d) => [d.path, d.headOid]));
  for (const d of headDiff) {
    const other = tipChanged.get(d.path);
    if (other !== undefined && other !== d.headOid) return 'CONFLICTING';
  }
  return 'MERGEABLE';
}

/**
 * Squash-merge a pull request onto its base branch: one commit whose tree is the
 * 3-way merge of (merge-base, head tip, base tip). Returns the merge commit sha,
 * or null when conflicted.
 */
function squashMerge(repo: Repo, pull: Pull): string | null {
  if (pull.merged || pull.state !== 'open') return null;
  const base = pullMergeBase(repo, pull);
  if (!base) return null;
  const headTip = resolveRef(repo, pull.headRef) ?? pull.headSha;
  const baseTip = resolveRef(repo, pull.baseRef) ?? pull.baseSha;
  const baseObj = repo.objects.get(base);
  const headObj = repo.objects.get(headTip);
  const tipObj = repo.objects.get(baseTip);
  if (!baseObj || !headObj || !tipObj) return null;
  const baseTree = parseCommit(baseObj.data).tree;
  const headTree = parseCommit(headObj.data).tree;
  const tipTree = parseCommit(tipObj.data).tree;
  const headDiff = diffTrees(repo.objects, baseTree, headTree);
  const tipDiff = diffTrees(repo.objects, baseTree, tipTree);
  const tipChanged = new Map(tipDiff.map((d) => [d.path, d.headOid]));
  for (const d of headDiff) {
    const other = tipChanged.get(d.path);
    if (other !== undefined && other !== d.headOid) return null;
  }
  let mergedTree = tipTree;
  for (const d of headDiff) {
    const segments = d.path.split('/');
    if (d.headOid === null) mergedTree = removePathFromTree(repo.objects, mergedTree, segments);
    else mergedTree = setPathInTree(repo.objects, mergedTree, segments, d.headOid);
  }
  const epoch = nextTick();
  const commit = buildCommit(mergedTree, [baseTip], pull.title, epoch);
  const sha = sha1Object('commit', commit);
  repo.objects.set(sha, { type: 'commit', data: commit });
  repo.refs.set(`refs/heads/${pull.baseRef}`, sha);
  pull.merged = true;
  pull.state = 'closed';
  pull.mergedSeq = epoch;
  pull.mergeCommitSha = sha;
  pull.updatedSeq = epoch;
  repo.updatedSeq = epoch;
  return sha;
}

/** Changed files of a pull request: diff of merge-base tree vs head tip tree. */
function pullFiles(repo: Repo, pull: Pull): FileDiff[] {
  const base = pullMergeBase(repo, pull);
  const headTip = resolveRef(repo, pull.headRef) ?? pull.headSha;
  const headObj = repo.objects.get(headTip);
  if (!headObj) return [];
  const headTree = parseCommit(headObj.data).tree;
  const baseTree = base ? parseCommit(repo.objects.get(base)!.data).tree : null;
  return diffTrees(repo.objects, baseTree, headTree);
}

// ---------------------------------------------------------------- JSON views

function repoJson(repo: Repo): Record<string, unknown> {
  const openIssues = [...repo.issues.values()].filter((issue) => issue.state === 'open').length;
  return {
    id: repo.dbId,
    node_id: globalId('Repository', [repo.dbId]),
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: userJson(),
    private: repo.isPrivate,
    html_url: `https://github.com/${repo.owner}/${repo.name}`,
    description: repo.description,
    fork: false,
    url: `https://api.github.com/repos/${repo.owner}/${repo.name}`,
    created_at: isoOf(repo.createdSeq),
    updated_at: isoOf(repo.updatedSeq),
    pushed_at: isoOf(repo.updatedSeq),
    homepage: '',
    size: 0,
    stargazers_count: 0,
    watchers_count: 0,
    language: null,
    has_issues: true,
    has_projects: true,
    has_downloads: true,
    has_wiki: true,
    has_pages: false,
    has_discussions: false,
    forks_count: 0,
    archived: false,
    disabled: false,
    open_issues_count: openIssues,
    license: null,
    allow_forking: true,
    is_template: false,
    topics: [],
    visibility: repo.isPrivate ? 'private' : 'public',
    default_branch: repo.defaultBranch,
  };
}

function issueJson(repo: Repo, issue: Issue): Record<string, unknown> {
  return {
    id: issue.dbId,
    node_id: globalId('Issue', [repo.dbId, issue.number]),
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    locked: false,
    labels: issue.labels.map((name) => {
      const label = repo.labels.get(name);
      return { id: label?.id ?? 0, name, color: label?.color ?? 'ededed', description: label?.description ?? '' };
    }),
    user: userJson(),
    assignee: null,
    assignees: [],
    comments: issue.comments.length,
    created_at: isoOf(issue.createdSeq),
    updated_at: isoOf(issue.updatedSeq),
    closed_at: issue.closedSeq === null ? null : isoOf(issue.closedSeq),
    url: `https://api.github.com/repos/${repo.owner}/${repo.name}/issues/${issue.number}`,
    html_url: `https://github.com/${repo.owner}/${repo.name}/issues/${issue.number}`,
  };
}

function commentJson(repo: Repo, issue: Issue, comment: Comment): Record<string, unknown> {
  return {
    id: comment.id,
    node_id: globalId('IssueComment', [repo.dbId, issue.number, comment.id]),
    body: comment.body,
    user: userJson(),
    created_at: isoOf(comment.createdSeq),
    updated_at: isoOf(comment.createdSeq),
    url: `https://api.github.com/repos/${repo.owner}/${repo.name}/issues/comments/${comment.id}`,
    html_url: `https://github.com/${repo.owner}/${repo.name}/issues/${issue.number}#issuecomment-${comment.id}`,
  };
}

function pullJson(repo: Repo, pull: Pull): Record<string, unknown> {
  const state = pull.merged ? 'closed' : pull.state;
  return {
    id: pull.dbId,
    node_id: globalId('PullRequest', [repo.dbId, pull.number]),
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state,
    locked: false,
    user: userJson(),
    labels: [],
    milestone: null,
    created_at: isoOf(pull.createdSeq),
    updated_at: isoOf(pull.updatedSeq),
    closed_at: pull.state === 'closed' ? isoOf(pull.updatedSeq) : null,
    merged_at: pull.mergedSeq === null ? null : isoOf(pull.mergedSeq),
    merge_commit_sha: pull.mergeCommitSha,
    merged: pull.merged,
    mergeable: pullMergeable(repo, pull) === 'MERGEABLE',
    mergeable_state: pullMergeable(repo, pull) === 'MERGEABLE' ? 'clean' : 'dirty',
    merged_by: pull.merged ? userJson() : null,
    comments: 0,
    review_comments: 0,
    commits: 1,
    additions: 0,
    deletions: 0,
    changed_files: 0,
    head: {
      label: `${repo.owner}:${pull.headRef}`,
      ref: pull.headRef,
      sha: resolveRef(repo, pull.headRef) ?? pull.headSha,
      user: userJson(),
      repo: repoJson(repo),
    },
    base: {
      label: `${repo.owner}:${pull.baseRef}`,
      ref: pull.baseRef,
      sha: resolveRef(repo, pull.baseRef) ?? pull.baseSha,
      user: userJson(),
      repo: repoJson(repo),
    },
    url: `https://api.github.com/repos/${repo.owner}/${repo.name}/pulls/${pull.number}`,
    html_url: `https://github.com/${repo.owner}/${repo.name}/pull/${pull.number}`,
  };
}

// ---------------------------------------------------------------- git smart HTTP

function sortedRefs(repo: Repo): Array<{ name: string; oid: string }> {
  const out: Array<{ name: string; oid: string }> = [];
  for (const [name, oid] of repo.refs) out.push({ name, oid });
  out.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return out;
}

function headOid(repo: Repo): string {
  return repo.refs.get(`refs/heads/${repo.defaultBranch}`) ?? ZERO_OID;
}

/** v0 advertisement body: service preamble, then ref lines (first carries capabilities). */
function v0Advertisement(service: 'git-upload-pack' | 'git-receive-pack', repo: Repo, capabilities: string): Buffer {
  const lines: Array<string | 'flush'> = [`# service=${service}\n`, 'flush'];
  const refs = sortedRefs(repo);
  const caps = `symref=HEAD:refs/heads/${repo.defaultBranch} ${capabilities} agent=${SERVER_AGENT}`;
  if (refs.length === 0) {
    lines.push(`${ZERO_OID} capabilities^{}\0${caps}\n`);
  } else {
    const tip = headOid(repo);
    lines.push(`${tip} HEAD\0${caps}\n`);
    for (const ref of refs) {
      lines.push(`${ref.oid} ${ref.name}\n`);
      if (ref.name.startsWith('refs/tags/')) {
        const peeled = peelToCommit(repo.objects, ref.oid);
        if (peeled && peeled !== ref.oid) lines.push(`${peeled} ${ref.name}^{}\n`);
      }
    }
  }
  lines.push('flush');
  return encodePktLines(lines);
}

/** v2 capability advertisement body. */
function v2Advertisement(): Buffer {
  return encodePktLines([
    '# service=git-upload-pack\n',
    'flush',
    'version 2\n',
    `agent=${SERVER_AGENT}\n`,
    'ls-refs=unborn\n',
    'fetch=shallow thin-pack ofs-delta\n',
    'object-format=sha1\n',
    'flush',
  ]);
}

/** Objects to send for a fetch: closure of wanted commits within depth, minus what the client holds. */
function fetchPackObjects(
  repo: Repo,
  wants: string[],
  haves: string[],
  shallowBoundaries: string[],
  depth: number | null,
  deepenSince: number | null,
  deepenNot: string[],
): Map<string, GitObject> {
  // Wanted commits: walk from wants, bounded by depth (generations) or commit time.
  const wanted = new Set<string>();
  const queue: Array<{ oid: string; gen: number }> = wants.map((oid) => ({ oid, gen: 1 }));
  const seenGen = new Map<string, number>();
  const notReachable = new Set<string>();
  for (const ref of deepenNot) {
    for (const oid of walkAncestors(repo.objects, [ref])) notReachable.add(oid);
  }
  while (queue.length > 0) {
    const { oid, gen } = queue.shift()!;
    if (notReachable.has(oid)) continue;
    const prev = seenGen.get(oid);
    if (prev !== undefined && prev <= gen) continue;
    seenGen.set(oid, gen);
    const obj = repo.objects.get(oid);
    if (!obj) continue;
    if (obj.type === 'tag') {
      wanted.add(oid);
      // A tag want is a want for its target commit: keep walking at the same
      // generation so depth and parents resolve through the tag.
      const target = peelToCommit(repo.objects, oid);
      if (target && target !== oid) queue.push({ oid: target, gen });
      continue;
    }
    if (obj.type !== 'commit') continue;
    if (deepenSince !== null) {
      const parsed = parseCommit(obj.data);
      const ts = parseInt((parsed.author.split(' ').slice(-2)[0] ?? '0'), 10);
      if (Number.isFinite(ts) && ts < deepenSince) continue;
    }
    wanted.add(oid);
    if (depth === null || gen < depth) {
      for (const parent of parseCommit(obj.data).parents) queue.push({ oid: parent, gen: gen + 1 });
    }
  }
  // Closure of the wanted commits only: each commit plus its tree (recursive) — never
  // the parents beyond the depth edge.
  const closure = new Map<string, GitObject>();
  const addTree = (treeOid: string): void => {
    const obj = repo.objects.get(treeOid);
    if (!obj || obj.type !== 'tree' || closure.has(treeOid)) return;
    closure.set(treeOid, obj);
    for (const entry of parseTree(obj.data)) {
      const child = repo.objects.get(entry.oid);
      if (!child) continue;
      if (child.type === 'tree') addTree(entry.oid);
      else closure.set(entry.oid, child);
    }
  };
  for (const oid of wanted) {
    const obj = repo.objects.get(oid);
    if (!obj) continue;
    closure.set(oid, obj);
    if (obj.type === 'commit') addTree(parseCommit(obj.data).tree);
    else if (obj.type === 'tag') {
      const target = peelToCommit(repo.objects, oid);
      if (target) {
        const targetObj = repo.objects.get(target);
        if (targetObj) {
          closure.set(target, targetObj);
          if (targetObj.type === 'commit') addTree(parseCommit(targetObj.data).tree);
        }
      }
    }
  }
  // What the client already holds. A have holds its ancestry only down to
  // the shallow boundaries beneath it: in a shallow repo the tip's parents
  // past the boundary are precisely what the client lacks, so the walk from
  // each have stops at boundaries (a boundary is held with itself and its
  // tree only). With no boundaries at all a have holds its full ancestry.
  const held = new Set<string>();
  const boundarySet = new Set(shallowBoundaries);
  const markTreeHeld = (treeOid: string): void => {
    // A dedicated visited set: entries are added to `held` as they are
    // found, so testing `held` here would skip every subtree (its oid was
    // already added as its parent's entry) and leave its blobs unmarked.
    const seenTrees = new Set<string>();
    const stack = [treeOid];
    while (stack.length > 0) {
      const t = stack.pop()!;
      if (seenTrees.has(t)) continue;
      seenTrees.add(t);
      const tObj = repo.objects.get(t);
      if (!tObj || tObj.type !== 'tree') continue;
      held.add(t);
      for (const e of parseTree(tObj.data)) {
        held.add(e.oid);
        if (e.mode === '40000') stack.push(e.oid);
      }
    }
  };
  const heldTreeOnly = (oid: string): void => {
    const obj = repo.objects.get(oid);
    if (!obj) return;
    held.add(oid);
    if (obj.type === 'commit') markTreeHeld(parseCommit(obj.data).tree);
    else if (obj.type === 'tag') {
      const target = peelToCommit(repo.objects, oid);
      if (target) heldTreeOnly(target);
    }
  };
  const heldFromHave = (startOid: string): void => {
    const stack = [startOid];
    const seen = new Set<string>();
    while (stack.length > 0) {
      const oid = stack.pop()!;
      if (seen.has(oid)) continue;
      seen.add(oid);
      const obj = repo.objects.get(oid);
      if (!obj) continue;
      if (boundarySet.has(oid)) {
        heldTreeOnly(oid);
        continue;
      }
      if (obj.type === 'commit') {
        held.add(oid);
        markTreeHeld(parseCommit(obj.data).tree);
        for (const parent of parseCommit(obj.data).parents) stack.push(parent);
      } else if (obj.type === 'tag') {
        held.add(oid);
        const target = peelToCommit(repo.objects, oid);
        if (target) stack.push(target);
      }
    }
  };
  for (const oid of haves) heldFromHave(oid);
  for (const oid of shallowBoundaries) {
    if (!haves.includes(oid)) heldTreeOnly(oid);
  }
  for (const oid of held) closure.delete(oid);
  return closure;
}

/** Effective depth for a fetch: with `deepen-relative` the requested depth
 * extends past the client's existing shallow boundaries (each boundary sits
 * some generations below the want; the new edge is boundary generation +
 * deepen). Without it, `deepen` is an absolute depth from the want. */
function effectiveDepth(
  repo: Repo,
  wants: string[],
  shallowBoundaries: string[],
  depth: number | null,
  deepenRelative: boolean,
): number | null {
  if (depth === null || !deepenRelative || shallowBoundaries.length === 0) return depth;
  const boundarySet = new Set(shallowBoundaries);
  const queue: Array<{ oid: string; gen: number }> = wants.map((oid) => ({ oid, gen: 1 }));
  const seen = new Set<string>();
  let best: number | null = null;
  while (queue.length > 0) {
    const { oid, gen } = queue.shift()!;
    if (seen.has(oid)) continue;
    seen.add(oid);
    if (boundarySet.has(oid)) {
      const candidate = gen + depth;
      if (best === null || candidate > best) best = candidate;
      continue;
    }
    const obj = repo.objects.get(oid);
    if (!obj) continue;
    if (obj.type === 'tag') {
      const target = peelToCommit(repo.objects, oid);
      if (target && target !== oid) queue.push({ oid: target, gen });
      continue;
    }
    if (obj.type !== 'commit') continue;
    for (const parent of parseCommit(obj.data).parents) queue.push({ oid: parent, gen: gen + 1 });
  }
  return best ?? depth;
}

/** A have covers a want when it is an ancestor of the want — seeing through
 * annotated tags, whose target commit is what the client actually holds. */
function isAncestorOfWant(objects: Map<string, GitObject>, have: string, want: string): boolean {
  const wantObj = objects.get(want);
  if (wantObj && wantObj.type === 'tag') {
    const target = peelToCommit(objects, want);
    return target !== null && isAncestor(objects, have, target);
  }
  return isAncestor(objects, have, want);
}
/** New shallow boundaries after a fetch: wanted commits at the depth edge whose parents are absent. */
function fetchShallowInfo(
  repo: Repo,
  wants: string[],
  depth: number | null,
  shallowBoundaries: string[],
): { shallow: string[]; unshallow: string[] } {
  if (depth === null) return { shallow: [], unshallow: [] };
  const shallow: string[] = [];
  const queue: Array<{ oid: string; gen: number }> = wants.map((oid) => ({ oid, gen: 1 }));
  const seen = new Set<string>();
  while (queue.length > 0) {
    const { oid, gen } = queue.shift()!;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = repo.objects.get(oid);
    if (!obj) continue;
    if (obj.type === 'tag') {
      const target = peelToCommit(repo.objects, oid);
      if (target && target !== oid) queue.push({ oid: target, gen });
      continue;
    }
    if (obj.type !== 'commit') continue;
    const parents = parseCommit(obj.data).parents;
    if (gen >= depth) {
      shallow.push(oid);
    } else {
      for (const parent of parents) queue.push({ oid: parent, gen: gen + 1 });
    }
  }
  const prev = new Set(shallowBoundaries);
  const unshallow = [...prev].filter((oid) => !shallow.includes(oid) && repo.objects.has(oid) && (() => {
    // A previous boundary is unshallow when its parent is now present in the wanted closure.
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'commit') return false;
    return parseCommit(obj.data).parents.some((p) => seen.has(p));
  })());
  return { shallow, unshallow };
}

function sidebandPackets(pack: Buffer): Buffer[] {
  const out: Buffer[] = [];
  const CHUNK = 65500;
  for (let off = 0; off < pack.length; off += CHUNK) {
    const slice = pack.subarray(off, Math.min(pack.length, off + CHUNK));
    const payload = Buffer.concat([Buffer.from([1]), slice]);
    out.push(pktLine(payload));
  }
  if (pack.length === 0) {
    out.push(pktLine(Buffer.from([1])));
  }
  return out;
}

interface V2FetchRequest {
  wants: string[];
  haves: string[];
  shallow: string[];
  depth: number | null;
  deepenSince: number | null;
  deepenNot: string[];
  done: boolean;
  deepenRelative: boolean;
}

function handleUploadPackV2(repo: Repo, body: Buffer): Buffer {
  const packets = decodePktLines(body);
  let command = '';
  let delimSeen = false;
  const req: V2FetchRequest = { wants: [], haves: [], shallow: [], depth: null, deepenSince: null, deepenNot: [], done: false, deepenRelative: false };
  let mode: 'ls-refs' | 'fetch' | null = null;
  const lsArgs = { peel: false, symrefs: false, unborn: false, prefixes: [] as string[] };
  for (const packet of packets) {
    if (packet.kind === 'flush') break;
    if (packet.kind === 'delim') {
      delimSeen = true;
      continue;
    }
    if (packet.kind !== 'data') continue;
    const line = packet.payload.toString('utf8').replace(/\n$/, '');
    if (!delimSeen) {
      if (line.startsWith('command=')) {
        command = line.slice('command='.length);
        mode = command === 'ls-refs' ? 'ls-refs' : command === 'fetch' ? 'fetch' : null;
      }
      continue;
    }
    if (mode === 'ls-refs') {
      if (line === 'peel') lsArgs.peel = true;
      else if (line === 'symrefs') lsArgs.symrefs = true;
      else if (line === 'unborn') lsArgs.unborn = true;
      else if (line.startsWith('ref-prefix ')) lsArgs.prefixes.push(line.slice('ref-prefix '.length));
    } else if (mode === 'fetch') {
      if (line.startsWith('want ')) req.wants.push(line.slice(5).trim());
      else if (line.startsWith('have ')) req.haves.push(line.slice(5).trim());
      else if (line.startsWith('shallow ')) req.shallow.push(line.slice(8).trim());
      else if (line.startsWith('deepen ')) req.depth = parseInt(line.slice(7), 10);
      else if (line.startsWith('deepen-since ')) req.deepenSince = parseInt(line.slice(13), 10);
      else if (line.startsWith('deepen-not ')) req.deepenNot.push(line.slice(11).trim());
      else if (line === 'deepen-relative') req.deepenRelative = true;
      else if (line === 'done') req.done = true;
    }
  }
  if (mode === 'ls-refs') {
    const parts: Buffer[] = [];
    const refs = sortedRefs(repo);
    const matches = (name: string): boolean => lsArgs.prefixes.length === 0 || lsArgs.prefixes.some((p) => name.startsWith(p));
    // HEAD is a ref too: emit it when the client asked for no prefixes, or
    // when any prefix selects it (e.g. `ref-prefix HEAD`). Without a HEAD
    // line git clone concludes the remote is empty and never fetches.
    const includeHead = matches('HEAD');
    if (includeHead) {
      const tip = headOid(repo);
      if (tip === ZERO_OID) {
        parts.push(pktLine(`unborn HEAD${lsArgs.symrefs ? ` symref-target:refs/heads/${repo.defaultBranch}` : ''}\n`));
      } else {
        parts.push(pktLine(`${tip} HEAD${lsArgs.symrefs ? ` symref-target:refs/heads/${repo.defaultBranch}` : ''}\n`));
      }
    }
    for (const ref of refs) {
      if (!matches(ref.name)) continue;
      let line = `${ref.oid} ${ref.name}`;
      if (ref.name.startsWith('refs/tags/') && lsArgs.peel) {
        const peeled = peelToCommit(repo.objects, ref.oid);
        if (peeled && peeled !== ref.oid) line += ` peeled:${peeled}`;
      }
      parts.push(pktLine(`${line}\n`));
    }
    parts.push(pktFlush());
    return Buffer.concat(parts);
  }
  if (mode === 'fetch') {
    const depth = effectiveDepth(repo, req.wants, req.shallow, req.depth, req.deepenRelative);
    const objects = fetchPackObjects(repo, req.wants, req.haves, req.shallow, depth, req.deepenSince, req.deepenNot);
    const pack = writePack(objects);
    const info = fetchShallowInfo(repo, req.wants, depth, req.shallow);
    const parts: Buffer[] = [];
    // Protocol v2 negotiation: when the client sends `done`, it has finished
    // sending haves, so the server must NOT send an acknowledgments section —
    // git goes straight to the packfile section and dies with
    // "expected 'packfile', received 'acknowledgments'" if it sees one.
    // The ack section only exists for open (multi-round) negotiation.
    if (!req.done) {
      const common = req.haves.filter(
        (have) => repo.objects.has(have) && req.wants.some((want) => isAncestorOfWant(repo.objects, have, want)),
      );
      const ready = req.wants.length > 0 && req.wants.every((want) => common.some((have) => isAncestorOfWant(repo.objects, have, want)));
      parts.push(pktLine('acknowledgments\n'));
      if (common.length === 0) {
        parts.push(pktLine('NAK\n'));
      } else {
        for (const oid of common) parts.push(pktLine(`ACK ${oid}\n`));
        if (ready) parts.push(pktLine('ready\n'));
      }
      if (!ready) {
        // No `ready`: the ack section ends with a FLUSH and the response
        // ends here; the client sends another negotiation round.
        parts.push(pktFlush());
        return Buffer.concat(parts);
      }
      // `ready`: the ack section ends with a DELIM and the packfile follows.
      parts.push(pktDelim());
    }
    if (info.shallow.length > 0 || info.unshallow.length > 0) {
      parts.push(pktLine('shallow-info\n'));
      for (const oid of info.shallow) parts.push(pktLine(`shallow ${oid}\n`));
      for (const oid of info.unshallow) parts.push(pktLine(`unshallow ${oid}\n`));
      parts.push(pktDelim());
    }
    parts.push(pktLine('packfile\n'));
    for (const packet of sidebandPackets(pack)) parts.push(packet);
    parts.push(pktFlush());
    return Buffer.concat(parts);
  }
  throw new Error(`unknown v2 command ${JSON.stringify(command)}`);
}

function handleUploadPackV0(repo: Repo, body: Buffer): Buffer {
  const packets = decodePktLines(body);
  const wants: string[] = [];
  const haves: string[] = [];
  const shallow: string[] = [];
  let depth: number | null = null;
  let deepenSince: number | null = null;
  let deepenRelative = false;
  const deepenNot: string[] = [];
  let section = 0;
  for (const packet of packets) {
    if (packet.kind === 'flush') {
      section += 1;
      continue;
    }
    if (packet.kind !== 'data') continue;
    const line = packet.payload.toString('utf8').replace(/\n$/, '');
    if (section === 0) {
      // First want line may carry capabilities after a NUL.
      const nul = line.indexOf('\0');
      const clean = nul >= 0 ? line.slice(0, nul) : line;
      if (clean.startsWith('want ')) wants.push(clean.slice(5).trim());
      else if (clean.startsWith('shallow ')) shallow.push(clean.slice(8).trim());
      else if (clean.startsWith('deepen ')) depth = parseInt(clean.slice(7), 10);
      else if (clean.startsWith('deepen-since ')) deepenSince = parseInt(clean.slice(13), 10);
      else if (clean.startsWith('deepen-not ')) deepenNot.push(clean.slice(11).trim());
      else if (clean === 'deepen-relative') deepenRelative = true;
    } else {
      if (line.startsWith('have ')) haves.push(line.slice(5).trim());
    }
  }
  const effDepth = effectiveDepth(repo, wants, shallow, depth, deepenRelative);
  const objects = fetchPackObjects(repo, wants, haves, shallow, effDepth, deepenSince, deepenNot);
  const pack = writePack(objects);
  const info = fetchShallowInfo(repo, wants, effDepth, shallow);
  const parts: Buffer[] = [pktLine('NAK\n')];
  for (const oid of info.shallow) parts.push(pktLine(`shallow ${oid}\n`));
  for (const oid of info.unshallow) parts.push(pktLine(`unshallow ${oid}\n`));
  for (const packet of sidebandPackets(pack)) parts.push(packet);
  parts.push(pktFlush());
  return Buffer.concat(parts);
}

interface PushCommand {
  oldOid: string;
  newOid: string;
  ref: string;
}

function handleReceivePack(repo: Repo, body: Buffer): Buffer {
  // Body: command pkt-lines + flush, then the raw pack (absent for delete-only pushes).
  const packets: PktPacket[] = [];
  let off = 0;
  let packStart = body.length;
  try {
    while (off < body.length) {
      if (off + 4 > body.length) throw new Error('truncated pkt-line');
      const hex = body.subarray(off, off + 4).toString('ascii');
      const len = parseInt(hex, 16);
      if (Number.isNaN(len) || len < 0 || len > 65520) throw new Error('bad pkt-line length');
      if (len === 0) {
        packets.push({ kind: 'flush', payload: Buffer.alloc(0) });
        off += 4;
        packStart = off;
        break;
      }
      if (len === 1) {
        packets.push({ kind: 'delim', payload: Buffer.alloc(0) });
        off += 4;
        continue;
      }
      if (off + len > body.length) throw new Error('truncated pkt-line');
      packets.push({ kind: 'data', payload: body.subarray(off + 4, off + len) });
      off += len;
    }
  } catch {
    // Malformed command framing: answer an unpack error rather than crashing.
    const report = encodePktLines(['unpack error\n', 'flush']);
    return Buffer.concat([pktLine(Buffer.concat([Buffer.from([1]), report])), pktFlush()]);
  }
  const commands: PushCommand[] = [];
  for (const packet of packets) {
    if (packet.kind !== 'data') continue;
    const line = packet.payload.toString('utf8').replace(/\n$/, '');
    const nul = line.indexOf('\0');
    const clean = nul >= 0 ? line.slice(0, nul) : line;
    const parts = clean.split(' ');
    if (parts.length >= 3 && isOid(parts[0]) && isOid(parts[1])) {
      commands.push({ oldOid: parts[0]!, newOid: parts[1]!, ref: parts.slice(2).join(' ') });
    }
  }
  const reportLines: string[] = [];
  const packBytes = body.subarray(packStart);
  const needsPack = commands.some((c) => c.newOid !== ZERO_OID);
  let unpackOk = true;
  let unpackDetail = 'ok';
  if (needsPack) {
    if (packBytes.length === 0) {
      unpackOk = false;
      unpackDetail = 'error';
    } else {
      try {
        const checksum = verifyPackChecksum(packBytes);
        if (!checksum.ok) throw new Error('pack checksum mismatch');
        const parsed = readPack(packBytes, repo.objects);
        for (const [oid, obj] of parsed.objects) repo.objects.set(oid, obj);
      } catch {
        unpackOk = false;
        unpackDetail = 'error';
      }
    }
  }
  if (unpackOk) {
    reportLines.push('unpack ok\n');
  } else {
    reportLines.push(`unpack ${unpackDetail}\n`);
  }
  for (const cmd of commands) {
    if (!unpackOk) {
      reportLines.push(`ng ${cmd.ref} unpack failed\n`);
      continue;
    }
    const current = repo.refs.get(cmd.ref);
    if (cmd.newOid === ZERO_OID) {
      // Delete.
      if (!current) {
        reportLines.push(`ng ${cmd.ref} no such ref\n`);
      } else if (cmd.oldOid !== ZERO_OID && cmd.oldOid.toLowerCase() !== current.toLowerCase()) {
        reportLines.push(`ng ${cmd.ref} stale info\n`);
      } else {
        repo.refs.delete(cmd.ref);
        reportLines.push(`ok ${cmd.ref}\n`);
      }
      continue;
    }
    const target = repo.objects.get(cmd.newOid);
    if (!target) {
      reportLines.push(`ng ${cmd.ref} object not found\n`);
      continue;
    }
    if (cmd.ref.startsWith('refs/heads/') && target.type !== 'commit') {
      reportLines.push(`ng ${cmd.ref} invalid object type\n`);
      continue;
    }
    if (cmd.oldOid === ZERO_OID) {
      if (current) {
        reportLines.push(`ng ${cmd.ref} already exists\n`);
      } else {
        repo.refs.set(cmd.ref, cmd.newOid);
        reportLines.push(`ok ${cmd.ref}\n`);
      }
      continue;
    }
    if (!current) {
      reportLines.push(`ng ${cmd.ref} no such ref\n`);
      continue;
    }
    if (cmd.oldOid.toLowerCase() !== current.toLowerCase()) {
      reportLines.push(`ng ${cmd.ref} stale info\n`);
      continue;
    }
    if (cmd.newOid.toLowerCase() === current.toLowerCase()) {
      reportLines.push(`ok ${cmd.ref}\n`);
      continue;
    }
    if (!isAncestor(repo.objects, current, cmd.newOid)) {
      reportLines.push(`ng ${cmd.ref} non-fast-forward\n`);
      continue;
    }
    repo.refs.set(cmd.ref, cmd.newOid);
    reportLines.push(`ok ${cmd.ref}\n`);
  }
  const report = encodePktLines([...reportLines, 'flush']);
  return Buffer.concat([pktLine(Buffer.concat([Buffer.from([1]), report])), pktFlush()]);
}

// ---------------------------------------------------------------- REST v3

function splitPath(pathname: string): string[] {
  return pathname.split('/').filter((part) => part !== '').map((part) => decodeURIComponent(part));
}

function parseQuery(req: http.IncomingMessage): URLSearchParams {
  const url = new URL(req.url ?? '/', 'http://localhost');
  return url.searchParams;
}

function paginate<T>(items: T[], query: URLSearchParams): { page: T[]; total: number; pageNum: number; perPage: number } {
  const perPage = Math.max(1, Math.min(100, parseInt(query.get('per_page') ?? '30', 10) || 30));
  const pageNum = Math.max(1, parseInt(query.get('page') ?? '1', 10) || 1);
  const start = (pageNum - 1) * perPage;
  return { page: items.slice(start, start + perPage), total: items.length, pageNum, perPage };
}

function pageLinkHeader(req: http.IncomingMessage, basePath: string, query: URLSearchParams, pageNum: number, perPage: number, total: number): string | null {
  const lastPage = Math.max(1, Math.ceil(total / perPage));
  if (pageNum >= lastPage) return null;
  const host = req.headers.host ?? 'localhost';
  const next = `http://${host}${basePath}?per_page=${perPage}&page=${pageNum + 1}`;
  const last = `http://${host}${basePath}?per_page=${perPage}&page=${lastPage}`;
  const first = `http://${host}${basePath}?per_page=${perPage}&page=1`;
  void query;
  return `<${next}>; rel="next", <${last}>; rel="last", <${first}>; rel="first"`;
}

function listJson(res: http.ServerResponse, req: http.IncomingMessage, basePath: string, query: URLSearchParams, items: unknown[]): void {
  const { page, total, pageNum, perPage } = paginate(items, query);
  const link = pageLinkHeader(req, basePath, query, pageNum, perPage, total);
  jsonBody(res, 200, page, link ? { link } : undefined);
}

/** A repo lookup that answers 404 for a missing repo or a foreign owner (never 403). */
function lookupRepo(res: http.ServerResponse, owner: string, name: string): Repo | null {
  if (owner !== VIEWER_LOGIN) {
    jsonError(res, 404, 'Not Found');
    return null;
  }
  const repo = getRepo(owner, name);
  if (!repo) {
    jsonError(res, 404, 'Not Found');
    return null;
  }
  return repo;
}

function commitJson(repo: Repo, oid: string): Record<string, unknown> | null {
  const obj = repo.objects.get(oid);
  if (!obj || obj.type !== 'commit') return null;
  const parsed = parseCommit(obj.data);
  const authorLine = parsed.author;
  const ts = parseInt((authorLine.split(' ').slice(-2)[0] ?? '0'), 10);
  const date = Number.isFinite(ts) ? isoOf(ts) : isoOf(repo.createdSeq);
  const authorName = authorLine.split('<')[0]?.trim() ?? VIEWER_NAME;
  const authorEmail = (authorLine.match(/<([^>]*)>/) ?? [])[1] ?? VIEWER_EMAIL;
  return {
    sha: oid,
    node_id: globalId('Commit', [repo.dbId, oid]),
    commit: {
      message: parsed.message,
      author: { name: authorName, email: authorEmail, date },
      committer: { name: authorName, email: authorEmail, date },
      tree: { sha: parsed.tree },
      url: `https://api.github.com/repos/${repo.owner}/${repo.name}/git/commits/${oid}`,
    },
    author: userJson(),
    committer: userJson(),
    parents: parsed.parents.map((p) => ({ sha: p })),
    url: `https://api.github.com/repos/${repo.owner}/${repo.name}/commits/${oid}`,
    html_url: `https://github.com/${repo.owner}/${repo.name}/commit/${oid}`,
  };
}

async function handleRest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
  const method = req.method ?? 'GET';
  const url = new URL(req.url ?? '/', 'http://localhost');
  const parts = splitPath(url.pathname);
  const query = url.searchParams;
  // parts[0] === 'api', parts[1] === 'v3'
  if (!authorized(req)) {
    jsonError(res, 401, 'Bad credentials');
    return;
  }
  const rest = parts.slice(2);

  // GET /api/v3/ (root) and /api/v3/meta
  if (rest.length === 0) {
    if (method === 'GET') {
      jsonBody(res, 200, {
        current_user_url: 'https://api.github.com/user',
        repository_url: 'https://api.github.com/repos/{owner}/{repo}',
        user_url: 'https://api.github.com/users/{user}',
        rate_limit_url: 'https://api.github.com/rate_limit',
      }, { 'x-oauth-scopes': 'repo, read:org' });
    } else {
      jsonError(res, 404, 'Not Found');
    }
    return;
  }
  if (rest.length === 1 && rest[0] === 'meta') {
    if (method === 'GET') jsonBody(res, 200, { installed_version: '1.0.0' });
    else jsonError(res, 404, 'Not Found');
    return;
  }
  if (rest.length === 1 && rest[0] === 'user') {
    if (method === 'GET') jsonBody(res, 200, userJson());
    else jsonError(res, 404, 'Not Found');
    return;
  }

  // POST /api/v3/user/repos and GET /api/v3/user/repos
  if (rest.length === 2 && rest[0] === 'user' && rest[1] === 'repos') {
    if (method === 'GET') {
      listJson(res, req, '/api/v3/user/repos', query, listViewerRepos().map((repo) => repoJson(repo)));
      return;
    }
    if (method === 'POST') {
      const raw = await readBody(req);
      const parsed = parseJsonBody(raw);
      if (!parsed.ok) {
        jsonError(res, 400, 'Problems parsing JSON');
        return;
      }
      const body = isRecord(parsed.value) ? parsed.value : {};
      const name = typeof body.name === 'string' ? body.name : '';
      if (name === '' || !/^[A-Za-z0-9._-]+$/.test(name)) {
        jsonError(res, 422, 'Repository name is invalid');
        return;
      }
      if (getRepo(VIEWER_LOGIN, name)) {
        jsonError(res, 422, 'Repository already exists');
        return;
      }
      const repo = createRepoRecord(
        name,
        typeof body.description === 'string' ? body.description : '',
        body.private === true,
      );
      jsonBody(res, 201, repoJson(repo));
      return;
    }
    jsonError(res, 404, 'Not Found');
    return;
  }

  // /api/v3/repos/{owner}/{repo}[...]
  if (rest.length >= 3 && rest[0] === 'repos') {
    const owner = rest[1]!;
    const name = rest[2]!;
    const tail = rest.slice(3);
    if (tail.length === 0) {
      if (method === 'GET') {
        const repo = lookupRepo(res, owner, name);
        if (repo) jsonBody(res, 200, repoJson(repo));
        return;
      }
      if (method === 'PATCH') {
        const repo = lookupRepo(res, owner, name);
        if (!repo) return;
        const raw = await readBody(req);
        const parsed = parseJsonBody(raw);
        if (!parsed.ok) {
          jsonError(res, 400, 'Problems parsing JSON');
          return;
        }
        const body = isRecord(parsed.value) ? parsed.value : {};
        if (typeof body.description === 'string') repo.description = body.description;
        if (typeof body.private === 'boolean') repo.isPrivate = body.private;
        repo.updatedSeq = nextTick();
        jsonBody(res, 200, repoJson(repo));
        return;
      }
      if (method === 'DELETE') {
        const repo = lookupRepo(res, owner, name);
        if (!repo) return;
        deleteRepoRecord(repo);
        res.writeHead(204, { 'x-github-request-id': nextRequestId() });
        res.end();
        return;
      }
      jsonError(res, 404, 'Not Found');
      return;
    }

    const repo = lookupRepo(res, owner, name);
    if (!repo) return;

    // branches
    if (tail.length === 1 && tail[0] === 'branches') {
      if (method !== 'GET') {
        jsonError(res, 404, 'Not Found');
        return;
      }
      const out = branchNames(repo).map((branch) => ({
        name: branch,
        commit: { sha: repo.refs.get(`refs/heads/${branch}`) ?? '', url: '' },
        protected: false,
      }));
      jsonBody(res, 200, out);
      return;
    }
    if (tail.length === 2 && tail[0] === 'branches') {
      if (method !== 'GET') {
        jsonError(res, 404, 'Not Found');
        return;
      }
      const branch = tail[1]!;
      const sha = repo.refs.get(`refs/heads/${branch}`);
      if (!sha) {
        jsonError(res, 404, 'Branch not found');
        return;
      }
      jsonBody(res, 200, { name: branch, commit: { sha, url: '' }, protected: false });
      return;
    }

    // commits
    if (tail.length === 1 && tail[0] === 'commits') {
      if (method !== 'GET') {
        jsonError(res, 404, 'Not Found');
        return;
      }
      const ref = query.get('sha');
      const tip = ref ? resolveRef(repo, ref) : headOid(repo);
      if (!tip || tip === ZERO_OID) {
        jsonBody(res, 200, []);
        return;
      }
      const list = walkAncestors(repo.objects, [tip])
        .map((oid) => commitJson(repo, oid))
        .filter((entry): entry is Record<string, unknown> => entry !== null);
      jsonBody(res, 200, list);
      return;
    }

    // git refs
    if (tail.length === 2 && tail[0] === 'git' && tail[1] === 'refs') {
      if (method === 'POST') {
        const raw = await readBody(req);
        const parsed = parseJsonBody(raw);
        if (!parsed.ok) {
          jsonError(res, 400, 'Problems parsing JSON');
          return;
        }
        const body = isRecord(parsed.value) ? parsed.value : {};
        const ref = typeof body.ref === 'string' ? body.ref : '';
        const sha = typeof body.sha === 'string' ? body.sha : '';
        if (!ref.startsWith('refs/') || !isOid(sha)) {
          jsonError(res, 422, 'Invalid ref or sha');
          return;
        }
        if (repo.refs.has(ref)) {
          jsonError(res, 422, 'Reference already exists');
          return;
        }
        const target = repo.objects.get(sha);
        if (!target || target.type !== 'commit') {
          jsonError(res, 422, 'Object does not exist or is not a commit');
          return;
        }
        repo.refs.set(ref, sha);
        jsonBody(res, 201, {
          ref,
          node_id: globalId('Ref', [repo.dbId, ref]),
          url: `https://api.github.com/repos/${owner}/${name}/git/refs/${ref}`,
          object: { sha, type: 'commit' },
        });
        return;
      }
      if (method === 'GET') {
        const out = sortedRefs(repo).map((ref) => ({
          ref: ref.name,
          node_id: globalId('Ref', [repo.dbId, ref.name]),
          url: `https://api.github.com/repos/${owner}/${name}/git/refs/${ref.name}`,
          object: { sha: ref.oid, type: repo.objects.get(ref.oid)?.type ?? 'commit' },
        }));
        jsonBody(res, 200, out);
        return;
      }
      jsonError(res, 404, 'Not Found');
      return;
    }
    if (tail.length >= 3 && tail[0] === 'git' && tail[1] === 'refs') {
      const refName = tail.slice(2).join('/');
      const fullRef = `refs/${refName}`;
      if (method === 'GET') {
        const sha = repo.refs.get(fullRef);
        if (!sha) {
          jsonError(res, 404, 'Not Found');
          return;
        }
        jsonBody(res, 200, {
          ref: fullRef,
          node_id: globalId('Ref', [repo.dbId, fullRef]),
          url: `https://api.github.com/repos/${owner}/${name}/git/refs/${fullRef}`,
          object: { sha, type: repo.objects.get(sha)?.type ?? 'commit' },
        });
        return;
      }
      if (method === 'PATCH') {
        const raw = await readBody(req);
        const parsed = parseJsonBody(raw);
        if (!parsed.ok) {
          jsonError(res, 400, 'Problems parsing JSON');
          return;
        }
        const body = isRecord(parsed.value) ? parsed.value : {};
        const sha = typeof body.sha === 'string' ? body.sha : '';
        if (!repo.refs.has(fullRef) || !isOid(sha) || !repo.objects.has(sha)) {
          jsonError(res, 404, 'Not Found');
          return;
        }
        repo.refs.set(fullRef, sha);
        jsonBody(res, 200, {
          ref: fullRef,
          node_id: globalId('Ref', [repo.dbId, fullRef]),
          url: `https://api.github.com/repos/${owner}/${name}/git/refs/${fullRef}`,
          object: { sha, type: repo.objects.get(sha)?.type ?? 'commit' },
        });
        return;
      }
      jsonError(res, 404, 'Not Found');
      return;
    }

    // contents
    if (tail.length >= 1 && tail[0] === 'contents') {
      await handleContents(req, res, repo, tail.slice(1), query);
      return;
    }

    // labels
    if (tail.length === 1 && tail[0] === 'labels') {
      if (method === 'GET') {
        jsonBody(res, 200, [...repo.labels.values()].map((label) => ({ id: label.id, name: label.name, color: label.color, description: label.description, default: false })));
        return;
      }
      if (method === 'POST') {
        const raw = await readBody(req);
        const parsed = parseJsonBody(raw);
        if (!parsed.ok) {
          jsonError(res, 400, 'Problems parsing JSON');
          return;
        }
        const body = isRecord(parsed.value) ? parsed.value : {};
        const labelName = typeof body.name === 'string' ? body.name : '';
        if (labelName === '') {
          jsonError(res, 422, 'Label name is required');
          return;
        }
        if (repo.labels.has(labelName)) {
          jsonError(res, 422, 'Label already exists');
          return;
        }
        const label: Label = {
          id: repo.nextLabelId,
          name: labelName,
          color: typeof body.color === 'string' ? body.color : 'ededed',
          description: typeof body.description === 'string' ? body.description : '',
        };
        repo.nextLabelId += 1;
        repo.labels.set(labelName, label);
        jsonBody(res, 201, { id: label.id, name: label.name, color: label.color, description: label.description, default: false });
        return;
      }
      jsonError(res, 404, 'Not Found');
      return;
    }

    // issues
    if (tail.length === 1 && tail[0] === 'issues') {
      if (method === 'GET') {
        let list = [...repo.issues.values()];
        const state = query.get('state') ?? 'open';
        if (state !== 'all') list = list.filter((issue) => issue.state === state);
        const direction = query.get('direction') ?? 'desc';
        list.sort((a, b) => (direction === 'asc' ? a.createdSeq - b.createdSeq || a.number - b.number : b.createdSeq - a.createdSeq || b.number - a.number));
        listJson(res, req, `/api/v3/repos/${owner}/${name}/issues`, query, list.map((issue) => issueJson(repo, issue)));
        return;
      }
      if (method === 'POST') {
        const raw = await readBody(req);
        const parsed = parseJsonBody(raw);
        if (!parsed.ok) {
          jsonError(res, 400, 'Problems parsing JSON');
          return;
        }
        const body = isRecord(parsed.value) ? parsed.value : {};
        const title = typeof body.title === 'string' ? body.title : '';
        if (title === '') {
          jsonError(res, 422, 'Title is required');
          return;
        }
        const labels = Array.isArray(body.labels) ? body.labels.filter((l): l is string => typeof l === 'string') : [];
        for (const label of labels) {
          if (!repo.labels.has(label)) {
            jsonError(res, 422, `Label does not exist: ${label}`);
            return;
          }
        }
        const issue = createIssueRecord(repo, title, typeof body.body === 'string' ? body.body : '', labels);
        jsonBody(res, 201, issueJson(repo, issue));
        return;
      }
      jsonError(res, 404, 'Not Found');
      return;
    }
    if (tail.length === 2 && tail[0] === 'issues') {
      const number = parseInt(tail[1]!, 10);
      const issue = repo.issues.get(number);
      if (!issue) {
        jsonError(res, 404, 'Not Found');
        return;
      }
      if (method === 'GET') {
        jsonBody(res, 200, issueJson(repo, issue));
        return;
      }
      if (method === 'PATCH') {
        const raw = await readBody(req);
        const parsed = parseJsonBody(raw);
        if (!parsed.ok) {
          jsonError(res, 400, 'Problems parsing JSON');
          return;
        }
        const body = isRecord(parsed.value) ? parsed.value : {};
        if (body.state === 'closed' || body.state === 'open') {
          issue.state = body.state;
          issue.closedSeq = body.state === 'closed' ? nextTick() : null;
        }
        if (typeof body.title === 'string') issue.title = body.title;
        if (typeof body.body === 'string') issue.body = body.body;
        issue.updatedSeq = nextTick();
        jsonBody(res, 200, issueJson(repo, issue));
        return;
      }
      jsonError(res, 404, 'Not Found');
      return;
    }
    if (tail.length === 3 && tail[0] === 'issues' && tail[2] === 'comments') {
      const number = parseInt(tail[1]!, 10);
      const issue = repo.issues.get(number);
      if (!issue) {
        jsonError(res, 404, 'Not Found');
        return;
      }
      if (method === 'GET') {
        jsonBody(res, 200, issue.comments.map((comment) => commentJson(repo, issue, comment)));
        return;
      }
      if (method === 'POST') {
        const raw = await readBody(req);
        const parsed = parseJsonBody(raw);
        if (!parsed.ok) {
          jsonError(res, 400, 'Problems parsing JSON');
          return;
        }
        const body = isRecord(parsed.value) ? parsed.value : {};
        const text = typeof body.body === 'string' ? body.body : '';
        if (text === '') {
          jsonError(res, 422, 'Comment body is required');
          return;
        }
        const comment: Comment = { id: issue.nextCommentId, body: text, createdSeq: nextTick() };
        issue.nextCommentId += 1;
        issue.comments.push(comment);
        issue.updatedSeq = tick;
        jsonBody(res, 201, commentJson(repo, issue, comment));
        return;
      }
      jsonError(res, 404, 'Not Found');
      return;
    }

    // pulls
    if (tail.length === 1 && tail[0] === 'pulls') {
      if (method === 'GET') {
        let list = [...repo.pulls.values()];
        const state = query.get('state') ?? 'open';
        if (state !== 'all') list = list.filter((pull) => (state === 'closed' ? pull.state === 'closed' : pull.state === 'open'));
        list.sort((a, b) => b.number - a.number);
        listJson(res, req, `/api/v3/repos/${owner}/${name}/pulls`, query, list.map((pull) => pullJson(repo, pull)));
        return;
      }
      if (method === 'POST') {
        const raw = await readBody(req);
        const parsed = parseJsonBody(raw);
        if (!parsed.ok) {
          jsonError(res, 400, 'Problems parsing JSON');
          return;
        }
        const body = isRecord(parsed.value) ? parsed.value : {};
        const title = typeof body.title === 'string' ? body.title : '';
        const head = typeof body.head === 'string' ? body.head : '';
        const base = typeof body.base === 'string' ? body.base : repo.defaultBranch;
        if (title === '' || head === '' || base === '') {
          jsonError(res, 422, 'Title, head and base are required');
          return;
        }
        if (!resolveRef(repo, head) || !resolveRef(repo, base)) {
          jsonError(res, 422, 'Head or base branch does not exist');
          return;
        }
        const existing = [...repo.pulls.values()].find((pull) => pull.state === 'open' && pull.headRef === head && pull.baseRef === base);
        if (existing) {
          jsonError(res, 422, 'A pull request already exists for this head branch');
          return;
        }
        const pull = createPullRecord(repo, title, typeof body.body === 'string' ? body.body : '', head, base);
        if (!pull) {
          jsonError(res, 422, 'Could not create pull request');
          return;
        }
        jsonBody(res, 201, pullJson(repo, pull));
        return;
      }
      jsonError(res, 404, 'Not Found');
      return;
    }
    if (tail.length === 2 && tail[0] === 'pulls') {
      const number = parseInt(tail[1]!, 10);
      const pull = repo.pulls.get(number);
      if (!pull) {
        jsonError(res, 404, 'Not Found');
        return;
      }
      if (method === 'GET') {
        jsonBody(res, 200, pullJson(repo, pull));
        return;
      }
      jsonError(res, 404, 'Not Found');
      return;
    }
    if (tail.length === 3 && tail[0] === 'pulls' && tail[2] === 'files') {
      const number = parseInt(tail[1]!, 10);
      const pull = repo.pulls.get(number);
      if (!pull) {
        jsonError(res, 404, 'Not Found');
        return;
      }
      if (method !== 'GET') {
        jsonError(res, 404, 'Not Found');
        return;
      }
      const files = pullFiles(repo, pull).map((diff) => ({
        sha: diff.headOid ?? diff.baseOid ?? '',
        filename: diff.path,
        status: diff.status,
        additions: diff.additions,
        deletions: diff.deletions,
        changes: diff.additions + diff.deletions,
        blob_url: '',
        raw_url: '',
        contents_url: '',
      }));
      jsonBody(res, 200, files);
      return;
    }
    if (tail.length === 3 && tail[0] === 'pulls' && tail[2] === 'merge') {
      const number = parseInt(tail[1]!, 10);
      const pull = repo.pulls.get(number);
      if (!pull) {
        jsonError(res, 404, 'Not Found');
        return;
      }
      if (method !== 'PUT') {
        jsonError(res, 404, 'Not Found');
        return;
      }
      const raw = await readBody(req);
      const parsed = parseJsonBody(raw);
      if (!parsed.ok) {
        jsonError(res, 400, 'Problems parsing JSON');
        return;
      }
      if (pull.merged || pull.state === 'closed') {
        jsonError(res, 405, 'Pull request has already been merged');
        return;
      }
      if (pullMergeable(repo, pull) === 'CONFLICTING') {
        jsonError(res, 405, 'Merge conflict');
        return;
      }
      const sha = squashMerge(repo, pull);
      if (!sha) {
        jsonError(res, 405, 'Merge conflict');
        return;
      }
      jsonBody(res, 200, { sha, merged: true, message: 'Pull request successfully merged' });
      return;
    }
  }

  jsonError(res, 404, 'Not Found');
}

async function handleContents(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  repo: Repo,
  segments: string[],
  query: URLSearchParams,
): Promise<void> {
  const method = req.method ?? 'GET';
  const refParam = query.get('ref');
  const branch = refParam ?? repo.defaultBranch;
  const tip = refParam ? resolveRef(repo, refParam) : headOid(repo);
  const treeOid = tip && tip !== ZERO_OID ? (() => {
    const obj = repo.objects.get(tip);
    return obj && obj.type === 'commit' ? parseCommit(obj.data).tree : null;
  })() : null;

  if (method === 'GET') {
    if (segments.length === 0) {
      const entries = listDirectory(repo.objects, treeOid, []) ?? [];
      jsonBody(res, 200, entries.map((entry) => ({
        type: entry.mode === '40000' ? 'dir' : 'file',
        name: entry.name,
        path: entry.name,
        sha: entry.oid,
        size: entry.mode === '40000' ? 0 : (repo.objects.get(entry.oid)?.data.length ?? 0),
        url: '',
        html_url: '',
        download_url: null,
      })));
      return;
    }
    const found = lookupPath(repo.objects, treeOid, segments);
    if (!found) {
      jsonError(res, 404, 'Not Found');
      return;
    }
    if (found.mode === '40000') {
      const entries = listDirectory(repo.objects, treeOid, segments) ?? [];
      const prefix = segments.join('/');
      jsonBody(res, 200, entries.map((entry) => ({
        type: entry.mode === '40000' ? 'dir' : 'file',
        name: entry.name,
        path: `${prefix}/${entry.name}`,
        sha: entry.oid,
        size: entry.mode === '40000' ? 0 : (repo.objects.get(entry.oid)?.data.length ?? 0),
        url: '',
        html_url: '',
        download_url: null,
      })));
      return;
    }
    const blob = repo.objects.get(found.oid);
    if (!blob) {
      jsonError(res, 404, 'Not Found');
      return;
    }
    const path = segments.join('/');
    jsonBody(res, 200, {
      type: 'file',
      encoding: 'base64',
      size: blob.data.length,
      name: segments[segments.length - 1] ?? '',
      path,
      content: b64encode(blob.data),
      sha: found.oid,
      url: `https://api.github.com/repos/${repo.owner}/${repo.name}/contents/${path}`,
      html_url: `https://github.com/${repo.owner}/${repo.name}/blob/${branch}/${path}`,
      download_url: `https://raw.githubusercontent.com/${repo.owner}/${repo.name}/${branch}/${path}`,
    });
    return;
  }

  if (method === 'PUT') {
    const raw = await readBody(req);
    const parsed = parseJsonBody(raw);
    if (!parsed.ok) {
      jsonError(res, 400, 'Problems parsing JSON');
      return;
    }
    const body = isRecord(parsed.value) ? parsed.value : {};
    const message = typeof body.message === 'string' ? body.message : `Update ${segments.join('/')}`;
    const contentB64 = typeof body.content === 'string' ? body.content : '';
    if (contentB64 === '' || segments.length === 0) {
      jsonError(res, 422, 'Content is required');
      return;
    }
    const targetBranch = typeof body.branch === 'string' && body.branch !== '' ? body.branch : repo.defaultBranch;
    // A write to a branch that does not exist yet creates it from the default tip.
    let branchTip = repo.refs.get(`refs/heads/${targetBranch}`);
    if (!branchTip) {
      const defaultTip = headOid(repo);
      if (defaultTip !== ZERO_OID) repo.refs.set(`refs/heads/${targetBranch}`, defaultTip);
      branchTip = repo.refs.get(`refs/heads/${targetBranch}`) ?? undefined;
    }
    const currentTree = branchTip ? (() => {
      const obj = repo.objects.get(branchTip!);
      return obj && obj.type === 'commit' ? parseCommit(obj.data).tree : null;
    })() : null;
    const existing = lookupPath(repo.objects, currentTree, segments);
    const shaParam = typeof body.sha === 'string' ? body.sha : null;
    if (existing) {
      if (shaParam === null) {
        jsonError(res, 422, 'File already exists; a sha is required to update it');
        return;
      }
      if (shaParam.toLowerCase() !== existing.oid.toLowerCase()) {
        jsonError(res, 409, 'The file has changed since the sha you provided');
        return;
      }
    }
    const bytes = b64decode(contentB64);
    const blobOid = sha1Object('blob', bytes);
    repo.objects.set(blobOid, { type: 'blob', data: bytes });
    const newTree = setPathInTree(repo.objects, currentTree, segments, blobOid);
    const commitSha = commitOnBranch(repo, targetBranch, newTree, message);
    const status = existing ? 200 : 201;
    jsonBody(res, status, {
      content: {
        name: segments[segments.length - 1] ?? '',
        path: segments.join('/'),
        sha: blobOid,
        size: bytes.length,
        type: 'file',
        encoding: 'base64',
        content: contentB64,
        url: '',
        html_url: '',
        download_url: null,
      },
      commit: { sha: commitSha },
    });
    return;
  }

  if (method === 'DELETE') {
    const raw = await readBody(req);
    const parsed = parseJsonBody(raw);
    if (!parsed.ok) {
      jsonError(res, 400, 'Problems parsing JSON');
      return;
    }
    const body = isRecord(parsed.value) ? parsed.value : {};
    const targetBranch = typeof body.branch === 'string' && body.branch !== '' ? body.branch : repo.defaultBranch;
    const branchTip = repo.refs.get(`refs/heads/${targetBranch}`);
    if (!branchTip) {
      jsonError(res, 404, 'Not Found');
      return;
    }
    const currentTree = (() => {
      const obj = repo.objects.get(branchTip);
      return obj && obj.type === 'commit' ? parseCommit(obj.data).tree : null;
    })();
    const existing = lookupPath(repo.objects, currentTree, segments);
    if (!existing) {
      jsonError(res, 404, 'Not Found');
      return;
    }
    const shaParam = typeof body.sha === 'string' ? body.sha : null;
    if (shaParam !== null && shaParam.toLowerCase() !== existing.oid.toLowerCase()) {
      jsonError(res, 409, 'The file has changed since the sha you provided');
      return;
    }
    const message = typeof body.message === 'string' ? body.message : `Delete ${segments.join('/')}`;
    const newTree = removePathFromTree(repo.objects, currentTree, segments);
    const commitSha = commitOnBranch(repo, targetBranch, newTree, message);
    jsonBody(res, 200, { commit: { sha: commitSha }, content: null });
    return;
  }

  jsonError(res, 404, 'Not Found');
}

// ---------------------------------------------------------------- GraphQL v4

type GqlValue =
  | { kind: 'variable'; name: string }
  | { kind: 'string'; value: string }
  | { kind: 'int'; value: number }
  | { kind: 'float'; value: number }
  | { kind: 'boolean'; value: boolean }
  | { kind: 'null' }
  | { kind: 'enum'; value: string }
  | { kind: 'list'; items: GqlValue[] }
  | { kind: 'object'; fields: Array<{ name: string; value: GqlValue }> };

interface GqlFieldSel {
  kind: 'field';
  alias: string;
  name: string;
  args: Record<string, GqlValue>;
  selectionSet: GqlSelection[] | null;
}
interface GqlFragmentSel {
  kind: 'fragment';
  typeCondition: string;
  selectionSet: GqlSelection[];
}
type GqlSelection = GqlFieldSel | GqlFragmentSel;

interface GqlOperation {
  kind: 'query' | 'mutation';
  name: string | null;
  selectionSet: GqlSelection[];
}

interface GqlToken {
  kind: 'name' | 'int' | 'float' | 'string' | 'punct' | 'spread';
  value: string;
}

function tokenizeGql(source: string): GqlToken[] {
  const tokens: GqlToken[] = [];
  let i = 0;
  while (i < source.length) {
    const ch = source[i]!;
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === ',') {
      i += 1;
      continue;
    }
    if (ch === '#') {
      while (i < source.length && source[i] !== '\n') i += 1;
      continue;
    }
    if (ch === '.' && source.slice(i, i + 3) === '...') {
      tokens.push({ kind: 'spread', value: '...' });
      i += 3;
      continue;
    }
    if ('{}()[]:!=$@|&='.includes(ch)) {
      tokens.push({ kind: 'punct', value: ch });
      i += 1;
      continue;
    }
    if (ch === '"') {
      let j = i + 1;
      let out = '';
      while (j < source.length && source[j] !== '"') {
        if (source[j] === '\\' && j + 1 < source.length) {
          const esc = source[j + 1]!;
          out += esc === 'n' ? '\n' : esc === 't' ? '\t' : esc === 'r' ? '\r' : esc;
          j += 2;
        } else {
          out += source[j]!;
          j += 1;
        }
      }
      tokens.push({ kind: 'string', value: out });
      i = j + 1;
      continue;
    }
    if (/[0-9-]/.test(ch)) {
      let j = i;
      while (j < source.length && /[0-9.]/.test(source[j]!)) j += 1;
      const text = source.slice(i, j);
      tokens.push({ kind: text.includes('.') ? 'float' : 'int', value: text });
      i = j;
      continue;
    }
    if (/[A-Za-z_]/.test(ch)) {
      let j = i;
      while (j < source.length && /[A-Za-z0-9_]/.test(source[j]!)) j += 1;
      tokens.push({ kind: 'name', value: source.slice(i, j) });
      i = j;
      continue;
    }
    throw new Error(`unexpected character ${JSON.stringify(ch)} in GraphQL document`);
  }
  tokens.push({ kind: 'punct', value: '' });
  return tokens;
}

class GqlParser {
  private tokens: GqlToken[];
  private pos = 0;

  constructor(source: string) {
    this.tokens = tokenizeGql(source);
  }

  private peek(): GqlToken {
    return this.tokens[this.pos]!;
  }

  private next(): GqlToken {
    return this.tokens[this.pos++]!;
  }

  private expectPunct(value: string): void {
    const token = this.next();
    if (token.kind !== 'punct' || token.value !== value) throw new Error(`expected ${JSON.stringify(value)} in GraphQL document`);
  }

  private expectName(): string {
    const token = this.next();
    if (token.kind !== 'name') throw new Error('expected a name in GraphQL document');
    return token.value;
  }

  parseDocument(): GqlOperation[] {
    const operations: GqlOperation[] = [];
    while (this.peek().value !== '') {
      operations.push(this.parseOperation());
    }
    return operations;
  }

  private parseOperation(): GqlOperation {
    let kind: 'query' | 'mutation' = 'query';
    const first = this.peek();
    if (first.kind === 'name' && (first.value === 'query' || first.value === 'mutation')) {
      kind = this.next().value as 'query' | 'mutation';
    }
    let name: string | null = null;
    if (this.peek().kind === 'name') name = this.next().value;
    // Variable definitions: ($x: Type, ...) — skip their contents.
    if (this.peek().kind === 'punct' && this.peek().value === '(') {
      let depth = 0;
      do {
        const token = this.next();
        if (token.value === '(') depth += 1;
        else if (token.value === ')') depth -= 1;
      } while (depth > 0);
    }
    const selectionSet = this.parseSelectionSet();
    return { kind, name, selectionSet };
  }

  private parseSelectionSet(): GqlSelection[] {
    this.expectPunct('{');
    const selections: GqlSelection[] = [];
    while (!(this.peek().kind === 'punct' && this.peek().value === '}')) {
      if (this.peek().kind === 'spread') {
        this.next();
        if (this.peek().kind === 'name' && this.peek().value === 'on') {
          this.next();
          const typeCondition = this.expectName();
          selections.push({ kind: 'fragment', typeCondition, selectionSet: this.parseSelectionSet() });
        } else {
          throw new Error('named fragments are not supported');
        }
        continue;
      }
      const first = this.expectName();
      let alias = first;
      let name = first;
      if (this.peek().kind === 'punct' && this.peek().value === ':') {
        this.next();
        name = this.expectName();
      }
      const args: Record<string, GqlValue> = {};
      if (this.peek().kind === 'punct' && this.peek().value === '(') {
        this.next();
        while (!(this.peek().kind === 'punct' && this.peek().value === ')')) {
          const argName = this.expectName();
          this.expectPunct(':');
          args[argName] = this.parseValue();
        }
        this.expectPunct(')');
      }
      let selectionSet: GqlSelection[] | null = null;
      if (this.peek().kind === 'punct' && this.peek().value === '{') {
        selectionSet = this.parseSelectionSet();
      }
      selections.push({ kind: 'field', alias, name, args, selectionSet });
    }
    this.expectPunct('}');
    return selections;
  }

  private parseValue(): GqlValue {
    const token = this.next();
    if (token.kind === 'punct' && token.value === '$') {
      return { kind: 'variable', name: this.expectName() };
    }
    if (token.kind === 'string') return { kind: 'string', value: token.value };
    if (token.kind === 'int') return { kind: 'int', value: parseInt(token.value, 10) };
    if (token.kind === 'float') return { kind: 'float', value: parseFloat(token.value) };
    if (token.kind === 'name') {
      if (token.value === 'true') return { kind: 'boolean', value: true };
      if (token.value === 'false') return { kind: 'boolean', value: false };
      if (token.value === 'null') return { kind: 'null' };
      return { kind: 'enum', value: token.value };
    }
    if (token.kind === 'punct' && token.value === '[') {
      const items: GqlValue[] = [];
      while (!(this.peek().kind === 'punct' && this.peek().value === ']')) items.push(this.parseValue());
      this.expectPunct(']');
      return { kind: 'list', items };
    }
    if (token.kind === 'punct' && token.value === '{') {
      const fields: Array<{ name: string; value: GqlValue }> = [];
      while (!(this.peek().kind === 'punct' && this.peek().value === '}')) {
        const name = this.expectName();
        this.expectPunct(':');
        fields.push({ name, value: this.parseValue() });
      }
      this.expectPunct('}');
      return { kind: 'object', fields };
    }
    throw new Error(`unexpected token ${JSON.stringify(token.value)} in GraphQL value`);
  }
}

function resolveGqlValue(value: GqlValue, variables: Record<string, unknown>): unknown {
  switch (value.kind) {
    case 'variable':
      return variables[value.name] ?? null;
    case 'string':
    case 'int':
    case 'float':
    case 'boolean':
      return value.value;
    case 'null':
      return null;
    case 'enum':
      return value.value;
    case 'list':
      return value.items.map((item) => resolveGqlValue(item, variables));
    case 'object': {
      const out: Record<string, unknown> = {};
      for (const field of value.fields) out[field.name] = resolveGqlValue(field.value, variables);
      return out;
    }
  }
}

// ---------------------------------------------------------------- GraphQL values

type GqlRuntime =
  | { __typename: 'User'; login: string }
  | { __typename: 'Repository'; repo: Repo }
  | { __typename: 'Issue'; repo: Repo; issue: Issue }
  | { __typename: 'PullRequest'; repo: Repo; pull: Pull }
  | { __typename: 'IssueConnection'; repo: Repo; nodes: Issue[]; hasNextPage: boolean; endCursor: string | null }
  | { __typename: 'PullRequestConnection'; repo: Repo; nodes: Pull[] }
  | { __typename: 'PageInfo'; hasNextPage: boolean; endCursor: string | null }
  | { __typename: 'Ref'; name: string }
  | { __typename: 'ChangedFile'; path: string }
  | { __typename: 'ChangedFiles'; files: FileDiff[] }
  | { __typename: '__Type'; name: string; fieldNames: string[]; enumNames: string[] }
  | { __typename: 'CreateIssuePayload'; repo: Repo; issue: Issue }
  | { __typename: 'CloseIssuePayload'; repo: Repo; issue: Issue }
  | { __typename: 'CreatePullRequestPayload'; repo: Repo; pull: Pull }
  | { __typename: 'MergePullRequestPayload'; repo: Repo; pull: Pull }
  | { __typename: 'AddCommentPayload'; repo: Repo; issue: Issue; comment: Comment }
  | { __typename: 'CommentEdge'; repo: Repo; issue: Issue; comment: Comment }
  | { __typename: 'IssueComment'; repo: Repo; issue: Issue; comment: Comment };

const INTROSPECTION: Record<string, { fields: string[]; enums: string[] }> = {
  Issue: {
    fields: ['id', 'number', 'title', 'body', 'state', 'url', 'createdAt', 'updatedAt', 'author', 'comments', 'labels', 'repository'],
    enums: [],
  },
  PullRequest: {
    fields: ['id', 'number', 'title', 'body', 'state', 'merged', 'mergeable', 'headRefName', 'baseRefName', 'files', 'headRef', 'baseRef', 'author', 'createdAt', 'updatedAt'],
    enums: [],
  },
  Repository: {
    fields: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest', 'description', 'url', 'createdAt', 'updatedAt'],
    enums: [],
  },
  SearchType: {
    fields: [],
    enums: ['ISSUE', 'REPOSITORY', 'USER', 'DISCUSSION', 'COMMIT'],
  },
  IssueState: {
    fields: [],
    enums: ['OPEN', 'CLOSED'],
  },
  PullRequestState: {
    fields: [],
    enums: ['OPEN', 'CLOSED', 'MERGED'],
  },
  MergeableState: {
    fields: [],
    enums: ['MERGEABLE', 'CONFLICTING', 'UNKNOWN'],
  },
  IssueOrderField: {
    fields: [],
    enums: ['CREATED_AT', 'UPDATED_AT', 'COMMENTS'],
  },
  OrderDirection: {
    fields: [],
    enums: ['ASC', 'DESC'],
  },
  RepositoryPermission: {
    fields: [],
    enums: ['ADMIN', 'MAINTAIN', 'WRITE', 'TRIAGE', 'READ'],
  },
  PullRequestMergeMethod: {
    fields: [],
    enums: ['MERGE', 'SQUASH', 'REBASE'],
  },
};

function issueStateGql(issue: Issue): string {
  return issue.state === 'open' ? 'OPEN' : 'CLOSED';
}

function pullStateGql(pull: Pull): string {
  if (pull.merged) return 'MERGED';
  return pull.state === 'open' ? 'OPEN' : 'CLOSED';
}

function issueCursor(repo: Repo, issue: Issue): string {
  return Buffer.from(`cursor:${repo.dbId}:${issue.number}`, 'utf8').toString('base64');
}

function decodeCursor(cursor: string): number | null {
  try {
    const text = Buffer.from(cursor, 'base64').toString('utf8');
    const parts = text.split(':');
    if (parts[0] !== 'cursor' || parts.length !== 3) return null;
    const n = parseInt(parts[2]!, 10);
    return Number.isFinite(n) ? n : null;
  } catch {
    return null;
  }
}

function repoByGlobalId(id: string): Repo | null {
  const decoded = decodeGlobalId(id);
  if (!decoded || decoded.kind !== 'Repository') return null;
  const dbId = parseInt(decoded.parts[0]!, 10);
  for (const repo of repos.values()) {
    if (repo.dbId === dbId) return repo;
  }
  return null;
}

function issueByGlobalId(id: string): { repo: Repo; issue: Issue } | null {
  const decoded = decodeGlobalId(id);
  if (!decoded || decoded.kind !== 'Issue') return null;
  const dbId = parseInt(decoded.parts[0]!, 10);
  const number = parseInt(decoded.parts[1]!, 10);
  for (const repo of repos.values()) {
    if (repo.dbId === dbId) {
      const issue = repo.issues.get(number);
      return issue ? { repo, issue } : null;
    }
  }
  return null;
}

function pullByGlobalId(id: string): { repo: Repo; pull: Pull } | null {
  const decoded = decodeGlobalId(id);
  if (!decoded || decoded.kind !== 'PullRequest') return null;
  const dbId = parseInt(decoded.parts[0]!, 10);
  const number = parseInt(decoded.parts[1]!, 10);
  for (const repo of repos.values()) {
    if (repo.dbId === dbId) {
      const pull = repo.pulls.get(number);
      return pull ? { repo, pull } : null;
    }
  }
  return null;
}

interface GqlError {
  message: string;
}

function executeSelections(
  selections: GqlSelection[],
  parentType: string,
  parent: GqlRuntime | null,
  variables: Record<string, unknown>,
  errors: GqlError[],
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const selection of selections) {
    if (selection.kind === 'fragment') {
      if (parent && parent.__typename === selection.typeCondition) {
        Object.assign(out, executeSelections(selection.selectionSet, parentType, parent, variables, errors));
      }
      continue;
    }
    const args: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(selection.args)) args[key] = resolveGqlValue(value, variables);
    out[selection.alias] = resolveField(parentType, parent, selection.name, args, selection.selectionSet, variables, errors);
  }
  return out;
}

function resolveField(
  parentType: string,
  parent: GqlRuntime | null,
  field: string,
  args: Record<string, unknown>,
  selectionSet: GqlSelection[] | null,
  variables: Record<string, unknown>,
  errors: GqlError[],
): unknown {
  const unknown = (): null => {
    errors.push({ message: `Cannot query field "${field}" on type "${parentType}".` });
    return null;
  };
  const sub = (value: GqlRuntime, typeName: string): unknown => {
    if (!selectionSet) return value;
    return executeSelections(selectionSet, typeName, value, variables, errors);
  };
  if (field === '__typename') return parentType;

  if (parentType === 'Query') {
    if (field === 'viewer') {
      const user: GqlRuntime = { __typename: 'User', login: VIEWER_LOGIN };
      return sub(user, 'User');
    }
    if (field === 'repository') {
      const owner = typeof args.owner === 'string' ? args.owner : '';
      const name = typeof args.name === 'string' ? args.name : '';
      const repo = owner === VIEWER_LOGIN ? getRepo(owner, name) : undefined;
      if (!repo) return null;
      const value: GqlRuntime = { __typename: 'Repository', repo };
      return sub(value, 'Repository');
    }
    if (field === 'node') {
      const id = typeof args.id === 'string' ? args.id : '';
      const decoded = decodeGlobalId(id);
      if (!decoded) return null;
      if (decoded.kind === 'Repository') {
        const repo = repoByGlobalId(id);
        if (!repo) return null;
        return sub({ __typename: 'Repository', repo }, 'Repository');
      }
      if (decoded.kind === 'Issue') {
        const found = issueByGlobalId(id);
        if (!found) return null;
        return sub({ __typename: 'Issue', repo: found.repo, issue: found.issue }, 'Issue');
      }
      if (decoded.kind === 'PullRequest') {
        const found = pullByGlobalId(id);
        if (!found) return null;
        return sub({ __typename: 'PullRequest', repo: found.repo, pull: found.pull }, 'PullRequest');
      }
      return null;
    }
    if (field === '__type') {
      const name = typeof args.name === 'string' ? args.name : '';
      const info = INTROSPECTION[name];
      if (!info) return null;
      const value: GqlRuntime = { __typename: '__Type', name, fieldNames: info.fields, enumNames: info.enums };
      return sub(value, '__Type');
    }
    return unknown();
  }

  if (parentType === 'Mutation') {
    if (field === 'createIssue') {
      const input = isRecord(args.input) ? args.input : {};
      const repo = typeof input.repositoryId === 'string' ? repoByGlobalId(input.repositoryId) : null;
      const title = typeof input.title === 'string' ? input.title : '';
      if (!repo || title === '') {
        errors.push({ message: 'createIssue: unknown repository or missing title.' });
        return null;
      }
      const issue = createIssueRecord(repo, title, typeof input.body === 'string' ? input.body : '', []);
      const value: GqlRuntime = { __typename: 'CreateIssuePayload', repo, issue };
      return sub(value, 'CreateIssuePayload');
    }
    if (field === 'closeIssue') {
      const input = isRecord(args.input) ? args.input : {};
      const found = typeof input.issueId === 'string' ? issueByGlobalId(input.issueId) : null;
      if (!found) {
        errors.push({ message: 'closeIssue: unknown issue.' });
        return null;
      }
      found.issue.state = 'closed';
      found.issue.closedSeq = nextTick();
      found.issue.updatedSeq = tick;
      const value: GqlRuntime = { __typename: 'CloseIssuePayload', repo: found.repo, issue: found.issue };
      return sub(value, 'CloseIssuePayload');
    }
    if (field === 'createPullRequest') {
      const input = isRecord(args.input) ? args.input : {};
      const repo = typeof input.repositoryId === 'string' ? repoByGlobalId(input.repositoryId) : null;
      const head = typeof input.headRefName === 'string' ? input.headRefName : '';
      const base = typeof input.baseRefName === 'string' ? input.baseRefName : '';
      const title = typeof input.title === 'string' ? input.title : '';
      if (!repo || head === '' || base === '') {
        errors.push({ message: 'createPullRequest: unknown repository or missing refs.' });
        return null;
      }
      const pull = createPullRecord(repo, title, typeof input.body === 'string' ? input.body : '', head, base);
      if (!pull) {
        errors.push({ message: 'createPullRequest: head or base branch does not exist.' });
        return null;
      }
      const value: GqlRuntime = { __typename: 'CreatePullRequestPayload', repo, pull };
      return sub(value, 'CreatePullRequestPayload');
    }
    if (field === 'mergePullRequest') {
      const input = isRecord(args.input) ? args.input : {};
      const found = typeof input.pullRequestId === 'string' ? pullByGlobalId(input.pullRequestId) : null;
      if (!found) {
        errors.push({ message: 'mergePullRequest: unknown pull request.' });
        return null;
      }
      if (!found.pull.merged && found.pull.state === 'open') {
        if (pullMergeable(found.repo, found.pull) === 'CONFLICTING') {
          errors.push({ message: 'mergePullRequest: the pull request is conflicted.' });
          return null;
        }
        squashMerge(found.repo, found.pull);
      }
      const value: GqlRuntime = { __typename: 'MergePullRequestPayload', repo: found.repo, pull: found.pull };
      return sub(value, 'MergePullRequestPayload');
    }
    if (field === 'addComment') {
      const input = isRecord(args.input) ? args.input : {};
      const found = typeof input.subjectId === 'string' ? issueByGlobalId(input.subjectId) : null;
      const text = typeof input.body === 'string' ? input.body : '';
      if (!found || text === '') {
        errors.push({ message: 'addComment: unknown subject or missing body.' });
        return null;
      }
      const comment: Comment = { id: found.issue.nextCommentId, body: text, createdSeq: nextTick() };
      found.issue.nextCommentId += 1;
      found.issue.comments.push(comment);
      found.issue.updatedSeq = tick;
      const value: GqlRuntime = { __typename: 'AddCommentPayload', repo: found.repo, issue: found.issue, comment };
      return sub(value, 'AddCommentPayload');
    }
    return unknown();
  }

  if (!parent) return unknown();

  if (parentType === 'User' && parent.__typename === 'User') {
    if (field === 'login') return parent.login;
    return unknown();
  }

  if (parentType === 'Repository' && parent.__typename === 'Repository') {
    const repo = parent.repo;
    switch (field) {
      case 'id': return globalId('Repository', [repo.dbId]);
      case 'databaseId': return repo.dbId;
      case 'name': return repo.name;
      case 'nameWithOwner': return `${repo.owner}/${repo.name}`;
      case 'description': return repo.description;
      case 'owner': return sub({ __typename: 'User', login: repo.owner }, 'User');
      case 'defaultBranchRef': {
        const tip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
        if (!tip) return null;
        return sub({ __typename: 'Ref', name: repo.defaultBranch }, 'Ref');
      }
      case 'viewerPermission': return 'ADMIN';
      case 'hasIssuesEnabled': return true;
      case 'url': return `https://github.com/${repo.owner}/${repo.name}`;
      case 'createdAt': return isoOf(repo.createdSeq);
      case 'updatedAt': return isoOf(repo.updatedSeq);
      case 'issue': {
        const number = typeof args.number === 'number' ? args.number : -1;
        const issue = repo.issues.get(number);
        if (!issue) return null;
        return sub({ __typename: 'Issue', repo, issue }, 'Issue');
      }
      case 'issues': {
        let list = [...repo.issues.values()];
        const states = Array.isArray(args.states) ? args.states : null;
        if (states) {
          const wanted = new Set(states.map((s) => String(s)));
          list = list.filter((issue) => wanted.has(issueStateGql(issue)));
        }
        const orderBy = isRecord(args.orderBy) ? args.orderBy : {};
        const direction = String(orderBy.direction ?? 'DESC');
        list.sort((a, b) => {
          const byCreated = direction === 'ASC' ? a.createdSeq - b.createdSeq : b.createdSeq - a.createdSeq;
          if (byCreated !== 0) return byCreated;
          return direction === 'ASC' ? a.number - b.number : b.number - a.number;
        });
        let start = 0;
        if (typeof args.after === 'string' && args.after !== '') {
          const afterNumber = decodeCursor(args.after);
          if (afterNumber !== null) {
            const idx = list.findIndex((issue) => issue.number === afterNumber);
            if (idx >= 0) start = idx + 1;
          }
        }
        const first = typeof args.first === 'number' ? args.first : 30;
        const page = list.slice(start, start + first);
        const hasNextPage = start + page.length < list.length;
        const endCursor = page.length > 0 ? issueCursor(repo, page[page.length - 1]!) : null;
        const value: GqlRuntime = { __typename: 'IssueConnection', repo, nodes: page, hasNextPage, endCursor };
        return sub(value, 'IssueConnection');
      }
      case 'pullRequests': {
        const list = [...repo.pulls.values()].sort((a, b) => b.number - a.number);
        const first = typeof args.first === 'number' ? args.first : 30;
        const value: GqlRuntime = { __typename: 'PullRequestConnection', repo, nodes: list.slice(0, first) };
        return sub(value, 'PullRequestConnection');
      }
      case 'pullRequest': {
        const number = typeof args.number === 'number' ? args.number : -1;
        const pull = repo.pulls.get(number);
        if (!pull) return null;
        return sub({ __typename: 'PullRequest', repo, pull }, 'PullRequest');
      }
      default: return unknown();
    }
  }

  if (parentType === 'Issue' && parent.__typename === 'Issue') {
    const issue = parent.issue;
    switch (field) {
      case 'id': return globalId('Issue', [parent.repo.dbId, issue.number]);
      case 'number': return issue.number;
      case 'title': return issue.title;
      case 'body': return issue.body;
      case 'state': return issueStateGql(issue);
      case 'url': return `https://github.com/${parent.repo.owner}/${parent.repo.name}/issues/${issue.number}`;
      case 'createdAt': return isoOf(issue.createdSeq);
      case 'updatedAt': return isoOf(issue.updatedSeq);
      case 'author': return sub({ __typename: 'User', login: VIEWER_LOGIN }, 'User');
      case 'repository': return sub({ __typename: 'Repository', repo: parent.repo }, 'Repository');
      default: return unknown();
    }
  }

  if (parentType === 'IssueConnection' && parent.__typename === 'IssueConnection') {
    if (field === 'nodes') {
      if (!selectionSet) return parent.nodes.map(() => null);
      return parent.nodes.map((issue) => executeSelections(selectionSet, 'Issue', { __typename: 'Issue', repo: parent.repo, issue }, variables, errors));
    }
    if (field === 'pageInfo') {
      const value: GqlRuntime = { __typename: 'PageInfo', hasNextPage: parent.hasNextPage, endCursor: parent.endCursor };
      return sub(value, 'PageInfo');
    }
    return unknown();
  }

  if (parentType === 'PageInfo' && parent.__typename === 'PageInfo') {
    if (field === 'hasNextPage') return parent.hasNextPage;
    if (field === 'hasPreviousPage') return false;
    if (field === 'endCursor') return parent.endCursor;
    if (field === 'startCursor') return parent.endCursor;
    return unknown();
  }

  if (parentType === 'PullRequest' && parent.__typename === 'PullRequest') {
    const pull = parent.pull;
    switch (field) {
      case 'id': return globalId('PullRequest', [parent.repo.dbId, pull.number]);
      case 'number': return pull.number;
      case 'title': return pull.title;
      case 'body': return pull.body;
      case 'state': return pullStateGql(pull);
      case 'merged': return pull.merged;
      case 'mergeable': return pullMergeable(parent.repo, pull);
      case 'headRefName': return pull.headRef;
      case 'baseRefName': return pull.baseRef;
      case 'author': return sub({ __typename: 'User', login: VIEWER_LOGIN }, 'User');
      case 'createdAt': return isoOf(pull.createdSeq);
      case 'updatedAt': return isoOf(pull.updatedSeq);
      case 'files': {
        const files = pullFiles(parent.repo, pull);
        const first = typeof args.first === 'number' ? args.first : 100;
        const value: GqlRuntime = { __typename: 'ChangedFiles', files: files.slice(0, first) };
        return sub(value, 'ChangedFiles');
      }
      default: return unknown();
    }
  }

  if (parentType === 'PullRequestConnection' && parent.__typename === 'PullRequestConnection') {
    if (field === 'nodes') {
      if (!selectionSet) return parent.nodes.map(() => null);
      return parent.nodes.map((pull) => executeSelections(selectionSet, 'PullRequest', { __typename: 'PullRequest', repo: parent.repo, pull }, variables, errors));
    }
    return unknown();
  }

  if (parentType === 'ChangedFiles' && parent.__typename === 'ChangedFiles') {
    if (field === 'nodes') {
      if (!selectionSet) return parent.files.map(() => null);
      return parent.files.map((file) => executeSelections(selectionSet, 'ChangedFile', { __typename: 'ChangedFile', path: file.path }, variables, errors));
    }
    return unknown();
  }

  if (parentType === 'ChangedFile' && parent.__typename === 'ChangedFile') {
    if (field === 'path') return parent.path;
    return unknown();
  }

  if (parentType === 'Ref' && parent.__typename === 'Ref') {
    if (field === 'name') return parent.name;
    return unknown();
  }

  if (parentType === '__Type' && parent.__typename === '__Type') {
    if (field === 'name') return parent.name;
    if (field === 'fields') {
      if (!selectionSet) return parent.fieldNames.map((name) => ({ name }));
      return parent.fieldNames.map((name) => executeSelections(selectionSet, '__Field', { __typename: '__Type', name, fieldNames: [], enumNames: [] } as unknown as GqlRuntime, variables, errors));
    }
    if (field === 'enumValues') {
      if (!selectionSet) return parent.enumNames.map((name) => ({ name }));
      return parent.enumNames.map((name) => executeSelections(selectionSet, '__EnumValue', { __typename: '__Type', name, fieldNames: [], enumNames: [] } as unknown as GqlRuntime, variables, errors));
    }
    return unknown();
  }

  if ((parentType === '__Field' || parentType === '__EnumValue') && parent.__typename === '__Type') {
    if (field === 'name') return parent.name;
    return unknown();
  }

  if (parentType === 'CreateIssuePayload' && parent.__typename === 'CreateIssuePayload') {
    if (field === 'issue') return sub({ __typename: 'Issue', repo: parent.repo, issue: parent.issue }, 'Issue');
    return unknown();
  }
  if (parentType === 'CloseIssuePayload' && parent.__typename === 'CloseIssuePayload') {
    if (field === 'issue') return sub({ __typename: 'Issue', repo: parent.repo, issue: parent.issue }, 'Issue');
    return unknown();
  }
  if (parentType === 'CreatePullRequestPayload' && parent.__typename === 'CreatePullRequestPayload') {
    if (field === 'pullRequest') return sub({ __typename: 'PullRequest', repo: parent.repo, pull: parent.pull }, 'PullRequest');
    return unknown();
  }
  if (parentType === 'MergePullRequestPayload' && parent.__typename === 'MergePullRequestPayload') {
    if (field === 'pullRequest') return sub({ __typename: 'PullRequest', repo: parent.repo, pull: parent.pull }, 'PullRequest');
    return unknown();
  }
  if (parentType === 'AddCommentPayload' && parent.__typename === 'AddCommentPayload') {
    if (field === 'commentEdge') {
      const value: GqlRuntime = { __typename: 'CommentEdge', repo: parent.repo, issue: parent.issue, comment: parent.comment };
      return sub(value, 'CommentEdge');
    }
    return unknown();
  }
  if (parentType === 'CommentEdge' && parent.__typename === 'CommentEdge') {
    if (field === 'node') {
      const value: GqlRuntime = { __typename: 'IssueComment', repo: parent.repo, issue: parent.issue, comment: parent.comment };
      return sub(value, 'IssueComment');
    }
    return unknown();
  }
  if (parentType === 'IssueComment' && parent.__typename === 'IssueComment') {
    if (field === 'id') return globalId('IssueComment', [parent.repo.dbId, parent.issue.number, parent.comment.id]);
    if (field === 'body') return parent.comment.body;
    return unknown();
  }

  return unknown();
}

function executeGqlOperation(operation: GqlOperation, variables: Record<string, unknown>): { data: Record<string, unknown>; errors?: GqlError[] } {
  const errors: GqlError[] = [];
  const rootType = operation.kind === 'mutation' ? 'Mutation' : 'Query';
  const data = executeSelections(operation.selectionSet, rootType, null, variables, errors);
  return errors.length > 0 ? { data, errors } : { data };
}

async function handleGraphql(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
  if (!authorized(req)) {
    jsonBody(res, 401, { message: 'Bad credentials' });
    return;
  }
  if ((req.method ?? '') !== 'POST') {
    jsonBody(res, 405, { message: 'Method Not Allowed' });
    return;
  }
  const raw = await readBody(req);
  const parsed = parseJsonBody(raw);
  if (!parsed.ok) {
    jsonBody(res, 400, { message: 'Problems parsing JSON' });
    return;
  }
  const runOne = (entry: unknown): Record<string, unknown> => {
    if (!isRecord(entry) || typeof entry.query !== 'string') {
      return { data: null, errors: [{ message: 'A query document is required.' }] };
    }
    const variables = isRecord(entry.variables) ? entry.variables : {};
    try {
      const operations = new GqlParser(entry.query).parseDocument();
      if (operations.length === 0) return { data: null, errors: [{ message: 'No operation in the document.' }] };
      const operation = operations[0]!;
      return executeGqlOperation(operation, variables);
    } catch (err) {
      return { data: null, errors: [{ message: err instanceof Error ? err.message : String(err) }] };
    }
  };
  if (Array.isArray(parsed.value)) {
    jsonBody(res, 200, parsed.value.map((entry) => runOne(entry)));
  } else {
    jsonBody(res, 200, runOne(parsed.value));
  }
}

// ---------------------------------------------------------------- MCP (JSON-RPC 2.0 Streamable HTTP)

const MCP_TOOLS: Array<{
  name: string;
  description: string;
  inputSchema: { type: 'object'; properties: Record<string, { type: string; description: string }>; required: string[] };
}> = [
  {
    name: 'create_repo',
    description: 'Create a new repository owned by the authenticated user.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Repository name.' },
        description: { type: 'string', description: 'Repository description.' },
        private: { type: 'boolean', description: 'Whether the repository is private.' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login.' },
        repo: { type: 'string', description: 'Repository name.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'list_repos',
    description: 'List repositories owned by the authenticated user.',
    inputSchema: {
      type: 'object',
      properties: {},
      required: [],
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login.' },
        repo: { type: 'string', description: 'Repository name.' },
        title: { type: 'string', description: 'Issue title.' },
        body: { type: 'string', description: 'Issue body.' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository, optionally filtered by state.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login.' },
        repo: { type: 'string', description: 'Repository name.' },
        state: { type: 'string', description: 'Issue state filter: open, closed, or all.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'get_issue',
    description: 'Get a single issue by number.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login.' },
        repo: { type: 'string', description: 'Repository name.' },
        issue_number: { type: 'integer', description: 'Issue number.' },
      },
      required: ['owner', 'repo', 'issue_number'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request from a head branch into a base branch.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login.' },
        repo: { type: 'string', description: 'Repository name.' },
        title: { type: 'string', description: 'Pull request title.' },
        head: { type: 'string', description: 'Head branch name.' },
        base: { type: 'string', description: 'Base branch name.' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Squash-merge an open pull request into its base branch.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login.' },
        repo: { type: 'string', description: 'Repository name.' },
        pull_number: { type: 'integer', description: 'Pull request number.' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];

function mcpToolText(text: string, isError = false): { content: Array<{ type: 'text'; text: string }>; isError?: boolean } {
  const out: { content: Array<{ type: 'text'; text: string }>; isError?: boolean } = {
    content: [{ type: 'text', text }],
  };
  if (isError) out.isError = true;
  return out;
}

function callMcpTool(name: string, args: Record<string, unknown>): { content: Array<{ type: 'text'; text: string }>; isError?: boolean } {
  const lower = name.toLowerCase();
  const tool = MCP_TOOLS.find((candidate) => candidate.name === lower || candidate.name.endsWith(lower) || lower.endsWith(candidate.name));
  if (!tool) {
    throw { code: -32601, message: `Unknown tool: ${name}` };
  }
  const missing = tool.inputSchema.required.filter((key) => args[key] === undefined || args[key] === null || args[key] === '');
  if (missing.length > 0) {
    return mcpToolText(`Missing required argument: ${missing.join(', ')}`, true);
  }
  const argStr = (key: string): string => String(args[key]);
  const argNum = (key: string): number => Number(args[key]);

  if (tool.name === 'create_repo') {
    const repo = createRepoRecord(argStr('name'), typeof args.description === 'string' ? args.description : '', args.private === true);
    if (!repo) return mcpToolText(`Repository ${argStr('name')} already exists.`, true);
    return mcpToolText(JSON.stringify(repoJson(repo)));
  }
  if (tool.name === 'get_repo') {
    const repo = getRepo(argStr('owner'), argStr('repo'));
    if (!repo) return mcpToolText(`Repository ${argStr('owner')}/${argStr('repo')} not found.`, true);
    return mcpToolText(JSON.stringify(repoJson(repo)));
  }
  if (tool.name === 'list_repos') {
    const list = listViewerRepos().map((repo) => repoJson(repo));
    return mcpToolText(JSON.stringify(list));
  }
  if (tool.name === 'create_issue') {
    const repo = getRepo(argStr('owner'), argStr('repo'));
    if (!repo) return mcpToolText(`Repository ${argStr('owner')}/${argStr('repo')} not found.`, true);
    const issue = createIssueRecord(repo, argStr('title'), typeof args.body === 'string' ? args.body : '', []);
    return mcpToolText(JSON.stringify(issueJson(repo, issue)));
  }
  if (tool.name === 'list_issues') {
    const repo = getRepo(argStr('owner'), argStr('repo'));
    if (!repo) return mcpToolText(`Repository ${argStr('owner')}/${argStr('repo')} not found.`, true);
    const state = typeof args.state === 'string' ? args.state : 'all';
    const list = [...repo.issues.values()]
      .filter((issue) => state === 'all' || issue.state === state)
      .sort((a, b) => b.createdSeq - a.createdSeq)
      .map((issue) => issueJson(repo, issue));
    return mcpToolText(JSON.stringify({ issues: list }));
  }
  if (tool.name === 'get_issue') {
    const repo = getRepo(argStr('owner'), argStr('repo'));
    const issue = repo?.issues.get(argNum('issue_number'));
    if (!repo || !issue) return mcpToolText(`Issue #${argNum('issue_number')} not found.`, true);
    return mcpToolText(JSON.stringify(issueJson(repo, issue)));
  }
  if (tool.name === 'create_pull_request') {
    const repo = getRepo(argStr('owner'), argStr('repo'));
    if (!repo) return mcpToolText(`Repository ${argStr('owner')}/${argStr('repo')} not found.`, true);
    const pull = createPullRecord(repo, argStr('title'), '', argStr('head'), argStr('base'));
    if (!pull) return mcpToolText(`Head branch ${argStr('head')} or base branch ${argStr('base')} does not exist.`, true);
    return mcpToolText(JSON.stringify(pullJson(repo, pull)));
  }
  if (tool.name === 'merge_pull_request') {
    const repo = getRepo(argStr('owner'), argStr('repo'));
    const pull = repo?.pulls.get(argNum('pull_number'));
    if (!repo || !pull) return mcpToolText(`Pull request #${argNum('pull_number')} not found.`, true);
    if (pull.merged) return mcpToolText('Pull request is already merged.', true);
    if (pull.state !== 'open') return mcpToolText('Pull request is not open.', true);
    if (pullMergeable(repo, pull) === 'CONFLICTING') return mcpToolText('Pull request has merge conflicts.', true);
    const sha = squashMerge(repo, pull);
    return mcpToolText(JSON.stringify({ sha, merged: true, message: 'Pull Request successfully merged' }));
  }
  return mcpToolText(`Tool ${name} is not implemented.`, true);
}

async function handleMcp(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
  if (!authorized(req)) {
    jsonBody(res, 401, { message: 'Bad credentials' });
    return;
  }
  if ((req.method ?? '') !== 'POST') {
    jsonBody(res, 405, { message: 'Method Not Allowed' });
    return;
  }
  const raw = await readBody(req);
  const parsed = parseJsonBody(raw);
  const sessionId = req.headers['mcp-session-id'];
  if (typeof sessionId === 'string' && sessionId !== '') res.setHeader('Mcp-Session-Id', sessionId);
  if (!parsed.ok) {
    jsonBody(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return;
  }
  const body = parsed.value;
  if (!isRecord(body) || typeof body.method !== 'string') {
    const id = isRecord(body) && (typeof body.id === 'string' || typeof body.id === 'number') ? body.id : null;
    jsonBody(res, 200, { jsonrpc: '2.0', id, error: { code: -32600, message: 'Invalid Request' } });
    return;
  }
  const id = body.id;
  const isNotification = id === undefined || id === null;
  const params = isRecord(body.params) ? body.params : {};
  const respond = (payload: Record<string, unknown>): void => {
    jsonBody(res, 200, { jsonrpc: '2.0', id, ...payload });
  };
  try {
    if (body.method === 'server/discover') {
      respond({
        result: {
          protocolVersion: '2026-07-28',
          supportedVersions: ['2026-07-28', '2025-11-25', '2025-03-26'],
          capabilities: { tools: {} },
          serverInfo: { name: 'github-forge', version: '1.0.0' },
          server: { name: 'github-forge', version: '1.0.0' },
        },
      });
      return;
    }
    if (body.method === 'initialize') {
      const requested = typeof params.protocolVersion === 'string' ? params.protocolVersion : '2025-11-25';
      const negotiated = requested >= '2026-07-28' ? '2026-07-28' : requested;
      respond({
        result: {
          protocolVersion: negotiated,
          capabilities: { tools: {} },
          serverInfo: { name: 'github-forge', version: '1.0.0' },
        },
      });
      return;
    }
    if (body.method === 'notifications/initialized' || body.method.startsWith('notifications/')) {
      if (isNotification) {
        res.writeHead(202);
        res.end();
      } else {
        respond({ result: {} });
      }
      return;
    }
    if (body.method === 'ping') {
      respond({ result: {} });
      return;
    }
    if (body.method === 'tools/list') {
      respond({ result: { tools: MCP_TOOLS } });
      return;
    }
    if (body.method === 'tools/call') {
      const name = typeof params.name === 'string' ? params.name : '';
      const args = isRecord(params.arguments) ? params.arguments : {};
      if (name === '') {
        respond({ error: { code: -32602, message: 'Invalid params: tools/call requires a name.' } });
        return;
      }
      const result = callMcpTool(name, args);
      respond({ result });
      return;
    }
    if (body.method === 'prompts/list') {
      respond({ result: { prompts: [] } });
      return;
    }
    if (body.method === 'resources/list') {
      respond({ result: { resources: [] } });
      return;
    }
    respond({ error: { code: -32601, message: `Method not found: ${body.method}` } });
  } catch (err) {
    if (isRecord(err) && typeof err.code === 'number') {
      respond({ error: { code: err.code, message: typeof err.message === 'string' ? err.message : 'Error' } });
      return;
    }
    respond({ error: { code: -32603, message: err instanceof Error ? err.message : 'Internal error' } });
  }
}

// ---------------------------------------------------------------- Git HTTP routing

function gitContentType(service: string): string {
  return `application/x-${service}-advertisement`;
}

// Git smart-HTTP replies must carry an explicit Content-Length: git's HTTP
// client misreads a chunked smart-HTTP body (it sees the first pkt-line and
// then a response-end), so never let Node fall back to chunked encoding here.
function sendGit(res: http.ServerResponse, contentType: string, body: Buffer): void {
  res.writeHead(200, { 'content-type': contentType, 'content-length': body.length });
  res.end(body);
}

async function handleGit(req: http.IncomingMessage, res: http.ServerResponse, owner: string, repoName: string, tail: string): Promise<void> {
  const repo = getRepo(owner, repoName);
  const method = req.method ?? '';
  if (method === 'GET' && tail === '/info/refs') {
    if (!repo) {
      jsonBody(res, 404, { message: 'Not Found' });
      return;
    }
    const service = String(new URL(req.url ?? '/', 'http://localhost').searchParams.get('service') ?? '');
    const protocol = req.headers['git-protocol'];
    if (service === 'git-upload-pack') {
      if (protocol === 'version=2') {
        sendGit(res, gitContentType('git-upload-pack'), v2Advertisement());
      } else {
        // v0Advertisement already carries the `# service=` preamble and the
        // surrounding flush packets; do not wrap it again.
        sendGit(res, gitContentType('git-upload-pack'), v0Advertisement('git-upload-pack', repo, 'multi_ack multi_ack_detailed thin-pack side-band-64k ofs-delta'));
      }
      return;
    }
    if (service === 'git-receive-pack') {
      sendGit(res, gitContentType('git-receive-pack'), v0Advertisement('git-receive-pack', repo, 'report-status side-band-64k delete-refs ofs-delta'));
      return;
    }
    jsonBody(res, 400, { message: 'Missing service parameter' });
    return;
  }
  if (!repo) {
    jsonBody(res, 404, { message: 'Not Found' });
    return;
  }
  if (method === 'POST' && tail === '/git-upload-pack') {
    const body = await readBody(req);
    if (req.headers['git-protocol'] === 'version=2') {
      sendGit(res, 'application/x-git-upload-pack-result', handleUploadPackV2(repo, body));
    } else {
      sendGit(res, 'application/x-git-upload-pack-result', handleUploadPackV0(repo, body));
    }
    return;
  }
  if (method === 'POST' && tail === '/git-receive-pack') {
    const body = await readBody(req);
    sendGit(res, 'application/x-git-receive-pack-result', handleReceivePack(repo, body));
    return;
  }
  jsonBody(res, 404, { message: 'Not Found' });
}

// ---------------------------------------------------------------- Dispatcher + lifecycle

const server = http.createServer((req, res) => {
  void (async () => {
    try {
      const url = new URL(req.url ?? '/', 'http://localhost');
      const path = url.pathname;
      if (path === '/healthz') {
        jsonBody(res, 200, { ok: true });
        return;
      }
      if (path === '/mcp') {
        await handleMcp(req, res);
        return;
      }
      if (path === '/api/graphql') {
        await handleGraphql(req, res);
        return;
      }
      if (path === '/api/v3' || path.startsWith('/api/v3/')) {
        await handleRest(req, res);
        return;
      }
      const gitMatch = /^\/([^/]+)\/([^/]+)\.git(\/.*)?$/.exec(path);
      if (gitMatch) {
        await handleGit(req, res, decodeURIComponent(gitMatch[1]!), decodeURIComponent(gitMatch[2]!), gitMatch[3] ?? '');
        return;
      }
      jsonBody(res, 404, { message: 'Not Found' });
    } catch (err) {
      process.stderr.write(`dispatch error: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
      if (!res.headersSent) {
        jsonBody(res, 500, { message: err instanceof Error ? err.message : 'Internal Server Error' });
      } else {
        try {
          res.end();
        } catch {
          // Already ended.
        }
      }
    }
  })();
});

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

server.listen(0, '127.0.0.1', () => {
  const address = server.address();
  const port = typeof address === 'object' && address !== null ? address.port : 0;
  void (async () => {
    if (!ENV_URL) {
      process.stderr.write(`forge listening on http://127.0.0.1:${port}\n`);
      return;
    }
    try {
      await fetch(`${ENV_URL}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ port }),
      });
    } catch {
      // The suite will retry its health check; keep the server up.
    }
    for (;;) {
      await sleep(500);
      try {
        const response = await fetch(`${ENV_URL}/done`);
        const payload = (await response.json()) as { done?: boolean };
        if (payload.done === true) break;
      } catch {
        // Keep polling until the suite signals completion.
      }
    }
    server.close(() => process.exit(0));
  })();
});
