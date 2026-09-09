/**
 * The real verification, running in the browser.
 *
 * This is an independent re-implementation of src/attestation/core.py. It is not a
 * simulation and it does not ask a server for a verdict: it rebuilds each entry's
 * signing bytes, hashes them with the browser's own SHA-256, and compares the result
 * against the hash recorded in the ledger.
 *
 * If this file and the Python ever disagree, every row goes red. That is the correct
 * failure, and it is exactly what tests/test_three_implementations.py exists to catch.
 */

/** The 16 signed fields, in order. Must match HASHED_FIELDS in core.py exactly. */
export const HASHED_FIELDS = [
  "entry_version", "chain_id", "seq", "prev_hash", "op_type", "target_ref",
  "timestamp", "method", "result_hash", "operator_decl", "concur_decl",
  "custody_tier", "outcome", "presence_ref", "operator_key_id", "tool_ref",
] as const;

const ENTRY_DOMAIN = "akhanda.entry.v2";
export const ZERO_HASH = "0".repeat(64);

const enc = new TextEncoder();

/**
 * Length-prefixed canonical encoding: a domain tag, then for every field a 4-byte
 * big-endian length followed by its bytes.
 *
 * The length prefix is the whole point. Joining fields with a separator would let two
 * different records produce identical signing bytes, which is a forgery primitive.
 */
export function encodeEntry(raw: Record<string, string>): Uint8Array {
  const parts: Uint8Array[] = [enc.encode(ENTRY_DOMAIN)];
  for (const name of HASHED_FIELDS) {
    const bytes = enc.encode(String(raw[name] ?? ""));
    const len = new Uint8Array(4);
    new DataView(len.buffer).setUint32(0, bytes.length, false); // big-endian
    parts.push(len, bytes);
  }
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes as BufferSource);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function entryHash(raw: Record<string, string>): Promise<string> {
  return sha256Hex(encodeEntry(raw));
}

export interface RowResult {
  seq: number;
  recorded: string;
  recomputed: string;
  linkOk: boolean;
  hashOk: boolean;
  problems: string[];
}

export interface ChainResult {
  ok: boolean;
  brokenSeq: number | null;
  rows: RowResult[];
  elapsedMs: number;
}

/**
 * Verify a whole chain. Checks three things per entry: that the sequence is in order,
 * that it links to the previous entry's hash, and that its content still hashes to the
 * value recorded against it.
 */
export async function verifyChain(
  entries: { hash: string; prevHash: string; raw: Record<string, string> }[],
): Promise<ChainResult> {
  const t0 = performance.now();
  const rows: RowResult[] = [];
  let expectedPrev = ZERO_HASH;
  let brokenSeq: number | null = null;

  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    const seq = Number(e.raw.seq);
    const problems: string[] = [];

    if (seq !== i) problems.push("sequence out of order");

    const linkOk = e.raw.prev_hash === expectedPrev;
    if (!linkOk) problems.push("does not link to the previous entry");

    const recomputed = await entryHash(e.raw);
    const hashOk = recomputed === e.hash;
    if (!hashOk) problems.push("content altered: hash mismatch");

    if (problems.length && brokenSeq === null) brokenSeq = seq;

    rows.push({ seq, recorded: e.hash, recomputed, linkOk, hashOk, problems });
    expectedPrev = e.hash;
  }

  return {
    ok: brokenSeq === null,
    brokenSeq,
    rows,
    elapsedMs: performance.now() - t0,
  };
}
