// GENERATED from the real ledger this tool produced. Do not hand-edit.
// Source: demo_bundle/chain.json   chain 05d05a01761a35ba
// Every entry below was re-hashed from its 16 signed fields at generation time and
// matched the recorded entry_hash. lib/verify.ts repeats that check in the browser,
// so nothing here is taken on trust.

export type EntryStatus = "verified" | "in-progress" | "tampered";

export interface ChainEntry {
  id: number;
  seq: string;
  timestamp: string;
  operator: string;
  action: string;
  details: string;
  hash: string;
  prevHash: string;
  witnessNode: string;
  witnessApproval: "APPROVED" | "PENDING" | "REJECTED";
  status: EntryStatus;
  custodyTier: string;
  outcome: string;
  /** The 16 signed fields, exactly as the tool hashed them. */
  raw: Record<string, string>;
}

export const CHAIN_ID = "05d05a01761a35ba";
export const OPERATOR_KEY_ID = "e3f68c5cfb2addf5";
export const CONCUR_KEY_ID = "1f3aa853d05dea0f";
/** Entries carrying a second, independent signature. Measured, not asserted. */
export const COSIGNED_COUNT = 1;
export const TOOL_REF = "akhanda/0.1.0+c508412d47c60e56";

export const CLEAN_CHAIN: ChainEntry[] = [
  {
    id: 1,
    seq: "AKH-05D05A01-000",
    timestamp: "2026-09-04T11:26:30Z",
    operator: "Operator key e3f68c5cfb2addf5",
    action: "FILE_RECOVERY",
    details: "Signature-based carving of the acquired image. Recovered artefacts were checked byte for byte against their originals.  Outcome recorded as PARTIAL.",
    hash: "164103253fafc1891232b37cc94fbec9f2540abf09f474fbd4df1d02a64e643c",
    prevHash: "0000000000000000000000000000000000000000000000000000000000000000",
    witnessNode: "witness 1f3aa853d05dea0f (separate machine)",
    witnessApproval: "APPROVED",
    status: "verified",
    custodyTier: "WITNESS_COSIGNED",
    outcome: "PARTIAL",
    raw: {
      "entry_version": "3",
      "chain_id": "05d05a01761a35ba",
      "seq": "0",
      "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
      "op_type": "RECOVER",
      "target_ref": "D:\\akhanda\\demo_bundle\\seized_media.dd",
      "timestamp": "2026-09-04T11:26:30Z",
      "method": "Clear",
      "result_hash": "d12d078ebec40e3afd270328febe24a2683f5e2534cdec6d56de0ca6300835c4",
      "operator_decl": "(operator not named)",
      "concur_decl": "(expert not named)",
      "custody_tier": "WITNESS_COSIGNED",
      "outcome": "PARTIAL",
      "presence_ref": "",
      "operator_key_id": "e3f68c5cfb2addf5",
      "tool_ref": "akhanda/0.1.0+c508412d47c60e56",
    },
  },
  {
    id: 2,
    seq: "AKH-05D05A01-001",
    timestamp: "2026-09-04T11:26:30Z",
    operator: "Operator key e3f68c5cfb2addf5",
    action: "SECURE_ERASURE",
    details: "Secure erasure of the target, single overwrite pass across every host-addressable block, followed by read-back sampling of the written pattern.  Outcome recorded as VERIFIED.",
    hash: "7f68a9cd63ef995480ae6a73144128c47ca432fcc00f7895c9fcd734e5345a41",
    prevHash: "164103253fafc1891232b37cc94fbec9f2540abf09f474fbd4df1d02a64e643c",
    witnessNode: "not co-signed (operator only)",
    witnessApproval: "PENDING",
    status: "verified",
    custodyTier: "SOFTWARE_KEY",
    outcome: "VERIFIED",
    raw: {
      "entry_version": "3",
      "chain_id": "05d05a01761a35ba",
      "seq": "1",
      "prev_hash": "164103253fafc1891232b37cc94fbec9f2540abf09f474fbd4df1d02a64e643c",
      "op_type": "ERASE",
      "target_ref": "D:\\akhanda\\demo_bundle\\to_erase",
      "timestamp": "2026-09-04T11:26:30Z",
      "method": "Clear",
      "result_hash": "bec6e83b7ef96974fe7297f10373d37c1b264c14a71f1096d10e76f2f68cbd93",
      "operator_decl": "(operator not named)",
      "concur_decl": "(expert not named)",
      "custody_tier": "SOFTWARE_KEY",
      "outcome": "VERIFIED",
      "presence_ref": "",
      "operator_key_id": "e3f68c5cfb2addf5",
      "tool_ref": "akhanda/0.1.0+c508412d47c60e56",
    },
  },
  {
    id: 3,
    seq: "AKH-05D05A01-002",
    timestamp: "2026-09-04T11:26:33Z",
    operator: "Operator key e3f68c5cfb2addf5",
    action: "OPERATION_REFUSED",
    details: "Blocked before any data was touched: the required co-signer was unreachable. Nothing was read, written or destroyed. The refusal itself is recorded here.  Outcome recorded as NOT_PERFORMED.",
    hash: "7d1fdeddf2cfaed3e97bba68708321d87b3383e381540ce0a9115bb48be4b913",
    prevHash: "7f68a9cd63ef995480ae6a73144128c47ca432fcc00f7895c9fcd734e5345a41",
    witnessNode: "not co-signed (operator only)",
    witnessApproval: "PENDING",
    status: "verified",
    custodyTier: "SOFTWARE_KEY",
    outcome: "NOT_PERFORMED",
    raw: {
      "entry_version": "3",
      "chain_id": "05d05a01761a35ba",
      "seq": "2",
      "prev_hash": "7f68a9cd63ef995480ae6a73144128c47ca432fcc00f7895c9fcd734e5345a41",
      "op_type": "REFUSED",
      "target_ref": "D:\\akhanda\\demo_bundle\\seized_media.dd",
      "timestamp": "2026-09-04T11:26:33Z",
      "method": "NotPerformed",
      "result_hash": "5297ce07993d11524caafbe6e24271d0d878515ffbba54c764c91bbe5bed18bb",
      "operator_decl": "(operator not named)",
      "concur_decl": "(expert not named)",
      "custody_tier": "SOFTWARE_KEY",
      "outcome": "NOT_PERFORMED",
      "presence_ref": "",
      "operator_key_id": "e3f68c5cfb2addf5",
      "tool_ref": "akhanda/0.1.0+c508412d47c60e56",
    },
  },
];
