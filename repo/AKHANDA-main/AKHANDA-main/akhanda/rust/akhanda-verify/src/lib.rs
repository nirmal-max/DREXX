//! Independent verifier for Akhanda chains.
//!
//! # Why this crate exists
//!
//! The entry encoding is already implemented twice: in Python (`src/attestation/core.py`)
//! and in JavaScript (`console/index.html`), and a test asserts the two agree. This is the
//! third. Three independent implementations of one contract is not redundancy for its own
//! sake, it is the only way to catch a misreading of the spec that both other
//! implementations happen to share, because they were written by the same hand.
//!
//! It also gives the verification path memory safety that is compiler-enforced rather
//! than asserted: `#![forbid(unsafe_code)]` means production code containing `unsafe`
//! does not build. For a forensic tool the verifier is the component that matters most , 
//! it is the one a third party runs on evidence they did not produce.
//!
//! # What it verifies
//!
//! Both layers, matching `verify_chain_report` in Python:
//!
//! * **key-free**, entry_version, chain_id constant, seq contiguous from 0, prev_hash
//!   links, and each entry re-hashes to its stated `entry_hash`. Catches edits, reorders,
//!   and deletion from the middle with no key at all.
//! * **key-bound**, Ed25519 over the entry hash, for the operator key and, when given,
//!   the concurring witness key. Catches a forger who rewrote the content AND recomputed
//!   every hash.
//!
//! # What it does NOT verify
//!
//! Tail truncation. Dropping the most recent entries leaves a shorter, self-consistent
//! chain that no local verifier can distinguish from one that was always that length.
//! Only the witness's independent head record separates those, and that comparison needs
//! a network the verifier deliberately does not have.

#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Must match `ENTRY_VERSION` in `src/attestation/core.py`. This is the version this
/// build WRITES; it is not the only version it can READ, see [`fields_for`].
pub const ENTRY_VERSION: &str = "4";

/// Must match `ENTRY_DOMAIN` in `src/attestation/core.py`.
pub const ENTRY_DOMAIN: &[u8] = b"akhanda.entry.v2";

/// The exact ordered set of fields that are hashed. Order is part of the contract.
/// If this list and the Python one ever disagree, every entry fails, which is the
/// correct failure, not a silent pass.
pub const FIELDS_V3: [&str; 16] = [
    "entry_version",
    "chain_id",
    "seq",
    "prev_hash",
    "op_type",
    "target_ref",
    "timestamp",
    "method",
    "result_hash",
    "operator_decl",
    "concur_decl",
    "custody_tier",
    "outcome",
    "presence_ref",
    "operator_key_id",
    // Added in ENTRY_VERSION 3. Every entry names the build that wrote it; this verifier
    // does not interpret the value, it only hashes it. Judging whether a build is the
    // right one is a question for a human with a validation report, not for a verifier.
    "tool_ref",
];

/// Added in ENTRY_VERSION 4: `place_ref` answers the BSA 2023 s.63(4) Schedule, which
/// asks for the PLACE of the operation, and the three `amend_*` fields let one entry
/// supersede an earlier one without mutating it.
///
/// v4 APPENDS to v3 and reorders nothing, so the two lists stay comparable by eye.
pub const FIELDS_V4: [&str; 20] = [
    "entry_version",
    "chain_id",
    "seq",
    "prev_hash",
    "op_type",
    "target_ref",
    "timestamp",
    "method",
    "result_hash",
    "operator_decl",
    "concur_decl",
    "custody_tier",
    "outcome",
    "presence_ref",
    "operator_key_id",
    "tool_ref",
    "place_ref",
    "amends_seq",
    "amends_hash",
    "amend_reason",
];

/// The field list this build writes. Kept under the old name so callers and the
/// cross-implementation tests keep one name for "the current contract".
pub const HASHED_FIELDS: [&str; 20] = FIELDS_V4;

/// The hashed field list for a given `entry_version`.
///
/// Keyed by version so an entry is re-hashed under the field list it was WRITTEN under.
/// A single global list would re-hash a v3 entry with four fields it never signed and
/// report the mismatch as tampering, making authentic history indistinguishable from
/// forgery for the sole crime of being old.
///
/// `None` for a version this build does not know. The caller must refuse, never guess:
/// guessing yields a confident wrong answer about evidence.
pub fn fields_for(version: &str) -> Option<&'static [&'static str]> {
    match version {
        "3" => Some(&FIELDS_V3),
        "4" => Some(&FIELDS_V4),
        _ => None,
    }
}

/// Versions this build can read, for error messages.
pub const KNOWN_VERSIONS: [&str; 2] = ["3", "4"];

const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Deserialize)]
pub struct Entry {
    #[serde(default)]
    pub entry_version: String,
    #[serde(default)]
    pub chain_id: String,
    #[serde(default)]
    pub seq: u64,
    #[serde(default)]
    pub prev_hash: String,
    #[serde(default)]
    pub op_type: String,
    #[serde(default)]
    pub target_ref: String,
    #[serde(default)]
    pub timestamp: String,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub result_hash: String,
    #[serde(default)]
    pub operator_decl: String,
    #[serde(default)]
    pub concur_decl: String,
    #[serde(default)]
    pub custody_tier: String,
    #[serde(default)]
    pub outcome: String,
    #[serde(default)]
    pub presence_ref: String,
    #[serde(default)]
    pub operator_key_id: String,
    #[serde(default)]
    pub tool_ref: String,
    // --- added in ENTRY_VERSION 4 ---
    #[serde(default)]
    pub place_ref: String,
    #[serde(default)]
    pub amends_seq: String,
    #[serde(default)]
    pub amends_hash: String,
    #[serde(default)]
    pub amend_reason: String,

    #[serde(default)]
    pub entry_hash: String,
    #[serde(default)]
    pub operator_sig: String,
    #[serde(default)]
    pub concur_sig: String,
    #[serde(default)]
    pub concur_key_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Chain {
    pub chain_id: String,
    pub entries: Vec<Entry>,
}

impl Entry {
    /// The value of one hashed field, by name. Returns `None` for an unknown name so a
    /// typo in `HASHED_FIELDS` is a build-visible failure rather than an empty string
    /// silently entering the preimage.
    fn field(&self, name: &str) -> Option<String> {
        Some(match name {
            "entry_version" => self.entry_version.clone(),
            "chain_id" => self.chain_id.clone(),
            "seq" => self.seq.to_string(),
            "prev_hash" => self.prev_hash.clone(),
            "op_type" => self.op_type.clone(),
            "target_ref" => self.target_ref.clone(),
            "timestamp" => self.timestamp.clone(),
            "method" => self.method.clone(),
            "result_hash" => self.result_hash.clone(),
            "operator_decl" => self.operator_decl.clone(),
            "concur_decl" => self.concur_decl.clone(),
            "custody_tier" => self.custody_tier.clone(),
            "outcome" => self.outcome.clone(),
            "presence_ref" => self.presence_ref.clone(),
            "operator_key_id" => self.operator_key_id.clone(),
            "tool_ref" => self.tool_ref.clone(),
            "place_ref" => self.place_ref.clone(),
            "amends_seq" => self.amends_seq.clone(),
            "amends_hash" => self.amends_hash.clone(),
            "amend_reason" => self.amend_reason.clone(),
            _ => return None,
        })
    }

    /// Canonical, length-prefixed encoding. Injective by design: every field is preceded
    /// by its own 4-byte big-endian length, so no value can shift a boundary into its
    /// neighbour. A delimiter join here would let two different entries share one
    /// preimage, and therefore one signature.
    pub fn encode(&self) -> Result<Vec<u8>, VerifyError> {
        // The field list comes from the entry's OWN version, not from this build's, so an
        // old entry is hashed exactly as it was written.
        let fields = fields_for(&self.entry_version)
            .ok_or_else(|| VerifyError::UnknownVersion(self.entry_version.clone()))?;
        let mut out = Vec::with_capacity(ENTRY_DOMAIN.len() + 256);
        out.extend_from_slice(ENTRY_DOMAIN);
        for &name in fields {
            let value = self
                .field(name)
                .ok_or_else(|| VerifyError::UnknownField(name.to_string()))?;
            let bytes = value.as_bytes();
            let len = u32::try_from(bytes.len()).map_err(|_| VerifyError::FieldTooLong)?;
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(bytes);
        }
        Ok(out)
    }

    /// The entry's hash with `presence_ref` empty, the value the human was shown.
    ///
    /// `presence_ref` is inside the preimage, so the final hash cannot exist until the
    /// human has already confirmed. The pre-hash is what they see, it is derivable by
    /// anyone holding the entry, and the device's token binds to it.
    pub fn pre_hash(&self) -> Result<String, VerifyError> {
        let mut probe = self.clone();
        probe.presence_ref = String::new();
        probe.recompute_hash()
    }

    /// Does the presence claim bind to what the human actually saw?
    ///
    /// An empty `presence_ref` is fine, no device confirmed, an honest lower tier. A
    /// non-empty one must carry the prefix of this entry's own pre-hash, or the claim is
    /// unfalsifiable: any entry could assert PRESENCE_CONFIRMED with an arbitrary string.
    pub fn verify_presence_binding(&self) -> (bool, &'static str) {
        if self.presence_ref.is_empty() {
            return (true, "no presence device confirmed this entry");
        }
        let parts: Vec<&str> = self.presence_ref.split(':').collect();
        if parts.len() != 3 {
            return (false, "presence_ref is not <device_id>:<nonce>:<pre_hash_prefix>");
        }
        let shown = parts[2];
        if shown.is_empty() {
            return (false, "presence_ref carries no pre-hash prefix");
        }
        match self.pre_hash() {
            Ok(expected) if expected.starts_with(shown) => {
                (true, "presence confirmation binds to this entry's pre-hash")
            }
            Ok(_) => (false, "the value confirmed on the presence device does not match                               this entry's pre-hash: the human approved different bytes"),
            Err(_) => (false, "could not recompute the pre-hash"),
        }
    }

    pub fn recompute_hash(&self) -> Result<String, VerifyError> {
        let mut hasher = Sha256::new();
        hasher.update(self.encode()?);
        Ok(hex::encode(hasher.finalize()))
    }

    pub fn is_dual_signed(&self) -> bool {
        !self.operator_sig.is_empty() && !self.concur_sig.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    UnknownField(String),
    /// The entry names an `entry_version` this build has no field list for. Encoding it
    /// under any other version would produce a confident wrong answer, so it is an error
    /// rather than a fallback.
    UnknownVersion(String),
    FieldTooLong,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::UnknownField(n) => write!(f, "unknown hashed field: {n}"),
            VerifyError::UnknownVersion(v) => write!(
                f,
                "entry_version {v:?} is not a version this verifier understands ({}); \
                 refusing to guess at its field list",
                KNOWN_VERSIONS.join(", ")
            ),
            VerifyError::FieldTooLong => write!(f, "field exceeds 4-byte length prefix"),
        }
    }
}

/// Outcome of a verification walk.
///
/// `unverifiable` is kept separate from `broken` on purpose: "I cannot check this entry"
/// and "this entry is forged" are different statements, and collapsing them makes an
/// authentic chain look tampered after a routine key rotation.
#[derive(Debug, Default)]
pub struct Report {
    pub total: usize,
    pub verified: usize,
    pub concur_verified: usize,
    pub dual_signed: usize,
    pub unverifiable: Vec<(u64, String)>,
    pub broken_seq: Option<u64>,
    pub reason: String,
    pub operator_layer: bool,
    pub concur_layer: bool,
}

impl Report {
    pub fn ok(&self) -> bool {
        self.broken_seq.is_none()
    }

    fn fail(mut self, seq: u64, reason: &str) -> Self {
        self.broken_seq = Some(seq);
        self.reason = reason.to_string();
        self
    }
}

fn parse_key(hex_key: &str) -> Option<VerifyingKey> {
    let raw = hex::decode(hex_key).ok()?;
    let arr: [u8; 32] = raw.try_into().ok()?;
    VerifyingKey::from_bytes(&arr).ok()
}

fn key_id(key: &VerifyingKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hex::encode(hasher.finalize())[..16].to_string()
}

/// Walk the chain. `operator_pub_hex` and `concur_pub_hex` are raw 32-byte Ed25519 public
/// keys, hex-encoded, the form `GET /witness/pubkey` returns and `keys.public_key_hex`
/// produces.
pub fn verify_chain(
    entries: &[Entry],
    operator_pub_hex: Option<&str>,
    concur_pub_hex: Option<&str>,
) -> Report {
    let operator_pub = operator_pub_hex.and_then(parse_key);
    let concur_pub = concur_pub_hex.and_then(parse_key);

    let mut report = Report {
        total: entries.len(),
        operator_layer: operator_pub.is_some(),
        concur_layer: concur_pub.is_some(),
        reason: "chain verified".to_string(),
        ..Default::default()
    };

    if entries.is_empty() {
        return report;
    }

    let chain_id = entries[0].chain_id.clone();
    let mut expected_prev = ZERO_HASH.to_string();

    for (i, e) in entries.iter().enumerate() {
        if e.seq != i as u64 {
            return report.fail(e.seq, "seq out of order");
        }
        if e.chain_id != chain_id {
            return report.fail(e.seq, "entry belongs to a different chain_id");
        }
        // Membership, not equality: a version this build HOLDS THE FIELD LIST FOR can be
        // verified exactly, so refusing it would discard authentic history for no gain.
        // A version we do not know is still refused outright rather than guessed at.
        if fields_for(&e.entry_version).is_none() {
            return report.fail(
                e.seq,
                "entry_version is not a version this verifier understands",
            );
        }
        if e.prev_hash != expected_prev {
            return report.fail(e.seq, "prev_hash does not link to previous entry");
        }

        match e.recompute_hash() {
            Ok(h) if h == e.entry_hash => {}
            Ok(_) => return report.fail(e.seq, "entry content altered: hash mismatch"),
            Err(err) => {
                let seq = e.seq;
                return report.fail(seq, &err.to_string());
            }
        }

        if let Some(ref key) = operator_pub {
            if key_id(key) != e.operator_key_id {
                report
                    .unverifiable
                    .push((e.seq, "no operator key held for this entry".to_string()));
            } else if verify_sig(key, &e.operator_sig, &e.entry_hash) {
                report.verified += 1;
            } else {
                return report.fail(e.seq, "operator signature invalid");
            }
        }

        let (presence_ok, presence_why) = e.verify_presence_binding();
        if !presence_ok {
            return report.fail(e.seq, presence_why);
        }

        if e.is_dual_signed() {
            report.dual_signed += 1;
        }

        if let Some(ref key) = concur_pub {
            if !e.concur_sig.is_empty() {
                if !e.concur_key_id.is_empty() && key_id(key) != e.concur_key_id {
                    report
                        .unverifiable
                        .push((e.seq, "no witness key held for this entry".to_string()));
                } else if verify_sig(key, &e.concur_sig, &e.entry_hash) {
                    report.concur_verified += 1;
                } else {
                    return report.fail(e.seq, "concurring signature invalid");
                }
            }
        }

        expected_prev = e.entry_hash.clone();
    }

    report
}

fn verify_sig(key: &VerifyingKey, sig_hex: &str, msg_hex: &str) -> bool {
    let (Ok(sig_raw), Ok(msg)) = (hex::decode(sig_hex), hex::decode(msg_hex)) else {
        return false;
    };
    let Ok(sig_arr): Result<[u8; 64], _> = sig_raw.try_into() else {
        return false;
    };
    key.verify(&msg, &Signature::from_bytes(&sig_arr)).is_ok()
}

pub fn load_chain(json: &str) -> Result<Chain, serde_json::Error> {
    serde_json::from_str(json)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> Entry {
        Entry {
            entry_version: ENTRY_VERSION.to_string(),
            chain_id: "c1".into(),
            seq: 1,
            prev_hash: "AB".into(),
            op_type: "C".into(),
            target_ref: "x".into(),
            timestamp: "t".into(),
            method: "Clear".into(),
            result_hash: "r".into(),
            operator_decl: "d".into(),
            concur_decl: "e".into(),
            custody_tier: "SOFTWARE_KEY".into(),
            outcome: "VERIFIED".into(),
            presence_ref: String::new(),
            operator_key_id: "k".into(),
            tool_ref: "akhanda/0.0.0+test".into(),
            // v4 fields, non-empty so the injectivity tests actually exercise them.
            place_ref: "FSL Hyderabad".into(),
            amends_seq: String::new(),
            amends_hash: String::new(),
            amend_reason: String::new(),
            entry_hash: String::new(),
            operator_sig: String::new(),
            concur_sig: String::new(),
            concur_key_id: String::new(),
        }
    }

    #[test]
    fn v4_appends_to_v3_and_reorders_nothing() {
        assert_eq!(&FIELDS_V4[..FIELDS_V3.len()], &FIELDS_V3[..]);
        assert_eq!(
            &FIELDS_V4[FIELDS_V3.len()..],
            &["place_ref", "amends_seq", "amends_hash", "amend_reason"]
        );
        assert_eq!(ENTRY_VERSION, "4");
    }

    #[test]
    fn a_v3_entry_hashes_under_the_v3_field_list() {
        // The migration guarantee: an old entry must encode exactly as it did when
        // written, without the four v4 fields appended to its preimage.
        let mut e = entry();
        e.entry_version = "3".into();
        e.place_ref = String::new();
        let encoded = e.encode().expect("a v3 entry must still encode");

        let mut v4 = entry();
        v4.entry_version = "4".into();
        v4.place_ref = String::new();
        let encoded_v4 = v4.encode().expect("a v4 entry must encode");

        // Same values, different versions => different preimages, and the v3 one is
        // shorter by exactly the four extra fields: each empty, so each contributes only
        // its 4-byte big-endian length prefix and no payload.
        assert_ne!(encoded, encoded_v4);
        assert_eq!(encoded_v4.len(), encoded.len() + 4 * 4);
    }

    #[test]
    fn an_unknown_version_is_refused_rather_than_guessed() {
        let mut e = entry();
        e.entry_version = "99".into();
        match e.encode() {
            Err(VerifyError::UnknownVersion(v)) => assert_eq!(v, "99"),
            other => panic!("expected UnknownVersion, got {other:?}"),
        }
        assert!(fields_for("99").is_none());
        assert!(fields_for("3").is_some());
        assert!(fields_for("4").is_some());
    }

    #[test]
    fn encoding_starts_with_the_domain_tag() {
        assert!(entry().encode().unwrap().starts_with(ENTRY_DOMAIN));
    }

    #[test]
    fn length_prefix_is_injective() {
        // "AB"+"C" and "A"+"BC" collide under a delimiter join. They must not here.
        let mut a = entry();
        a.prev_hash = "AB".into();
        a.op_type = "C".into();
        let mut b = entry();
        b.prev_hash = "A".into();
        b.op_type = "BC".into();
        assert_ne!(a.encode().unwrap(), b.encode().unwrap());
    }

    #[test]
    fn delimiter_injection_cannot_shift_a_boundary() {
        let mut poison = entry();
        poison.target_ref = "x|y:z|1:2".into();
        assert_ne!(entry().encode().unwrap(), poison.encode().unwrap());
    }

    #[test]
    fn empty_and_shifted_fields_are_distinguished() {
        let mut a = entry();
        a.presence_ref = String::new();
        a.operator_key_id = "ab".into();
        let mut b = entry();
        b.presence_ref = "a".into();
        b.operator_key_id = "b".into();
        assert_ne!(a.encode().unwrap(), b.encode().unwrap());
    }

    #[test]
    fn every_hashed_field_is_resolvable() {
        let e = entry();
        for name in HASHED_FIELDS {
            assert!(e.field(name).is_some(), "unresolved field: {name}");
        }
        assert!(e.field("not_a_field").is_none());
    }

    #[test]
    fn field_count_matches_the_contract() {
        // 20 since ENTRY_VERSION 4 added place_ref and the three amend_* fields; 16 in
        // v3, which this build still reads. These numbers are written out rather than
        // derived from the arrays on purpose: deriving them would make the test agree
        // with whatever the arrays happen to say, which is not a contract, it is an echo.
        assert_eq!(HASHED_FIELDS.len(), 20);
        assert_eq!(FIELDS_V4.len(), 20);
        assert_eq!(FIELDS_V3.len(), 16);
    }

    #[test]
    fn presence_binding_accepts_a_ref_that_matches_the_pre_hash() {
        let mut e = entry();
        e.seq = 0;
        e.prev_hash = ZERO_HASH.into();
        let ph = e.pre_hash().unwrap();
        e.presence_ref = format!("COM9:nonce:{}", &ph[..16]);
        assert!(e.verify_presence_binding().0);
    }

    #[test]
    fn presence_binding_rejects_a_ref_for_different_bytes() {
        let mut e = entry();
        e.presence_ref = "COM9:nonce:ffffffffffffffff".into();
        assert!(!e.verify_presence_binding().0);
    }

    #[test]
    fn presence_binding_rejects_the_old_two_part_format() {
        let mut e = entry();
        e.presence_ref = "COM9:nonce".into();
        let (ok, why) = e.verify_presence_binding();
        assert!(!ok);
        assert!(why.contains("pre_hash_prefix"));
    }

    #[test]
    fn an_absent_presence_claim_is_not_a_failure() {
        let e = entry();
        assert!(e.verify_presence_binding().0);
    }

    #[test]
    fn empty_chain_verifies_vacuously() {
        let r = verify_chain(&[], None, None);
        assert!(r.ok());
        assert_eq!(r.total, 0);
    }

    #[test]
    fn a_wrong_entry_version_is_refused() {
        let mut e = entry();
        e.seq = 0;
        e.prev_hash = ZERO_HASH.into();
        // Hash it while the version is still one this build knows, then relabel it. An
        // unknown version can no longer be hashed at all (encode returns UnknownVersion),
        // which is itself the point: the walk must reject it before it ever gets there.
        e.entry_hash = e.recompute_hash().unwrap();
        e.entry_version = "1".into();
        let r = verify_chain(&[e], None, None);
        assert!(!r.ok());
        assert!(r.reason.contains("entry_version"));
    }
}
