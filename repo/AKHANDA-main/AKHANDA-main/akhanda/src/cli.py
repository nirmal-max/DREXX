"""
Akhanda command line, the one entry point that wires the pieces together.

    PYTHONPATH=src python -m cli init
    PYTHONPATH=src python -m cli recover image.dd --out recovered/
    PYTHONPATH=src python -m cli erase /dev/sdb --level Clear --confirm <token>
    PYTHONPATH=src python -m cli verify
    PYTHONPATH=src python -m cli certify --out certs/
    PYTHONPATH=src python -m cli anchor
    PYTHONPATH=src python -m cli show

FAIL CLOSED BY DEFAULT. Asking for a component makes it required: if you did not pass
--no-witness and the witness does not answer, the operation is BLOCKED before it runs and
the blocked attempt is written to the chain as a REFUSED entry. Opting out explicitly
(--no-witness / --no-presence) still degrades cleanly and records the honest lower tier.
--allow-degraded is the deliberate escape hatch. See src/attestation/policy.py for why
silent downgrade was removed.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# The certificate is a legal-style document and uses real typography. A Windows console
# defaults to cp1252 and turns every em dash into a replacement character, which makes a
# projected demo look broken. Ask for UTF-8 and fall back quietly if the stream cannot.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

from attestation import (canonical, case as case_mod, keys, policy,  # noqa: E402
                         signers, store, tiers)                      # noqa: E402
from attestation.core import Chain, Entry, key_id, verify_chain_report  # noqa: E402
from anchor import ots                                          # noqa: E402
from certificate import generator as cert_gen                   # noqa: E402
from erasure import engine as erasure                           # noqa: E402
from erasure import file_eraser                                 # noqa: E402
from presence import client as presence                         # noqa: E402
from recovery import engine as recovery                         # noqa: E402
from witness.client import WitnessClient, compare_witness_head  # noqa: E402

TOOL_VERSION = "Akhanda 0.1.0"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _gather_custody(entry_hash_hint: str, args) -> tuple[dict, dict]:
    """Ask the optional components what they can offer, right now.

    Returns (presence_result, witness_client_or_none_state). Neither is required.
    """
    pres = {"confirmed": False, "reason": "presence device not requested"}
    if not args.no_presence:
        pres = presence.request_presence(entry_hash_hint, port=args.presence_port)
        print(f"  presence : {'CONFIRMED' if pres['confirmed'] else 'absent'} "
              f",  {pres.get('reason', '')}")
    return pres, {}


def _probe_components(args) -> tuple[bool, bool]:
    """Cheap availability probes. Neither consumes a button press or writes anything."""
    presence_ok = False
    if not args.no_presence:
        presence_ok = (args.presence_port is not None
                       or presence.find_device() is not None)
    witness_ok = False
    if not args.no_witness:
        witness_ok = WitnessClient(args.witness).head().get("ok", False)
    return presence_ok, witness_ok


def _preflight_or_refuse(args, chain: Chain, op_key, op_type: str, target: str,
                         intended_method: str) -> bool:
    """Fail closed BEFORE the operation runs. Returns True if it may proceed.

    On refusal the attempt is written to the chain as a REFUSED entry, so unplugging the
    co-signer records the attempt instead of erasing it.
    """
    if args.allow_degraded:
        return True

    presence_ok, witness_ok = _probe_components(args)
    check = policy.preflight(
        want_presence=not args.no_presence, want_witness=not args.no_witness,
        presence_available=presence_ok, witness_available=witness_ok,
    )
    if check["ok"]:
        print(f"  preflight: OK, {check['reason']}")
        return True

    print(f"  preflight: BLOCKED, {check['reason']}")
    record = policy.refusal_record(
        op_type=op_type, target=target, intended_method=intended_method,
        preflight_result=check, timestamp=_now(),
    )
    # The refusal itself is signed by the operator alone, the co-signer is, by
    # definition, unavailable. A SOFTWARE_KEY-tier record of a blocked higher-tier
    # operation is exactly what it claims to be.
    entry = chain.append(
        op_type="REFUSED", target_ref=target, timestamp=_now(),
        method="NotPerformed", outcome="NOT_PERFORMED",
        result_hash=canonical.result_digest(record),
        operator_decl=args.operator or "(operator not named)",
        concur_decl=args.expert or "(expert not named)",
        custody_tier=tiers.SOFTWARE_KEY, operator_key=op_key,
    )
    store.save_result(entry.entry_hash, record)
    store.save_chain(chain, args.chain)
    print(f"  refusal  : recorded as entry seq {entry.seq} (op_type REFUSED)")
    print(f"  hash     : {entry.entry_hash}")
    print("  NOTHING was read, written, or destroyed on the target.")
    print("  To proceed at a lower tier, disable the missing component explicitly "
          "(--no-witness / --no-presence) or pass --allow-degraded.")
    return False


def _witness_pubkey(args):
    """The witness's public key: cached copy first, network second, None last.

    Cache-first because verification must keep working when the Pi is off. Fetching is
    only for the first contact; after that the key is local and the verify path has no
    network dependency at all.
    """
    cached = keys.load_witness_key()
    if cached is not None:
        return cached
    if args.no_witness:
        return None
    pub = WitnessClient(args.witness).pubkey()
    if pub is not None:
        keys.cache_witness_key(pub)
    return pub


def _cosign(chain: Chain, entry, args) -> dict:
    """Ask the witness to co-sign. Unreachable is a tier, not a failure."""
    if args.no_witness:
        return {"ok": False, "reason": "witness not requested"}
    wc = WitnessClient(args.witness)
    res = wc.cosign(entry.seq, entry.entry_hash)
    if res["ok"]:
        # First contact caches the key, so every later verification is offline.
        if keys.load_witness_key() is None:
            pub = wc.pubkey()
            if pub is not None:
                keys.cache_witness_key(pub)
        chain.attach_cosignature(
            entry.seq, res["concur_sig"], res.get("concur_key_id", ""),
            res.get("witness_head_hash", ""), res.get("witness_seq", -1),
        )
        print(f"  witness  : CO-SIGNED (witness seq {res['witness_seq']})")
    else:
        print(f"  witness  : absent, {res['reason']}")
    return res


def _append(chain: Chain, op_type: str, target: str, method: str, result,
            args, op_key, outcome: str = "VERIFIED") -> None:
    """Build the entry at the tier that actually held, then sign it.

    Ordering note: presence is requested BEFORE signing, using a preview of the hash,
    because the human must see the value that is about to be signed. The tier is then
    resolved from what answered, and only then is the entry built, so custody_tier and
    presence_ref are inside the signed preimage rather than attached afterwards.
    """
    result_hash = canonical.result_digest(result)

    # The two-phase presence binding lives in Chain.append, so there is one implementation
    # of the ordering rather than one per caller. We hand it a callback: it builds the
    # entry with presence_ref empty, hands us the pre-hash, and we show THAT to the human.
    seen = {}

    def _confirm(pre_hash: str) -> str:
        seen["pre_hash"] = pre_hash
        print(f"  pre-hash : {pre_hash[:16]}  <- shown on the presence device")
        pres = _gather_custody(pre_hash, args)[0]
        seen["pres"] = pres
        return presence.presence_ref(pres)

    entry = chain.append(
        op_type=op_type, target_ref=target, timestamp=_now(), method=method,
        result_hash=result_hash,
        operator_decl=args.operator or "(operator not named)",
        concur_decl=args.expert or "(expert not named)",
        custody_tier=tiers.SOFTWARE_KEY, operator_key=op_key, outcome=outcome,
        presence_fn=None if args.no_presence else _confirm,
    )
    pres = seen.get("pres", {"confirmed": False})

    # The tier is resolved from what ANSWERED, then the entry is rebuilt so custody_tier
    # sits inside the signed preimage rather than being attached afterwards.
    tier = tiers.resolve(pres.get("confirmed", False),
                         witness_cosigned=not args.no_witness)
    if tier != tiers.SOFTWARE_KEY:
        chain.entries.pop()
        entry = chain.append(
            op_type=op_type, target_ref=target, timestamp=_now(), method=method,
            result_hash=result_hash,
            operator_decl=args.operator or "(operator not named)",
            concur_decl=args.expert or "(expert not named)",
            custody_tier=tier, operator_key=op_key, outcome=outcome,
            presence_fn=(lambda _ph: presence.presence_ref(pres)) if pres.get("confirmed") else None,
        )

    res = _cosign(chain, entry, args)

    # If the witness did not answer, the entry claims a tier it did not reach. Rebuild
    # it at the honest tier rather than shipping an overclaim.
    actual = tiers.resolve(pres.get("confirmed", False), res.get("ok", False))
    if actual != tier:
        chain.entries.pop()
        entry = chain.append(
            op_type=op_type, target_ref=target, timestamp=_now(), method=method,
            result_hash=result_hash,
            operator_decl=args.operator or "(operator not named)",
            concur_decl=args.expert or "(expert not named)",
            custody_tier=actual, operator_key=op_key, outcome=outcome,
            presence_ref=presence.presence_ref(pres),
        )
        if res.get("ok"):
            chain.attach_cosignature(
                entry.seq, res["concur_sig"], res.get("concur_key_id", ""),
                res.get("witness_head_hash", ""), res.get("witness_seq", -1))

    # Persist the record the entry commits to, BEFORE the chain is saved. If the process
    # dies between the two, the worst case is an orphan record with no entry, harmless.
    # The reverse order would leave an entry pointing at evidence that was never written.
    record = store.save_result(entry.entry_hash, result)

    print(f"  entry    : seq {entry.seq}  tier {entry.custody_tier}")
    print(f"  hash     : {entry.entry_hash}")
    print(f"  record   : {record}")

    # The residual window: preflight said every required component was answering, and one
    # of them died before the entry was co-signed. The operation already happened and
    # cannot be undone, so it is recorded at the tier actually reached, loudly, because
    # this is the one path that produces an entry below what the operator required.
    if not args.allow_degraded:
        required = policy.required_tier(not args.no_presence, not args.no_witness)
        state = policy.degraded_after_preflight(required, entry.custody_tier)
        if state["degraded"]:
            print(f"  DEGRADED : {state['reason']}")
            print("             the operation is recorded at the tier it actually "
                  "reached, not the tier that was required")

    store.save_chain(chain, args.chain)


# --------------------------------------------------------------------- commands

def cmd_init(args) -> int:
    key = keys.load_or_create_operator_key()
    print(f"operator key : {keys.operator_key_path()}")
    print(f"public key   : {keys.operator_pub_path()}")
    print(f"key id       : {key_id(key.public_key())}")
    chain = store.load_chain(args.chain)
    store.save_chain(chain, args.chain)
    print(f"chain        : {store.chain_path(args.chain)}  (chain_id {chain.chain_id})")
    if not keys._passphrase():
        print("\nNOTE: AKHANDA_KEY_PASSPHRASE is not set. The private key is on disk "
              "unencrypted;\n      anyone who can read that file can sign as the operator.")
    return 0


def cmd_erase(args) -> int:
    op_key = keys.load_or_create_operator_key()
    chain = store.load_chain(args.chain)
    print(f"erase {args.device} (requested level {args.level})")
    # Preflight runs FIRST. An erase is irreversible; checking custody afterwards would
    # be checking whether we were allowed to do the thing we already did.
    if not _preflight_or_refuse(args, chain, op_key, "ERASE", args.device, args.level):
        return 3
    result = erasure.erase(args.device, args.level, confirm=args.confirm)
    print(f"  achieved : {result['method_used']}  verified={result['verified']}")
    print(f"  note     : {result['honest_note']}")
    # The engine decides the outcome, not this call site. A mapping invented here is a
    # mapping that drifts from the one recovery uses (G9).
    outcome = erasure.outcome_for(result)
    if result.get("bad_ranges"):
        print(f"  SKIPPED  : {len(result['bad_ranges'])} unreadable region(s), "
              f"{result['bytes_skipped']} bytes. Each is a signed record, not a gap.")
        for b in result["bad_ranges"][:8]:
            print(f"             {b['phase']:5} offset {b['offset']:>12}  "
                  f"{b['length']:>8} bytes  {b['strerror'][:60]}")
        if len(result["bad_ranges"]) > 8:
            print(f"             ... {len(result['bad_ranges']) - 8} more, all in the record")
    if result.get("aborted"):
        print(f"  ABORTED  : {result['abort_reason']}")
    if outcome != "VERIFIED":
        print(f"  OUTCOME  : {outcome}, recorded in the signed entry, not only in the "
              "result record. The certificate cannot present this as a clean wipe.")
    _append(chain, "ERASE", args.device, result["method_used"], result, args, op_key,
            outcome=outcome)
    if args.result_out:
        Path(args.result_out).write_text(json.dumps(result, indent=2), encoding="utf-8")
    return 0


def cmd_recover(args) -> int:
    op_key = keys.load_or_create_operator_key()
    chain = store.load_chain(args.chain)
    print(f"carve {args.image}")
    if not _preflight_or_refuse(args, chain, op_key, "RECOVER", args.image, "Clear"):
        return 3
    artifacts = recovery.carve(args.image, out_dir=args.out)
    summary = recovery.summarize(artifacts)
    print(f"  found    : {summary['total']} artefact(s) {summary['by_type']}")
    print(f"  note     : {summary['note']}")
    # The engine decides this, not the CLI: VERIFIED only when EVERY extent was confirmed
    # by the file's own structure. Validated against NIST CFReDS, where a fragmented image
    # must never come back looking like a clean recovery.
    outcome = recovery.outcome_for(artifacts)
    print(f"  confidence: {summary['by_confidence']}")
    if outcome != "VERIFIED":
        print(f"  OUTCOME  : {outcome}, {summary['note']}")
    _append(chain, "RECOVER", args.image, "Clear", artifacts, args, op_key,
            outcome=outcome)
    if args.result_out:
        Path(args.result_out).write_text(json.dumps(artifacts, indent=2), encoding="utf-8")
    return 0


def cmd_erase_files(args) -> int:
    """PS module (b): secure file and folder eraser.

    Goes through the same preflight as a drive erase. A recursive file wipe destroys as
    much as a block-device wipe, so it gets the same fail-closed policy rather than a
    weaker one because it happens to run in userspace.
    """
    op_key = keys.load_or_create_operator_key()
    chain = store.load_chain(args.chain)
    print(f"erase-files {args.path} (recursive={args.recursive})")
    if not _preflight_or_refuse(args, chain, op_key, "ERASE", args.path, "Clear"):
        return 3

    result = file_eraser.erase_path(
        args.path, recursive=args.recursive, passes=args.passes, confirm=args.confirm)
    print(f"  filesystem: {result['filesystem']}")
    print(f"  achieved  : {result['method_used']}  outcome={result['outcome']}  "
          f"performed={result['performed']} of {len(result['targets'])}")
    for lim in result["limitations"]:
        print(f"  limit     : {lim}")

    _append(chain, "ERASE", args.path, result["method_used"], result, args, op_key,
            outcome=result["outcome"])
    if args.result_out:
        Path(args.result_out).write_text(json.dumps(result, indent=2), encoding="utf-8")
    return 0


def cmd_verify(args) -> int:
    chain = store.load_chain(args.chain)
    pub = None
    try:
        pub = keys.load_public_key()
    except OSError:
        print("no operator public key on disk; running the key-free layer only")

    concur_pub = _witness_pubkey(args)
    report = verify_chain_report(chain.entries, pub, concur_pub)
    signed = sum(1 for e in chain.entries if e.concur_sig)

    print(f"chain    : {chain.chain_id}  ({len(chain.entries)} entries)")
    print(f"result   : {report!r}")
    if not report.ok:
        print(f"BROKEN at sequence {report.broken_seq}: {report.reason}")

    # SIGNER CONTINUITY RUNS ON EVERY VERIFY, not on request (Gap 7).
    #
    # A substituted signing key leaves a chain that verifies perfectly: every signature
    # checks out against the key it was signed with, and a verifier handed the substituted
    # key confirms it honestly. The change is only visible if something looks for it, and
    # a check nobody remembers to run is a check that is not there.
    expected = {key_id(pub)} if pub is not None else None
    cont = signers.verify_signer_continuity(chain.entries, expected_key_ids=expected)
    if len(cont["roster"]) > 1 or cont["unexplained"] or cont["unknown_keys"]:
        print(f"signers  : {len(cont['roster'])} key(s), ok={cont['ok']}")
        print(f"           {cont['reason']}")
        for u in cont["unexplained"]:
            print(f"  UNEXPLAINED at seq {u['at_seq']}: "
                  f"{u['from_key_id']} -> {u['to_key_id']}")
    if cont["unexplained"]:
        # A signer substituted without announcement is a custody failure even when every
        # hash and signature is intact, so it must change the exit code. Printing a
        # warning beside a zero exit is how a finding gets scripted past.
        print("VERIFY FAILS: the signer changed without a signed announcement.")
        return 1

    if concur_pub is not None:
        print(f"expert   : {report.concur_verified} of {signed} concurring "
              f"signature(s) re-verified against {key_id(concur_pub)}")
    elif signed:
        print(f"expert   : {signed} concurring signature(s) present but NOT verified "
              ",  no witness public key held")
        print("           run once with the witness reachable to cache its key")
    else:
        print("expert   : no concurring signatures in this chain")

    # The chain commits to result records by hash. Verifying the chain without checking
    # that those records still exist and still match leaves the commitment pointing at
    # nothing, a hash whose subject is gone proves nothing to anyone.
    records = store.verify_all_results(chain)
    print(f"records  : {records['matched']} of {records['total']} result record(s) "
          "present and matching")
    if records["missing"]:
        print(f"           MISSING for entries {records['missing']}, the ledger "
              "commits to evidence that is not on disk")
    if records["altered"]:
        print(f"           ALTERED for entries {records['altered']}, the stored record "
              "no longer matches the hash the entry signed")

    if not args.no_witness:
        wc = WitnessClient(args.witness)
        cmp_ = compare_witness_head(chain, wc.head())
        if cmp_["checked"]:
            state = "DIVERGED" if cmp_["diverged"] else "agrees"
            print(f"witness  : {state}, {cmp_['reason']}")
        else:
            print(f"witness  : not checked, {cmp_['reason']}")
            print("           a full-chain rewrite would NOT have been detected here")

    # An altered result record is a failure, not a warning: the entry's signature is
    # still valid, so nothing else in this command would catch it. A missing record is
    # reported but not fatal, the commitment is intact, the evidence is merely absent,
    # and those are different problems for whoever has to explain them.
    return 0 if (report.ok and not records["altered"]) else 1


def cmd_certify(args) -> int:
    chain = store.load_chain(args.chain)
    if not chain.entries:
        print("chain is empty; nothing to certify")
        return 1

    entries = chain.entries
    if args.target:
        entries = [e for e in chain.entries if e.target_ref == args.target]
        if not entries:
            print(f"no entries for target {args.target!r}")
            return 1

    pub = None
    try:
        pub = keys.load_public_key()
    except OSError:
        pass
    report = verify_chain_report(chain.entries, pub, _witness_pubkey(args))

    witness_state = {"checked": False, "note": "witness not contacted"}
    if not args.no_witness:
        wc = WitnessClient(args.witness)
        witness_state = compare_witness_head(chain, wc.head())
        witness_state["endpoint"] = args.witness

    anchor_state = {"confirmed": False, "note": "chain not anchored"}
    if args.anchor_proof:
        anchor_state = ots.verify(args.anchor_proof)

    operator = cert_gen.Party(
        name=args.operator or "", title=args.operator_title or "",
        organisation=args.organisation or "", location=args.location or "",
        key_id=entries[0].operator_key_id,
    )
    expert = cert_gen.Party(
        name=args.expert or "", title=args.expert_title or "",
        organisation=args.organisation or "", location=args.location or "",
        key_id=next((e.concur_key_id for e in entries if e.concur_key_id), ""),
    )
    media = cert_gen.MediaInfo(
        make_model=args.media_model or "", property_number=args.media_property or "",
        media_type=args.media_type or "", serial_number=args.media_serial or "",
        source=args.media_source or "", classification=args.media_class or "",
        destination=args.media_destination or "",
    )

    cert = cert_gen.build_certificate(
        chain, entries, operator, expert, media,
        chain_report=report, witness_state=witness_state, anchor_state=anchor_state,
        tool_version=TOOL_VERSION, notes=args.notes or "",
    )
    paths = cert_gen.save(cert, args.out, basename=args.basename)
    print(cert_gen.render_text(cert))
    print(f"\nwritten: {paths['json']}\n         {paths['text']}")
    return 0


def cmd_anchor(args) -> int:
    chain = store.load_chain(args.chain)
    if not chain.entries:
        print("chain is empty; nothing to anchor")
        return 1
    root = ots.merkle_root(chain.entry_hashes())
    print(f"merkle root : {root.hex()}")
    res = ots.submit(root, out_dir=args.out)
    print(f"submit      : ok={res['ok']}, {res['reason']}")
    print(f"proof       : {res['proof_path']}")
    if not res["ok"]:
        print("the chain is recorded as UNANCHORED; that is what the certificate will say")
    return 0


def _load_case(paths: list) -> dict:
    """{device_id: Chain} from chain files. device_id defaults to the filename stem.

    A device id is how the case names a drive, so it must not be silently derived from
    something that can change: `--device id=path` is the explicit form, and the filename
    fallback exists only so the common case is not tedious.
    """
    chains = {}
    for spec in paths:
        if "=" in spec:
            device_id, _, path = spec.partition("=")
        else:
            path, device_id = spec, Path(spec).stem
        chains[device_id] = store.load_chain(Path(path))
    return chains


def cmd_case(args) -> int:
    """Bind the SET of device chains in one case, so a whole drive going missing shows.

    Chaining stops removal from the middle of ONE device's history. Nothing inside a chain
    knows how many sibling chains the case had, so deleting a drive's whole chain leaves
    every survivor verifying perfectly. This is the level that closes that.
    """
    chains = _load_case(args.device)
    try:
        manifest = case_mod.build_manifest(chains, case_id=args.case_id,
                                           examiner=args.examiner or "",
                                           note=args.note or "")
    except case_mod.CaseError as exc:
        print(f"refused: {exc}")
        return 2

    print(f"case        : {manifest['case_id']}")
    print(f"devices     : {manifest['device_count']}, "
          f"{manifest['total_entries']} entries total")
    for d in manifest["devices"]:
        print(f"  {d['device_id']:<16} {d['count']:>3} entries  head {d['head_hash'][:16]}…")
    print(f"case root   : {manifest['case_root']}")

    if args.verify:
        report = case_mod.verify_manifest(
            json.loads(Path(args.verify).read_text(encoding="utf-8")), chains)
        print(f"\nverify      : ok={report['ok']}")
        print(f"  {report['reason']}")
        if report["missing_devices"]:
            print(f"  MISSING   : {report['missing_devices']}")
        for c in report["changed_devices"]:
            print(f"  CHANGED   : {c['device_id']} "
                  f"stated {c['stated']['count']} entries, found {c['found']['count']}")
        if not report["ok"]:
            return 1

    if args.prove:
        try:
            proof = case_mod.device_proof(chains, args.prove)
        except case_mod.CaseError as exc:
            print(f"refused: {exc}")
            return 2
        out = Path(args.out) / f"case_proof_{args.prove}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(proof, indent=2), encoding="utf-8")
        print(f"\nproof for {args.prove}: {len(proof['path'])} sibling hashes -> {out}")
        print("  Proves this device belongs to the case WITHOUT disclosing the others , ")
        print("  for when one drive is released while the rest of the case stays live.")

    if args.out and not args.no_manifest:
        mpath = Path(args.out) / f"case_{args.case_id}.json"
        mpath.parent.mkdir(parents=True, exist_ok=True)
        mpath.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        print(f"\nmanifest    : {mpath}")
        print("  UNANCHORED. Until this root is anchored or co-signed it is a claim the")
        print("  operator made about their own case. `cli anchor-case` is the next step.")
    return 0


def cmd_show(args) -> int:
    chain = store.load_chain(args.chain)
    print(f"chain {chain.chain_id}  ({len(chain.entries)} entries)")
    print(f"head  {chain.head_hash()}")
    for e in chain.entries:
        dual = "dual" if e.is_dual_signed() else "solo"
        print(f"  [{e.seq:>3}] {e.timestamp}  {e.op_type:<8} {e.method:<12} "
              f"{e.outcome:<14} {dual}  {e.custody_tier:<19} {e.target_ref}")
        print(f"        hash {e.entry_hash}")
    return 0


# ------------------------------------------------------------------------ parser

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="akhanda", description=__doc__.split("\n")[1])
    p.add_argument("--chain", default=None, help="path to chain.json (default: ~/.akhanda)")
    p.add_argument("--witness", default="http://raspberrypi.local:8000",
                   help="witness node base URL")
    p.add_argument("--no-witness", action="store_true", help="do not contact the witness")
    p.add_argument("--no-presence", action="store_true", help="do not query the ESP32")
    p.add_argument("--allow-degraded", action="store_true",
                   help="proceed even if a required component is unavailable, recording "
                        "the lower tier. Opt-in on purpose: without it, a missing "
                        "co-signer BLOCKS the operation instead of silently downgrading.")
    p.add_argument("--presence-port", default=None, help="serial port of the ESP32")
    p.add_argument("--operator", default=None, help="name of the person in charge (BSA Part A)")
    p.add_argument("--expert", default=None, help="name of the expert (BSA Part B)")

    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="create the operator key and an empty chain").set_defaults(
        func=cmd_init)

    e = sub.add_parser("erase", help="erase a device and record it")
    e.add_argument("device")
    e.add_argument("--level", default="Clear", choices=["Clear", "Purge"])
    e.add_argument("--confirm", default="", help=f"required token: {erasure.CONFIRM_TOKEN}")
    e.add_argument("--result-out", default=None)
    e.set_defaults(func=cmd_erase)

    r = sub.add_parser("recover", help="carve an image and record it")
    r.add_argument("image")
    r.add_argument("--out", default=None, help="directory to extract artefacts into")
    r.add_argument("--result-out", default=None)
    r.set_defaults(func=cmd_recover)

    ef = sub.add_parser("erase-files",
                        help="securely erase files and folders (PS module b)")
    ef.add_argument("path")
    ef.add_argument("--recursive", action="store_true",
                    help="descend into directories")
    ef.add_argument("--passes", type=int, default=1,
                    help="overwrite passes; 1 is NIST Clear, more only wears flash")
    ef.add_argument("--confirm", default="",
                    help=f"required token: {file_eraser.CONFIRM_TOKEN}")
    ef.add_argument("--result-out", default=None)
    ef.set_defaults(func=cmd_erase_files)

    sub.add_parser("verify", help="verify the chain and compare the witness head"
                   ).set_defaults(func=cmd_verify)

    c = sub.add_parser("certify", help="produce the NIST + BSA certificate")
    c.add_argument("--out", default="certificates")
    c.add_argument("--basename", default="certificate")
    c.add_argument("--target", default=None, help="restrict to one target_ref")
    c.add_argument("--anchor-proof", default=None, help="path to a .ots proof")
    c.add_argument("--operator-title", default=None)
    c.add_argument("--expert-title", default=None)
    c.add_argument("--organisation", default=None)
    c.add_argument("--location", default=None)
    c.add_argument("--media-model", default=None)
    c.add_argument("--media-property", default=None)
    c.add_argument("--media-type", default=None,
                   choices=["Magnetic", "Flash Memory", "Optical", "Hybrid", None])
    c.add_argument("--media-serial", default=None)
    c.add_argument("--media-source", default=None)
    c.add_argument("--media-class", default=None)
    c.add_argument("--media-destination", default=None)
    c.add_argument("--notes", default=None)
    c.set_defaults(func=cmd_certify)

    cs = sub.add_parser("case",
                        help="bind many device chains into one case (Merkle root)")
    cs.add_argument("--device", action="append", default=[], required=True,
                    metavar="[ID=]CHAIN.json",
                    help="a device chain; repeat once per device")
    cs.add_argument("--case-id", required=True)
    cs.add_argument("--examiner", default=None)
    cs.add_argument("--note", default=None)
    cs.add_argument("--out", default="evidence")
    cs.add_argument("--verify", default=None, metavar="MANIFEST.json",
                    help="re-derive a manifest from the chains actually present")
    cs.add_argument("--prove", default=None, metavar="DEVICE_ID",
                    help="emit an inclusion proof for one device only")
    cs.add_argument("--no-manifest", action="store_true")
    cs.set_defaults(func=cmd_case)

    a = sub.add_parser("anchor", help="checkpoint the chain to OpenTimestamps")
    a.add_argument("--out", default="anchors")
    a.set_defaults(func=cmd_anchor)

    sub.add_parser("show", help="print the chain").set_defaults(func=cmd_show)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (erasure.ErasureRefused, file_eraser.FileErasureRefused) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
