//! `akhanda-verify`, verify an Akhanda chain from the command line.
//!
//! ```text
//! akhanda-verify chain.json [--operator-key <hex>] [--witness-key <hex>] [--json]
//! ```
//!
//! Exit codes, chosen so this is usable in a script and in CI:
//!   0  chain verified
//!   1  chain BROKEN, the sequence number is named in the output
//!   2  usage error, or the file could not be read or parsed
//!
//! Reads only the file it is given. No network, no configuration, no environment. A
//! forensic verifier that needs a server is a verifier that stops working when the
//! server does, and the whole point is that a third party can check the evidence years
//! later with nothing but this binary and a public key.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use akhanda_verify::{load_chain, verify_chain};

fn usage() -> ExitCode {
    eprintln!(
        "usage: akhanda-verify <chain.json> [--operator-key <hex>] \
         [--witness-key <hex>] [--json]\n\n\
         Verifies the key-free layer always (hashes, links, sequence, version).\n\
         Supply keys to additionally re-verify Ed25519 signatures."
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args[0] == "-h" || args[0] == "--help" {
        return usage();
    }

    let path = &args[0];
    let mut operator_key: Option<String> = None;
    let mut witness_key: Option<String> = None;
    let mut as_json = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--operator-key" if i + 1 < args.len() => {
                operator_key = Some(args[i + 1].clone());
                i += 2;
            }
            "--witness-key" if i + 1 < args.len() => {
                witness_key = Some(args[i + 1].clone());
                i += 2;
            }
            "--json" => {
                as_json = true;
                i += 1;
            }
            _ => return usage(),
        }
    }

    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cannot read {path}: {e}");
            return ExitCode::from(2);
        }
    };

    let chain = match load_chain(&text) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{path} is not an Akhanda chain: {e}");
            return ExitCode::from(2);
        }
    };

    let report = verify_chain(
        &chain.entries,
        operator_key.as_deref(),
        witness_key.as_deref(),
    );

    if as_json {
        println!(
            "{{\"ok\":{},\"total\":{},\"verified\":{},\"concur_verified\":{},\
             \"dual_signed\":{},\"unverifiable\":{},\"broken_seq\":{},\"reason\":{:?}}}",
            report.ok(),
            report.total,
            report.verified,
            report.concur_verified,
            report.dual_signed,
            report.unverifiable.len(),
            report
                .broken_seq
                .map(|s| s.to_string())
                .unwrap_or_else(|| "null".into()),
            report.reason,
        );
    } else {
        println!("chain    : {}  ({} entries)", chain.chain_id, report.total);
        if report.ok() {
            println!("result   : VERIFIED, {}", report.reason);
        } else {
            println!(
                "result   : BROKEN at sequence {}, {}",
                report.broken_seq.unwrap(),
                report.reason
            );
        }
        if report.operator_layer {
            println!(
                "operator : {} of {} signature(s) re-verified",
                report.verified, report.total
            );
        } else {
            println!("operator : signatures NOT checked (no key given)");
        }
        if report.concur_layer {
            println!(
                "expert   : {} of {} concurring signature(s) re-verified",
                report.concur_verified, report.dual_signed
            );
        }
        for (seq, why) in &report.unverifiable {
            println!("           seq {seq}: {why}");
        }
        println!(
            "note     : tail truncation is NOT detectable here, only the witness's \
             independent head record separates a truncated chain from a short one"
        );
    }

    if report.ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
