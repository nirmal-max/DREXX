"""G24, two-laptop link check. Run this NOW, not on the day.

The main laptop has no Ethernet port. The link between operator and witness is the single
point of failure for the whole demo: if it does not come up at GITAM, there is no second
signature, and the one thing that distinguishes this tool from BitRaser is the second
signature.

    # on the WITNESS machine:
    python src/witness/node.py
    # on the OPERATOR machine:
    python scripts/prep/g24_link_check.py --witness http://192.168.1.42:8000

Writes evidence/g24_link_check.json. Measures what actually matters: does the witness
answer, how fast, and does it stay answering. A link that works once and drops under load
is worse than no link, because it fails halfway through an irreversible operation.

PREFERRED transport: USB-to-Ethernet adapter + a direct cable between the two machines.
No venue WiFi, no DHCP server, no captive portal, nothing to negotiate on the day.
Static addresses on both ends: 192.168.50.1 (witness) and 192.168.50.2 (operator).
FALLBACK: phone hotspot with both machines joined. Test it here too, on the same script,
and record both results.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "evidence"


def probe(url: str, timeout: float) -> tuple[bool, float, str, dict | None]:
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            body = json.loads(r.read().decode())
        return True, (time.perf_counter() - t0) * 1000.0, "", body
    except urllib.error.URLError as exc:
        return False, (time.perf_counter() - t0) * 1000.0, f"{type(exc).__name__}: {exc.reason}", None
    except Exception as exc:  # noqa: BLE001 - a link check reports, never raises
        return False, (time.perf_counter() - t0) * 1000.0, f"{type(exc).__name__}: {exc}", None


def main() -> int:
    ap = argparse.ArgumentParser(description="Check the operator-to-witness link.")
    ap.add_argument("--witness", required=True, help="e.g. http://192.168.50.1:8000")
    ap.add_argument("--samples", type=int, default=30)
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--transport", default="unspecified",
                    help='"usb-ethernet-direct" or "phone-hotspot" - recorded verbatim')
    args = ap.parse_args()

    base = args.witness.rstrip("/")
    out: dict = {
        "check": "G24 operator-to-witness link",
        "ran_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "witness_url": base,
        "transport": args.transport,
        "samples": args.samples,
    }

    # 1. Does it answer at all, and does it identify itself as a witness?
    ok, ms, err, head = probe(f"{base}/witness/head", args.timeout)
    out["reachable"] = ok
    out["first_response_ms"] = round(ms, 1)
    out["error"] = err
    out["head"] = head

    if not ok:
        out["verdict"] = "FAIL - WITNESS UNREACHABLE"
        out["meaning"] = ("No link, so no second signature. Fix the transport before "
                          "4 Sept. Check: both machines on the same subnet, the witness "
                          "bound to 0.0.0.0 not 127.0.0.1, and Windows Defender Firewall "
                          "allowing inbound TCP 8000 on a PRIVATE profile.")
    else:
        ok_key, _, _, pub = probe(f"{base}/witness/pubkey", args.timeout)
        out["pubkey_reachable"] = ok_key
        out["witness_key_id"] = (pub or {}).get("key_id", "")

        # 2. Stability. One success proves nothing; the demo makes many calls.
        lat, fails = [], 0
        for _ in range(args.samples):
            s_ok, s_ms, _, _ = probe(f"{base}/witness/head", args.timeout)
            (lat.append(s_ms) if s_ok else None)
            fails += 0 if s_ok else 1
        out["failed_probes"] = fails
        out["loss_pct"] = round(100.0 * fails / args.samples, 1)
        if lat:
            out["latency_ms"] = {
                "median": round(statistics.median(lat), 1),
                "min": round(min(lat), 1),
                "max": round(max(lat), 1),
            }

        if fails == 0:
            out["verdict"] = "PASS - LINK STABLE"
            out["meaning"] = (f"{args.samples}/{args.samples} probes answered, median "
                              f"{out['latency_ms']['median']} ms. Record the transport "
                              "and reuse exactly it on the day.")
        else:
            out["verdict"] = "MARGINAL - INTERMITTENT"
            out["meaning"] = (f"{fails}/{args.samples} probes failed. An intermittent "
                              "link fails mid-operation, which is the worst case: the "
                              "preflight passes and the co-signature then does not "
                              "arrive. Prefer the direct cable over the hotspot.")

    EVIDENCE.mkdir(parents=True, exist_ok=True)
    path = EVIDENCE / "g24_link_check.json"
    path.write_text(json.dumps(out, indent=2), encoding="utf-8")

    print(f"verdict   {out['verdict']}")
    print(f"witness   {base}  ({args.transport})")
    if out.get("latency_ms"):
        print(f"latency   {out['latency_ms']['median']} ms median, "
              f"{out['loss_pct']}% loss over {args.samples} probes")
    if out.get("witness_key_id"):
        print(f"key id    {out['witness_key_id']}")
    print(f"meaning   {out['meaning']}")
    print(f"written   {path}")
    return 0 if out["verdict"].startswith("PASS") else 1


if __name__ == "__main__":
    sys.exit(main())
