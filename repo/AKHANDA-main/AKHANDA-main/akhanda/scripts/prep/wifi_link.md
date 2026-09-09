# G24 over Wi-Fi, the working transport for this hardware

**Tested 1 Sep 2026:** the USB-C to USB-C direct cable **does not link the two laptops** and
cannot on this machine, no Thunderbolt/USB4 controller, and plain USB-C is host-to-device,
so neither laptop will act as a device to the other (`evidence/link_detect.json`). No
USB-to-Ethernet adapter is present either.

**What both laptops do have is Wi-Fi.** So the link is wireless: put both machines on **one
small network they own**, and the witness node is reachable across it. This is a real,
supported transport, not a downgrade, and it needs nothing bought.

---

## Which hotspot to use, best first

1. **Your phone's hotspot** (simplest). Turn on the phone's mobile hotspot; join **both**
   laptops to it. Done.
2. **This laptop as the hotspot** (no phone needed). Windows → Settings → Network & internet
   → **Mobile hotspot** → On, "Share over Wi-Fi". The witness laptop joins that hotspot.
3. **Any Wi-Fi you both already sit on** (home router). Works, with one caveat below.

The Wi-Fi adapter on this machine is up and the OS supports Mobile Hotspot, so option 2 is
available with no extra hardware.

---

## Steps

1. **Join both laptops to the same hotspot.** Confirm each got an address on the same subnet:
   ```powershell
   ipconfig | findstr /i "IPv4"
   ```
   Both should be `192.168.x.y` on the same `192.168.x` (a phone hotspot is typically
   `192.168.43.x`; Windows Mobile Hotspot is `192.168.137.x`).

2. **On the witness laptop**, note its address and start the node:
   ```powershell
   $env:AKHANDA_WITNESS_HOST = "0.0.0.0"   # bind all interfaces so the hotspot side reaches it
   python src\witness\node.py
   ```
   Allow inbound **TCP 8000** on the **Private** firewall profile when Windows prompts.

3. **On the operator laptop**, point the link check at the witness's hotspot IP:
   ```bash
   python scripts/prep/g24_link_check.py --witness http://<witness-ip>:8000 --transport wifi-hotspot
   ```
   30 probes. **0% loss is the pass.** Any loss and the hotspot is dropping packets, move
   closer, or switch to option 1/2.

4. Then the handshake runs over the same link:
   ```bash
   python scripts/prep/g1_handshake.py --witness http://<witness-ip>:8000 --phase a
   ```

---

## The one caveat, and why to test it now not on the day

Some access points enable **client isolation** (also "AP isolation" / "station isolation"),
which blocks the two laptops from seeing each other even on the same SSID, every packet goes
to the internet and none to the peer. Venue and enterprise Wi-Fi very often has this on;
**that is exactly why the roadmap says test the link once before the day.**

- **A phone hotspot and Windows Mobile Hotspot normally allow client-to-client**, options 1
  and 2 are the safe choices.
- **Venue Wi-Fi is the risky one.** If `g24_link_check.py` shows 100% loss on a network that
  otherwise has internet, client isolation is the cause. Fall back to option 1 or 2.

---

## What this does NOT change

Wireless is fine for the *link*. It does not weaken the *security boundary*: the witness key
still lives in a separate OS account the operator cannot read (LB-03), and the co-signature
is still an independent Ed25519 signature over the entry hash. The transport carries the
handshake; it is not trusted with anything. A hostile network can drop or delay packets, in
which case the operation **fails closed** and a REFUSED entry is written, but it cannot forge
a signature it does not have the key for.

**Record the result** of `g24_link_check.py` into `evidence/` and note in `BUILD_LOG.md`
which hotspot was used, so the transport that worked in rehearsal is the one used on the day.
