# Witness node, set this up on LAPTOP B (5 minutes)

This is the second party. It holds **its own signing key**, on **its own machine**, and
co-signs entries the operator laptop sends it. That physical separation is the claim , 
it is why an operator cannot quietly produce a complete-looking chain alone.

`node.py` imports nothing from the Akhanda repo. **Copy this folder to laptop B and that
is the whole install.**

---

## Setup, on laptop B

**1. Python**, if `python --version` fails, install Python 3.11+ from python.org and
tick **"Add python.exe to PATH"** during install.

**2. Install the three dependencies**
```bash
pip install fastapi uvicorn cryptography
```

**3. Start the node**
```bash
python node.py
```

You should see:
```
witness node on 0.0.0.0:8000  (AKHANDA_WITNESS_HOST to narrow)
```

**Windows will prompt for firewall access, click Allow, and make sure "Private networks"
is ticked.** If you miss this prompt the operator laptop cannot reach it, and that is the
single most common failure here.

**4. Find laptop B's IP address**
```bash
ipconfig | findstr /i "IPv4"
```
Note the address on the same network as the operator laptop. Give that to the operator.

---

## Both laptops must be on the same network

Put both on **one phone hotspot** (simplest) or Windows Mobile Hotspot. Do **not** rely on
venue or campus Wi-Fi: many access points enable **client isolation**, which blocks the two
laptops from seeing each other even though both have internet. That is a rehearsal-killer
discovered on the day, so use a hotspot you control.

Typical address ranges: phone hotspot `192.168.43.x`, Windows Mobile Hotspot
`192.168.137.x`.

---

## Check it from the OPERATOR laptop

```bash
curl http://<laptop-B-ip>:8000/witness/pubkey
```

A JSON response with `pubkey_hex` and `key_id` means the link is up. **A different `key_id`
than the operator laptop's own witness is the point**, it proves the second signature comes
from a key this machine does not hold.

Then, on the operator laptop:
```bash
cd D:\akhanda
python scripts/demo_bundle.py --witness http://<laptop-B-ip>:8000
```

Entries recorded through it carry a real second signature from laptop B's key, and the
custody tier rises accordingly.

---

## What this does and does not prove

**Does:** a second, independent Ed25519 key on a physically separate machine signed the same
entry hash. Removing or altering an entry breaks verification and names the sequence number.

**Does not:** prove nothing was withheld before it was ever written. Omission is a structural
limit of any ledger and is disclosed openly, recording refused attempts narrows it, nothing
closes it.

Say "the same class of cryptographic guarantee", never "legally guaranteed".

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `curl` hangs or times out | Windows Firewall blocked the port | Re-run `node.py`, click **Allow** on the prompt, tick Private |
| Connection refused | node not running, or wrong IP | Check `node.py` is still in the foreground; re-check `ipconfig` |
| Works one way only | client isolation on the access point | Switch to a phone hotspot |
| `ModuleNotFoundError` | deps missing | `pip install fastapi uvicorn cryptography` |
| IP changed since yesterday | DHCP lease renewed | Re-run `ipconfig`, use the new address |

Keep `node.py` running in its own terminal window for the whole demo. Closing that window
stops the witness, and the operator tool will then **block** rather than silently downgrade , 
which is correct behaviour, but not what you want mid-demo.
