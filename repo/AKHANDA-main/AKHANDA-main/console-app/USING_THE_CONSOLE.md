# Using the console with laptop B

## First, the thing that trips everyone up

**The console does not fetch files from laptop B. Laptop B has no case files on it.**

That is not a missing feature, it is the security property the whole design rests on.
Laptop B exists to hold **one signing key** and answer **four questions**. If it also
served files, an attacker who reached it would get both the evidence and the key that
vouches for it.

| Machine | Holds | Serves |
|---|---|---|
| **Laptop A**, operator (this one, `192.168.137.1`) | the repo, the operator key, `chain.json`, certificates, carved files | nothing |
| **Laptop B**, witness (LOQ, `192.168.137.132`) | its own signing key, its own witness log | four read-only endpoints |

Everything you open in the console lives **on laptop A**. Pressing **Connect** does not
download anything, it asks laptop B "are you alive, and which key are you?" and compares
the answer against the chain you loaded.

---

## What laptop B actually exposes

```
GET  /witness/pubkey   the key id and public key, proves WHICH witness this is
GET  /witness/head     its own head hash, seq and record count
GET  /witness/log      the entry hashes it has co-signed
POST /witness/cosign   the only write: sign one entry hash
```

No file listing. No directory access. No way to pull a document off it.

---

## The run order, do it in exactly this sequence

### 1. On laptop B, start the witness and leave it running

```powershell
cd E:\witness_node_for_laptop_b      # or wherever you copied it
python node.py
```

You must see, and then **leave this window open**:

```
witness node on 0.0.0.0:8000
INFO:     Application startup complete.
```

> **Closing that window stops the witness.** The tool will then BLOCK operations rather
> than silently downgrade them, correct behaviour, but not what you want mid-demo.
> If the console says "unreachable" and the network is fine, this window is the first
> thing to check.

### 2. On laptop B, get its address

```powershell
ipconfig | findstr /i "IPv4"
```

On your hotspot it will be `192.168.137.x`. Give that to laptop A.

### 3. On laptop A, confirm the link before doing anything else

```bash
curl http://192.168.137.132:8000/witness/pubkey
```

Expected:

```json
{"pubkey_hex":"f9229f5c...","key_id":"0b1088f7140ef514"}
```

Nothing back means either `node.py` is not running, or laptop B's firewall is blocking
inbound 8000.

### 4. On laptop A, run the operations. This is what creates the files

```bash
cd "D:\akhanda SIH\akhanda"
python scripts/demo_bundle.py --witness http://192.168.137.132:8000
```

Roughly five seconds. It writes into `D:\akhanda SIH\akhanda\demo_bundle\`:

| File | What it is | Console view |
|---|---|---|
| **`chain.json`** | the ledger, **this is the file you open in the console** | Ledger |
| `chain_tampered.json` | a deliberately altered copy | Integrity |
| `certificate.json` / `.txt` | the NIST + BSA certificate | Certificate |
| `byte_identical_proof.json` | original vs carved SHA-256, per file | Evidence |
| `recover_result.json` | every artefact carved, with truncation flags |, |
| `erase_result.json` | the secure file erase result |, |
| `MANIFEST.json` | which steps ran, and which failed |, |
| `recovered/` | the carved files themselves |, |

`_akhanda_home/` in that folder holds the **operator private key**. Never share it, never
commit it, never put it on a USB you hand someone.

### 5. On laptop A, open the console and load the file

```bash
cd "D:\akhanda SIH\console-app"
python -m http.server 8080
```

Then at `http://localhost:8080`:

1. **Open chain.json** (or drag the file anywhere onto the page) → point at
   `D:\akhanda SIH\akhanda\demo_bundle\chain.json`
2. The status strip fills in and Integrity goes **green**, the browser recomputed every
   hash itself.
3. Put laptop B's URL in the witness box and press **Connect**.

### 6. What "Connect" tells you, and why it matters

On success the log records the live key id, and then does the check that matters:

```
witness  CONNECTED key_id=0b1088f7140ef514 seq=0 records=1
match    live witness holds the key that co-signed seq 0
```

That `match` line is the demo. It says the key answering on the other laptop is the same
key that signed entry 0 in the file you just opened, **so the second signature could not
have been made on this machine.**

If the ids differ it says so instead, which is equally honest: a different witness, or a
chain from a different run.

---

## Demonstrating it, the three-minute version

1. **Ledger.** Three entries. Point at row 2: `REFUSED`, `NotPerformed`. *"That is an
   operation that did not happen, recorded permanently. Ask any other tool to show you the
   log entry for an operation it declined to perform."*
2. **Connect.** Show the `match` line. *"The key that signed entry 0 lives on that laptop,
   not this one."*
3. **Integrity → Alter selected entry.** It turns red and names **seq 1**. *"The tool does
   not say 'invalid'. It says which record, and every record after it also fails, because
   each commits to the hash of the one before."*
4. **Restore.** Green again.
5. **Evidence.** Original and carved SHA-256, side by side, identical. *"Byte-identical, or
   we do not claim recovery at all."*

Open DevTools if anyone doubts it, `crypto.subtle.digest` runs in front of them. No
server is asked for a verdict.

---

## When it does not work

| Symptom | Cause | Fix |
|---|---|---|
| Console says **unreachable**, network is fine | `node.py` window was closed on laptop B | restart it, leave it open |
| `curl` hangs or times out | laptop B firewall blocking inbound 8000 | rerun `node.py`, click **Allow**, tick **Private**; or add the rule below |
| Works one direction only | client isolation on the access point | use a phone hotspot or Windows Mobile Hotspot, not campus Wi-Fi |
| Console loads but shows **no witness** on entries | the run used `--no-witness` | re-run `demo_bundle.py` with `--witness` |
| IP changed since yesterday | DHCP lease renewed | re-check `ipconfig` on laptop B |
| Hosted page cannot connect | a page on the internet cannot reach your LAN | run the console locally, this is expected, not a bug |

Firewall rule, in an **elevated** PowerShell on laptop B:

```powershell
New-NetFirewallRule -DisplayName "Akhanda witness 8000" -Direction Inbound `
  -LocalPort 8000 -Protocol TCP -Action Allow
```

---

## Before you present

```
[ ] node.py running on laptop B, window left open
[ ] curl to /witness/pubkey returns a key id from laptop A
[ ] demo_bundle.py run WITH --witness, so an entry is co-signed
[ ] console open at localhost:8080, chain.json loaded, Integrity green
[ ] Connect pressed, "match" line visible in the log
[ ] tamper and restore rehearsed once
```

Both laptops on **one hotspot you control**, and one power strip, the venue gives one
socket per team.
