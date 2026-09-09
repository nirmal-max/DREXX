# Run it, the commands, in order

Everything here has been run and its output checked. Commands are Windows-first; the
Linux/macOS difference is only `export PYTHONPATH=src` instead of `set PYTHONPATH=src`.

---

## 0. One-time setup

```bash
cd "D:\akhanda SIH\akhanda"
pip install -r requirements.txt
```

Optional but worth doing, it recovers 9 otherwise-skipped tests and gives you the
independent verifier:

```bash
cargo build --release --manifest-path rust/akhanda-verify/Cargo.toml
```

---

## 1. Prove the build is sound

```bash
set PYTHONPATH=src
python -m pytest tests/ -q
```

**Expected in this package: 630 collected, 630 passed, 0 skipped, 0 failed.**

Measured on this exact folder. The test corpora (`tests/data/`, `corpus/`,
`research/reference/*.docx`) are included, so **nothing skips and no test file is left
unexercised**, including fragment reassembly, NIST CFReDS recovery, and the
three-implementation canary.

If you move this package somewhere without those corpora, tests will skip rather than
fail, and each will say exactly what it could not check:

| If missing | Skips | Effect |
|---|---:|---|
| `tests/data/` (NIST CFReDS, 312 MB) | 34 | recovery + reassembly unverified |
| `research/reference/*.docx` (1.2 MB) | 16 | ZIP/document reassembly unverified |
| Rust build | 9 | **three-implementation agreement NOT checked** |
| `corpus/` | 2 | regression corpus unverified |

They say *"was NOT checked"* rather than passing quietly. A skipped test is never counted
as a passing one anywhere in this project.

Full automation, 11 checks including the three-implementation canary and a security scan:

```bash
python scripts/run_all.py
```

---

## 2. Start the second party, on the WITNESS laptop

Copy the `witness/` folder to the other machine. It needs **one file and three packages**;
the project source is not required there.

```bash
pip install fastapi uvicorn cryptography
python node.py
```

Click **Allow** on the Windows firewall prompt and tick **Private networks**, missing
that prompt is the most common failure. Then find its address:

```bash
ipconfig | findstr /i "IPv4"
```

The node generates **its own signing key on first run**. That key never leaves that
machine, which is the entire basis of the separation claim.

---

## 3. Confirm the link, from the OPERATOR laptop

```bash
curl http://<witness-ip>:8000/witness/pubkey
```

You want JSON back with a `key_id`. **Check that key id differs from any witness key on
this machine**, if they match, both signatures came from one box and the claim is void.

---

## 4. Run the operations

```bash
cd "D:\akhanda SIH\akhanda"
python scripts/demo_bundle.py --witness http://<witness-ip>:8000
```

Five real operations in about five seconds:

| Step | What it proves |
|---|---|
| Carves 4 real files from a disk image | recovery is **byte-identical**, hash for hash |
| Securely erases 3 files, verifies the overwrite | problem statement module (b), real filesystem |
| Attempts an operation with the witness unreachable | it is **blocked**, and the refusal is written to the chain |
| Issues the NIST + BSA certificate | every field carries its clause reference |
| Alters one entry and re-verifies | verification fails and **names the sequence number** |

A failed step is recorded as failed in `MANIFEST.json`. It is never dropped or replaced
with something that looks fine.

Without a witness, use `--no-witness`-equivalent by simply omitting the flag:

```bash
python scripts/demo_bundle.py
```

Entries then record `SOFTWARE_KEY`, honest, and visibly weaker.

---

## 5. Show it

```bash
cd "D:\akhanda SIH\console-app"
python -m http.server 8080        # http://localhost:8080
```

Four views: **Ledger**, **Integrity**, **Certificate**, **Evidence**.

The Integrity view is the one to demonstrate. It re-implements the length-prefixed
encoding and SHA-256 **in the browser** and recomputes every hash, it does not ask a
backend whether the chain is valid. Press *Alter selected entry*, and it breaks and names
the sequence.

---

## 6. Verify a chain independently

The check to hand a sceptic, because it shares no code with the Python:

```bash
akhanda-verify demo-data/chain.json
# exit 0 verified · 1 broken · 2 usage
```

No network, no config, no environment variables.

---

## Individual commands

```bash
python src/cli.py --help                                    # entry point
python src/cli.py --no-witness show                         # print the chain
python src/cli.py --no-witness verify                       # verify + witness compare
python src/cli.py --no-witness recover <image> --out out/   # carve an image
python src/cli.py --no-witness --operator "Name" --expert "Name" certify --out cert/
```

**Note:** it is `python src/cli.py`, not `python -m cli`.

### Erasing a real device

Guarded by six gates on purpose. It requires the confirm token, the environment switch,
**and** the exact device path in `AKHANDA_TARGET_DEVICE`, a typo reaches nothing. The
system disk is refused even when fully authorised.

```bash
set AKHANDA_ALLOW_DEVICE_WRITE=1
set AKHANDA_TARGET_DEVICE=\\.\PhysicalDriveN
python src/cli.py erase \\.\PhysicalDriveN --level Clear --confirm I-UNDERSTAND-THIS-DESTROYS-DATA
```

**This destroys data and cannot be undone.** Confirm the drive number twice, `Get-Disk`
in PowerShell shows which is which. Ask for `--level Purge` on a USB stick and the tool
will record **Clear**, because flash cannot reach Purge; that refusal to overclaim is the
point.
