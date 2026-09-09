# G2b, erasure on real media

Two paths, and **both** are required. They answer different questions and neither
substitutes for the other.

| | Question it answers | Repeatable? |
|---|---|---|
| **(a) Virtual block device** | Does the erasure path do the right thing, every time, on demand? | Yes, this is the demo |
| **(b) One real USB stick** | Does it do the right thing on hardware that reports its own geometry and lies about its own flash translation? | No, one stick, once |

The reason the virtual device is the *primary* demo and not the fallback: a stage demo
that depends on a specific physical stick enumerating correctly is a demo with a single
point of failure you cannot rehearse away. The real wipe is the evidence that the virtual
one is not a simulation of a simulation.

---

## (a) Virtual block device, the reproducible path

On Linux (WSL2 works; **`scsi_debug` needs a real kernel module, so prefer a Hyper-V
guest or a live USB if the WSL2 kernel has no module support**):

```bash
# 64 MB fake SCSI disk that behaves like a block device all the way down
sudo modprobe scsi_debug dev_size_mb=64
lsblk -o NAME,SIZE,MODEL | grep -i scsi_debug     # note the /dev/sdX it landed on

sudo AKHANDA_ALLOW_DEVICE_WRITE=1 python -m cli erase /dev/sdX \
     --level Clear --confirm "$(python -c 'import sys;sys.path.insert(0,"src");
                                from erasure.engine import CONFIRM_TOKEN;print(CONFIRM_TOKEN)')"
```

Loopback is the zero-privilege fallback and is honest about being weaker, it exercises
the write and read-back path but never touches a real block layer:

```bash
dd if=/dev/zero of=/tmp/fake.img bs=1M count=64
sudo losetup -fP --show /tmp/fake.img          # -> /dev/loopN
```

**Record in the log which of the three you used.** They are not equivalent, and saying
"we erased a block device" when it was a loopback file is exactly the overclaim rule 2
exists to prevent.

---

## (b) One real USB stick, the evidence run

**Do this once, deliberately, with the stick you are willing to lose.**

### Before

1. Put known, recognisable content on it, a handful of JPEGs and a text file with a
   phrase you can grep for. `AKHANDA-CANARY-<date>` works.
2. Image it first, so the "before" state is provable and the carve is repeatable:
   ```bash
   sudo dd if=/dev/sdX of=evidence/g2b_before.img bs=4M status=progress
   sha256sum evidence/g2b_before.img | tee evidence/g2b_before.sha256
   ```
3. Confirm the canary is findable in the image: `grep -c AKHANDA-CANARY evidence/g2b_before.img`

### The wipe

```bash
sudo AKHANDA_ALLOW_DEVICE_WRITE=1 python -m cli erase /dev/sdX --level Clear \
     --confirm <token> --witness http://<witness>:8000
```

### After, this is the part that is the evidence

```bash
sudo dd if=/dev/sdX of=evidence/g2b_after.img bs=4M status=progress
grep -c AKHANDA-CANARY evidence/g2b_after.img    # must be 0
python -m cli verify
python -m cli certify --out evidence/
```

Keep in `evidence/`: the two SHA-256 sums, the canary counts before and after, the chain,
the certificate, and the terminal transcript.

### The two things to check that are easy to skip

**Asking for Purge on flash must still record Clear.** Run it deliberately:

```bash
sudo AKHANDA_ALLOW_DEVICE_WRITE=1 python -m cli erase /dev/sdX --level Purge --confirm <token>
```

The entry's `method` must read **`Clear`**, not `Purge`. USB flash supports neither ATA
Secure Erase nor NVMe Sanitize, so Purge is unreachable and the tool must say so. If it
records `Purge`, that is a rule-2 violation and it blocks the demo, not a cosmetic bug.

**A failed read-back must not look like a clean wipe.** `outcome` is the 15th signed
field precisely so that a wipe whose verification sampling failed cannot present itself
as `VERIFIED`. Confirm the recorded `outcome` matches what actually happened.

---

## G9, bad sectors must be skipped, logged, and signed

A stick with unreadable sectors must **not** hang, and must **not** leave a silent gap.
Each skipped region becomes a record the entry commits to.

Build the fixture on Linux with `dm-flakey`, which returns I/O errors on a schedule:

```bash
# 64 MB backing file, errors for 2s out of every 4s window
size=$((64*1024*1024/512))
sudo dmsetup create flakey-test --table "0 $size flakey /dev/loopN 0 2 2"
```

The CI version does not need a kernel: a fixture image plus a monkeypatched read that
raises `OSError` on a chosen offset range reproduces the same code path deterministically.
Assert three things:

1. The operation **completes**, no hang, no unhandled exception.
2. The skipped ranges are **in the result record**, with offsets and lengths.
3. The `outcome` is **`PARTIAL`**, never `VERIFIED`. A wipe with unreadable regions is not
   a verified wipe, and the closed `OUTCOMES` vocabulary already has the honest word.

---

## Windows note

`\\.\PhysicalDriveN` is the device path, `diskpart` or `Get-Disk` finds the number, and
the shell must be **elevated**. There is no `dd`; use the imaging step from a Linux boot
or WSL2 with the disk attached via `wsl --mount`. If the imaging cannot be done, say in
the log that the before/after images are missing and why, an unimaged wipe is still a
wipe, but it is weaker evidence and should be labelled as such rather than written up as
if the images existed.
