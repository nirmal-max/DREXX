# Samsung Galaxy Note 10+, device analysis

**Probed:** 1 September 2026 · read-only · `probe_device.ps1`
**Verdict:** `MTP_ONLY_NO_BLOCK_DEVICE`
**Usable as an AKHANDA target:** **No.** Reasoning below, with the alternative that is.

---

## What was and was not done

| | |
|---|---|
| **Written to the device** | **Nothing.** Not a byte, under any flag. |
| **Owner's files enumerated** | **No.** The device reports itself as belonging to a named person. USB topology answers the question; their photographs do not. |
| **Backup taken** | **No**, as instructed, and consistent with the above. |

Everything captured is device topology the phone broadcasts to any host it is plugged into.

---

## What is attached

```
[WPD  ] Karthikeyan's Note10+
        USB\VID_04E8&PID_6860&MS_COMP_MTP&SAMSUNG_ANDROID\...
[Modem] SAMSUNG Mobile USB Modem
[USB  ] SAMSUNG Mobile USB Composite Device   serial RF8M832R4DE
[USB  ] SAMSUNG Mobile USB Connectivity Device V2
```

- **VID 04E8** = Samsung · **PID 6860** = the Android composite (MTP + ADB + modem)
- **`MS_COMP_MTP`** in the compatible ID, Windows matched it as an MTP device
- **Class WPD**, Windows Portable Devices
- **USB serial `RF8M832R4DE`**, the real device serial, from the USB descriptor

The phone is **alive and enumerating correctly.** The water damage has not affected the USB
stack, the storage controller, or the descriptors. That is a genuinely useful thing to know
and it is not what stops us.

---

## The finding

```
Win32_DiskDrive count: 1
disk 0   NVMe INTEL SSDPEKNW512GZL   SCSI   512,105,932,800 bytes
```

**Only the laptop's own NVMe. The phone exposes no block device.**

There is no `\\.\PhysicalDrive1`. There is no LBA space to address.

### Why, precisely

**MTP is a file-transfer protocol, not a storage protocol.** The phone answers requests for
*named objects*, "give me DCIM/Camera/IMG_0421.jpg", and never exposes sectors. A USB
mass-storage device says *"I am 256 GB of blocks, here is block 0."* An MTP device says
*"I have a file called that, here are its bytes."*

So nothing host-side can address a sector on it. **Not AKHANDA, not FTK, not dd, not
EnCase.** This is a property of the transport, not a limitation of any tool, and stating it
that way matters, because "our tool cannot" and "no tool can over this transport" are
different sentences and only the second is true.

> Android has not offered USB Mass Storage since **Android 4.0 (2011)**. Every modern phone
> is MTP or nothing, precisely so the host cannot get block access to a mounted filesystem.

---

## What block access would actually require

Each of these was considered and rejected, with the reason.

| Route | Why not |
|---|---|
| **ADB + root** | Requires unlocking the bootloader. On Samsung that **wipes userdata**, destroying the evidence to reach it, and permanently trips the **Knox** e-fuse. |
| **EDL / Qualcomm 9008** | Needs a signed **Firehose programmer**, issued by the OEM and not public. Note 10+ variants are Exynos or Snapdragon; neither has a public authenticated loader. |
| **Odin / Download mode** | Flashes *to* the device. It is a write path, not a read path. |
| **Chip-off (UFS reball)** | Physical, destructive, needs a rework station and a UFS reader. Out of scope for a software tool. |

### And even with raw access, the data is encrypted

The Note 10+ ships **Android 9+ with File-Based Encryption**. Per-file keys are wrapped by
keys held in the **TEE/Keymaster**, bound to the user's screen-lock credential and to the
hardware. A raw UFS image without the PIN is **ciphertext**.

This is worth stating in the project's own honest-limits register: **AKHANDA is a
host-side, software-only tool. Modern mobile devices are outside its reach by design, not by
oversight.**

---

## Why this is a useful result

It is a *measured* boundary rather than an assumed one, and it maps onto the problem
statement.

SIH26149 asks for erasure and recovery on **HDDs, SSDs, USB drives, memory cards and
external storage**, all block devices. It does not ask for mobile forensics, which is a
separate discipline (Cellebrite, Oxygen, Magnet) built on exploit chains and hardware
interfaces rather than a block-device model.

**The right sentence for a judge who asks about phones:**

> *"Mobile is a different evidence class. A phone in MTP mode exposes named objects, not
> sectors, no host-side tool can image or erase it at block level, ours included. We
> measured that on a real Note 10+ rather than assuming it. Our scope is block storage,
> which is what the problem statement names."*

That is a stronger answer than silence, and much stronger than a claim that would collapse
the moment someone plugged a phone in.

---

## If the phone is genuinely being disposed of

The owner is discarding it. If sanitisation is actually wanted, the correct method is the
one built into the device:

**Settings → General management → Reset → Factory data reset.**

On an FBE device this performs a **cryptographic erase**: the Keymaster key material is
destroyed, so every per-file key becomes unrecoverable and the ciphertext on the UFS is
inert. That is a genuine NIST **Purge**-class outcome, stronger than anything an overwrite
could achieve through a host interface, and it is the manufacturer's own path.

**AKHANDA should not be pointed at this device, and could not be even if it should.**

---

## Files

```
validation/device_note10/
├─ probe_device.ps1                       read-only probe; writes nothing
├─ ANALYSIS.md                            this document
├─ logs/probe-<timestamp>.log             human-readable transcript
└─ evidence/device_probe-<timestamp>.json machine-readable record
```

Re-runnable at any time. Each run writes a new timestamped log rather than overwriting the
last, so a second probe after a state change is comparable against the first.
