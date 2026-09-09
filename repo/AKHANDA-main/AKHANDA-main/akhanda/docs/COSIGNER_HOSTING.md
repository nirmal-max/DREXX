# Where the co-signer can actually run

The whole design rests on one sentence in `src/witness/node.py`:

> Holds the concurring party key, **which the workstation never sees.**

That sentence is either true or the project's central claim is decoration. This document
records what was measured on the development machine, not what was assumed.

---

## Measured: WSL2 provides no key-custody boundary at all

Kali WSL2 on `D:\WSL\kali-linux`, `DefaultUid=0`. Every command below ran as the ordinary
desktop user `gareeb-ka-pc\pulki`, **not elevated** (`IsElevated: False`).

**1. Linux permissions work, inside Linux.**

```
-rw------- 1 root root 39 /root/.akhanda-witness/concur_key.pem
$ su witnesstest -c 'cat /root/.akhanda-witness/concur_key.pem'
cat: /root/.akhanda-witness/concur_key.pem: Permission denied
```

**2. And are irrelevant from Windows.**

```
PS> whoami
gareeb-ka-pc\pulki
PS> Get-Content \\wsl.localhost\kali-linux\root\.akhanda-witness\concur_key.pem
WITNESS-PRIVATE-KEY-DO-NOT-EXFILTRATE-
```

**3. Write access too, which is the one that breaks the demo.**

```
PS> Set-Content $log '{"witness_head_hash":"FORGED-TO-MATCH-REWRITTEN-CHAIN"}'
WRITE SUCCEEDED
$ cat /root/.akhanda-witness/witness_log.jsonl
{"witness_head_hash":"FORGED-TO-MATCH-REWRITTEN-CHAIN"}
```

**4. No filesystem needed anyway, the escalation is a documented feature.**

```
PS> wsl -d kali-linux --user root --exec id
uid=0(root) gid=0(root) groups=0(root)
PS> wsl -d kali-linux --user root --exec cat /etc/shadow
root:*:20636:0:99999:7:::
```

Still works with the root account locked (`passwd -l root` → `root L`). Microsoft's own
enterprise guidance states that controlling which Linux user a Windows user may become is
**currently unsupported**.

**5. And the disk image is just a file.**

```
PS> [IO.File]::Open("D:\WSL\kali-linux\ext4.vhdx",'Open','ReadWrite')
OPENED READ-WRITE by non-elevated user (1218 MB)
PS> Copy-Item ... ; COPIED (1218 MB)
ACL: NT AUTHORITY\Authenticated Users  Modify, Synchronize  Allow
```

### What this means for the architecture

`compare_witness_head()` catches a full-chain rewrite, Act 3 of the demo, **because the
operator cannot write to the witness's independent head record.** If the witness runs in
WSL2, they can, with one `Set-Content`. The detection does not degrade; it stops working.

So: **WSL2 is a fine place to develop and rehearse. It is not a co-signer.** Presenting it
as one is precisely the overclaim this project exists to refuse.

---

## The options, ranked by the boundary they actually provide

| Option | Key readable by the Windows operator? | Head log forgeable? | Honest claim |
|---|---|---|---|
| **Separate physical machine** (Pi Zero 2W on the LAN) | No, requires network compromise or physical access | No | "A second party on a machine the workstation cannot write to" |
| **Hyper-V VM, separate Windows account owns the VHDX** | Not live; the VHDX can be mounted offline by an admin | Only via offline VHDX edit, which is detectable and slow | "Dual control across administrative domains on one host" |
| **Hyper-V VM, same account** | VHDX is a file the account owns | Yes, offline | "Process isolation." Not custody. |
| **WSL2** | **Yes, trivially, unelevated, live** | **Yes, one command** | None. Do not claim a boundary here. |

### The mitigation that works regardless of host

Derive the concurring key from a passphrase at node start and **never persist it**:

- Reading the filesystem yields nothing, because the key is not on it.
- The operator must know the expert's passphrase to forge a co-signature, which is what
  "two parties" was supposed to mean in the first place.
- It survives the VHDX being copied.
- Cost: the node cannot restart unattended. For a forensic co-signer that is a feature.

This does **not** rescue the head log, an attacker who cannot forge signatures can still
delete the record on WSL2. Combine with publishing the head (`GET /witness/head`) to
somewhere the operator does not control, or accept the physical machine.

---

## Recommendation

1. **For the demo and the pitch: use the physical Pi.** It is the only option where the
   sentence at the top of this document is true without qualification.
2. **If the Pi fails on the day**, fall back to a Hyper-V guest owned by a second Windows
   account, and say *"dual control across administrative domains"*, never *"physically
   separate"*.
3. **Never present WSL2 as the co-signer.** If asked why, the answer above is a strength:
   we measured our own claim and found it false, so we changed the claim.

---

## Correction recorded: VT-x was never disabled

`Win32_Processor.VirtualizationFirmwareEnabled: False` on this machine reads as "VT-x off
in BIOS". It is not.

```
HypervisorPresent            : True
DeviceGuard VBS status       : 2  (running)
systeminfo: "A hypervisor has been detected. Features required for Hyper-V
             will not be displayed."
```

Hyper-V and VBS already hold VMX root, so Windows reports the CPU flags as `False` from
inside the guest it is now running in. **VT-x is enabled.**

Consequence: **KVM is Linux-host only and is not the right answer on this machine.** The
co-signer VM here is a Hyper-V guest or WSL2, and per the measurements above, only one of
those two is a co-signer at all.

Hardware note: this is a 2-core / 4-thread i3-1115G4 with 19.8 GB RAM. Memory is ample;
**cores are the constraint** for running host plus guests during a live demo.
