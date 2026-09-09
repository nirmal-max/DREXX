# Hosting, deployment, and real usage

The honest starting point, because it shapes everything below:

> **Akhanda is not a web service, and most of it must never be hosted.**

It is a forensic tool that erases disks and holds signing keys. Three of its four parts
are *deliberately* local-only. Putting them on the internet would not be a deployment , 
it would be a vulnerability. What *can* be hosted is the read-only viewer.

---

## 1. What runs where

| Part | Where it runs | Public internet? | Why |
|---|---|---|---|
| **CLI / erasure engine** | operator's machine only | **Never** | It writes to raw block devices. A network-reachable disk eraser is a remote-wipe weapon |
| **Witness node** | the second party's machine, on a private LAN | **Never** | Holds the co-signing key. Exposing it lets anyone request signatures |
| **Console / viewer** | anywhere, it is static | **Yes, safe** | Read-only. It verifies a chain in the browser and holds no key |
| **Certificate output** | a file you hand over | n/a | JSON and text, no runtime |

**The one-sentence version:** host the viewer, never the tool.

---

## 2. Demo-day deployment (what you actually do tomorrow)

Two machines and a phone hotspot. No internet, no cloud, nothing to fail on venue Wi-Fi.

```
   OPERATOR LAPTOP                          WITNESS LAPTOP
   192.168.137.1                            192.168.137.132
   ├── the CLI + chain                      └── witness/node.py
   └── console-app/index.html                   (its own signing key)
            │                                        ▲
            └────── hotspot, entry hash ─────────────┘
                    co-signature returns
```

**Why a hotspot and not campus Wi-Fi:** many access points enable *client isolation*,
which blocks laptop-to-laptop traffic while both still have internet. A phone hotspot or
Windows Mobile Hotspot allows client-to-client. Test the link before the day, not on it.

Serving the console locally:

```bash
cd "console-app"
python -m http.server 8080      # then open http://localhost:8080
```

It also opens fine as a plain `file://`, it embeds its data and needs no server.

---

## 3. Hosting the viewer publicly

The console is a single static HTML file with its data embedded, so any static host works
and there is no backend to deploy.

| Option | Command | Notes |
|---|---|---|
| **Local** (safest for a demo) | `python -m http.server 8080` | No network dependency, recommended for judging |
| **GitHub Pages** | push `console-app/` to a `gh-pages` branch | Free, public URL |
| **Vercel / Netlify** | drag the folder onto their dashboard | Zero config for static files |

Whichever you choose, **the demo should not depend on it.** Have the local copy open in a
second browser tab.

> **Before publishing:** the console embeds a real chain. That is fine, a chain is
> designed to be shown; it contains hashes and public key ids, never private keys. But if
> you ever swap in a chain from real case work, the `target_ref` fields carry file paths.
> Check what you are publishing.

---

## 4. Real usage, a forensic lab

This is the deployment that matters after the hackathon.

### Topology

```
Evidence workstation (air-gapped or on an isolated VLAN)
  └── Akhanda CLI, operator key
        │  private LAN only
        ▼
Witness machine (different person's login, different physical box)
  └── witness node, co-signing key

Optional, outbound only:
  OpenTimestamps anchoring, the ONLY step needing internet, and it is optional
```

### The rules that make it real rather than theatre

1. **Two people, two machines.** If the same person controls both, the second signature
   proves nothing. The witness must be someone who can refuse.
2. **The witness is never on the internet.** A private LAN or a direct cable. It answers
   only the operator workstation.
3. **The evidence workstation does not browse.** Air-gapped, or an isolated VLAN with no
   general egress.
4. **Anchoring is the one outbound step,** and it is optional. An unanchored chain is
   reported as unanchored, never as anchored.
5. **Key custody is a procedure, not a setting.** Keys are files on disk today, set
   `AKHANDA_KEY_PASSPHRASE` to encrypt the operator key at rest, and put the witness
   machine under separate administrative control.

### Installing on a lab machine

```bash
pip install -r akhanda/requirements.txt
cargo build --release --manifest-path akhanda/rust/akhanda-verify/Cargo.toml
```

The Rust verifier is worth building everywhere: it reads a chain with **no network, no
config, and no environment**, which makes it the right tool to hand a third party who
should not have to trust your Python.

---

## 5. Containers, what the image will and will not do

A Dockerfile ships with the source. Its scope is deliberately narrow:

**It runs:** `verify`, `carve`, `certify`, `test`
**It refuses:** device erasure, and the witness node

Both refusals are by design, not omission:

- A container **shares the host kernel**, so a containerised witness is not a second
  principal. It is the same machine wearing a costume, and the separation claim would be
  false.
- A containerised device wipe is a privileged write to the host's real hardware.

```bash
docker build -t akhanda akhanda/
docker run --rm -v "$PWD/demo-data:/work" akhanda verify /work/chain.json
```

Verification runs **both** implementations on the same file and prints both exit codes.
Disagreement between them is the most useful signal the container can produce, so it is
the default behaviour rather than an option.

---

## 6. What is deliberately not built

Stated so nobody discovers it during a demo and assumes it was hidden.

| Missing | Status |
|---|---|
| Installer / packaged binary | Not built. Runs from source via Python + Cargo |
| Multi-user access control | Out of scope. Anyone who can run the CLI can run it |
| Central case server | Not built, and not obviously desirable, centralising evidence adds a single point of compromise |
| Hosted SaaS | Deliberately not. See section 1 |
| Presence device | **Designed, not shipped.** Which is why `FULL_CUSTODY` is never printed |
| Signed release artifacts | Not built. Verify by running the suite from a clean checkout |

---

## 7. Pre-demo checklist

Run this the night before, not the morning of.

```bash
# 1. the suite, from this folder
cd akhanda && set PYTHONPATH=src && python -m pytest tests/ -q

# 2. the independent verifier builds
cargo build --release --manifest-path rust/akhanda-verify/Cargo.toml

# 3. the witness answers, from the OPERATOR machine
curl http://<witness-ip>:8000/witness/pubkey

# 4. the key ids differ, this is the separation proof
#    a matching key id would mean both signatures came from one machine

# 5. the console opens and verifies green
```

If step 3 fails, it is almost always the witness machine's firewall refusing inbound 8000,
or client isolation on the access point. Both are covered in `witness/SETUP.md`.
