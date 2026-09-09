# Hardening pass, real scans, triaged findings

Tools: `bandit -r src/` (PyCQA, CWE-mapped) and `pip-audit` (PyPA, OSV + PyPI advisories).
Raw output in `evidence/bandit.json` and `evidence/pip_audit.json`.

---

## pip-audit, read the closure, not the machine

The first run reported **115 vulnerabilities in 19 packages**. Quoting that number would
have been alarmist and wrong: `transformers`, `nltk`, `gitpython`, `pdfminer-six`,
`fonttools` and most of the rest are other projects on this workstation, not AKHANDA
dependencies. A global audit on a dev machine measures the machine, the same lesson as
the benchmark that "showed" the carver degrading.

Audited against AKHANDA's declared closure instead:

| Package | Version | Vulnerabilities |
|---|---|---|
| cryptography | 50.0.0 | 0 |
| fastapi | 0.141.1 | 0 |
| starlette | 1.6.0 | 0 |
| uvicorn | 0.52.4 | 0 |
| pydantic | 2.13.4 | 0 |
| pyserial | 3.5 | 0 |
| pytest | 9.0.3 | 0 |
| **Pillow** | **11.1.0** | **24** |

**Pillow was the one that mattered, and it mattered specifically.** It is the decoder used
to confirm a carved or reassembled file parses, which means it is fed
**attacker-controlled bytes taken from a forensic disk image**. That is precisely the
threat model those 24 CVEs describe: a malformed image reaching a parser bug. A crafted
image planted on seized media could have targeted the tool examining it.

→ **Upgraded to Pillow 12.3.0.** Decoder paths re-run and green.

---

## bandit, 0 HIGH, 3 MEDIUM, 13 LOW over 5,164 lines

### Fixed, because they were real

**B310, `urlopen` accepts any scheme (`witness/client.py`).** The one that mattered.
`urlopen` honours every scheme urllib knows, `file://` included, and the witness URL is
*configuration*, a CLI flag, an environment variable, a saved profile. Pointed at
`file:///path/to/anything`, the client would read a local file and hand it back as a
witness response. The operator could then supply their own co-signature record from a file
they wrote, and **the "independent second party" would be a path on their own disk**, the
exact failure the witness exists to prevent, reached through the transport rather than the
crypto.

Fixed with an allowlist (`http`, `https` only) checked *before* `urlopen` sees the URL,
plus a host check, because a witness with no host is not a second machine.

**B101, `assert` in the witness key loader (`witness/node.py`).** Python run with `-O`
strips asserts, and this one was the only thing between a wrong key file and a witness
signing with it. A check that disappears under an optimisation flag is not a check.
Now a `TypeError` that refuses to start. A sweep test asserts no security-path module
relies on `assert` anywhere.

**B607, bare `stat` on macOS (`erasure/file_eraser.py`).** Resolved through `PATH`, so
anything earlier on `PATH` answers instead, and that answer decides whether an erasure is
recorded `VERIFIED` or `PARTIAL`. Not a decision to delegate to the environment on a
forensic workstation. Now an absolute path, existence-checked, falling back to `unknown`
(which downgrades the outcome honestly).

### Triaged and kept visible, deliberately *not* suppressed

No `# nosec` comments were added. A suppression makes a finding vanish from every future
scan, which is how a real one ends up buried next to an accepted one. Both remain in the
report and are pinned in `test_the_medium_findings_are_the_ones_already_triaged`, so a
**new** medium finding fails the build instead of blending into a count someone once
decided was acceptable.

| Finding | Why it stays |
|---|---|
| **B104**, binds `0.0.0.0` (`witness/node.py`) | The point of the node: the witness must be reachable from a *different* machine. Now configurable via `AKHANDA_WITNESS_HOST`, defaulting to reachable because a witness nobody can reach silently degrades every operation to `SOFTWARE_KEY`. |
| **B310**, `urlopen` (`witness/client.py`) | Mitigated by `_check_url`; bandit cannot see the guard. Proven by `test_a_non_http_witness_url_is_refused`. |

### Noise, recorded with the reason

| Finding | Why it is not a finding |
|---|---|
| B105 ×3, "hardcoded password" | `AKHANDA_KEY_PASSPHRASE` is an environment-variable *name*; `I-UNDERSTAND-THIS-DESTROYS-DATA` is a confirm token that is meant to be public, it exists to make an action deliberate, not to be secret. |
| B404/B603 ×5, subprocess import and calls | `hdparm`, `nvme`, `ots`. Every argv is built from module constants, never from caller input, and no call uses a shell. A test asserts `shell=True` appears nowhere in `src/`. |

---

## Gates now in CI

* `bandit` **HIGH** severity → build fails.
* A **new** MEDIUM finding → build fails (the two known ones are pinned with reasons).
* `assert` in any security-path module → build fails.
* `shell=True` anywhere in `src/` → build fails.

## Not done

* **`cargo audit`** on the Rust verifier, not run. It has two dependencies
  (`ed25519-dalek`, `sha2`) and `#![forbid(unsafe_code)]` on both crate roots, but "small
  and unsafe-free" is an argument, not an audit.
* **SLSA provenance / reproducible builds**, `tool_ref` already records *which* build
  produced an entry, which is the prerequisite. Reproducing that build byte-for-byte from
  source is a separate claim and is not made.
