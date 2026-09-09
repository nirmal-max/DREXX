# The container, and what it deliberately refuses

```bash
docker build -t akhanda .
docker run --rm -v "$PWD/evidence:/work" akhanda verify /work/chain.json
```

## Scope

**It runs** the parts that are pure computation over bytes you hand it:

| Command | Does |
|---|---|
| `verify <chain.json>` | verifies in **Python and Rust**, prints both exit codes |
| `carve <image>` | carves a disk image into artefacts |
| `certify <chain.json>` | produces the NIST + BSA certificate |
| `test` | the full suite, so "it passes on my machine" stops being the claim |
| `shell` | a shell inside the image |

**It refuses** two things, by design rather than omission:

## Why it will not run the witness

The witness exists to be a **second principal**, a party the operator cannot impersonate.
A container shares the host kernel and is administered by whoever administers the host. A
containerised witness on the operator's machine is the same machine wearing a costume: the
operator can read its memory, its filesystem, and therefore its key.

Running it there would not weaken the guarantee slightly. It would make the separation
claim **false while still printing `WITNESS_COSIGNED`**, precisely the overclaim this
project exists to prevent.

The witness runs on a different physical machine, under a different person's control. See
`../witness/SETUP.md`.

## Why it will not erase devices

A containerised device wipe is a privileged write to the host's real hardware wearing the
costume of a sandbox. It would require `--privileged` and `/dev` access, at which point
the container provides no isolation while *appearing* to.

Erasure runs on the host, behind its six gates, where the operator can see exactly which
device is named.

## What the container is genuinely good for

**Handing a sceptic a verification they do not have to trust you for.** It has no network,
no host mounts beyond the volume you name, and runs as an unprivileged user with no
package manager left behind.

`verify` runs both implementations on the same file and prints both exit codes, because
**disagreement between them is the single most useful signal this container can
produce**, so it is the default, not an option. Two implementations by one author can
share a misreading of a spec; two that disagree have found something.
