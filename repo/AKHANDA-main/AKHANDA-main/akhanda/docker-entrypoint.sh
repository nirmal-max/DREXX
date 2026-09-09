#!/bin/sh
# Thin front door. Every subcommand here is read-only with respect to the host except
# where it writes into the volume you explicitly mounted.
set -e
CMD="${1:-help}"; shift 2>/dev/null || true

case "$CMD" in
  verify)
      # Both implementations, on the same file, in one command. Disagreement is the
      # single most useful signal this container can produce, so it is the default.
      CHAIN="${1:?usage: verify <chain.json> [--operator-key HEX]}"; shift
      echo "== python =="; python -m cli verify --chain "$CHAIN" "$@" || PY=$?
      echo; echo "== rust (independent implementation) =="
      akhanda-verify "$CHAIN" "$@" || RS=$?
      echo; echo "python exit=${PY:-0}  rust exit=${RS:-0}"
      [ "${PY:-0}" = "${RS:-0}" ] || { echo "IMPLEMENTATIONS DISAGREE - do not trust this chain"; exit 9; }
      exit "${PY:-0}" ;;
  rust)      exec akhanda-verify "$@" ;;
  carve)     exec python -m cli recover "$@" ;;
  certify)   exec python -m cli certify "$@" ;;
  cli)       exec python -m cli "$@" ;;
  test)      cd /app && exec python -m pytest "$@" ;;
  stress)    cd /app && exec python scripts/stress_forensic.py "$@" ;;
  shell)     exec /bin/sh ;;
  erase|erase-files)
      cat >&2 <<'EOF'
REFUSED: device and file erasure are not available in this container.

This is a deliberate boundary, not a missing feature. A container shares the host kernel,
so erasing from inside one requires --privileged and a passed-through device -- at which
point the write goes to the host's real hardware with none of the isolation the container
appears to provide. Worse, ATA Secure Erase and NVMe Sanitize (NIST Purge) are issued to
the drive's own firmware and cannot be meaningfully namespaced at all.

Run erasure on the host, where the guard rails are visible:
    AKHANDA_ALLOW_DEVICE_WRITE=1 python -m cli erase /dev/sdX --level Clear --confirm <token>
EOF
      exit 3 ;;
  witness)
      cat >&2 <<'EOF'
REFUSED: the witness co-signer must not run in a container on the operator's host.

The witness exists to be a SECOND PRINCIPAL the operator cannot impersonate. A container
on the operator's machine is not one: whoever can run `docker` is effectively root on the
host and can read the container's filesystem, its memory, and therefore its private key.
Containerising it would produce a system that LOOKS dual-signed while both signatures are
reachable by one person -- the precise failure this project is built to prevent.

Run the witness as a separate OS account, ideally on a second machine (LB-03).
EOF
      exit 3 ;;
  help|*)
      cat <<'EOF'
AKHANDA, verifier and recovery container

  verify <chain.json> [--operator-key HEX]   both implementations, disagreement = exit 9
  rust <chain.json> [...]                    the Rust verifier alone
  carve <image> [--out DIR]                  carve a disk image
  certify [...]                              generate the certificate
  cli [...]                                  any other CLI subcommand
  test [pytest args]                         the full suite
  stress                                     CFReDS stress run (needs tests/data)
  shell                                      a shell

NOT AVAILABLE HERE, ON PURPOSE:  erase, erase-files, witness   (run `... erase` for why)

  docker run --rm -v "$PWD:/work" akhanda verify /work/chain.json
EOF
      exit 0 ;;
esac
