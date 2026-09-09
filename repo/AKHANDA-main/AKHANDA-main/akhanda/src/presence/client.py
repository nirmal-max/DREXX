"""
Presence client, OWNER: lead. Talks to the ESP32 over USB serial.

Contract:
    request_presence(pre_hash, port=None, timeout_s=15.0)
        -> {"confirmed", "nonce", "device_id", "shown", "reason"}

STATUS: DESIGNED AND BUILT AGAINST AN ESP32 BUTTON, NOT VALIDATED ON HARDWARE (G19/G9).
The serial path below is real code, not a stub, but no entry in any chain has yet been
produced with a physical device attached. Say "designed" until one has. The intended
Phase 1 replacement is a WebAuthn/FIDO2 relying party whose assertion is bound to the
exact pre-hash; that is NOT implemented here and must not be described as if it were.

Proves a human was physically present at a separate device at signing time. It does NOT
prove the key is protected, the ESP32 is not a secure element (CVE-2019-17391 extracts
eFuse keys by voltage glitching, unpatchable on shipped silicon). Keep that distinction
in every description. docs/ENGINEERING_RULES.md section 6.

DEGRADATION IS THE FEATURE (docs/ENGINEERING_RULES.md rule 3). Every failure path here returns
confirmed=False with a reason. Nothing in this module raises. No device, wrong port,
pyserial missing, operator walked away, all of them are a lower custody tier recorded
honestly, never a crashed erasure.

Wire protocol (firmware/esp32/presence.ino):
    ->  "REQ <hash_prefix>\\n"
    <-  "WAITING <hash_prefix>"     immediately, device is armed
    <-  "CONFIRMED <hash_prefix>"   on physical button press
"""

from __future__ import annotations
import secrets
import time

try:
    import serial  # pyserial
    from serial.tools import list_ports
except ImportError:  # pragma: no cover - exercised on machines without pyserial
    serial = None
    list_ports = None

BAUD = 115200
PREFIX_LEN = 16  # how much of the entry hash is shown on the device


def _absent(reason: str) -> dict:
    return {"confirmed": False, "nonce": None, "device_id": None, "reason": reason}


# USB-serial bridges ESP32 dev boards actually ship with. Matching is by these, and
# ONLY by these.
KNOWN_BRIDGES = ("cp210", "ch340", "ch341", "ch910", "silicon labs", "silabs",
                 "esp32", "ftdi", "ft232")

# Ports that are serial-shaped but can never be a presence device. Discovered on real
# hardware: a laptop with paired Bluetooth peripherals enumerates six COM ports, and the
# old "first port wins" fallback selected a Bluetooth link as the presence device.
NEVER_PRESENCE = ("bluetooth", "bthenum", "bthmodem")


def find_device() -> str | None:
    """The ESP32's port, or None. Never a guess.

    THE FALLBACK WAS THE BUG. This used to end with `return ports[0].device`, on the
    reasoning that any serial port is better than none. It is not: a presence device must
    be a SPECIFIC device, and "any port will do" is exactly the wrong instinct for the one
    component whose job is proving a particular human touched a particular thing.

    Found on real hardware, not in a test, the development laptop has six Bluetooth
    virtual COM ports and zero ESP32s, and the old code confidently returned COM4. That
    made `policy.preflight()` report a presence device as AVAILABLE on a machine with no
    presence device attached, which is a false claim in the preflight that is supposed to
    stop false claims.
    """
    if list_ports is None:
        return None
    try:
        ports = list(list_ports.comports())
    except Exception:
        return None

    for p in ports:
        blob = f"{p.description} {p.manufacturer or ''} {p.hwid or ''}".lower()
        if any(bad in blob for bad in NEVER_PRESENCE):
            continue
        if any(k in blob for k in KNOWN_BRIDGES):
            return p.device
    return None


def request_presence(
    pre_hash: str,
    port: str | None = None,
    timeout_s: float = 15.0,
) -> dict:
    """Ask the ESP32 for a physical button confirmation. Degrades cleanly if absent.

    `pre_hash` is the entry's hash computed with `presence_ref` empty, see
    `Entry.pre_hash()`. It is the value the human is shown, and the value their press is
    bound to.

    WHY NOT THE FINAL ENTRY HASH. `presence_ref` is inside the signed preimage, so the
    final hash cannot exist until this call has already returned. That is a real
    circularity, not an oversight. The previous version dodged it by displaying a prefix
    of the *result* digest, a value that is never signed and that the human had no way to
    relate to the operation, while this module's own docstring claimed they were seeing
    the entry hash. A wrong comment is a lie a judge can read.

    The two-phase binding: the human confirms the pre-hash, the token records which
    pre-hash they confirmed, and the final entry hash then covers that token. Both values
    are recoverable from the stored entry, so `verify_presence_binding()` can check that
    the human approved *these* bytes rather than some others.
    """
    if serial is None:
        return _absent("pyserial not installed; recording SOFTWARE_KEY tier")

    port = port or find_device()
    if not port:
        return _absent("no serial device found; recording SOFTWARE_KEY tier")

    prefix = pre_hash[:PREFIX_LEN]
    nonce = secrets.token_hex(8)

    try:
        with serial.Serial(port, BAUD, timeout=1.0) as ser:
            time.sleep(2.0)          # ESP32 resets when the port opens; wait for boot
            ser.reset_input_buffer()
            ser.write(f"REQ {prefix}\n".encode("ascii"))
            ser.flush()

            deadline = time.monotonic() + timeout_s
            armed = False
            while time.monotonic() < deadline:
                raw = ser.readline()
                if not raw:
                    continue
                line = raw.decode("ascii", errors="replace").strip()
                if line.startswith("WAITING "):
                    armed = True
                elif line.startswith("CONFIRMED "):
                    got = line.split(" ", 1)[1].strip()
                    if got != prefix:
                        # The device confirmed a DIFFERENT operation. Never accept it:
                        # that would bind a human's press to bytes they did not see.
                        return _absent(
                            f"device confirmed a different prefix ({got!r}); rejected")
                    return {"confirmed": True, "nonce": nonce, "device_id": port,
                            "shown": prefix,
                            "reason": f"physical press confirmed against {prefix}"}

            return _absent(
                "device armed but no press within timeout" if armed
                else f"no response from {port} within {timeout_s:.0f}s")

    except Exception as exc:  # serial errors, permissions, unplug mid-read
        return _absent(f"serial error on {port}: {exc}")


def presence_ref(result: dict) -> str:
    """The signed representation of a presence result.

    Format: ``<device_id>:<nonce>:<pre_hash_prefix>``, or "" when no device confirmed.

    The third component is what makes the claim checkable. It records WHICH value the
    human was shown, so `attestation.core.verify_presence_binding()` can recompute the
    entry's pre-hash and confirm the two agree. Without it, presence_ref was an
    unfalsifiable string: any entry could assert PRESENCE_CONFIRMED and no verifier could
    contradict it.

    This goes INSIDE the entry preimage, so the presence claim cannot be attached after
    the fact either.
    """
    if not result.get("confirmed"):
        return ""
    device = str(result.get("device_id", "")).replace(":", "_")
    return f"{device}:{result.get('nonce', '')}:{result.get('shown', '')}"
