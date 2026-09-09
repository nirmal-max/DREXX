"""
Presence device discovery, the bug real hardware found.

`find_device()` used to end with `return ports[0].device if ports else None`. On the
development laptop that returned COM4, a Bluetooth virtual COM port, on a machine with no
ESP32 attached at all. The consequence is not cosmetic: `policy.preflight()` asks
`find_device() is not None` to decide whether a presence device is AVAILABLE, so the
preflight, the thing whose entire job is refusing to proceed on a false claim, reported
a presence device that did not exist.

The fixture below is the real enumeration from that laptop, captured verbatim.
"""

import pytest

from presence import client as presence


class FakePort:
    def __init__(self, device, description, manufacturer="", hwid=""):
        self.device = device
        self.description = description
        self.manufacturer = manufacturer
        self.hwid = hwid


# Captured verbatim from the development laptop, 26 Aug: six paired Bluetooth devices,
# zero ESP32s. This is what the old fallback was handed.
REAL_BLUETOOTH_ONLY = [
    FakePort("COM4", "Standard Serial over Bluetooth link (COM4)", "Microsoft",
             r"BTHENUM\{00001101-0000-1000-8000-00805F9B34FB}_LOCALMFG&0000"),
    FakePort("COM5", "Standard Serial over Bluetooth link (COM5)", "Microsoft",
             r"BTHENUM\{00001101-0000-1000-8000-00805F9B34FB}_LOCALMFG&0000"),
    FakePort("COM8", "Standard Serial over Bluetooth link (COM8)", "Microsoft",
             r"BTHENUM\{00001101-0000-1000-8000-00805F9B34FB}_LOCALMFG&0000"),
    FakePort("COM6", "Standard Serial over Bluetooth link (COM6)", "Microsoft",
             r"BTHENUM\{00001101-0000-1000-8000-00805F9B34FB}_VID&000105D6"),
    FakePort("COM3", "Standard Serial over Bluetooth link (COM3)", "Microsoft",
             r"BTHENUM\{00001101-0000-1000-8000-00805F9B34FB}_VID&000105D6"),
    FakePort("COM7", "Standard Serial over Bluetooth link (COM7)", "Microsoft",
             r"BTHENUM\{00001101-0000-1000-8000-00805F9B34FB}_VID&000105D6"),
]

ESP32_CP210X = FakePort("COM9", "Silicon Labs CP210x USB to UART Bridge (COM9)",
                        "Silicon Labs", r"USB VID:PID=10C4:EA60")
ESP32_CH340 = FakePort("COM10", "USB-SERIAL CH340 (COM10)", "wch.cn",
                       r"USB VID:PID=1A86:7523")


@pytest.fixture()
def ports(monkeypatch):
    """Install a fake comports() enumeration."""
    def install(port_list):
        monkeypatch.setattr(presence.list_ports, "comports", lambda: list(port_list))
    return install


# ------------------------------------------------- the regression, on real data

def test_bluetooth_only_machine_finds_no_presence_device(ports):
    """THE BUG. Six Bluetooth ports, no ESP32, the answer is None, not COM4."""
    ports(REAL_BLUETOOTH_ONLY)
    assert presence.find_device() is None


def test_bluetooth_ports_are_never_selected_even_alongside_a_real_one(ports):
    ports(REAL_BLUETOOTH_ONLY + [ESP32_CP210X])
    assert presence.find_device() == "COM9"


def test_no_ports_at_all_is_none(ports):
    ports([])
    assert presence.find_device() is None


# ------------------------------------------------------- recognised bridges

@pytest.mark.parametrize("port,expected", [
    (ESP32_CP210X, "COM9"),
    (ESP32_CH340, "COM10"),
    (FakePort("COM11", "USB Serial Device", "", "USB VID:PID=10C4:EA60 CP210x"), "COM11"),
    (FakePort("/dev/ttyUSB0", "CP2102 USB to UART Bridge Controller"), "/dev/ttyUSB0"),
])
def test_known_usb_serial_bridges_are_recognised(ports, port, expected):
    ports([port])
    assert presence.find_device() == expected


def test_an_unrecognised_adapter_is_not_guessed_at(ports):
    """The old fallback would have returned this. A presence device must be specific."""
    ports([FakePort("COM12", "Generic Serial Adapter", "Nobody", "USB VID:PID=DEAD:BEEF")])
    assert presence.find_device() is None


# ------------------------------------ the consequence this bug had on preflight

def test_preflight_no_longer_claims_a_presence_device_that_is_not_there(ports):
    """The reason this matters. Preflight asks find_device() whether presence is
    available; a false answer there is a false claim in the check that exists to stop
    false claims."""
    from attestation import policy, tiers
    ports(REAL_BLUETOOTH_ONLY)

    available = presence.find_device() is not None
    check = policy.preflight(want_presence=True, want_witness=False,
                             presence_available=available, witness_available=False)
    assert available is False
    assert check["ok"] is False
    assert check["missing"] == ["presence device"]
    assert check["required_tier"] == tiers.PRESENCE_CONFIRMED


def test_preflight_passes_when_a_real_bridge_is_present(ports):
    from attestation import policy
    ports(REAL_BLUETOOTH_ONLY + [ESP32_CH340])
    available = presence.find_device() is not None
    check = policy.preflight(want_presence=True, want_witness=False,
                             presence_available=available, witness_available=False)
    assert available is True
    assert check["ok"] is True


# ------------------------------------------------------------- still degrades

def test_enumeration_failure_is_none_not_an_exception(monkeypatch):
    def boom():
        raise OSError("driver exploded")
    monkeypatch.setattr(presence.list_ports, "comports", boom)
    assert presence.find_device() is None


def test_no_pyserial_is_none(monkeypatch):
    monkeypatch.setattr(presence, "list_ports", None)
    assert presence.find_device() is None
