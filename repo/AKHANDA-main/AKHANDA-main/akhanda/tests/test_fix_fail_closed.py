"""
FIX, fail closed when a required co-signer or presence device is unavailable.

The trigger the judge panel named: an operator who wants an operation off the record
unplugs the co-signer. The previous behaviour was to downgrade the tier silently and
carry on, which is a silent-omission vector with a one-second trigger.

Three properties are asserted here, and all three are needed:

  1. BLOCKED  , a missing required component stops the operation.
  2. RECORDED , the blocked attempt is written to the chain as a REFUSED entry, so
                 unplugging the co-signer records the attempt instead of erasing it.
  3. UNTOUCHED, for an erase, the target is byte-identical afterwards. Preflight runs
                 before the destructive step, not after it.

Plus the honest escape hatch (explicitly disabling a component still degrades cleanly)
and the residual window (preflight cannot cover a component that dies mid-operation).
"""

import json

import pytest

import cli
from attestation import policy, store, tiers
from attestation.core import Chain, verify_chain_report


JPG = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"J" * 300 + b"\xff\xd9"
SECRET = b"SENSITIVE-EVIDENCE-" * 500


@pytest.fixture()
def image(tmp_path):
    p = tmp_path / "evidence.dd"
    p.write_bytes(b"\x00" * 256 + JPG + b"\x00" * 256)
    return p


@pytest.fixture()
def target(tmp_path):
    p = tmp_path / "wipe.img"
    p.write_bytes(SECRET)
    return p


@pytest.fixture()
def chain_arg(akhanda_home):
    return ["--chain", str(akhanda_home / "chain.json")]


@pytest.fixture()
def unreachable_witness(monkeypatch):
    """The witness is configured but does not answer, the exact unplug scenario."""
    monkeypatch.setattr("witness.client.WitnessClient.head",
                        lambda self: {"ok": False, "head_hash": "", "seq": -1,
                                      "count": 0, "reason": "witness unreachable"})
    monkeypatch.setattr("witness.client.WitnessClient.cosign",
                        lambda self, s, h: {"ok": False, "concur_sig": "",
                                            "witness_head_hash": "", "witness_seq": -1,
                                            "concur_key_id": "",
                                            "reason": "witness unreachable"})
    monkeypatch.setattr("witness.client.WitnessClient.pubkey", lambda self: None)


# ------------------------------------------------------------ the policy in isolation

def test_asking_for_a_component_makes_it_required():
    assert policy.required_tier(True, True) == tiers.FULL_CUSTODY
    assert policy.required_tier(False, True) == tiers.WITNESS_COSIGNED
    assert policy.required_tier(True, False) == tiers.PRESENCE_CONFIRMED
    assert policy.required_tier(False, False) == tiers.SOFTWARE_KEY


def test_preflight_passes_when_everything_answers():
    r = policy.preflight(want_presence=True, want_witness=True,
                         presence_available=True, witness_available=True)
    assert r["ok"] is True
    assert r["required_tier"] == tiers.FULL_CUSTODY
    assert r["missing"] == []


def test_preflight_blocks_on_a_missing_witness():
    r = policy.preflight(want_presence=False, want_witness=True,
                         presence_available=False, witness_available=False)
    assert r["ok"] is False
    assert r["missing"] == ["witness co-signer"]
    assert "operation blocked" in r["reason"]


def test_preflight_blocks_on_a_missing_presence_device():
    r = policy.preflight(want_presence=True, want_witness=False,
                         presence_available=False, witness_available=False)
    assert r["ok"] is False
    assert r["missing"] == ["presence device"]


def test_preflight_names_every_missing_component():
    r = policy.preflight(want_presence=True, want_witness=True,
                         presence_available=False, witness_available=False)
    assert r["missing"] == ["presence device", "witness co-signer"]
    assert r["reachable_tier"] == tiers.SOFTWARE_KEY


def test_a_component_you_did_not_ask_for_cannot_block_you():
    """The escape hatch is explicit disabling, and it must actually work."""
    r = policy.preflight(want_presence=False, want_witness=False,
                         presence_available=False, witness_available=False)
    assert r["ok"] is True
    assert r["required_tier"] == tiers.SOFTWARE_KEY


def test_refusal_record_states_that_nothing_was_performed():
    check = policy.preflight(want_presence=False, want_witness=True,
                             presence_available=False, witness_available=False)
    rec = policy.refusal_record(op_type="ERASE", target="/dev/sdb",
                                intended_method="Clear", preflight_result=check,
                                timestamp="2026-01-01T00:00:00Z")
    assert rec["performed"] is False
    assert rec["outcome"] == "REFUSED"
    assert rec["missing_components"] == ["witness co-signer"]
    assert "nothing on the target was read, written, or destroyed" in rec["honest_note"].lower()


def test_residual_window_is_described_not_denied():
    state = policy.degraded_after_preflight(tiers.FULL_CUSTODY, tiers.PRESENCE_CONFIRMED)
    assert state["degraded"] is True
    assert "after the point of no return" in state["reason"]
    assert "cannot eliminate the window" in state["residual_window_note"]


def test_reaching_the_required_tier_is_not_degraded():
    state = policy.degraded_after_preflight(tiers.FULL_CUSTODY, tiers.FULL_CUSTODY)
    assert state["degraded"] is False


# ------------------------------------------ 1. BLOCKED  2. RECORDED  3. UNTOUCHED

def test_erase_is_blocked_when_the_witness_is_unplugged(akhanda_home, chain_arg,
                                                        target, unreachable_witness,
                                                        capsys):
    cli.main(chain_arg + ["--no-witness", "--no-presence", "init"])
    rc = cli.main(chain_arg + ["--no-presence", "erase", str(target)])
    out = capsys.readouterr().out
    assert rc == 3
    assert "preflight: BLOCKED" in out


def test_the_target_is_byte_identical_after_a_refusal(akhanda_home, chain_arg, target,
                                                      unreachable_witness):
    """Preflight runs BEFORE the wipe. This is the whole point of the ordering."""
    cli.main(chain_arg + ["--no-witness", "--no-presence", "init"])
    cli.main(chain_arg + ["--no-presence", "erase", str(target)])
    assert target.read_bytes() == SECRET


def test_the_refusal_is_recorded_in_the_chain(akhanda_home, chain_arg, target,
                                              unreachable_witness):
    """Unplugging the co-signer must record the attempt, not erase it."""
    cli.main(chain_arg + ["--no-witness", "--no-presence", "init"])
    cli.main(chain_arg + ["--no-presence", "erase", str(target)])

    chain = store.load_chain(akhanda_home / "chain.json")
    assert len(chain.entries) == 1
    e = chain.entries[0]
    assert e.op_type == "REFUSED"
    assert e.method == "NotPerformed"
    assert e.target_ref == str(target)
    assert e.custody_tier == tiers.SOFTWARE_KEY


def test_the_refusal_record_is_persisted_and_matches_its_hash(akhanda_home, chain_arg,
                                                              target,
                                                              unreachable_witness):
    cli.main(chain_arg + ["--no-witness", "--no-presence", "init"])
    cli.main(chain_arg + ["--no-presence", "erase", str(target)])

    chain = store.load_chain(akhanda_home / "chain.json")
    rec = store.load_result(chain.entries[0].entry_hash)
    assert rec["performed"] is False
    assert rec["attempted_op"] == "ERASE"
    assert store.verify_result(chain.entries[0])["ok"] is True


def test_a_refused_chain_still_verifies(akhanda_home, chain_arg, target,
                                        unreachable_witness):
    """A REFUSED entry is a normal, signed, linked entry, not a special case."""
    cli.main(chain_arg + ["--no-witness", "--no-presence", "init"])
    cli.main(chain_arg + ["--no-presence", "erase", str(target)])
    chain = store.load_chain(akhanda_home / "chain.json")
    assert verify_chain_report(chain.entries).ok is True


def test_recover_is_blocked_too(akhanda_home, chain_arg, image, unreachable_witness):
    cli.main(chain_arg + ["--no-witness", "--no-presence", "init"])
    rc = cli.main(chain_arg + ["--no-presence", "recover", str(image)])
    assert rc == 3
    chain = store.load_chain(akhanda_home / "chain.json")
    assert chain.entries[0].op_type == "REFUSED"


def test_repeated_unplugging_leaves_a_visible_trail(akhanda_home, chain_arg, target,
                                                    unreachable_witness):
    """Three blocked attempts are three entries. Silence is no longer an option."""
    cli.main(chain_arg + ["--no-witness", "--no-presence", "init"])
    for _ in range(3):
        cli.main(chain_arg + ["--no-presence", "erase", str(target)])
    chain = store.load_chain(akhanda_home / "chain.json")
    assert [e.op_type for e in chain.entries] == ["REFUSED"] * 3
    assert verify_chain_report(chain.entries).ok is True


# -------------------------------------------------------- the honest escape hatches

def test_explicitly_disabling_the_witness_still_degrades_cleanly(akhanda_home,
                                                                 chain_arg, target):
    """docs/ENGINEERING_RULES.md rule 3 survives: an component you opted out of is a labelled fallback."""
    cli.main(chain_arg + ["--no-witness", "--no-presence", "init"])
    rc = cli.main(chain_arg + ["--no-witness", "--no-presence", "erase", str(target)])
    assert rc == 0
    chain = store.load_chain(akhanda_home / "chain.json")
    assert chain.entries[0].op_type == "ERASE"
    assert chain.entries[0].custody_tier == tiers.SOFTWARE_KEY
    assert target.read_bytes() != SECRET


def test_allow_degraded_proceeds_and_records_the_lower_tier(akhanda_home, chain_arg,
                                                            target, unreachable_witness,
                                                            capsys):
    cli.main(chain_arg + ["--no-witness", "--no-presence", "init"])
    rc = cli.main(chain_arg + ["--no-presence", "--allow-degraded",
                               "erase", str(target)])
    assert rc == 0
    chain = store.load_chain(akhanda_home / "chain.json")
    assert chain.entries[0].op_type == "ERASE"
    assert chain.entries[0].custody_tier == tiers.SOFTWARE_KEY   # honest, not claimed


def test_allow_degraded_is_opt_in_not_the_default(akhanda_home, chain_arg, target,
                                                  unreachable_witness):
    """Without the flag, the same command blocks. The difference is the operator's
    explicit choice, which is the property the whole policy rests on."""
    cli.main(chain_arg + ["--no-witness", "--no-presence", "init"])
    assert cli.main(chain_arg + ["--no-presence", "erase", str(target)]) == 3
    assert target.read_bytes() == SECRET


# ------------------------------------------------------------- the residual window

def test_a_component_dying_after_preflight_is_flagged_as_degraded(akhanda_home,
                                                                  chain_arg, target,
                                                                  monkeypatch, capsys):
    """Preflight passes, then the witness dies before co-signing. The erase already
    happened, so it is recorded at the tier reached and the gap is announced."""
    monkeypatch.setattr("witness.client.WitnessClient.head",
                        lambda self: {"ok": True, "head_hash": "00" * 32, "seq": -1,
                                      "count": 0, "reason": "alive at preflight"})
    monkeypatch.setattr("witness.client.WitnessClient.cosign",
                        lambda self, s, h: {"ok": False, "concur_sig": "",
                                            "witness_head_hash": "", "witness_seq": -1,
                                            "concur_key_id": "",
                                            "reason": "died mid-operation"})
    monkeypatch.setattr("witness.client.WitnessClient.pubkey", lambda self: None)

    cli.main(chain_arg + ["--no-witness", "--no-presence", "init"])
    rc = cli.main(chain_arg + ["--no-presence", "erase", str(target)])
    out = capsys.readouterr().out

    assert rc == 0                                   # the erase happened; it is recorded
    assert "preflight: OK" in out
    assert "DEGRADED" in out
    assert "after the point of no return" in out
    chain = store.load_chain(akhanda_home / "chain.json")
    assert chain.entries[0].custody_tier == tiers.SOFTWARE_KEY
    assert chain.entries[0].op_type == "ERASE"


def test_the_residual_window_note_is_available_to_quote(capsys):
    """It must be a stated, quotable sentence, not a comment nobody can cite."""
    assert "narrows it to the duration of a single operation" in policy.RESIDUAL_WINDOW_NOTE
    assert "states its size rather than implying it is closed" in policy.RESIDUAL_WINDOW_NOTE
