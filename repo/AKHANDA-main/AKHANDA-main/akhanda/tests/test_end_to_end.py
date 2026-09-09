"""
End-to-end tests through the CLI, with no hardware attached.

This is the acceptance test for the whole system as a demo: with no Pi and no ESP32 on
the bench, every command must still complete, and every record must say the tier it
actually reached. If these pass on a bare laptop, the demo cannot be broken by a device
failing to enumerate on stage.
"""

import json

import pytest

import cli
from attestation import store, tiers
from attestation.core import verify_chain_report


JPG = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"J" * 400 + b"\xff\xd9"
PDF = b"%PDF-1.7\n" + b"D" * 400 + b"%%EOF"


@pytest.fixture()
def image(tmp_path):
    p = tmp_path / "evidence.dd"
    p.write_bytes(b"\x00" * 512 + JPG + b"\x00" * 512 + PDF + b"\x00" * 512)
    return p


@pytest.fixture()
def base_args(akhanda_home):
    """Every optional component switched off, the bare-laptop case."""
    return ["--no-witness", "--no-presence",
            "--chain", str(akhanda_home / "chain.json")]


def test_init_creates_key_and_chain(akhanda_home, base_args, capsys):
    assert cli.main(base_args + ["init"]) == 0
    out = capsys.readouterr().out
    assert "key id" in out
    assert (akhanda_home / "operator_key.pem").exists()


def test_recover_records_an_entry_at_the_honest_tier(akhanda_home, base_args, image,
                                                     tmp_path, capsys):
    cli.main(base_args + ["init"])
    rc = cli.main(base_args + ["recover", str(image), "--out", str(tmp_path / "out")])
    assert rc == 0

    chain = store.load_chain(akhanda_home / "chain.json")
    assert len(chain.entries) == 1
    e = chain.entries[0]
    assert e.op_type == "RECOVER"
    assert e.custody_tier == tiers.SOFTWARE_KEY      # nothing else answered
    assert e.presence_ref == ""
    assert not e.is_dual_signed()


def test_erase_records_clear_on_a_file_image(akhanda_home, base_args, tmp_path):
    target = tmp_path / "wipe.img"
    target.write_bytes(b"SECRET" * 2000)
    cli.main(base_args + ["init"])
    assert cli.main(base_args + ["erase", str(target)]) == 0

    chain = store.load_chain(akhanda_home / "chain.json")
    assert chain.entries[0].method == "Clear"
    assert b"SECRET" not in target.read_bytes()


def test_purge_request_still_records_clear_end_to_end(akhanda_home, base_args, tmp_path):
    target = tmp_path / "wipe.img"
    target.write_bytes(b"SECRET" * 2000)
    cli.main(base_args + ["init"])
    cli.main(base_args + ["erase", str(target), "--level", "Purge"])
    chain = store.load_chain(akhanda_home / "chain.json")
    assert chain.entries[0].method == "Clear"


def test_multiple_operations_chain_together(akhanda_home, base_args, image, tmp_path):
    target = tmp_path / "wipe.img"
    target.write_bytes(b"SECRET" * 2000)
    cli.main(base_args + ["init"])
    cli.main(base_args + ["recover", str(image)])
    cli.main(base_args + ["erase", str(target)])
    cli.main(base_args + ["recover", str(image)])

    chain = store.load_chain(akhanda_home / "chain.json")
    assert [e.seq for e in chain.entries] == [0, 1, 2]
    assert [e.op_type for e in chain.entries] == ["RECOVER", "ERASE", "RECOVER"]
    report = verify_chain_report(chain.entries)
    assert report.ok is True


def test_verify_passes_on_a_clean_chain(akhanda_home, base_args, image):
    cli.main(base_args + ["init"])
    cli.main(base_args + ["recover", str(image)])
    assert cli.main(base_args + ["verify"]) == 0


def test_verify_fails_and_names_the_entry_after_tampering(akhanda_home, base_args,
                                                          image, capsys):
    cli.main(base_args + ["init"])
    cli.main(base_args + ["recover", str(image)])
    cli.main(base_args + ["recover", str(image)])

    path = akhanda_home / "chain.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["entries"][1]["result_hash"] = "de" * 32
    path.write_text(json.dumps(data), encoding="utf-8")

    assert cli.main(base_args + ["verify"]) == 1
    out = capsys.readouterr().out
    assert "BROKEN at sequence 1" in out


def test_certify_produces_both_files_and_states_its_limits(akhanda_home, base_args,
                                                           image, tmp_path):
    cli.main(base_args + ["init"])
    cli.main(base_args + ["recover", str(image)])
    out = tmp_path / "certs"
    rc = cli.main(base_args + ["--operator", "J. Rao", "--expert", "K. Singh",
                               "certify", "--out", str(out)])
    assert rc == 0
    cert = json.loads((out / "certificate.json").read_text(encoding="utf-8"))
    assert cert["chain"]["custody_tier"]["weakest_tier_covered"] == tiers.SOFTWARE_KEY
    assert any("WITNESS NOT COMPARED" in l for l in cert["limits"])
    assert (out / "certificate.txt").read_text(encoding="utf-8").startswith("=")


def test_certify_on_an_empty_chain_refuses(akhanda_home, base_args, tmp_path):
    cli.main(base_args + ["init"])
    assert cli.main(base_args + ["certify", "--out", str(tmp_path / "c")]) == 1


def test_anchor_degrades_without_the_ots_client(akhanda_home, base_args, image,
                                                tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("anchor.ots.shutil.which", lambda _: None)
    cli.main(base_args + ["init"])
    cli.main(base_args + ["recover", str(image)])
    assert cli.main(base_args + ["anchor", "--out", str(tmp_path / "anchors")]) == 0
    assert "UNANCHORED" in capsys.readouterr().out


def test_show_prints_every_entry(akhanda_home, base_args, image, capsys):
    cli.main(base_args + ["init"])
    cli.main(base_args + ["recover", str(image)])
    cli.main(base_args + ["show"])
    out = capsys.readouterr().out
    assert "RECOVER" in out
    assert "solo" in out           # not dual-signed, and it says so


def test_erase_on_a_block_device_is_refused_without_the_token(akhanda_home, base_args,
                                                              capsys):
    cli.main(base_args + ["init"])
    assert cli.main(base_args + ["erase", "/dev/sdz"]) == 2
    assert "REFUSED" in capsys.readouterr().err
