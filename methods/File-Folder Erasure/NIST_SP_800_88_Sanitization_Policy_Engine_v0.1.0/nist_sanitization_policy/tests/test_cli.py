import json
from pathlib import Path
from sanitization_policy.cli import main


def test_cli_example(tmp_path, capsys):
    p = tmp_path / "request.json"
    p.write_text(json.dumps({
        "media_type": "hdd",
        "assurance": "clear",
        "scope": "full_media",
        "capabilities": ["verified_overwrite"],
        "verification_available": True
    }), encoding="utf-8")
    assert main([str(p), "--pretty"]) == 0
    output = capsys.readouterr().out
    assert "verified_overwrite" in output
