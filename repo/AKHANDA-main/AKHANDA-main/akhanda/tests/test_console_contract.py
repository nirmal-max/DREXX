"""
Console contract test.

The console re-implements the entry encoding in JavaScript so the browser independently
re-hashes every entry. That is only worth something if the two implementations agree on
the field list and its ORDER. If they drift, the console reddens every row and the demo
dies on stage for a reason nobody can debug under time pressure.

This test pins the JS constant to the Python one by reading the HTML.
"""

import re
from pathlib import Path

from attestation.core import ENTRY_DOMAIN, FIELDS_BY_VERSION, HASHED_FIELDS

CONSOLE = Path(__file__).resolve().parents[1] / "console" / "index.html"


def _js_fields(name: str = "FIELDS_V4") -> list:
    """The named JS field-list constant, read out of the page source."""
    text = CONSOLE.read_text(encoding="utf-8")
    m = re.search(rf"const {name} = (?:FIELDS_V\d\.concat\()?\[(.*?)\]", text, re.S)
    assert m, f"{name} not found in console/index.html"
    return re.findall(r'"([a-z_]+)"', m.group(1))


def test_console_field_list_matches_python_exactly():
    # v4 is declared as FIELDS_V3.concat([...]), so the literal block holds only the
    # four appended names; prepending v3 reconstructs the full list the browser uses.
    assert _js_fields("FIELDS_V3") + _js_fields("FIELDS_V4") == HASHED_FIELDS


def test_console_still_knows_how_to_hash_a_v3_chain():
    """The frozen round-one chain is v3 and can never be regenerated.

    If the console stops carrying the v3 field list, that chain goes red in the browser
    a judge is looking at, for the crime of being old, which is the exact false positive
    the version-keyed encoding exists to prevent.
    """
    assert _js_fields("FIELDS_V3") == FIELDS_BY_VERSION["3"]

    text = CONSOLE.read_text(encoding="utf-8")
    # And the map the browser actually dispatches on must name both versions.
    m = re.search(r"const FIELDS_BY_VERSION = \{(.*?)\};", text, re.S)
    assert m, "FIELDS_BY_VERSION not found in console/index.html"
    assert set(re.findall(r'"(\d+)"\s*:', m.group(1))) == set(FIELDS_BY_VERSION)


def test_console_uses_the_same_domain_tag():
    text = CONSOLE.read_text(encoding="utf-8")
    m = re.search(r'const ENTRY_DOMAIN = "([^"]+)"', text)
    assert m, "ENTRY_DOMAIN not found in console/index.html"
    assert m.group(1) == ENTRY_DOMAIN.decode()


def test_console_states_that_it_does_not_verify_signatures():
    """The page must not imply full verification. It checks the key-free layer only."""
    text = CONSOLE.read_text(encoding="utf-8")
    assert "does <b>not</b> verify Ed25519 signatures" in text


def test_console_states_the_completeness_limit():
    text = CONSOLE.read_text(encoding="utf-8")
    assert "withheld" in text
    assert "single-operator ledger" in text
