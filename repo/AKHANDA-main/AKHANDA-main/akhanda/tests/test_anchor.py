"""
Anchor tests, Merkle correctness first, OpenTimestamps degradation second.

The first two tests are regressions for real, named defects. They must never be deleted:

  * CVE-2012-2459 (Bitcoin): duplicating an odd node to pad a level makes [A,B,C] and
    [A,B,C,C] produce an IDENTICAL root. A chain could then be extended by a duplicate
    entry without changing its anchor.
  * RFC 6962 §2.1 second-preimage: with no leaf/node domain separation every node is a
    bare digest, so an internal node can be presented as a leaf and the root no longer
    identifies one unique tree.
"""

import hashlib

import pytest

from anchor.ots import (
    inclusion_proof, merkle_leaf, merkle_node, merkle_root, submit, verify,
    verify_inclusion,
)


def H(n: int) -> bytes:
    return hashlib.sha256(bytes([n])).digest()


# ------------------------------------------------------------------- regressions

def test_odd_node_is_not_duplicated_cve_2012_2459():
    """[A,B,C] and [A,B,C,C] must NOT share a root."""
    three = [H(1), H(2), H(3)]
    padded = [H(1), H(2), H(3), H(3)]
    assert merkle_root(three) != merkle_root(padded)


def test_leaf_and_internal_nodes_are_domain_separated_rfc6962():
    """An internal node must not be replayable as a leaf."""
    a, b = H(1), H(2)
    internal = merkle_node(merkle_leaf(a), merkle_leaf(b))
    assert merkle_leaf(internal) != internal
    # a two-leaf tree's root must differ from a one-leaf tree over that same digest
    assert merkle_root([a, b]) != merkle_root([internal])


def test_single_leaf_returns_its_tagged_hash_not_the_raw_input():
    a = H(7)
    assert merkle_root([a]) == merkle_leaf(a)
    assert merkle_root([a]) != a


# --------------------------------------------------------------------- behaviour

def test_empty_tree_is_the_zero_root():
    assert merkle_root([]) == b"\x00" * 32


def test_root_changes_when_any_leaf_changes():
    base = [H(i) for i in range(5)]
    root = merkle_root(base)
    for i in range(5):
        mutated = list(base)
        mutated[i] = H(99)
        assert merkle_root(mutated) != root


def test_root_changes_when_order_changes():
    base = [H(1), H(2), H(3)]
    assert merkle_root(base) != merkle_root([H(2), H(1), H(3)])


def test_root_is_deterministic():
    leaves = [H(i) for i in range(9)]
    assert merkle_root(leaves) == merkle_root(leaves)


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 7, 8, 16, 17])
def test_every_leaf_has_a_verifiable_inclusion_proof(n):
    leaves = [H(i) for i in range(n)]
    root = merkle_root(leaves)
    for i in range(n):
        path = inclusion_proof(leaves, i)
        assert verify_inclusion(leaves[i], path, root) is True


def test_inclusion_proof_rejects_a_leaf_that_is_not_in_the_tree():
    leaves = [H(i) for i in range(6)]
    root = merkle_root(leaves)
    path = inclusion_proof(leaves, 2)
    assert verify_inclusion(H(200), path, root) is False


def test_inclusion_proof_index_out_of_range_raises():
    with pytest.raises(IndexError):
        inclusion_proof([H(1)], 5)


# ------------------------------------------------------------------- degradation

def test_submit_degrades_cleanly_without_the_ots_client(tmp_path, monkeypatch):
    """No client installed is a recorded state, never an exception (docs/ENGINEERING_RULES.md rule 3)."""
    monkeypatch.setattr("anchor.ots.shutil.which", lambda _: None)
    res = submit(merkle_root([H(1), H(2)]), out_dir=str(tmp_path))
    assert res["ok"] is False
    assert "not installed" in res["reason"]
    assert "unanchored" in res["reason"]


def test_verify_reports_a_missing_proof_file_without_raising(tmp_path):
    res = verify(str(tmp_path / "absent.ots"))
    assert res["confirmed"] is False
    assert "not found" in res["reason"]


def test_verify_does_not_claim_confirmation_without_the_client(tmp_path, monkeypatch):
    proof = tmp_path / "x.ots"
    proof.write_bytes(b"stub")
    monkeypatch.setattr("anchor.ots.shutil.which", lambda _: None)
    res = verify(str(proof))
    assert res["confirmed"] is False
    assert res["block_height"] is None
