"""
Custody tiers, the honest record of how much assurance an operation actually had.

docs/ENGINEERING_RULES.md rule 3: optional components degrade cleanly when absent. The system behaves
identically and records the tier it actually ran at. A missing device is a labelled
fallback, never a crash. This module is where that rule is made mechanical instead of
a habit, so no caller can silently claim a tier it did not reach.

The ladder is additive. Each tier is the one below it plus one independent party:

  SOFTWARE_KEY        one key, on the operator's own machine. Nothing else present.
  PRESENCE_CONFIRMED  + a human pressed a button on a physically separate device.
  WITNESS_COSIGNED    + a second key on a physically separate machine signed the same
                        entry hash and kept its own independent head record.
  FULL_CUSTODY        + both of the above.

What no tier claims: that the ESP32 protects a key (it does not, CVE-2019-17391), or
that the witness is an independent institution (in this deployment the operator can
reach both machines). See docs/ENGINEERING_RULES.md section 6.
"""

from __future__ import annotations

SOFTWARE_KEY = "SOFTWARE_KEY"
PRESENCE_CONFIRMED = "PRESENCE_CONFIRMED"
WITNESS_COSIGNED = "WITNESS_COSIGNED"
FULL_CUSTODY = "FULL_CUSTODY"

TIERS = (SOFTWARE_KEY, PRESENCE_CONFIRMED, WITNESS_COSIGNED, FULL_CUSTODY)

# Rank is for reporting only. A higher rank is never assumed, it is computed from what
# actually answered.
RANK = {name: i for i, name in enumerate(TIERS)}

DESCRIPTION = {
    SOFTWARE_KEY: (
        "Signed by one operator key held in software on the workstation. No second "
        "party, no physical presence confirmation."
    ),
    PRESENCE_CONFIRMED: (
        "Operator key plus a physical button press on a separate device at signing "
        "time. Confirms a human was present; does NOT protect the key."
    ),
    WITNESS_COSIGNED: (
        "Operator key plus a concurring key held on a physically separate machine "
        "that keeps its own independent record of chain heads."
    ),
    FULL_CUSTODY: (
        "Operator key, physical presence confirmation, and an independent "
        "witness co-signature over the same entry hash."
    ),
}


def resolve(presence_confirmed: bool, witness_cosigned: bool) -> str:
    """The single place a custody tier is decided. Inputs are facts, not intentions.

    Pass what actually happened: `presence_confirmed` is True only if a device returned
    a confirmation, `witness_cosigned` only if a witness signature came back. Absence of
    either is a lower tier, never an error.
    """
    if presence_confirmed and witness_cosigned:
        return FULL_CUSTODY
    if witness_cosigned:
        return WITNESS_COSIGNED
    if presence_confirmed:
        return PRESENCE_CONFIRMED
    return SOFTWARE_KEY


def has_presence(tier: str) -> bool:
    return tier in (PRESENCE_CONFIRMED, FULL_CUSTODY)


def has_witness(tier: str) -> bool:
    return tier in (WITNESS_COSIGNED, FULL_CUSTODY)


def describe(tier: str) -> str:
    return DESCRIPTION.get(tier, f"unknown tier: {tier}")


# Operations that performed no work. A REFUSED entry is a record that something was
# BLOCKED, it read nothing, wrote nothing, and destroyed nothing.
# None of these performed forensic work, so none may drag a case's quoted custody
# tier down. A key rotation is administrative: it is correctly signed with SOFTWARE_KEY
# and no witness, because there is no erasure or recovery for a witness to co-sign.
#
# AMEND is here for the same reason and NOT for a weaker one. An amendment corrects the
# RECORD of an operation; it erases nothing and recovers nothing, so counting it as
# performed work would inflate how much forensic activity a chain appears to contain.
#
# Being listed here is about what an entry may BOUND, not about how carefully it is
# controlled. An amendment is still co-signed like any operation, see the fail-closed
# policy, because rewriting history is precisely what an attacker most wants, so it gets
# the strongest available control and the weakest claim on the certificate at the
# same time. Those two facts are not in tension: one is about authority, the other about
# accounting.
NOT_PERFORMED_OPS = ("REFUSED", "SIGNER_CHANGE", "AMEND")


def is_performed(op_type: str) -> bool:
    """Did this entry represent work that actually happened?"""
    return op_type not in NOT_PERFORMED_OPS


def lowest(tiers: list[str], *, op_types: list[str] | None = None) -> str:
    """The weakest tier across PERFORMED operations. Certificates quote this.

    Quoting the best tier would overstate the chain, one strong entry cannot launder a
    weak one beside it. That much was always true.

    WHY `op_types` EXISTS. When the fail-closed policy blocks an operation it writes a
    REFUSED entry, which by construction has no co-signature and no presence (that is
    *why* it was blocked), so its tier is SOFTWARE_KEY. Without this filter one blocked
    attempt dragged the quoted custody of an entire case down to SOFTWARE_KEY even when
    every operation that actually happened reached FULL_CUSTODY.

    That is backwards. The fail-closed policy exists to STRENGTHEN custody; as written it
    weakened the certificate, so exercising the safety feature damaged the evidence. A
    refusal performed no work and cannot bound the custody of work that was performed.

    Refusals are not thereby hidden, the certificate reports them on their own line.
    Suppressing them would be the opposite error and just as dishonest.

    Raises ValueError when there is nothing to quote. A certificate must not fall back to
    a default tier for a chain with no performed operations; it has to say so instead.
    """
    if op_types is not None:
        if len(op_types) != len(tiers):
            raise ValueError("op_types must be parallel to tiers")
        tiers = [t for t, op in zip(tiers, op_types) if is_performed(op)]

    if not tiers:
        raise ValueError(
            "no performed operations to quote a custody tier for. A chain of refusals "
            "has no custody level; the certificate must state that rather than default "
            "to one."
        )
    return min(tiers, key=lambda t: RANK.get(t, 0))
