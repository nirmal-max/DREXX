"""
Custody policy, what the tool does when a required co-signer or presence device is
unavailable.

THE DECISION THIS MODULE ENCODES, AND WHY IT OVERRIDES A LOOSE READING OF RULE 3.

docs/ENGINEERING_RULES.md rule 3 says a missing device is "a labelled fallback, never a crash". Read
loosely, that means: witness unreachable, quietly record a weaker tier, carry on. That
reading is a silent-omission vector with a trivial trigger, an operator who wants an
operation off the record simply unplugs the co-signer, and the tool downgrades itself
without complaint. The label is written into a ledger nobody reads before the fact.

The rule is kept, but sharpened:

    Asking for a component makes it REQUIRED. Disabling it is the explicit act.

So `--no-witness` still degrades cleanly and records the honest lower tier, that is the
labelled fallback rule 3 asks for. But if you did NOT disable the witness, its silence
BLOCKS the operation. There is no path where a component you asked for goes missing and
the tool proceeds as if nothing happened.

Blocking alone is not enough. A blocked operation that leaves no trace is
indistinguishable from an operation nobody attempted, so a refusal is itself written to
the chain as a REFUSED entry. That is the part that actually narrows the omission gap:
unplugging the co-signer no longer erases the attempt, it records it.

THE ORDERING PROBLEM, STATED RATHER THAN HIDDEN.

An erase is irreversible. If the co-signer answers at the start and dies before the entry
is co-signed, the data is already gone and no policy can un-destroy it. So the check runs
as a PREFLIGHT, before the destructive step, and the residual window between preflight and
co-signature is narrowed but not closed. Any tool that performs an irreversible action has
this window. Ours is measured and reported (`residual_window_note`) instead of denied.
"""

from __future__ import annotations

from . import tiers


def required_tier(want_presence: bool, want_witness: bool) -> str:
    """The tier an operation MUST reach, derived from what the operator asked for.

    Not a separate setting to forget: requesting a component is the request for its
    assurance. Disabling one lowers the bar deliberately and visibly.
    """
    return tiers.resolve(presence_confirmed=want_presence, witness_cosigned=want_witness)


def preflight(*, want_presence: bool, want_witness: bool,
              presence_available: bool, witness_available: bool) -> dict:
    """Can this operation reach the tier it is required to reach? Check BEFORE acting.

    Availability here means "the component answered a cheap probe", a serial port that
    enumerates, a witness that returns its head. It deliberately does NOT consume a
    button press: asking a human to confirm twice for one operation trains them to press
    without reading, which destroys the only thing presence is for.

    Returns a dict rather than raising, because the caller has to record the refusal
    before it can fail.
    """
    missing = []
    if want_presence and not presence_available:
        missing.append("presence device")
    if want_witness and not witness_available:
        missing.append("witness co-signer")

    required = required_tier(want_presence, want_witness)
    reachable = tiers.resolve(
        presence_confirmed=want_presence and presence_available,
        witness_cosigned=want_witness and witness_available,
    )

    if not missing:
        return {
            "ok": True, "required_tier": required, "reachable_tier": reachable,
            "missing": [], "reason": f"all required components answered; {required} reachable",
        }

    return {
        "ok": False, "required_tier": required, "reachable_tier": reachable,
        "missing": missing,
        "reason": (f"{' and '.join(missing)} unavailable; required {required}, "
                   f"only {reachable} reachable, operation blocked"),
    }


def refusal_record(*, op_type: str, target: str, intended_method: str,
                   preflight_result: dict, timestamp: str) -> dict:
    """The document a REFUSED entry commits to.

    It records what was attempted, what was missing, and that nothing was performed , 
    so the refusal is evidence rather than an absence.
    """
    return {
        "outcome": "REFUSED",
        "attempted_op": op_type,
        "attempted_target": target,
        "intended_method": intended_method,
        "performed": False,
        "required_tier": preflight_result["required_tier"],
        "reachable_tier": preflight_result["reachable_tier"],
        "missing_components": preflight_result["missing"],
        "reason": preflight_result["reason"],
        "timestamp": timestamp,
        "honest_note": (
            "The operation was blocked before it ran. Nothing on the target was read, "
            "written, or destroyed. This entry exists so that a blocked attempt is "
            "distinguishable from an attempt that was never made."
        ),
    }


RESIDUAL_WINDOW_NOTE = (
    "Preflight confirms every required component is answering BEFORE an irreversible "
    "operation begins. It cannot eliminate the window between that check and the "
    "co-signature: if the co-signer fails during the operation itself, the data is "
    "already destroyed and the entry is recorded at the tier actually reached, marked "
    "as degraded. Every tool that performs an irreversible action has this window; this "
    "one narrows it to the duration of a single operation and states its size rather "
    "than implying it is closed."
)


def degraded_after_preflight(required: str, reached: str) -> dict:
    """Describe the residual-window case: preflight passed, a component died mid-op.

    This is not a refusal, the operation already happened and must be recorded. It is a
    degradation that has to be flagged loudly, because it is the one path where the tool
    produces an entry below the tier the operator required.
    """
    return {
        "degraded": required != reached,
        "required_tier": required,
        "reached_tier": reached,
        "reason": (
            f"preflight passed at {required} but the operation completed at {reached}: "
            "a required component failed after the point of no return"
            if required != reached else
            f"operation completed at the required tier {required}"
        ),
        "residual_window_note": RESIDUAL_WINDOW_NOTE,
    }
