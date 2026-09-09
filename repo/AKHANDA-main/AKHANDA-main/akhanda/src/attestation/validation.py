"""Sanitization validation, NIST SP 800-88 Rev. 2 §4.5.2.

THE GAP THIS CLOSES. Rev. 2 splits *sanitization assurance* into two things, and AKHANDA
implemented only the first:

    VERIFICATION (§4.5.1), "inspecting the outcomes of a sanitization technique to
        determine the outcome of the technique used". Read-back sampling, error counts,
        skipped ranges, media health. AKHANDA does this, and does it well.

    VALIDATION (§4.5.2), "a decision to either approve the sanitization as being
        effective or reject it, which would require repeating the sanitization method
        using a different sanitization technique or escalating to a more secure
        sanitization method."

The Appendix C certificate carries `Verification/Status:` **and** a separate `Validation:`
field. Two fields on the form; one was implemented. `verified` and `outcome` are
verification outputs, **nobody decided anything.**

WHY THE TOOL MUST NOT DECIDE. Rev. 2 is explicit that validation weighs "the sanitization
outcomes **and the sensitivity of the target data**" and turns on whether "the organization
accepts any residual risks". Software knows the outcomes. It does not know how sensitive the
data was, what the organisation's risk appetite is, or whether this drive held payroll or
classified material. A tool that auto-approves has not performed validation, it has
renamed verification and hidden a human judgement inside a boolean.

So this module **assembles the case and refuses to rule on it**. It maps measured evidence
onto the five grounds Rev. 2 names, states which are triggered, and then requires a named
human to approve or reject. `AWAITING_DECISION` is a real state and certificates say so.

    assess(result) -> ValidationAssessment      # the evidence, against NIST's five grounds
    decide(...)    -> ValidationRecord          # a named human approves or rejects
    UNDECIDED                                   # what a certificate says before anyone has

THE VALIDATOR IS THE CONCURRENCE SIGNER. Rev. 2's own certificate form has two signature
blocks and the second is labelled *Concurrence*; BSA 2023 §63(4) requires Part B from an
expert. The party who validates is the party who co-signs, which is why this returns a
record for the concurrence signer to commit to rather than something the operator fills in.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Optional

APPROVED = "APPROVED"
REJECTED = "REJECTED"
UNDECIDED = "AWAITING_DECISION"

DECISIONS = (APPROVED, REJECTED, UNDECIDED)

# The remedies Rev. 2 names for a rejection, verbatim in substance: "repeating the
# sanitization method using a different sanitization technique or escalating to a more
# secure sanitization method". A rejection with no remedy is a complaint, not a decision.
REMEDIES = (
    "REPEAT_DIFFERENT_TECHNIQUE",   # same method, another technique
    "ESCALATE_METHOD",              # Clear -> Purge -> Destroy
    "PHYSICAL_DESTRUCTION",         # the terminal escalation
    "QUARANTINE",                   # do not release the media at all
)

# The five considerations §4.5.2 lists as calling effectiveness into question. Ground IDs
# are ours; the descriptions follow the standard's own examples so a reader can match them.
GROUNDS = {
    "G1_INACCESSIBLE_REGIONS": (
        "The media may appear fully functional while some portion is no longer accessible "
        "through its interface due to errors or performance conditions."),
    "G2_METHOD_INAPPROPRIATE": (
        "The selected method or technique is not appropriate for this media or for the "
        "security category of the information, the standard's example is degaussing an "
        "SSD, which completes successfully and sanitizes nothing."),
    "G3_UNQUALIFIED_OR_UNCALIBRATED": (
        "The sanitization may have been performed by unqualified personnel, or with tools "
        "that were not approved or were improperly calibrated."),
    "G4_BELOW_MINIMUM": (
        "The outcome does not meet the organisation's minimum requirements even though the "
        "technique completed successfully."),
    "G5_SCOPE_TOO_NARROW": (
        "The scope of the sanitization was too narrowly focused, the standard's example is "
        "media using overprovisioning cleared by simple writes, leaving a substantial "
        "amount of user data unchanged."),
}


@dataclass
class Ground:
    """One of NIST's five considerations, and what the run actually measured about it."""
    ground: str
    triggered: bool
    evidence: str
    machine_determinable: bool

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ValidationAssessment:
    """The case for validation. Deliberately NOT a verdict."""
    grounds: list = field(default_factory=list)
    triggered: list = field(default_factory=list)
    requires_human: bool = True
    summary: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["grounds"] = [g.to_dict() if isinstance(g, Ground) else g for g in self.grounds]
        return d


@dataclass
class ValidationRecord:
    """§4.5.2's decision, with the human who made it named."""
    decision: str = UNDECIDED
    decided_by: str = ""
    role: str = ""
    rationale: str = ""
    data_sensitivity: str = ""
    remedy: str = ""
    assessment: dict = field(default_factory=dict)
    standard: str = "NIST SP 800-88 Rev. 2 §4.5.2"
    meaning: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ─────────────────────────────────────────────────────────────── assessment

def assess(result: dict) -> ValidationAssessment:
    """Map a measured erasure result onto NIST's five grounds. Reports; never rules.

    Three of the five are machine-determinable from what the engine already records. Two
    are not, and are reported as *undetermined* rather than assumed clear, an assessment
    that silently treats "we cannot tell" as "no problem" is how a rejection ground
    disappears.
    """
    grounds: list = []

    # G1, inaccessible regions. AKHANDA measures this exactly: bad_ranges are regions the
    # device would not accept or return, and they are already signed.
    bad = result.get("bad_ranges") or []
    skipped = result.get("bytes_skipped", 0) or 0
    aborted = bool(result.get("aborted"))
    g1 = bool(bad) or aborted
    grounds.append(Ground(
        "G1_INACCESSIBLE_REGIONS", g1,
        (f"{len(bad)} unreadable region(s) totalling {skipped} bytes were skipped and "
         f"logged{'; the pass was aborted' if aborted else ''}. Data in unwritable regions "
         "was not destroyed."
         if g1 else
         "no region was skipped and the pass ran to completion"),
        machine_determinable=True))

    # G5, scope too narrow. The standard's own example is AKHANDA's normal case: flash
    # media, cleared by overwrite, where overprovisioned blocks are unreachable from the
    # host. This is not a defect in the tool; it is a fact the validator must weigh.
    kind = (result.get("media_kind") or "").lower()
    note = (result.get("media_note") or "").lower()
    method = result.get("method_used", "")
    flashish = any(k in (kind + " " + note) for k in ("flash", "usb", "sd", "removable", "ssd"))
    g5 = flashish and method == "Clear"
    grounds.append(Ground(
        "G5_SCOPE_TOO_NARROW", g5,
        ("this is flash media cleared by host-addressable overwrite; a flash translation "
         "layer keeps spare and remapped blocks the host cannot address, which is the "
         "standard's own overprovisioning example. Residual user data may remain."
         if g5 else
         f"method {method or 'unknown'} on media reported as "
         f"{result.get('media_kind', 'unknown')}; the overprovisioning case does not apply"),
        machine_determinable=True))

    # G2, method inappropriate. Determinable in one direction only: the engine refuses to
    # claim Purge on media that cannot reach it, so a Purge claim on flash would be a bug
    # rather than a validation finding. The wider question -- appropriate for the SECURITY
    # CATEGORY of the information -- needs the data's sensitivity and is not machine-known.
    verified = bool(result.get("verified"))
    g2 = flashish and method == "Purge"
    grounds.append(Ground(
        "G2_METHOD_INAPPROPRIATE", g2,
        ("Purge is claimed on media that cannot support a firmware sanitize, this "
         "should be impossible and indicates a defect, not merely a validation concern"
         if g2 else
         "the recorded method is reachable on this media class. Whether it suits the "
         "SECURITY CATEGORY of the information is not machine-determinable and is part "
         "of the human decision."),
        machine_determinable=False))

    # G3, personnel and tool qualification. tool_ref identifies the build; it does not
    # validate it, and nothing here knows who ran it or whether they were qualified.
    grounds.append(Ground(
        "G3_UNQUALIFIED_OR_UNCALIBRATED", False,
        ("undetermined. The chain records which build performed the operation (tool_ref) "
         "and which key signed it, which IDENTIFIES the tool and the operator. It does not "
         "establish that either was approved or qualified, that is an organisational fact."),
        machine_determinable=False))

    # G4, organisational minimum. A threshold the tool does not hold.
    grounds.append(Ground(
        "G4_BELOW_MINIMUM", False,
        (f"undetermined. Read-back sampling {'confirmed' if verified else 'did NOT confirm'} "
         "the pattern, but whether that meets the organisation's minimum requirement is a "
         "policy threshold this tool does not hold."),
        machine_determinable=False))

    triggered = [g.ground for g in grounds if g.triggered]
    undetermined = [g.ground for g in grounds if not g.machine_determinable]

    summary = (
        f"{len(triggered)} of NIST's five grounds are triggered by measurement"
        + (f" ({', '.join(triggered)})" if triggered else "")
        + f"; {len(undetermined)} cannot be determined by software "
          f"({', '.join(undetermined)}) and are reported as undetermined rather than clear."
    )
    return ValidationAssessment(grounds=grounds, triggered=triggered,
                                requires_human=True, summary=summary)


# ─────────────────────────────────────────────────────────────── the decision

def pending(result: dict) -> ValidationRecord:
    """What a certificate must say before anyone has validated. Not a failure state.

    A certificate printed before validation is a real and ordinary document, the
    sanitization happened, and the decision has not been made yet. Saying
    AWAITING_DECISION is accurate. Leaving the field blank, or defaulting it to approved,
    is the overclaim.
    """
    a = assess(result)
    return ValidationRecord(
        decision=UNDECIDED, assessment=a.to_dict(),
        meaning=("Sanitization validation has not been performed. NIST SP 800-88 Rev. 2 "
                 "§4.5.2 requires a decision to approve or reject, weighing the outcomes "
                 "against the sensitivity of the target data. That decision is not made by "
                 "this tool and has not yet been made by anyone."))


def decide(result: dict, *, decision: str, decided_by: str, role: str,
           rationale: str, data_sensitivity: str,
           remedy: Optional[str] = None) -> ValidationRecord:
    """Record a named human's approve/reject decision. Validates its own arguments.

    `data_sensitivity` is required and cannot be empty, because §4.5.2's decision is a
    function of it. A validation recorded without it is not the decision the standard
    describes, and accepting one would let the field be filled in without the judgement
    behind it ever having been made.
    """
    if decision not in (APPROVED, REJECTED):
        raise ValueError(
            f"decision must be {APPROVED!r} or {REJECTED!r}; got {decision!r}. "
            f"Use pending() for {UNDECIDED!r}, it is a state, not a choice.")
    if not decided_by.strip():
        raise ValueError("decided_by is required: a validation with no validator is not a "
                         "decision, and §4.5.2 describes a decision")
    if not rationale.strip():
        raise ValueError("rationale is required: the standard asks that identified errors "
                         "and anomalies be ANALYSED, and an unexplained verdict records "
                         "none of that analysis")
    if not data_sensitivity.strip():
        raise ValueError("data_sensitivity is required: §4.5.2 decides whether the target "
                         "data was sanitized to an acceptable level, which is a function "
                         "of how sensitive it was")

    if decision == REJECTED:
        if remedy not in REMEDIES:
            raise ValueError(
                f"a rejection must name a remedy from {REMEDIES}; got {remedy!r}. "
                "§4.5.2 states rejection 'would require repeating the sanitization method "
                "using a different sanitization technique or escalating to a more secure "
                "sanitization method'. A rejection with no remedy is a complaint.")
    elif remedy:
        raise ValueError("remedy applies only to a rejection")

    a = assess(result)
    meaning = (
        f"{decided_by} ({role}) approved this sanitization as effective for data "
        f"classified {data_sensitivity}. The organisation accepts the residual risk."
        if decision == APPROVED else
        f"{decided_by} ({role}) REJECTED this sanitization as insufficient for data "
        f"classified {data_sensitivity}. Required remedy: {remedy}. The media must not be "
        "released on the strength of this operation.")

    if decision == APPROVED and a.triggered:
        meaning += (f" Approved despite {len(a.triggered)} triggered ground(s) "
                    f"({', '.join(a.triggered)}), the rationale records why.")

    return ValidationRecord(
        decision=decision, decided_by=decided_by, role=role, rationale=rationale,
        data_sensitivity=data_sensitivity, remedy=remedy or "",
        assessment=a.to_dict(), meaning=meaning)


def certificate_field(record: ValidationRecord) -> str:
    """The one-line `Validation:` value for the Appendix C certificate."""
    if record.decision == UNDECIDED:
        return "AWAITING DECISION, not yet validated (NIST SP 800-88r2 §4.5.2)"
    if record.decision == REJECTED:
        return (f"REJECTED by {record.decided_by} ({record.role}), "
                f"remedy required: {record.remedy}")
    return f"APPROVED by {record.decided_by} ({record.role})"
