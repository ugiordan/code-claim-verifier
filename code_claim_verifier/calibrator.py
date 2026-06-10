from code_claim_verifier.types import VerifiedClaim, VerificationReport


def calibrate(verified_claims: list[VerifiedClaim]) -> VerificationReport:
    """Compute verification report from verified claims."""
    if not verified_claims:
        return VerificationReport(
            total_claims=0, verifiable_claims=0, verified=0, refuted=0,
            unverifiable=0, errored=0, verification_rate=0.0,
            hallucination_rate=0.0, calibrated_confidence=0.0,
            action="NO_CHANGE", reason="no claims extracted",
        )

    verifiable = [c for c in verified_claims if c.verdict != "UNVERIFIABLE"]
    verified = [c for c in verifiable if c.verdict == "VERIFIED"]
    refuted = [c for c in verifiable if c.verdict == "REFUTED"]
    errored = sum(1 for c in verified_claims if c.error)

    if not verifiable:
        return VerificationReport(
            total_claims=len(verified_claims),
            verifiable_claims=0, verified=0, refuted=0,
            unverifiable=len(verified_claims), errored=errored,
            verification_rate=0.0, hallucination_rate=0.0,
            calibrated_confidence=0.0,
            action="NO_CHANGE", reason="no verifiable claims",
        )

    weighted_verified = sum(c.method_confidence for c in verified)
    weighted_total = sum(c.method_confidence for c in verifiable)
    rate = weighted_verified / weighted_total if weighted_total > 0 else 0.0

    if rate >= 0.8:
        action = "BOOST"
    elif rate >= 0.5:
        action = "FLAG"
    else:
        action = "OVERRIDE"

    return VerificationReport(
        total_claims=len(verified_claims),
        verifiable_claims=len(verifiable),
        verified=len(verified),
        refuted=len(refuted),
        unverifiable=len(verified_claims) - len(verifiable),
        errored=errored,
        verification_rate=round(rate, 2),
        hallucination_rate=round(1 - rate, 2),
        calibrated_confidence=round(rate, 2),
        action=action,
        reason=f"{len(verified)}/{len(verifiable)} claims verified",
        per_claim=verified_claims,
    )
