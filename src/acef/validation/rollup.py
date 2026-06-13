"""ACEF provision rollup — 7-step deterministic precedence algorithm.

Per spec Section 3.7:
1. Any fail-severity rule failed → NOT_SATISFIED
2. Any rule errored → NOT_ASSESSED
3. All rules skipped → SKIPPED
4. Evidence gap exists, no fails failed → GAP_ACKNOWLEDGED
5. All fails passed, some warnings failed → PARTIALLY_SATISFIED
6. All non-skipped rules passed → SATISFIED (LITERAL: a failed info-severity
   rule means NOT all passed, so it falls through to NOT_ASSESSED, never SATISFIED)
7. No rules for provision (or a residual info-failed mix matching no step) → NOT_ASSESSED
"""

from __future__ import annotations

from acef.models.assessment import ProvisionSummary, RuleResult
from acef.models.enums import ProvisionOutcome, RuleOutcome, RuleSeverity
from acef.models.records import RecordEnvelope


def compute_provision_outcome(
    provision_id: str,
    profile_id: str,
    rule_results: list[RuleResult],
    records: list[RecordEnvelope],
    *,
    subject_scope: list[str] | None = None,
) -> ProvisionSummary:
    """Compute the provision outcome using the 7-step precedence algorithm.

    Args:
        provision_id: The provision being assessed.
        profile_id: The profile/template ID.
        rule_results: All rule results for this provision.
        records: All evidence records (for checking evidence_gap).
        subject_scope: Subject URNs this summary covers.

    Returns:
        A ProvisionSummary with the computed outcome.
    """
    if subject_scope is None:
        subject_scope = []

    # Filter results for this provision. Per spec §3.5 + §3.7 "extension
    # semantics", vendor-namespaced (x-*) rule outcomes MUST NOT affect
    # standard ACEF conformance. Pull such rules out of the rollup —
    # they remain visible in assessment.results[] for informational
    # purposes but cannot drive provision_outcome.
    provision_results = [r for r in rule_results if r.provision_id == provision_id and not r.rule_id.startswith("x-")]

    # Count by outcome and severity
    fail_count = 0
    warning_count = 0
    skipped_count = 0
    total = len(provision_results)

    all_evidence_refs: list[str] = []

    has_fail_severity_failed = False
    has_error = False
    all_skipped = True
    has_warning_failed = False
    # Step 6 is LITERAL ("If ALL rules have outcome: passed -> satisfied"): track
    # whether EVERY non-skipped result PASSED. An info-severity rule that FAILED
    # increments neither fail_count nor warning_count and trips none of steps 1-5,
    # but it means NOT all rules passed, so the provision MUST NOT roll up to
    # SATISFIED (assessment-rollup-1). Skipped rules are not-applicable and do not
    # block SATISFIED, so they are excluded from the all-passed tally.
    all_non_skipped_passed = True

    for result in provision_results:
        all_evidence_refs.extend(result.evidence_refs)

        if result.outcome == RuleOutcome.SKIPPED:
            skipped_count += 1
        else:
            all_skipped = False
            if result.outcome != RuleOutcome.PASSED:
                all_non_skipped_passed = False

        if result.outcome == RuleOutcome.ERROR:
            has_error = True

        if result.outcome == RuleOutcome.FAILED:
            if result.rule_severity == RuleSeverity.FAIL:
                fail_count += 1
                has_fail_severity_failed = True
            elif result.rule_severity == RuleSeverity.WARNING:
                warning_count += 1
                has_warning_failed = True

    # Check for evidence gaps for this provision, honoring subject_scope.
    # Spec §3.7 evaluates provisions per-subject by default. An evidence_gap
    # record bound only to subject A must NOT mask missing evidence when the
    # provision is being assessed for subject B. Filter the gap-detection to
    # records whose entity_refs.subject_refs intersect subject_scope (or are
    # empty, meaning package-wide acknowledgment that applies to every
    # subject).
    def _gap_applies(r: RecordEnvelope) -> bool:
        if r.record_type != "evidence_gap":
            return False
        if provision_id not in r.provisions_addressed:
            return False
        if not subject_scope:
            # Caller is doing package-scope evaluation; any gap applies.
            return True
        gap_subjects = list(r.entity_refs.subject_refs) if r.entity_refs else []
        if not gap_subjects:
            # Package-wide gap with no subject binding applies to all subjects.
            return True
        return any(s in subject_scope for s in gap_subjects)

    has_evidence_gap = any(_gap_applies(r) for r in records)

    # 7-step precedence algorithm (first match wins)
    if total == 0:
        # Step 7: No rules for provision
        outcome = ProvisionOutcome.NOT_ASSESSED
    elif has_fail_severity_failed:
        # Step 1: Any fail-severity rule failed
        outcome = ProvisionOutcome.NOT_SATISFIED
    elif has_error:
        # Step 2: Any rule errored
        outcome = ProvisionOutcome.NOT_ASSESSED
    elif all_skipped:
        # Step 3: All rules skipped
        outcome = ProvisionOutcome.SKIPPED
    elif has_evidence_gap:
        # Step 4: Evidence gap acknowledged (no fail-severity failures since step 1 didn't match)
        outcome = ProvisionOutcome.GAP_ACKNOWLEDGED
    elif has_warning_failed:
        # Step 5: All fail-severity rules passed (step 1 didn't match), some warnings failed
        outcome = ProvisionOutcome.PARTIALLY_SATISFIED
    elif all_non_skipped_passed:
        # Step 6 (LITERAL): every non-skipped rule PASSED -> satisfied. Skipped
        # rules are not-applicable, so a mix of passed + skipped with no
        # failures/errors is satisfied. A FAILED info-severity rule clears
        # ``all_non_skipped_passed`` here (it tripped none of steps 1-5), so it
        # falls through to the documented NOT_ASSESSED fallback below rather than
        # being reported as fully SATISFIED (assessment-rollup-1).
        outcome = ProvisionOutcome.SATISFIED
    else:
        # Fallback: reached when a non-fail/non-warning rule (i.e. an info-severity
        # rule) has outcome=failed and nothing in steps 1-5 matched. The spec §3.7
        # precedence defines no info-driven slot, so a residual info-failed mix
        # falls through to the documented NOT_ASSESSED outcome (step 7's outcome) —
        # it is NOT SATISFIED because not all rules passed.
        outcome = ProvisionOutcome.NOT_ASSESSED

    # Deduplicate evidence refs
    unique_refs = list(dict.fromkeys(all_evidence_refs))

    return ProvisionSummary(
        provision_id=provision_id,
        profile_id=profile_id,
        provision_outcome=outcome,
        subject_scope=subject_scope,
        fail_count=fail_count,
        warning_count=warning_count,
        skipped_count=skipped_count,
        evidence_refs=unique_refs,
    )
