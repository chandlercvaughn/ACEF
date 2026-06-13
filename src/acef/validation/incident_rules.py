"""ACEF RFC-0002 offline incident validation rules (v1.1, core_version 1.1.0).

This module carries the OFFLINE-DETERMINISTIC and SOURCE-BACKED incident
validation rules for the v1.1 incident-reporting profile. It is invoked ONLY
from the v1.1 dispatch in :mod:`acef.validation.engine` (after the resolved
schema version is ``v1.1``), so a v1.0 bundle (no ``core_version: 1.1.0``)
validates identically to pre-operation behavior — none of these rules fire
(VAL-VLD-001 / regression-safety per VAL-REGRESSION-001).

Rule families (RFC-0002 §7; reserved error band ACEF-081..088 only):

- **ACEF-081** — incident profile declared but ``taxonomy_crosswalk`` is missing a
  mandatory member (§5.7).
- **ACEF-082** — ``severity_vector`` present but not parseable against the
  ``ACEF-SEV:1.0`` grammar (§5.4).
- **ACEF-083** — ``public_incident_id`` OFFLINE id-trust failure (§5.3). HONESTY
  DISCIPLINE: the offline class checks pattern + (optional) bundled-snapshot
  membership + (optional) self-contained JWS consistency, computed wholly from
  bundle bytes, and NEVER attributes the id to the assigner domain. A forged
  ``AIIC-OPENAI-…`` card with a valid pattern (and no contradicting snapshot/JWS)
  PASSES the offline class by design — attribution is the OPTIONAL online
  domain-control verifier's job (a separate module, F-M3-DOMAIN-CONTROL), not
  this one. An offline failure is class-tagged ``offline-deterministic``.
- **ACEF-084** — Art. 73 ``regulatory_timeline`` deadline inconsistent with the
  shortest applicable clock; AND (ART73-DELEGATED) the existential dual-source
  rule + the ``framework == "eu-ai-act-art73"`` match rule (§5.7).
- **ACEF-085** — a present ``taxonomy_crosswalk`` member contradicts the value
  derived from ``harm_core`` (§5.5, harm-core-taxonomy derivation rows).
- **ACEF-086** — public disclosure without satisfying the §5.11 publishability
  gate (declared_publication_basis, commitment linkage, pointer resolution).
- **ACEF-087** — ``realization`` is ``near_miss``: an INFO marker, never a failure
  (§5.5).
- **ACEF-088** — a record carries BOTH ``severity`` and ``severity_vector`` and the
  coarse ``severity`` disagrees with ``band(severity_vector)`` (§5.4).

Every function returns a list of :class:`ValidationDiagnostic`; the engine merges
them into ``AssessmentBundle.structural_errors``. Determinism: rules iterate
records and arrays in given order; no wall-clock or random values are read.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any

from acef.errors import ACEFProfileError, Severity, ValidationDiagnostic
from acef.integrity import canonicalize, sha256_hex
from acef.templates.registry import load_template

# ---------------------------------------------------------------------------
# Constants — RFC-0002 §5.7 Art. 73 profile id and clock days.
# ---------------------------------------------------------------------------

ART73_PROFILE_ID = "eu-ai-act-art73-2026"
ART73_TIMELINE_FRAMEWORK = "eu-ai-act-art73"

# §5.7 shortest-applicable-clock days.
_DEATH_CLOCK_DAYS = 10
_SHORT_CLOCK_DAYS = 2  # 3.49.b (critical-infrastructure) OR widespread
_GENERAL_CLOCK_DAYS = 15

_PUBLIC_INCIDENT_ID_PATTERN = re.compile(r"^AIIC-([A-Z0-9]{2,8})-([0-9]{4})-[0-9A-HJKMNP-TV-Z]{26,}$")

# §5.4 — the mandatory Group-I prefix the band() projection keys on. The full
# wire grammar lives in severity_vector.schema.json; band() needs only the
# Group-I metrics HG (gravity), BR (breadth), RV (reversibility). HT/SC are
# parsed for grammar-conformance but excluded from the band (HT is
# incommensurable, SC is folded into BR per §5.4).
_SEV_VECTOR_PATTERN = re.compile(
    r"^ACEF-SEV:1\.0/HT:[PRKES]/HG:[HLN]/RV:[AUI]/SC:[CU]/BR:[IGP]"
    r"(/RZ:[ESN])?(/RP:(0(\.[0-9]+)?|1(\.0+)?)@[1-9][0-9]*)?(/XF:[YNX])?"
    r"(/AU:[LOA])?(/EX:[HLN])?(/KC:[HML])?(/SF:[PN])?(/VL:[FTAC])?(/DB:[YN])?$"
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _records_iter(records: list[dict[str, Any]]) -> Iterator[tuple[int, dict[str, Any]]]:
    for idx, r in enumerate(records):
        if isinstance(r, dict):
            yield idx, r


def _record_id_of(rec: dict[str, Any]) -> str:
    rid = rec.get("record_id", "")
    return rid if isinstance(rid, str) else ""


def _record_type_of(rec: dict[str, Any]) -> str:
    rt = rec.get("record_type", "")
    return rt if isinstance(rt, str) else ""


def _payload_of(rec: dict[str, Any]) -> dict[str, Any]:
    p = rec.get("payload")
    return p if isinstance(p, dict) else {}


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _coordinated_disclosure_of(payload: dict[str, Any]) -> dict[str, Any]:
    """Resolve coordinated_disclosure on an incident_card payload or on a
    card_source block carried by an incident_report payload."""
    cd = payload.get("coordinated_disclosure")
    if isinstance(cd, dict):
        return cd
    cs = _as_dict(payload.get("card_source"))
    cd2 = cs.get("coordinated_disclosure")
    return cd2 if isinstance(cd2, dict) else {}


# ---------------------------------------------------------------------------
# band() — §5.4 normative band() projection (severity_vector.schema.json)
# ---------------------------------------------------------------------------


def band(severity_vector: str) -> str | None:
    """Project an ``ACEF-SEV:1.0`` vector to the coarse ``severity`` enum.

    Implements the NORMATIVE band() table from §5.4 (reproduced in
    severity_vector.schema.json#/$defs/band_table). Inputs are the Group-I
    metrics HG (gravity), BR (breadth), RV (reversibility). Evaluate top-to-
    bottom; the FIRST matching row wins:

        1. HG:H AND (BR:P OR RV:I)  -> critical
        2. HG:H                     -> major
        3. HG:L AND (BR:P OR RV:I)  -> major
        4. HG:L                     -> minor
        5. HG:N                     -> informational

    Returns ``None`` when ``severity_vector`` is not a string or does not parse
    against the ACEF-SEV:1.0 grammar (a non-bandable / HG-less vector). HT is
    deliberately EXCLUDED (harm types are incommensurable); SC is folded into BR
    rather than scored twice (§5.4); RP prevalence never changes the band.
    """
    if not isinstance(severity_vector, str):
        return None
    if _SEV_VECTOR_PATTERN.match(severity_vector) is None:
        return None
    metrics = _parse_sev_metrics(severity_vector)
    hg = metrics.get("HG")
    br = metrics.get("BR")
    rv = metrics.get("RV")
    escalate = br == "P" or rv == "I"
    if hg == "H":
        return "critical" if escalate else "major"
    if hg == "L":
        return "major" if escalate else "minor"
    if hg == "N":
        return "informational"
    return None


def _parse_sev_metrics(severity_vector: str) -> dict[str, str]:
    """Parse a grammar-valid ACEF-SEV vector into a ``{metric: value}`` map.

    Assumes the vector already matched :data:`_SEV_VECTOR_PATTERN`. Splits on
    ``/`` and reads each ``Name:Value`` pair (skipping the ``ACEF-SEV:1.0``
    prefix segment). RP carries an ``@`` (``RP:<rate>@<N>``) but is never a band
    input, so its raw value is stored verbatim.
    """
    out: dict[str, str] = {}
    parts = severity_vector.split("/")
    for segment in parts[1:]:  # parts[0] == "ACEF-SEV:1.0"
        name, sep, value = segment.partition(":")
        if sep and name:
            out[name] = value
    return out


def is_parseable_severity_vector(severity_vector: Any) -> bool:
    """True iff ``severity_vector`` is a string conforming to ACEF-SEV:1.0."""
    return isinstance(severity_vector, str) and _SEV_VECTOR_PATTERN.match(severity_vector) is not None


# ---------------------------------------------------------------------------
# Art. 73 clock — §5.7 shortest applicable clock
# ---------------------------------------------------------------------------


def shortest_art73_clock_days(eu_ai_act_facts: dict[str, Any]) -> int:
    """Return the shortest applicable Art. 73 reporting clock in days (§5.7).

    Rule (shortest applicable for compound incidents):

        death_involved: true            -> 10 days
        3.49.b OR widespread            -> 2 days
        else                            -> 15 days

    The 2-day clock wins over the 10-day clock for a compound death + 3.49.b
    incident (shortest applicable). ``serious_incident_triggers`` is read as a
    SET; ``widespread`` / ``death_involved`` are booleans. Non-dict / wrong-typed
    facts fall back to the general 15-day clock (the schema phase diagnoses the
    type error separately).
    """
    facts = _as_dict(eu_ai_act_facts)
    triggers = {t for t in _as_list(facts.get("serious_incident_triggers")) if isinstance(t, str)}
    widespread = facts.get("widespread") is True
    death = facts.get("death_involved") is True

    candidates: list[int] = [_GENERAL_CLOCK_DAYS]
    if death:
        candidates.append(_DEATH_CLOCK_DAYS)
    if "3.49.b" in triggers or widespread:
        candidates.append(_SHORT_CLOCK_DAYS)
    return min(candidates)


def _parse_instant(value: Any) -> datetime | None:
    """Parse an ISO 8601 date-time (Zulu or offset) into a UTC datetime."""
    if not isinstance(value, str) or not value:
        return None
    candidate = value.strip()
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def _eu_facts_for_clock(payload: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
    """Return ``(facts, source_kind)`` for the Art. 73 clock.

    Source of the trigger facts depends on validation context (§5.7):
    - confidential/source-backed: ``incident_report.card_source.eu_ai_act_facts``
    - public-card: ``incident_card.taxonomy_crosswalk.eu_ai_act``

    ``source_kind`` is ``"card_source"`` or ``"taxonomy_crosswalk"`` (or ``""``
    when neither path carries facts). card_source is preferred when present.
    """
    card_source = _as_dict(payload.get("card_source"))
    facts = card_source.get("eu_ai_act_facts")
    if isinstance(facts, dict):
        return facts, "card_source"
    crosswalk = _as_dict(payload.get("taxonomy_crosswalk"))
    eu = crosswalk.get("eu_ai_act")
    if isinstance(eu, dict):
        return eu, "taxonomy_crosswalk"
    return None, ""


def _art73_facts_complete(facts: dict[str, Any]) -> bool:
    """True iff an ``eu_ai_act`` fact block carries the FULL Art.73 trigger set the
    shortest-clock derivation depends on (§5.7): at least one ``serious_incident_triggers``
    member AND BOTH ``widespread`` and ``death_involved`` as explicit BOOLEANS.

    The confidential ``card_source.eu_ai_act_facts`` schema already REQUIRES both
    booleans; this helper applies the SAME completeness requirement to the public
    ``taxonomy_crosswalk.eu_ai_act`` path. Without it, a public card declaring only
    triggers + id would let the clock silently DEFAULT ``widespread`` /
    ``death_involved`` to ``false`` and accept a wrong 15-day deadline instead of
    surfacing the missing facts. An incomplete declared-Art.73 fact block is NOT a
    valid clock source — it is an ACEF-084 (missing required Art.73 facts) failure.
    """
    triggers = [t for t in _as_list(facts.get("serious_incident_triggers")) if isinstance(t, str)]
    if not triggers:
        return False
    if not isinstance(facts.get("widespread"), bool):
        return False
    if not isinstance(facts.get("death_involved"), bool):
        return False
    return True


def _has_art73_facts(payload: dict[str, Any]) -> bool:
    """True iff this payload carries public_incident_id + a COMPLETE Art.3(49) trigger
    fact block on EITHER the public path or the confidential card_source path (§5.7).

    "Complete" requires the booleans ``widespread`` + ``death_involved`` (the
    shortest-clock inputs) to be PRESENT, not silently defaulted — see
    :func:`_art73_facts_complete`. An incomplete public fact block does NOT satisfy
    the existential dual-source rule (it cannot anchor a correct clock)."""
    facts, kind = _eu_facts_for_clock(payload)
    if facts is None or not kind:
        return False
    if not _art73_facts_complete(facts):
        return False
    # The public_incident_id lives on the card payload, or on card_source.
    pid = payload.get("public_incident_id")
    if not isinstance(pid, str) or not pid:
        cs = _as_dict(payload.get("card_source"))
        pid = cs.get("public_incident_id")
    return isinstance(pid, str) and bool(pid)


def check_art73_clock(
    records: list[dict[str, Any]],
    *,
    profiles: list[str],
) -> list[ValidationDiagnostic]:
    """ACEF-084: the stated Art. 73 ``regulatory_timeline`` deadline MUST equal the
    shortest applicable clock (§5.7). Only evaluated when ``eu-ai-act-art73-2026``
    is among the declared ``profiles``.

    For each incident record carrying eu_ai_act facts (source-backed or public),
    locate the ``coordinated_disclosure.regulatory_timeline[]`` entry whose
    ``framework == "eu-ai-act-art73"`` and compare its computed ``deadline`` to
    ``awareness_date + shortest_clock``. A mismatch (or a missing deadline on a
    framework-matched entry) raises ACEF-084.
    """
    if ART73_PROFILE_ID not in profiles:
        return []

    diags: list[ValidationDiagnostic] = []
    for _idx, rec in _records_iter(records):
        if _record_type_of(rec) not in ("incident_card", "incident_report"):
            continue
        payload = _payload_of(rec)
        facts, kind = _eu_facts_for_clock(payload)
        if facts is None or not kind:
            continue
        # A declared-Art.73 fact block MUST carry the full shortest-clock input set
        # (>=1 trigger + boolean widespread + boolean death_involved). An incomplete
        # block (e.g. a public taxonomy_crosswalk.eu_ai_act with triggers + id but no
        # widespread/death_involved) must NOT silently default the missing booleans
        # to false and pass a wrong 15-day deadline — raise ACEF-084 (missing facts).
        if not _art73_facts_complete(facts):
            diags.append(
                ValidationDiagnostic(
                    "ACEF-084",
                    (
                        f"Record {_record_id_of(rec)!r}: eu-ai-act-art73-2026 declared and the Art.73 "
                        f"fact block (read from {kind}) is INCOMPLETE — it must carry at least one "
                        f"serious_incident_triggers member AND boolean 'widespread' AND boolean "
                        f"'death_involved' (the shortest-clock inputs, §5.7). The clock MUST NOT "
                        f"default the missing booleans to false. Add the missing widespread / "
                        f"death_involved facts at {kind}."
                    ),
                    path=f"/{_record_id_of(rec)}/{kind}",
                )
            )
            continue
        clock_days = shortest_art73_clock_days(facts)
        cd = _coordinated_disclosure_of(payload)
        timeline = _as_list(cd.get("regulatory_timeline"))
        for entry in timeline:
            if not isinstance(entry, dict):
                continue
            if entry.get("framework") != ART73_TIMELINE_FRAMEWORK:
                continue
            awareness = _parse_instant(entry.get("awareness_date"))
            stated_deadline = _parse_instant(entry.get("deadline"))
            if awareness is None:
                continue  # schema phase diagnoses the missing/invalid awareness_date
            expected = awareness + timedelta(days=clock_days)
            if stated_deadline is None or stated_deadline != expected:
                diags.append(
                    ValidationDiagnostic(
                        "ACEF-084",
                        (
                            f"Record {_record_id_of(rec)!r}: eu-ai-act-art73-2026 declared and the "
                            f"stated regulatory_timeline deadline "
                            f"({entry.get('deadline')!r}) is inconsistent with the shortest "
                            f"applicable clock ({clock_days} days from awareness_date "
                            f"{entry.get('awareness_date')!r} -> {expected.isoformat()}; trigger "
                            f"facts read from {kind}). death_involved -> 10 days; 3.49.b or "
                            f"widespread -> 2 days; else 15 days (§5.7)."
                        ),
                        path=f"/{_record_id_of(rec)}/coordinated_disclosure/regulatory_timeline",
                    )
                )
    return diags


def check_art73_existential(
    records: list[dict[str, Any]],
    *,
    profiles: list[str],
) -> list[ValidationDiagnostic]:
    """ACEF-084 (ART73-DELEGATED): the existential dual-source + framework-match
    enforcement the generic template DSL cannot express (§5.7, boundaries.md
    §ART73-DELEGATED). Only evaluated when ``eu-ai-act-art73-2026`` is declared.

    Two conditions, both of which MUST hold for an Art. 73 bundle:

    1. **Existential dual-source.** At least ONE incident record carries
       ``public_incident_id`` + Art.3(49) trigger facts on the public path
       (``incident_card.taxonomy_crosswalk.eu_ai_act``) OR the confidential path
       (``incident_report.card_source.eu_ai_act_facts``). A reserved-id
       no-public-card report is satisfied by card_source alone; an empty /
       no-evidence Art. 73 bundle FAILS.
    2. **regulatory_timeline framework-match.** Some order-insensitive
       ``coordinated_disclosure.regulatory_timeline[]`` entry on a fact-carrying
       record has ``framework == "eu-ai-act-art73"`` (with awareness_date +
       deadline). An empty ``regulatory_timeline: []`` does NOT satisfy this.
    """
    if ART73_PROFILE_ID not in profiles:
        return []

    diags: list[ValidationDiagnostic] = []
    fact_carriers: list[dict[str, Any]] = []
    for _idx, rec in _records_iter(records):
        if _record_type_of(rec) not in ("incident_card", "incident_report"):
            continue
        payload = _payload_of(rec)
        if _has_art73_facts(payload):
            fact_carriers.append(payload)

    if not fact_carriers:
        diags.append(
            ValidationDiagnostic(
                "ACEF-084",
                (
                    "eu-ai-act-art73-2026 declared but NO incident record carries "
                    "public_incident_id + Art.3(49) trigger facts on either the public path "
                    "(incident_card.taxonomy_crosswalk.eu_ai_act) or the confidential path "
                    "(incident_report.card_source.eu_ai_act_facts) — the existential dual-source "
                    "rule fails (§5.7). Add the trigger facts at one of those paths."
                ),
            )
        )
        return diags

    # framework-match: at least one fact-carrying record must have a matching
    # eu-ai-act-art73 regulatory_timeline entry.
    matched = False
    for payload in fact_carriers:
        cd = _coordinated_disclosure_of(payload)
        for entry in _as_list(cd.get("regulatory_timeline")):
            if isinstance(entry, dict) and entry.get("framework") == ART73_TIMELINE_FRAMEWORK:
                matched = True
                break
        if matched:
            break
    if not matched:
        diags.append(
            ValidationDiagnostic(
                "ACEF-084",
                (
                    "eu-ai-act-art73-2026 declared but no coordinated_disclosure.regulatory_timeline[] "
                    "entry has framework == 'eu-ai-act-art73' (an empty regulatory_timeline: [] or a "
                    "non-EU-only timeline does NOT satisfy the framework-match rule, §5.7). Add a "
                    "matching eu-ai-act-art73 timeline entry with awareness_date + deadline."
                ),
            )
        )
    return diags


# ---------------------------------------------------------------------------
# ACEF-081 — crosswalk missing a mandatory member for a declared profile
# ---------------------------------------------------------------------------

# Per-profile mandatory crosswalk members (§5.7). eu-ai-act-art73-2026 requires
# the eu_ai_act member; oecd-ai-incidents-2025 requires the oecd member.
_MANDATORY_CROSSWALK_MEMBERS: dict[str, str] = {
    ART73_PROFILE_ID: "eu_ai_act",
    "oecd-ai-incidents-2025": "oecd",
}

# legal_force values that make a profile's diagnostics ADVISORY (non-binding):
# an unmet criterion surfaces a warning, never an error that blocks conformance.
_ADVISORY_LEGAL_FORCES: frozenset[str] = frozenset({"voluntary", "advisory"})


@lru_cache(maxsize=32)
def _profile_legal_force(profile_id: str) -> str:
    """Return the declared ``legal_force`` of a profile's crosswalk template.

    Loads the template through the registry (the single source of truth) and
    reads its ``legal_force`` field (``binding`` | ``voluntary`` | ``advisory``).
    A profile with NO template on disk (an unknown id), or a template that omits
    ``legal_force``, defaults to ``"binding"`` — the STRICT behavior — so an
    unknown or unmarked profile is never silently downgraded to advisory. Only a
    template that explicitly declares ``voluntary`` / ``advisory`` relaxes a
    diagnostic to advisory severity (Finding 1).
    """
    try:
        template = load_template(profile_id)
    except ACEFProfileError:
        return "binding"
    force = getattr(template, "legal_force", "") or ""
    return force if isinstance(force, str) and force else "binding"


def _is_advisory_profile(profile_id: str) -> bool:
    """True iff the profile's template is voluntary/advisory (non-binding)."""
    return _profile_legal_force(profile_id) in _ADVISORY_LEGAL_FORCES


def _advisory_severity(diag: ValidationDiagnostic) -> ValidationDiagnostic:
    """Downgrade a diagnostic to WARNING severity in place and return it.

    The error CODE stays within the reserved incident band (ACEF-081..088); only
    the SEVERITY is relaxed from ERROR to WARNING so a voluntary/advisory profile's
    finding is non-binding (it does not block conformance) while remaining visible.
    ``ValidationDiagnostic`` resolves severity from the code at construction; this
    overrides that resolution for the context-dependent (legal_force-aware) case.
    """
    diag.severity = Severity.WARNING
    return diag


def check_crosswalk_mandatory_members(
    records: list[dict[str, Any]],
    *,
    profiles: list[str],
) -> list[ValidationDiagnostic]:
    """ACEF-081: an incident profile is declared but the card's
    ``taxonomy_crosswalk`` is missing the mandatory member for that profile
    (§5.7). The diagnostic carries the ``profile_id`` and an RFC 6901 ``path``.

    **legal_force-aware (Finding 1).** The diagnostic's binding-ness follows the
    declared profile's template ``legal_force`` (looked up via the registry):

    - a **binding** profile (e.g. ``eu-ai-act-art73-2026``) keeps ACEF-081 at its
      registered ERROR severity — a missing mandatory member blocks conformance;
    - a **voluntary/advisory** profile (e.g. ``oecd-ai-incidents-2025``) surfaces
      the same gap as an ADVISORY (WARNING) ACEF-081 — visible but non-binding,
      consistent with the template's ``legal_force: voluntary`` marking. Encoding
      a voluntary benchmark's unmet member as a binding error would misrepresent
      it as conformance-blocking law.

    An unknown / unmarked profile defaults to binding (strict) — see
    :func:`_profile_legal_force`.

    Confidential/source-backed Art. 73 reports validate from
    ``card_source.eu_ai_act_facts`` and need not carry a public
    ``taxonomy_crosswalk`` member, so a record whose Art.73 facts live on the
    card_source path is exempt from the eu_ai_act crosswalk requirement.
    """
    diags: list[ValidationDiagnostic] = []
    for profile_id in profiles:
        member = _MANDATORY_CROSSWALK_MEMBERS.get(profile_id)
        if member is None:
            continue
        advisory = _is_advisory_profile(profile_id)
        for _idx, rec in _records_iter(records):
            if _record_type_of(rec) != "incident_card":
                continue
            payload = _payload_of(rec)
            crosswalk = _as_dict(payload.get("taxonomy_crosswalk"))
            if member in crosswalk:
                continue
            force = _profile_legal_force(profile_id)
            if advisory:
                tail = (
                    f"This profile is legal_force={force!r}, so the gap is ADVISORY "
                    f"(non-binding): add the {member!r} crosswalk member to align with the "
                    f"framework, or remove the profile declaration."
                )
            else:
                tail = f"Add the {member!r} crosswalk member, or remove the profile declaration."
            diag = ValidationDiagnostic(
                "ACEF-081",
                (
                    f"incident profile {profile_id!r} declared but taxonomy_crosswalk on "
                    f"record {_record_id_of(rec)!r} is missing the mandatory member "
                    f"{member!r} (§5.7). {tail}"
                ),
                path=f"/{_record_id_of(rec)}/taxonomy_crosswalk/{member}",
                details={"profile_id": profile_id, "legal_force": force},
            )
            diags.append(_advisory_severity(diag) if advisory else diag)
    return diags


# ---------------------------------------------------------------------------
# OECD mandatory-core completeness — advisory (Finding 2)
# ---------------------------------------------------------------------------

OECD_PROFILE_ID = "oecd-ai-incidents-2025"
_OECD_EDITION = "oecd-crf-2025"


@lru_cache(maxsize=1)
def _oecd_mandatory_ordinals() -> tuple[int, ...]:
    """Return the 7 OECD mandatory criterion ordinals, read from the OECD template.

    SINGLE SOURCE OF TRUTH: the ordinals come from
    ``oecd_framework.mandatory_criteria_ordinals`` in the OECD template, accessed
    through the registry-loaded :class:`~acef.templates.models.Template` (whose
    ``extra="allow"`` config preserves the template-level ``oecd_framework`` block
    in ``model_extra``). Reading via ``load_template`` — rather than a raw-file
    ``json.loads`` — guarantees the completeness check and the loaded template can
    never diverge. Returns an empty tuple if the template is unavailable or the
    block is malformed (defensive — the completeness check then becomes a no-op
    rather than crashing).
    """
    try:
        template = load_template(OECD_PROFILE_ID)
    except ACEFProfileError:
        return ()
    extra = template.model_extra or {}
    framework = extra.get("oecd_framework")
    if not isinstance(framework, dict):
        return ()
    ordinals = framework.get("mandatory_criteria_ordinals")
    if not isinstance(ordinals, list):
        return ()
    return tuple(o for o in ordinals if isinstance(o, int))


def _oecd_criterion_id(ordinal: int) -> str:
    """The ACEF-local OECD criterion id for an ordinal (``oecd-crf-2025/<n>``, §5.5)."""
    return f"{_OECD_EDITION}/{ordinal}"


def _present_oecd_criterion_ids(oecd_member: dict[str, Any]) -> set[str]:
    """Collect the set of ``criteria[].id`` strings present on an OECD crosswalk
    member, order-insensitive (§5.10). Non-dict / id-less entries are ignored."""
    present: set[str] = set()
    for entry in _as_list(oecd_member.get("criteria")):
        if isinstance(entry, dict):
            cid = entry.get("id")
            if isinstance(cid, str) and cid:
                present.add(cid)
    return present


def check_oecd_mandatory_core_completeness(
    records: list[dict[str, Any]],
    *,
    profiles: list[str],
) -> list[ValidationDiagnostic]:
    """Advisory OECD mandatory-core completeness (Finding 2).

    Only evaluated when ``oecd-ai-incidents-2025`` is among the declared
    ``profiles``. For each ``incident_card`` whose ``taxonomy_crosswalk.oecd``
    member is PRESENT, scan ``criteria[].id`` (order-insensitive) for the 7
    mandatory OECD ordinals (#1,#2,#3,#4,#7,#10,#11 — read from the OECD template
    metadata, the single source of truth). Any missing mandatory id surfaces an
    ADVISORY (WARNING) diagnostic listing the gaps.

    DISCIPLINE:

    - This is the per-ordinal array-scan completeness the generic template DSL
      cannot express (``criteria[]`` is an order-insensitive array; ``exists_where``
      resolves a single RFC-6901 pointer and jsonpointer has no array-wildcard), so
      it is correctly delegated to this validator (per the template's
      ``validator_delegated_enforcement`` block).
    - It is NEVER binding. The OECD framework is ``legal_force: voluntary``; a
      missing mandatory criterion is the framework's own completeness gap, not an
      ACEF conformance fail. The diagnostic carries WARNING severity within the
      reserved ACEF-081 band.
    - When the ``oecd`` member is ABSENT, this is a no-op (the missing-member case
      is handled by the legal_force-aware ACEF-081 advisory in
      :func:`check_crosswalk_mandatory_members`).
    """
    if OECD_PROFILE_ID not in profiles:
        return []
    mandatory = _oecd_mandatory_ordinals()
    if not mandatory:
        return []

    diags: list[ValidationDiagnostic] = []
    for _idx, rec in _records_iter(records):
        if _record_type_of(rec) != "incident_card":
            continue
        payload = _payload_of(rec)
        crosswalk = _as_dict(payload.get("taxonomy_crosswalk"))
        oecd_member = crosswalk.get("oecd")
        if not isinstance(oecd_member, dict):
            continue  # missing-member case handled by ACEF-081 (advisory)
        present = _present_oecd_criterion_ids(oecd_member)
        missing = [_oecd_criterion_id(o) for o in mandatory if _oecd_criterion_id(o) not in present]
        if not missing:
            continue
        missing_list = ", ".join(missing)
        diag = ValidationDiagnostic(
            "ACEF-081",
            (
                f"ADVISORY (voluntary, non-binding): record {_record_id_of(rec)!r} declares an OECD "
                f"taxonomy_crosswalk.oecd member but is MISSING {len(missing)} of the 7 mandatory OECD "
                f"core criteria — {missing_list}. The OECD common reporting framework is "
                f"legal_force=voluntary, so this completeness gap surfaces advisory (warning), never a "
                f"binding fail. Add criteria[] entries for the missing mandatory ordinals to complete "
                f"the OECD mandatory core (§5.5)."
            ),
            path=f"/{_record_id_of(rec)}/taxonomy_crosswalk/oecd/criteria",
            details={
                "profile_id": OECD_PROFILE_ID,
                "legal_force": "voluntary",
                "missing_mandatory_criteria": missing,
            },
        )
        diags.append(_advisory_severity(diag))
    return diags


# ---------------------------------------------------------------------------
# ACEF-082 — severity_vector unparseable against ACEF-SEV:1.0
# ---------------------------------------------------------------------------


def check_severity_vector_parse(records: list[dict[str, Any]]) -> list[ValidationDiagnostic]:
    """ACEF-082: a present ``severity_vector`` that does not parse against the
    ``ACEF-SEV:1.0`` grammar (§5.4). Reads the vector from the card payload or
    from a card_source block. Absent vectors are a no-op."""
    diags: list[ValidationDiagnostic] = []
    for _idx, rec in _records_iter(records):
        if _record_type_of(rec) not in ("incident_card", "incident_report"):
            continue
        payload = _payload_of(rec)
        for container, where in ((payload, ""), (_as_dict(payload.get("card_source")), "/card_source")):
            sv = container.get("severity_vector")
            if sv is None:
                continue
            if not is_parseable_severity_vector(sv):
                diags.append(
                    ValidationDiagnostic(
                        "ACEF-082",
                        (
                            f"Record {_record_id_of(rec)!r}: severity_vector present but not "
                            f"parseable against the ACEF-SEV:1.0 grammar (§5.4). Emit a vector "
                            f"conforming to ACEF-SEV:1.0 (full mandatory Group-I HT/HG/RV/SC/BR), "
                            f"or omit severity_vector."
                        ),
                        path=f"/{_record_id_of(rec)}{where}/severity_vector",
                    )
                )
    return diags


# ---------------------------------------------------------------------------
# ACEF-083 — offline public_incident_id id-trust (NO attribution)
# ---------------------------------------------------------------------------


def _bundled_assigner_snapshot(manifest: dict[str, Any]) -> list[dict[str, Any]] | None:
    """Return the bundled ``{assigner, public_key}`` assigner-registry snapshot if
    the bundle embeds one, else ``None`` (the snapshot sub-check is skipped).

    The snapshot is an OPTIONAL local list a bundle MAY embed under
    ``manifest.namespaces['x-acef-incident'].assigner_registry_snapshot`` (§5.3).
    It is consulted ONLY when present; it is NEVER a network or central lookup.
    """
    namespaces = _as_dict(manifest.get("namespaces"))
    for ns_value in namespaces.values():
        ns = _as_dict(ns_value)
        snap = ns.get("assigner_registry_snapshot")
        if isinstance(snap, list):
            return [s for s in snap if isinstance(s, dict)]
    return None


def check_public_incident_id_offline(
    records: list[dict[str, Any]],
    *,
    manifest: dict[str, Any],
) -> list[ValidationDiagnostic]:
    """ACEF-083 ``class: offline-deterministic`` (§5.3 / §7).

    The OFFLINE id-trust surface, computed WHOLLY from bundle bytes:

    1. **pattern** — ``public_incident_id`` matches ``AIIC-{assigner}-{year}-{suffix}``
       (assigner 2-8 uppercase alphanumerics, year 4 digits, suffix >=26
       Crockford-base32 chars).
    2. **bundled-snapshot membership** — ONLY IF the bundle embeds a
       ``{assigner, public_key}`` snapshot, ``{assigner}`` MUST be locally listed.
       Skipped entirely when no snapshot is bundled.

    HONESTY DISCIPLINE: this NEVER attributes the id to the assigner domain and
    performs NO network call, central allocation, registry admission, or
    global-uniqueness attestation. A forged ``AIIC-OPENAI-…`` card with a valid
    pattern and no contradicting snapshot PASSES offline by design — attribution
    is the OPTIONAL online domain-control verifier's job (F-M3-DOMAIN-CONTROL),
    not this offline rule.
    """
    snapshot = _bundled_assigner_snapshot(manifest)
    snapshot_assigners: set[str] | None = None
    if snapshot is not None:
        snapshot_assigners = set()
        for entry in snapshot:
            assigner_value = entry.get("assigner")
            if isinstance(assigner_value, str):
                snapshot_assigners.add(assigner_value)

    diags: list[ValidationDiagnostic] = []
    for _idx, rec in _records_iter(records):
        if _record_type_of(rec) not in ("incident_card", "incident_report"):
            continue
        payload = _payload_of(rec)
        for container, where in ((payload, ""), (_as_dict(payload.get("card_source")), "/card_source")):
            pid = container.get("public_incident_id")
            if pid is None:
                continue
            if not isinstance(pid, str):
                diags.append(
                    ValidationDiagnostic(
                        "ACEF-083",
                        (
                            f"Record {_record_id_of(rec)!r}: public_incident_id id-trust failure "
                            f"(class: offline-deterministic) — value is not a string. Correct it to "
                            f"the AIIC-{{assigner}}-{{year}}-{{random}} pattern (§5.3)."
                        ),
                        path=f"/{_record_id_of(rec)}{where}/public_incident_id",
                    )
                )
                continue
            match = _PUBLIC_INCIDENT_ID_PATTERN.match(pid)
            if match is None:
                diags.append(
                    ValidationDiagnostic(
                        "ACEF-083",
                        (
                            f"Record {_record_id_of(rec)!r}: public_incident_id id-trust failure "
                            f"(class: offline-deterministic) — {pid!r} does not match the "
                            f"AIIC-{{assigner}}-{{year}}-{{random}} pattern (§5.3). Correct the "
                            f"public_incident_id (assigner 2-8 uppercase alphanumerics, year 4 "
                            f"digits, suffix >=26 Crockford-base32 chars), and re-sign so the JWS "
                            f"verifies."
                        ),
                        path=f"/{_record_id_of(rec)}{where}/public_incident_id",
                    )
                )
                continue
            assigner = match.group(1)
            if snapshot_assigners is not None and assigner not in snapshot_assigners:
                diags.append(
                    ValidationDiagnostic(
                        "ACEF-083",
                        (
                            f"Record {_record_id_of(rec)!r}: public_incident_id id-trust failure "
                            f"(class: offline-deterministic) — assigner {assigner!r} is absent from "
                            f"the bundle's local assigner-registry snapshot (a LOCAL membership "
                            f"check, never a network or central lookup; §5.3). Bundle the assigner "
                            f"in the snapshot if one is referenced."
                        ),
                        path=f"/{_record_id_of(rec)}{where}/public_incident_id",
                    )
                )
    return diags


# ---------------------------------------------------------------------------
# ACEF-085 — crosswalk member contradicts harm_core derivation
# ---------------------------------------------------------------------------


def _harm_core_taxonomy_path() -> Path:
    """Resolve the v1.1 harm-core-taxonomy.json path (editable + wheel install)."""
    here = Path(__file__).resolve()
    for ancestor in here.parents:
        candidate = ancestor / "acef-conventions" / "v1.1" / "harm-core-taxonomy.json"
        if candidate.is_file():
            return candidate
    return Path("acef-conventions/v1.1/harm-core-taxonomy.json")


@lru_cache(maxsize=1)
def _load_harm_core_taxonomy() -> dict[str, Any]:
    """Load harm-core-taxonomy.json once per process (defensive: {} on error)."""
    try:
        data = json.loads(_harm_core_taxonomy_path().read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return {}
    return data if isinstance(data, dict) else {}


@lru_cache(maxsize=1)
def _derivation_rows_by_class() -> dict[str, dict[str, Any]]:
    """Return ``{harm_class: derivation_row}`` from harm-core-taxonomy.json."""
    tax = _load_harm_core_taxonomy()
    rows_block = _as_dict(tax.get("derivation_rows"))
    out: dict[str, dict[str, Any]] = {}
    for row in _as_list(rows_block.get("rows")):
        if isinstance(row, dict):
            hc = row.get("harm_class")
            if isinstance(hc, str):
                out[hc] = row
    return out


@lru_cache(maxsize=1)
def _trigger_to_class() -> dict[str, str]:
    """Return ``{3.49.x: harm_class}`` from the art3_49_trigger_keying rows."""
    tax = _load_harm_core_taxonomy()
    keying = _as_dict(tax.get("art3_49_trigger_keying"))
    out: dict[str, str] = {}
    for row in _as_list(keying.get("rows")):
        if isinstance(row, dict):
            trig = row.get("art3_49_trigger")
            hc = row.get("harm_class")
            if isinstance(trig, str) and isinstance(hc, str):
                out[trig] = hc
    return out


@lru_cache(maxsize=1)
def _class_to_triggers() -> dict[str, frozenset[str]]:
    """Return ``{harm_class: {3.49.x, ...}}`` — the REVERSE of the trigger keying.

    A harm_class may derive zero or more Art.3(49) triggers (the keying is partial:
    only 4 of the 11 classes key to a 3.49.* letter). This drives the
    derivation-CONSISTENCY direction of ACEF-085: if a card lists EU triggers, the
    trigger derived from its ``harm_class`` MUST be among them. Additional triggers
    keying to a different class are valid COMPOUND members, not contradictions.
    """
    out: dict[str, set[str]] = {}
    for trig, hc in _trigger_to_class().items():
        out.setdefault(hc, set()).add(trig)
    return {hc: frozenset(trigs) for hc, trigs in out.items()}


def check_crosswalk_harm_core_consistency(records: list[dict[str, Any]]) -> list[ValidationDiagnostic]:
    """ACEF-085: a PRESENT ``taxonomy_crosswalk`` member contradicts the value
    derived from ``harm_core`` (§5.5). Derivation is one-directional and partial:
    an UNMAPPABLE core leaves a member legitimately absent (not an error); only a
    PRESENT member that CONTRADICTS the core's row is an error.

    Two concrete checks against the harm-core-taxonomy derivation rows:

    - ``nist_ai_600_1.categories[]`` — every listed category MUST belong to the
      derivation row's NIST projection for the card's ``harm_class`` (the one
      external enum already transcribed/closed). A category outside the row
      contradicts the core.
    - ``eu_ai_act.serious_incident_triggers[]`` — the trigger DERIVED from the
      card's ``harm_class`` (via art3_49_trigger_keying) MUST be PRESENT in the
      listed triggers. One incident MAY satisfy MULTIPLE Art.3(49) triggers
      (RFC §5.5/§5.7), so additional triggers keying to a DIFFERENT harm_class are
      valid COMPOUND members, NOT contradictions. A contradiction is a list that
      omits the derived trigger while still asserting other triggers (the card
      claims harm_class X but does not list X's own 3.49 trigger). When the card's
      harm_class derives no 3.49.* trigger (the keying is partial), this check is a
      no-op for that card.
    """
    diags: list[ValidationDiagnostic] = []
    rows = _derivation_rows_by_class()
    class_to_triggers = _class_to_triggers()

    for _idx, rec in _records_iter(records):
        if _record_type_of(rec) != "incident_card":
            continue
        payload = _payload_of(rec)
        harm_core = _as_dict(payload.get("harm_core"))
        harm_class = harm_core.get("harm_class")
        if not isinstance(harm_class, str):
            continue
        crosswalk = _as_dict(payload.get("taxonomy_crosswalk"))
        row = rows.get(harm_class)

        # nist_ai_600_1 contradiction.
        nist = _as_dict(crosswalk.get("nist_ai_600_1"))
        listed_categories = [c for c in _as_list(nist.get("categories")) if isinstance(c, str)]
        if listed_categories and row is not None:
            allowed = {m for m in _as_list(_as_dict(row.get("nist_ai_600_1")).get("members")) if isinstance(m, str)}
            for cat in listed_categories:
                if cat not in allowed:
                    diags.append(
                        ValidationDiagnostic(
                            "ACEF-085",
                            (
                                f"Record {_record_id_of(rec)!r}: taxonomy_crosswalk.nist_ai_600_1 "
                                f"member lists category {cat!r}, which contradicts the value derived "
                                f"from harm_core.harm_class={harm_class!r} (§5.5). Re-derive the "
                                f"crosswalk member from harm_core, or correct harm_core."
                            ),
                            path=f"/{_record_id_of(rec)}/taxonomy_crosswalk/nist_ai_600_1/categories",
                        )
                    )

        # eu_ai_act derivation consistency: the trigger derived from harm_class MUST
        # be present in a non-empty trigger list. Additional triggers keying to other
        # classes are valid compound members (NOT contradictions). When harm_class
        # derives no 3.49.* trigger, the check is a no-op.
        eu = _as_dict(crosswalk.get("eu_ai_act"))
        listed_triggers = {t for t in _as_list(eu.get("serious_incident_triggers")) if isinstance(t, str)}
        derived_triggers = class_to_triggers.get(harm_class, frozenset())
        if listed_triggers and derived_triggers and derived_triggers.isdisjoint(listed_triggers):
            expected = ", ".join(sorted(derived_triggers))
            present = ", ".join(sorted(listed_triggers))
            diags.append(
                ValidationDiagnostic(
                    "ACEF-085",
                    (
                        f"Record {_record_id_of(rec)!r}: taxonomy_crosswalk.eu_ai_act asserts "
                        f"serious_incident_triggers [{present}] but OMITS the trigger derived from "
                        f"harm_core.harm_class={harm_class!r} (expected {expected}; §5.5). A compound "
                        f"incident MAY list additional Art.3(49) triggers, but the harm_class's own "
                        f"derived trigger must be present. Add {expected}, or correct harm_core."
                    ),
                    path=f"/{_record_id_of(rec)}/taxonomy_crosswalk/eu_ai_act/serious_incident_triggers",
                )
            )
    return diags


# ---------------------------------------------------------------------------
# ACEF-087 — near_miss INFO marker
# ---------------------------------------------------------------------------


def check_near_miss_marker(records: list[dict[str, Any]]) -> list[ValidationDiagnostic]:
    """ACEF-087 (INFO): ``harm_core.realization == "near_miss"`` is an
    informational marker, never a failure (§5.5)."""
    diags: list[ValidationDiagnostic] = []
    for _idx, rec in _records_iter(records):
        if _record_type_of(rec) not in ("incident_card", "incident_report"):
            continue
        payload = _payload_of(rec)
        for container in (payload, _as_dict(payload.get("card_source"))):
            harm_core = _as_dict(container.get("harm_core"))
            if harm_core.get("realization") == "near_miss":
                diags.append(
                    ValidationDiagnostic(
                        "ACEF-087",
                        (
                            f"Record {_record_id_of(rec)!r}: realization is near_miss — "
                            f"informational marker, never a failure (§5.5)."
                        ),
                        path=f"/{_record_id_of(rec)}/harm_core/realization",
                    )
                )
                break  # one marker per record
    return diags


# ---------------------------------------------------------------------------
# ACEF-088 — severity disagrees with band(severity_vector)
# ---------------------------------------------------------------------------


def check_severity_band_consistency(records: list[dict[str, Any]]) -> list[ValidationDiagnostic]:
    """ACEF-088: a record carries BOTH ``severity`` and ``severity_vector`` and the
    coarse ``severity`` disagrees with ``band(severity_vector)`` (§5.4). Fires ONLY
    when both fields are present and the vector is bandable.

    Three comparison surfaces (§5.4):

    - same-container on the public payload (incident_card: root severity/vector);
    - same-container on a card_source block;
    - CROSS-container on a source-backed incident_report — the REQUIRED root
      ``payload.severity`` vs the ``payload.card_source.severity_vector`` (the
      private card carries the precise vector while the public root carries only
      the coarse band). A root severity disagreeing with ``band(card_source.vector)``
      is an ACEF-088 mismatch.

    Each distinct severity_vector PATH that disagrees with its governing
    ``severity`` produces one diagnostic. The root ``severity`` is compared against
    EVERY vector that governs it — its OWN root vector (same-container) AND, on a
    source-backed report, the ``card_source.severity_vector`` (cross-container) —
    so a matching root vector NEVER masks a disagreeing card_source vector. After
    both comparisons run, diagnostics are de-duplicated by (record, vector path) so
    a single genuine mismatch is reported once, never collapsed into a passing one.
    """
    diags: list[ValidationDiagnostic] = []
    for _idx, rec in _records_iter(records):
        if _record_type_of(rec) not in ("incident_card", "incident_report"):
            continue
        payload = _payload_of(rec)
        card_source = _as_dict(payload.get("card_source"))
        rid = _record_id_of(rec)

        root_severity = payload.get("severity")
        root_vector = payload.get("severity_vector")
        cs_severity = card_source.get("severity")
        cs_vector = card_source.get("severity_vector")

        # (governing_severity, severity_path, vector_value, vector_path) comparison
        # tuples. The vector PATH keys de-duplication so each distinct vector is
        # judged at most once, but a matching root vector cannot suppress a
        # card_source-vector comparison:
        #   - root severity vs its OWN root vector (same-container);
        #   - root severity vs card_source vector (cross-container, source-backed) —
        #     ALWAYS evaluated when a card_source vector is present, independent of
        #     whether a root vector exists or matches;
        #   - card_source severity vs card_source vector (same-container).
        comparisons: list[tuple[Any, str, Any, str]] = [
            (root_severity, f"/{rid}/severity", root_vector, f"/{rid}/severity_vector"),
            (
                root_severity,
                f"/{rid}/severity",
                cs_vector,
                f"/{rid}/card_source/severity_vector",
            ),
            (
                cs_severity,
                f"/{rid}/card_source/severity",
                cs_vector,
                f"/{rid}/card_source/severity_vector",
            ),
        ]

        seen_vector_paths: set[str] = set()
        for severity, sev_path, vector, vec_path in comparisons:
            if not isinstance(severity, str) or not isinstance(vector, str):
                continue
            projected = band(vector)
            if projected is None:
                continue  # unbandable vector is ACEF-082, not ACEF-088
            if severity == projected:
                continue
            if vec_path in seen_vector_paths:
                continue  # one diagnostic per distinct disagreeing vector path
            seen_vector_paths.add(vec_path)
            diags.append(
                ValidationDiagnostic(
                    "ACEF-088",
                    (
                        f"Record {rid!r}: severity {severity!r} disagrees with "
                        f"band(severity_vector)={projected!r} (§5.4). Set severity to the band() "
                        f"projection of severity_vector, or remove one of the two fields."
                    ),
                    path=sev_path,
                )
            )
    return diags


# ---------------------------------------------------------------------------
# ACEF-086 — §5.11 publishability gate
# ---------------------------------------------------------------------------

# GDPR Art.9 special-category / identifying card fields that require a declared
# publication basis before being projected `public` or `anonymized` (§5.11). The
# privileged-analysis free-text fields default to regulator-only/omitted.
_SPECIAL_CATEGORY_CARD_FIELDS: tuple[str, ...] = ("harm_distribution_basis",)


def _basis_is_satisfying(basis: dict[str, Any]) -> bool:
    """True iff ``declared_publication_basis`` declares (Art.6 basis + Art.9
    condition) OR a declared ``anonymization_method`` (§5.11)."""
    art6 = basis.get("art6_basis")
    art9 = basis.get("art9_condition")
    if isinstance(art6, str) and art6 and isinstance(art9, str) and art9:
        return True
    anon = basis.get("anonymization_method")
    return isinstance(anon, str) and bool(anon)


def _resolve_json_pointer(doc: dict[str, Any], pointer: str) -> tuple[bool, Any]:
    """Resolve an RFC 6901 JSON Pointer against ``doc``.

    Returns ``(resolved, value)``. The root pointer ``""`` is not resolvable
    here (it is forbidden as a publishability_map key, §5.11). Supports ~0/~1
    unescaping and integer array indices.
    """
    if pointer == "":
        return False, None
    if not pointer.startswith("/"):
        return False, None
    current: Any = doc
    for raw_token in pointer.split("/")[1:]:
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            if token not in current:
                return False, None
            current = current[token]
        elif isinstance(current, list):
            if not token.isdigit():
                return False, None
            idx = int(token)
            if idx >= len(current):
                return False, None
            current = current[idx]
        else:
            return False, None
    return True, current


def _is_public_disclosure(card_payload: dict[str, Any], source_payload: dict[str, Any] | None) -> bool:
    """True iff the §5.11 publishability gate applies: the card is at the public
    disclosure boundary (``coordinated_disclosure.status: public`` OR the
    ``id_state`` snapshot is PUBLISHED)."""
    cd = _coordinated_disclosure_of(card_payload)
    if cd.get("status") == "public":
        return True
    if source_payload is not None:
        cs = _as_dict(source_payload.get("card_source"))
        if cs.get("id_state") == "PUBLISHED":
            return True
    return False


def check_publishability(
    records: list[dict[str, Any]],
    *,
    source_backed: bool,
) -> list[ValidationDiagnostic]:
    """ACEF-086: the §5.11 publishability gate (NOT ACEF-022).

    Two named modes (§5.11):

    - **card-only** (``source_backed=False``) — checks the *presence* of a
      satisfying ``declared_publication_basis`` when a special-category/identifying
      card field is projected ``public``, and ``*_commitment`` FORMAT only. It does
      NOT resolve publishability_map pointers and does NOT check commitment
      preimages/linkage.
    - **source-backed** (``source_backed=True``) — additionally resolves each
      ``card_source.publishability_map`` pointer against the source incident_report
      (an unresolvable pointer -> ACEF-086), and links every ``*_commitment`` card
      key to a source field whose disposition is ``hash-committed`` with a matching
      ``sha256(JCS(source_value))`` preimage (orphan/mismatch -> ACEF-086).

    The gate applies only at the public-disclosure boundary
    (``coordinated_disclosure.status: public`` or ``id_state: PUBLISHED``).
    """
    diags: list[ValidationDiagnostic] = []

    # Index incident_report records by public_incident_id so a public card can be
    # paired with its private source in source-backed mode.
    reports_by_id: dict[str, dict[str, Any]] = {}
    for _idx, rec in _records_iter(records):
        if _record_type_of(rec) != "incident_report":
            continue
        cs = _as_dict(_payload_of(rec).get("card_source"))
        pid = cs.get("public_incident_id")
        if isinstance(pid, str) and pid:
            reports_by_id[pid] = rec

    for _idx, rec in _records_iter(records):
        rtype = _record_type_of(rec)
        if rtype not in ("incident_card", "incident_report"):
            continue
        payload = _payload_of(rec)

        # The card payload whose public projection is gated; for an
        # incident_report the projected fields are not present on the public
        # card, so card-only special-category checks key on incident_card.
        card_payload = payload if rtype == "incident_card" else payload
        source_rec: dict[str, Any] | None = None
        if rtype == "incident_card":
            pid = payload.get("public_incident_id")
            if isinstance(pid, str):
                source_rec = reports_by_id.get(pid)
        else:
            source_rec = rec
        source_payload = _payload_of(source_rec) if source_rec is not None else None

        if not _is_public_disclosure(card_payload, source_payload):
            continue

        # --- declared_publication_basis presence (both modes) ---
        basis = _as_dict(card_payload.get("declared_publication_basis"))
        basis_ok = _basis_is_satisfying(basis)
        if rtype == "incident_card":
            for field in _SPECIAL_CATEGORY_CARD_FIELDS:
                value = card_payload.get(field)
                if value in (None, "", [], {}):
                    continue  # field not projected public -> no basis needed
                if not basis_ok:
                    diags.append(
                        ValidationDiagnostic(
                            "ACEF-086",
                            (
                                f"Record {_record_id_of(rec)!r}: special-category/identifying field "
                                f"{field!r} is projected public without a satisfying "
                                f"declared_publication_basis (§5.11). Add a declared_publication_basis "
                                f"(Art.6(1) basis + Art.9(2) condition, or a declared "
                                f"anonymization_method), or change the field's disposition to "
                                f"omitted/regulator-only/hash-committed."
                            ),
                            path=f"/{_record_id_of(rec)}/{field}",
                        )
                    )

        # --- *_commitment FORMAT (both modes) ---
        commitments = {k: v for k, v in card_payload.items() if isinstance(k, str) and k.endswith("_commitment")}
        for key, value in commitments.items():
            if not (isinstance(value, str) and re.match(r"^sha256:[0-9a-f]{64}$", value)):
                diags.append(
                    ValidationDiagnostic(
                        "ACEF-086",
                        (
                            f"Record {_record_id_of(rec)!r}: commitment field {key!r} is not a valid "
                            f"sha256:<64-hex> value (§5.11). Emit 'sha256:' + hex(SHA-256(JCS(source))) "
                            f"for the hash-committed source field."
                        ),
                        path=f"/{_record_id_of(rec)}/{key}",
                    )
                )

        if not source_backed:
            continue

        # --- source-backed: publishability_map pointer resolution + commitment linkage ---
        if source_payload is None:
            continue
        card_source = _as_dict(source_payload.get("card_source"))
        pub_map = _as_dict(card_source.get("publishability_map"))

        # Pointer resolution against the source incident_report payload.
        for pointer, disposition in pub_map.items():
            if not isinstance(pointer, str):
                continue
            resolved, _value = _resolve_json_pointer(source_payload, pointer)
            if not resolved:
                diags.append(
                    ValidationDiagnostic(
                        "ACEF-086",
                        (
                            f"Record {_record_id_of(rec)!r}: publishability_map pointer {pointer!r} "
                            f"does not resolve to a value in the source incident_report (§5.11). "
                            f"Correct the pointer, or remove the map entry."
                        ),
                        path=f"/{_record_id_of(rec)}/card_source/publishability_map/{pointer}",
                    )
                )

        # Commitment linkage: every *_commitment card key MUST correspond to a
        # source field whose disposition is hash-committed, with a matching
        # sha256(JCS(source_value)) preimage.
        hash_committed_pointers = {
            ptr: disp for ptr, disp in pub_map.items() if disp == "hash-committed" and isinstance(ptr, str)
        }
        # Build {field_name: pointer} from the last path token for linkage.
        committed_field_to_pointer: dict[str, str] = {}
        for ptr in hash_committed_pointers:
            last = ptr.split("/")[-1].replace("~1", "/").replace("~0", "~")
            committed_field_to_pointer[last] = ptr

        for key, value in commitments.items():
            field_name = key[: -len("_commitment")]
            linked_pointer = committed_field_to_pointer.get(field_name)
            if linked_pointer is None:
                diags.append(
                    ValidationDiagnostic(
                        "ACEF-086",
                        (
                            f"Record {_record_id_of(rec)!r}: orphan commitment {key!r} — no source "
                            f"field with disposition 'hash-committed' in card_source.publishability_map "
                            f"links to it (§5.11 commitment-linkage). Add a hash-committed map entry, or "
                            f"remove the commitment."
                        ),
                        path=f"/{_record_id_of(rec)}/{key}",
                    )
                )
                continue
            resolved, source_value = _resolve_json_pointer(source_payload, linked_pointer)
            if not resolved:
                continue  # pointer-resolution diagnostic already emitted above
            expected = "sha256:" + sha256_hex(canonicalize(source_value))
            if isinstance(value, str) and value != expected:
                diags.append(
                    ValidationDiagnostic(
                        "ACEF-086",
                        (
                            f"Record {_record_id_of(rec)!r}: commitment {key!r} does not equal "
                            f"sha256(JCS(source_value)) at {linked_pointer!r} (§5.11 commitment-linkage). "
                            f"Recompute the commitment over the canonicalized source value."
                        ),
                        path=f"/{_record_id_of(rec)}/{key}",
                    )
                )
    return diags


# ---------------------------------------------------------------------------
# §5.5 incident_dedupe_key emit/omit confidentiality rule (ACEF-086).
# ---------------------------------------------------------------------------


def _record_confidentiality_of(rec: dict[str, Any]) -> str:
    """The record-envelope ``confidentiality`` of an on-disk record.

    The serialized record carries ``confidentiality`` at the envelope level
    (sibling of ``payload``); it defaults to ``"public"`` when absent (the
    envelope default). A record with ANY non-public confidentiality is treated
    as non-public for the §5.5 emit/omit gate (fail-closed: an unrecognized /
    missing value is NOT treated as public when it carries a subject-bearing
    key, so a forged emit-on-non-public cannot slip through)."""
    conf = rec.get("confidentiality")
    return conf if isinstance(conf, str) and conf else "public"


def check_dedupe_key_confidentiality(records: list[dict[str, Any]]) -> list[ValidationDiagnostic]:
    """ACEF-086: the §5.5 ``incident_dedupe_key`` confidentiality MUST (resolves Q20).

    The subject-bearing ``incident_dedupe_key`` MUST be emitted ONLY on a
    PUBLISHED/public record; on ANY non-public record it MUST be OMITTED. Three
    of the four dedupe inputs are low-entropy/enumerable, so a published unsalted
    key over a non-public (often guessable) subject would be offline-enumerable —
    a confidentiality leak. A non-public record (``confidentiality != public``)
    that EMITS ``incident_dedupe_key`` is a forged emit-on-non-public and FAILS
    validation with the reserved §5.11 publishability code ACEF-086 (NOT ACEF-022).

    The keyed ``incident_dedupe_key_hmac`` variant is the redacted-subject dedupe
    path; because it is pepper-keyed (held by the §5.3 resolver) it is NOT
    enumerable and is therefore NOT subject to this public-only omit rule — a
    non-public record MAY carry it.
    """
    diags: list[ValidationDiagnostic] = []
    for _idx, rec in _records_iter(records):
        if _record_type_of(rec) not in ("incident_card", "incident_report"):
            continue
        payload = _payload_of(rec)
        if "incident_dedupe_key" not in payload:
            continue
        confidentiality = _record_confidentiality_of(rec)
        if confidentiality == "public":
            continue
        diags.append(
            ValidationDiagnostic(
                "ACEF-086",
                (
                    f"Record {_record_id_of(rec)!r}: the subject-bearing incident_dedupe_key is "
                    f"emitted on a NON-public record (confidentiality={confidentiality!r}), violating "
                    f"the §5.5 confidentiality MUST. Three of the four dedupe inputs are low-entropy, "
                    f"so a published unsalted key over a non-public subject is offline-enumerable. Omit "
                    f"incident_dedupe_key on any non-public record; for redacted-subject dedupe emit the "
                    f"pepper-keyed incident_dedupe_key_hmac instead, or publish the record."
                ),
                path=f"/{_record_id_of(rec)}/incident_dedupe_key",
            )
        )
    return diags


# ---------------------------------------------------------------------------
# Top-level entry point — invoked from the engine's v1.1 dispatch.
# ---------------------------------------------------------------------------


def _declared_profile_ids(manifest: dict[str, Any]) -> list[str]:
    """Collect declared profile ids from ``manifest.profiles[]``."""
    out: list[str] = []
    for decl in _as_list(manifest.get("profiles")):
        if isinstance(decl, dict):
            pid = decl.get("profile_id")
            if isinstance(pid, str) and pid:
                out.append(pid)
    return out


def run_incident_rules(
    manifest: dict[str, Any],
    records: list[dict[str, Any]],
    *,
    requested_profiles: list[str] | None = None,
) -> list[ValidationDiagnostic]:
    """Run all offline incident rule families and return a merged diagnostic list.

    Invoked from the engine's v1.1 dispatch ONLY (after ``schema_version ==
    "v1.1"``), so a v1.0 bundle never reaches these checks (VAL-VLD-001).

    Profile-conditional rules (the Art.73 clock + existential checks, the
    ACEF-081 mandatory-crosswalk check) evaluate against the UNION of the
    manifest-declared profile ids (``manifest.profiles[]``) and the profile ids
    REQUESTED by the caller (``validate_bundle(..., profiles=[...])`` / CLI
    ``--profile``). Without the requested set, a bundle that does not self-declare
    ``eu-ai-act-art73-2026`` but is validated against it by argument would bypass
    the delegated ACEF-084 checks entirely.

    The validation mode is **source-backed** when the bundle carries any
    incident_report with a ``card_source`` (the producer/holder-of-both context);
    otherwise it is **card-only** (a standalone public card). This mirrors the
    §5.11 two-mode split and the §6 conformance-class boundary.
    """
    if not isinstance(manifest, dict):
        manifest = {}
    if not isinstance(records, list):
        records = []

    # Union of manifest-declared + caller-requested profile ids, order-stable:
    # declared ids first (manifest order), then any requested id not already
    # present. Deterministic (no set iteration) for reproducible diagnostics.
    profiles = _declared_profile_ids(manifest)
    if requested_profiles:
        seen = set(profiles)
        for pid in requested_profiles:
            if isinstance(pid, str) and pid and pid not in seen:
                profiles.append(pid)
                seen.add(pid)

    # Source-backed iff some incident_report carries a card_source block.
    source_backed = any(
        _record_type_of(rec) == "incident_report" and isinstance(_payload_of(rec).get("card_source"), dict)
        for _i, rec in _records_iter(records)
    )

    diags: list[ValidationDiagnostic] = []
    diags.extend(check_crosswalk_mandatory_members(records, profiles=profiles))
    diags.extend(check_oecd_mandatory_core_completeness(records, profiles=profiles))
    diags.extend(check_severity_vector_parse(records))
    diags.extend(check_public_incident_id_offline(records, manifest=manifest))
    diags.extend(check_art73_clock(records, profiles=profiles))
    diags.extend(check_art73_existential(records, profiles=profiles))
    diags.extend(check_crosswalk_harm_core_consistency(records))
    diags.extend(check_publishability(records, source_backed=source_backed))
    diags.extend(check_dedupe_key_confidentiality(records))
    diags.extend(check_near_miss_marker(records))
    diags.extend(check_severity_band_consistency(records))
    return diags
