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

import jsonpointer  # type: ignore[import-untyped]  # no published stubs / py.typed (no types-jsonpointer on PyPI)
import rfc8785

from acef.errors import ACEFProfileError, Severity, ValidationDiagnostic
from acef.integrity import canonicalize, sha256_hex
from acef.signing import verify_detached_jws
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

# End-anchored with ``(?![\s\S])`` (NOT ``$``): ``$`` matches BEFORE a single trailing
# ``\n``, so an otherwise-valid ``AIIC-…<suffix>\n`` id would MATCH and silently pass the
# offline ACEF-083 id-trust gate, admitting a newline-corrupted, cross-reference-breaking
# id (the same trailing-newline bypass class hardened on the dedupe/severity/commitment
# patterns). The absolute end assertion rejects ANY trailing character and mirrors the
# ``incident_card.schema.json`` / ``incident_report.card_source.schema.json`` id patterns.
_PUBLIC_INCIDENT_ID_PATTERN = re.compile(r"^AIIC-([A-Z0-9]{2,8})-([0-9]{4})-[0-9A-HJKMNP-TV-Z]{26,}(?![\s\S])")

# §5.4 — the mandatory Group-I prefix the band() projection keys on. The full
# wire grammar lives in severity_vector.schema.json; band() needs only the
# Group-I metrics HG (gravity), BR (breadth), RV (reversibility). HT/SC are
# parsed for grammar-conformance but excluded from the band (HT is
# incommensurable, SC is folded into BR per §5.4).
_SEV_VECTOR_PATTERN = re.compile(
    r"^ACEF-SEV:1\.0/HT:[PRKES]/HG:[HLN]/RV:[AUI]/SC:[CU]/BR:[IGP]"
    r"(/RZ:[ESN])?(/RP:(0(\.[0-9]+)?|1(\.0+)?)@[1-9][0-9]*)?(/XF:[YNX])?"
    # End the grammar at the last metric with an ABSOLUTE end-of-string assertion,
    # NOT ``$``: Python (and JSON-Schema) ``$`` matches BEFORE a single trailing
    # ``\n``, so ``<vector>\n`` would parse as valid and the captured newline would
    # silently corrupt band() (critical -> major) and bypass ACEF-082/088 (§5.4
    # recomputability). ``(?![\s\S])`` rejects ANY trailing character (newline, CR,
    # space) and is portable across Python ``re`` and the ECMA-262 dialect the schema
    # ``pattern`` mirrors.
    r"(/AU:[LOA])?(/EX:[HLN])?(/KC:[HML])?(/SF:[PN])?(/VL:[FTAC])?(/DB:[YN])?(?![\s\S])"
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
            # INCVAL-005: the public taxonomy_crosswalk.eu_ai_act subschema requires
            # only `edition` (widespread/death_involved are schema-OPTIONAL), but a
            # COMPLETE Art.73 fact block is needed to compute the shortest clock. The
            # validator enforces presence even though the schema permits omission —
            # defaulting the missing booleans to false would be a dangerous
            # false-green that silently accepts a wrong 15-day clock. The message
            # makes this schema-permits-vs-validator-enforces tension explicit so a
            # producer building from the schema alone understands the requirement.
            schema_tension = (
                "the public taxonomy_crosswalk.eu_ai_act SCHEMA requires only 'edition' "
                "(widespread/death_involved are schema-optional), but the VALIDATOR "
                "additionally ENFORCES presence of these booleans here — it MUST NOT "
                "default the missing booleans to false (that would silently accept a "
                "wrong 15-day clock)"
                if kind == "taxonomy_crosswalk"
                else "the VALIDATOR ENFORCES presence of these facts — it MUST NOT default "
                "the missing booleans to false (that would silently accept a wrong "
                "15-day clock)"
            )
            diags.append(
                ValidationDiagnostic(
                    "ACEF-084",
                    (
                        f"Record {_record_id_of(rec)!r}: eu-ai-act-art73-2026 declared and the Art.73 "
                        f"fact block (read from {kind}) is INCOMPLETE — a public Art.73 fact block MUST "
                        f"carry at least one 'serious_incident_triggers' member AND boolean 'widespread' "
                        f"AND boolean 'death_involved' (the shortest-clock inputs, §5.7). {schema_tension}. "
                        f"Add the missing widespread / death_involved facts at {kind}."
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
            # §5.7 legal clock relation (NOT exact-instant equality). The Art.73
            # clock is a CEILING — the report must be filed "not later than N days
            # from awareness" (§5.1/Appendix), not at the same wall-clock second as
            # awareness+N. Both fields are schema format:date-time, so a producer may
            # legitimately carry a time-of-day on awareness while stating the
            # legally-natural midnight/end-of-day-N deadline; comparing on the exact
            # instant false-rejected that conformant case (INCVAL-004). The chosen
            # rule: the deadline is consistent iff it falls WITHIN the clock window —
            #   awareness <= stated_deadline <= awareness + N days
            # The upper bound keeps rejecting a genuinely-too-late deadline (after
            # awareness+N still raises); the lower bound rejects an incoherent
            # deadline before awareness (a clock cannot expire before it starts). A
            # deadline EARLIER than the ceiling (reported more promptly) is conformant.
            clock_ceiling = awareness + timedelta(days=clock_days)
            within_clock = stated_deadline is not None and awareness <= stated_deadline <= clock_ceiling
            if not within_clock:
                diags.append(
                    ValidationDiagnostic(
                        "ACEF-084",
                        (
                            f"Record {_record_id_of(rec)!r}: eu-ai-act-art73-2026 declared and the "
                            f"stated regulatory_timeline deadline "
                            f"({entry.get('deadline')!r}) is inconsistent with the shortest "
                            f"applicable clock ({clock_days} days from awareness_date "
                            f"{entry.get('awareness_date')!r}; the deadline MUST fall on or before "
                            f"{clock_ceiling.isoformat()} and not before awareness; trigger "
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


def _attestation_self_inconsistent(rec: dict[str, Any], *, manifest_timestamp: str | None) -> bool:
    """True iff ``rec`` carries a JWS ``attestation`` that does NOT verify against
    its OWN embedded/referenced key — the §5.3(ii) JWS self-inconsistency.

    The signed incident card carries its signature in the record-envelope
    ``attestation`` block (record-envelope.schema.json: ``{method, signer,
    signed_fields, signature}``). The detached JWS embeds its verification key in
    its OWN header (jwk or x5c), so verification is fully self-contained:

    1. Only ``method == "jws"`` with a non-empty ``signature`` carries a JWS to
       check; an absent / non-jws / empty attestation is NOT a self-inconsistency
       (the card is simply unsigned for this purpose) -> returns ``False``.
    2. Extract each ``signed_fields`` JSON Pointer (RFC 6901) from the serialized
       record dict, RFC 8785-canonicalize the ``{pointer: value}`` subset, and
       verify the detached JWS over those canonical bytes via
       :func:`acef.signing.verify_detached_jws` (which enforces RS256/ES256 only,
       requires ``kid``, and resolves the key from the header's embedded jwk/x5c).
       For x5c-backed cards, ``manifest_timestamp`` anchors cert-validity (§3.1.3).

    ATTRIBUTION-FREE (critical honesty discipline): this verifies the signature
    ONLY against the key EMBEDDED IN / REFERENCED BY the card's own JWS. It does
    NOT resolve the key to a domain, performs NO network access, and never
    attributes the id to an assigner. A FORGED-assigner card whose JWS is
    SELF-CONSISTENT (signed by SOME key embedded in its own header) returns
    ``False`` here — it passes offline by design; only a JWS that fails to verify
    against its own embedded key (tampered payload, or a grafted signature that
    does not cover this card's signed fields) returns ``True`` -> ACEF-083.

    Fail-closed honesty: a non-verifying signature (any cryptographic failure,
    unsupported alg, unresolvable pointer, non-canonicalizable content) is a
    self-inconsistency -> ``True``. This never raises (a malformed attestation is
    treated as self-inconsistent, not a crash).
    """
    att = rec.get("attestation")
    if not isinstance(att, dict):
        return False
    method = att.get("method")
    signature = att.get("signature")
    if method != "jws" or not isinstance(signature, str) or not signature:
        return False
    signed_fields = att.get("signed_fields")
    if not isinstance(signed_fields, list) or not signed_fields:
        # A jws attestation with a signature but no signed_fields cannot be
        # verified against any subtree — treat as self-inconsistent (the signature
        # attests nothing resolvable). Fail-closed.
        return True
    pointers = [p for p in signed_fields if isinstance(p, str)]
    if len(pointers) != len(signed_fields):
        return True  # a non-string pointer entry is malformed -> self-inconsistent
    try:
        subset = {pointer: jsonpointer.resolve_pointer(rec, pointer) for pointer in pointers}
        canonical = canonicalize(subset)
        verify_detached_jws(signature, canonical, manifest_timestamp=manifest_timestamp)
    except Exception:
        # Any failure (ACEFSigningError on a non-verifying/forged signature,
        # unsupported algorithm, JsonPointerException, rfc8785 domain error, …)
        # means the JWS does not self-verify -> self-inconsistency. Intentionally
        # broad: this must never crash offline validation.
        return True
    return False


def check_public_incident_id_offline(
    records: list[dict[str, Any]],
    *,
    manifest: dict[str, Any],
    manifest_timestamp: str | None = None,
) -> list[ValidationDiagnostic]:
    """ACEF-083 ``class: offline-deterministic`` (§5.3 / §7).

    The OFFLINE id-trust surface, computed WHOLLY from bundle bytes:

    1. **pattern** — ``public_incident_id`` matches ``AIIC-{assigner}-{year}-{suffix}``
       (assigner 2-8 uppercase alphanumerics, year 4 digits, suffix >=26
       Crockford-base32 chars).
    2. **JWS self-consistency** — when the record carries a JWS ``attestation``
       block (record-envelope ``{method:"jws", signed_fields, signature}``), the
       detached signature MUST verify against the key EMBEDDED IN / REFERENCED BY
       its own JWS header (jwk/x5c), over the RFC-8785 canonicalization of the
       signed fields. A self-INconsistent JWS (tampered card, or a signature not
       covering this card) raises ACEF-083 (§5.3(ii)). ATTRIBUTION-FREE: verified
       ONLY against the embedded key, never resolved to a domain, never networked.
    3. **bundled-snapshot membership** — ONLY IF the bundle embeds a
       ``{assigner, public_key}`` snapshot, ``{assigner}`` MUST be locally listed.
       Skipped entirely when no snapshot is bundled.

    HONESTY DISCIPLINE: this NEVER attributes the id to the assigner domain and
    performs NO network call, central allocation, registry admission, or
    global-uniqueness attestation. A forged ``AIIC-OPENAI-…`` card with a valid
    pattern, a SELF-CONSISTENT JWS, and no contradicting snapshot PASSES offline by
    design — attribution is the OPTIONAL online domain-control verifier's job
    (F-M3-DOMAIN-CONTROL), not this offline rule. ``manifest_timestamp`` anchors
    x5c certificate-validity for the JWS sub-check (spec §3.1.3, reproducible
    verification); it is threaded from the engine's ``metadata.timestamp``.
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

        # §5.3(ii) JWS self-consistency: a SIGNED card (JWS attestation block)
        # whose signature does not verify against its OWN embedded/referenced key
        # is a self-inconsistency (tampered card, or a grafted signature not
        # covering this card) -> ACEF-083 (class:offline-deterministic). Checked
        # once per record (the attestation covers the whole record, not a single
        # container), and ONLY for a record that carries a public_incident_id (the
        # JWS sub-check is part of the id-trust surface; a non-incident-id record
        # with an unverifiable attestation is the generic record_attested operator's
        # concern, not ACEF-083). ATTRIBUTION-FREE: verified ONLY against the
        # embedded key; an unsigned card, or a forged-assigner card with a
        # SELF-CONSISTENT JWS, never raises here.
        _root_pid = payload.get("public_incident_id")
        _cs_pid = _as_dict(payload.get("card_source")).get("public_incident_id")
        _carries_incident_id = bool(isinstance(_root_pid, str) and _root_pid) or bool(
            isinstance(_cs_pid, str) and _cs_pid
        )
        if _carries_incident_id and _attestation_self_inconsistent(rec, manifest_timestamp=manifest_timestamp):
            diags.append(
                ValidationDiagnostic(
                    "ACEF-083",
                    (
                        f"Record {_record_id_of(rec)!r}: public_incident_id id-trust failure "
                        f"(class: offline-deterministic) — the card's JWS attestation does not "
                        f"self-verify (JWS self-inconsistency): the detached signature fails to "
                        f"verify against the key embedded in / referenced by its own JWS header "
                        f"over the RFC-8785 canonicalization of signed_fields (§5.3(ii); this is "
                        f"an attribution-free self-consistency check, never a domain-control "
                        f"proof). Re-sign the card so the JWS verifies, or remove the attestation."
                    ),
                    path=f"/{_record_id_of(rec)}/attestation/signature",
                )
            )

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


# ---------------------------------------------------------------------------
# §5.11 source-to-card projection (disposition-honored check, ACEF-086)
# ---------------------------------------------------------------------------

# FROZEN, INSTALL-SAFE projectable-field sets for the disposition-honored ACEF-086
# check (RFC-0002 §5.11). This module lives under ``src/acef`` and is ALWAYS packaged,
# so the check resolves every projection edge with NO disk read — fail-CLOSED even in
# a pip-installed deployment where ``acef-conventions/v1.1/`` is absent.
#
# A publishability_map source JSON Pointer PROJECTS to a card-root field ``<X>`` only
# from that field's ONE authoritative origin (see :func:`_pointer_to_card_root_field`):
#
# - a CARD_SOURCE-OWNED field (``<X>`` in ``_CARD_SOURCE_PROJECTED_FIELDS``, i.e. an
#   ``incident_card`` root property that is ALSO an ``incident_report.card_source``
#   property) projects ONLY from ``/card_source/<X>``; its stray report-root mirror
#   ``/<X>`` is IGNORED (no false positive), because the card's public value comes from
#   card_source, not the report root.
# - a REPORT-ROOT EVIDENCE field (``<X>`` in ``_REPORT_ROOT_PROJECTED_FIELDS``) projects
#   ONLY from the report payload root ``/<X>``.
#
# A deeper-nested pointer (``/impact_assessment/notes``,
# ``/card_source/coordinated_disclosure/foo``) names a SUB-field and projects to nothing.
#
# The two sets together are the FULL set of card-root EVIDENCE fields — every
# ``incident_card`` named root property EXCEPT the three CARD-AUTHORED / COMPUTED meta
# fields that are NOT projected from a disposed source field (``_CARD_AUTHORED_FIELDS``:
# ``declared_publication_basis`` — a published special-category card MUST carry it, so
# flagging it would be a false positive — and the two §5.5 dedupe keys
# ``incident_dedupe_key`` / ``incident_dedupe_key_hmac``, computed on the card).
# Covering both origins (not just the card_source∩incident_card overlap) closes the
# audit gap where a card-root-but-not-card_source field — ``harm_distribution_basis``
# (GDPR Art.9), ``transferability``, ``sector_of_deployment``, ``autonomy_level``,
# ``value_chain_role``, ``taxonomy_crosswalk`` — disposed ``regulator-only``/``omitted``
# yet PUBLISHED on the card was silently accepted (the basis-gate at §5.11 line 333 is a
# SEPARATE additional check, not a substitute).
#
# DRIFT GUARD: ``tests/unit/test_validation_incident_rules.py`` re-derives BOTH sets
# from the v1.1 ``incident_card`` + ``card_source`` schemas in a checkout and asserts
# equality, so any additive card-root field change is caught in CI while runtime NEVER
# reads schema.
_CARD_AUTHORED_FIELDS: frozenset[str] = frozenset(
    {"declared_publication_basis", "incident_dedupe_key", "incident_dedupe_key_hmac"}
)
# A card-root field's AUTHORITATIVE source-backed projection origin depends on whether
# the field is owned by the card_source overlay or lives at the report payload root.
# Splitting the two prevents a false positive (roborev): a card_source-OWNED field
# (public_incident_id, harm_core, ...) carries its public projection from
# /card_source/<X>, so a stray /<X> mirror at the REPORT ROOT is NOT the projection
# source and a disposition on it must not fire ACEF-086 against the card_source-derived
# card field.
#
# CARD_SOURCE-OWNED: an ``incident_card`` root property that is ALSO an
# ``incident_report.card_source`` property — projects ONLY from ``/card_source/<X>``.
_CARD_SOURCE_PROJECTED_FIELDS: frozenset[str] = frozenset(
    {"coordinated_disclosure", "harm_core", "id_grade", "public_incident_id", "severity_vector"}
)
# REPORT-ROOT: an ``incident_card`` root EVIDENCE property that is NOT a card_source
# property (and not a card-authored/computed meta field) — projects ONLY from the
# report payload root ``/<X>``. Includes the original ``severity`` plus the audit-gap
# fields (harm_distribution_basis, transferability, sector_of_deployment, ...).
_REPORT_ROOT_PROJECTED_FIELDS: frozenset[str] = frozenset(
    {
        "autonomy_level",
        "harm_distribution_basis",
        "sector_of_deployment",
        "severity",
        "taxonomy_crosswalk",
        "transferability",
        "value_chain_role",
    }
)


def _pointer_to_card_root_field(pointer: str) -> str | None:
    """The ``incident_card`` ROOT field a publishability_map JSON-Pointer projects to
    (§5.11), or ``None``.

    The public card is a PROJECTION of the source ``incident_report``. The
    AUTHORITATIVE projection origin is field-specific: a card_source-OWNED field projects
    ONLY from ``/card_source/<X>`` (so its stray report-root mirror ``/<X>`` is ignored —
    no false positive), while a report-root EVIDENCE field projects ONLY from ``/<X>``.
    Resolution is on the FULL pointer (NEVER a leaf token), so two distinct source fields
    sharing a leaf name (``/a/notes``, ``/b/notes``) never collide; a deeper-nested
    pointer names a SUB-field and projects to nothing.
    """
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        return None
    segments = [seg.replace("~1", "/").replace("~0", "~") for seg in pointer[1:].split("/")]
    if len(segments) == 1 and segments[0] in _REPORT_ROOT_PROJECTED_FIELDS:
        return segments[0]
    if len(segments) == 2 and segments[0] == "card_source" and segments[1] in _CARD_SOURCE_PROJECTED_FIELDS:
        return segments[1]
    return None


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
            # End with an ABSOLUTE end-of-string assertion, NOT ``$``: ``$`` matches
            # BEFORE a trailing ``\n``, so ``sha256:<64hex>\n`` would pass this card-only
            # FORMAT check (the ONLY commitment guard in card-only mode) and corrupt the
            # value's canonical/hash bytes (§5.11). Mirrors ``_SEV_VECTOR_PATTERN``.
            if not (isinstance(value, str) and re.match(r"^sha256:[0-9a-f]{64}(?![\s\S])", value)):
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

        # Disposition-honored check (INCVAL-003): §5.11 source-backed mode MUST
        # verify the publishability_map dispositions were HONORED in the public
        # projection. For a source field disposed 'omitted' or 'regulator-only',
        # the field it PROJECTS to MUST NOT appear on the public incident_card.
        #
        # This runs ONLY when ``rec`` is a genuine ``incident_card`` (the PUBLIC
        # projection, distinct from its source report). It is NOT run on the source
        # incident_report itself: the private report legitimately carries the very
        # fields it disposes regulator-only/omitted (it IS the regulator-only
        # source) — comparing the source against its own map would be a guaranteed
        # false-positive. ``card_payload`` here is the incident_card's payload.
        #
        # SCOPE — EXPLICIT source-to-card projection via :func:`_pointer_to_card_root_field`
        # (full pointer, never a leaf token), resolving each field from its ONE
        # authoritative origin: a card_source-OWNED field (``_CARD_SOURCE_PROJECTED_FIELDS``)
        # ONLY from ``/card_source/<X>``, a report-root EVIDENCE field
        # (``_REPORT_ROOT_PROJECTED_FIELDS``) ONLY from ``/<X>``. Together these cover NOT
        # just the card_source∩incident_card overlap but also card-root-but-not-card_source
        # fields (harm_distribution_basis, transferability, sector_of_deployment,
        # autonomy_level, value_chain_role, taxonomy_crosswalk). A deeper-nested or
        # wrong-origin pointer projects to nothing and is IGNORED — no leaf-name inference,
        # no false-positive on a stray report-root mirror of a card_source-owned field.
        # Iterate in canonical sorted order so diagnostics are order-independent.
        if rtype == "incident_card":
            for pointer, disposition in sorted(pub_map.items(), key=lambda kv: str(kv[0])):
                if not isinstance(pointer, str) or disposition not in ("omitted", "regulator-only"):
                    continue
                card_field = _pointer_to_card_root_field(pointer)
                if card_field is None:
                    continue  # not a source-to-card projection pointer -> ignore
                if card_field in card_payload:
                    diags.append(
                        ValidationDiagnostic(
                            "ACEF-086",
                            (
                                f"Record {_record_id_of(rec)!r}: source field {pointer!r} is disposed "
                                f"{disposition!r} in card_source.publishability_map but the projected field "
                                f"{card_field!r} IS present on the public incident_card — the disposition "
                                f"was NOT honored (§5.11). A {disposition!r} field MUST NOT appear in the "
                                f"public projection. Remove {card_field!r} from the public card, or change "
                                f"its disposition to 'public'/'anonymized'/'hash-committed'."
                            ),
                            path=f"/{_record_id_of(rec)}/{card_field}",
                        )
                    )

        # Commitment linkage: every ``<field>_commitment`` card key MUST correspond to
        # EXACTLY ONE source field disposed 'hash-committed' (§5.11 line 327), with a
        # matching sha256(JCS(source_value)) preimage AT THAT SOURCE PATH. The source
        # field is identified by its NAME — the JSON-Pointer LEAF token. So two distinct
        # hash-committed source pointers sharing a leaf (``/a/notes``, ``/b/notes``) are
        # an 'exactly one' VIOLATION, NOT a silent last-writer-wins overwrite: the old
        # ``dict[leaf] = ptr`` collapse kept only the last-iterated pointer, making the
        # verdict ORDER-DEPENDENT (a false-ACCEPT of a card whose secret source is never
        # verified when the survivor's value matched, a false-REJECT otherwise). Group by
        # leaf into a SORTED list and require exactly one; a collision raises ACEF-086.
        committed_field_to_pointers: dict[str, list[str]] = {}
        for ptr, disp in sorted(pub_map.items(), key=lambda kv: str(kv[0])):
            if disp != "hash-committed" or not isinstance(ptr, str):
                continue
            leaf = ptr.split("/")[-1].replace("~1", "/").replace("~0", "~")
            committed_field_to_pointers.setdefault(leaf, []).append(ptr)

        for key, value in commitments.items():
            field_name = key[: -len("_commitment")]
            linked_pointers = committed_field_to_pointers.get(field_name, [])
            if not linked_pointers:
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
            if len(linked_pointers) > 1:
                diags.append(
                    ValidationDiagnostic(
                        "ACEF-086",
                        (
                            f"Record {_record_id_of(rec)!r}: commitment {key!r} is AMBIGUOUS — more than "
                            f"one source field disposed 'hash-committed' shares the name {field_name!r} "
                            f"({', '.join(repr(p) for p in linked_pointers)}); §5.11 commitment-linkage "
                            f"requires EXACTLY ONE source field per commitment. Disambiguate the "
                            f"publishability_map so a single hash-committed source field corresponds to {key!r}."
                        ),
                        path=f"/{_record_id_of(rec)}/{key}",
                    )
                )
                continue
            linked_pointer = linked_pointers[0]
            resolved, source_value = _resolve_json_pointer(source_payload, linked_pointer)
            if not resolved:
                continue  # pointer-resolution diagnostic already emitted above
            # The committed source value is attacker-controlled: it is whatever sits
            # at ``linked_pointer`` in the (additionalProperties:true) source payload,
            # so it may be OUTSIDE the RFC-8785 / I-JSON / encodable domain in TWO
            # distinct ways, BOTH of which ``json.loads`` parses but ``rfc8785.dumps``
            # REJECTS:
            #   (a) a number out of the I-JSON number domain — an integer with
            #       |value| > 2^53, or NaN/Infinity — raising
            #       ``rfc8785.CanonicalizationError`` (IntegerDomainError /
            #       FloatDomainError); and
            #   (b) a string or object KEY holding a LONE UTF-16 SURROGATE (e.g. an
            #       escaped ``\udce9``), which ``rfc8785.dumps`` must
            #       ``str.encode("utf-16-be")`` for its UTF-16 key sort and CANNOT
            #       encode, raising a raw ``UnicodeEncodeError`` (NOT a
            #       ``CanonicalizationError``).
            # These are the SAME two non-canonicalizable classes that
            # ``integrity._canonicalize_hash_domain`` catches together. The raw
            # ``canonicalize`` contract re-raises both; if either propagated here it
            # would escape ``run_incident_rules`` to the engine's outermost backstop,
            # collapsing into ONE generic FATAL ACEF-001 and ABORTING the remaining
            # incident rules + later phases — violating the "report ALL errors within
            # each phase" MUST. So, mirroring the sibling guards (canonicalize "must
            # never crash offline validation"), we wrap ONLY the canonicalize call: a
            # non-canonicalizable committed source value is a commitment FAILURE (no
            # valid sha256(JCS(source_value)) can exist for it) — a precise, non-fatal,
            # in-lane ACEF-086 — never a crash. The guard is scoped to JUST this
            # evaluation so a legitimate in-domain mismatch still takes the existing
            # ACEF-086 mismatch path below, unchanged. The except tuple is held to
            # exactly these two CONCRETE non-encodable classes (no broad
            # ``except Exception``): they are the only faults ``rfc8785.dumps`` raises
            # on attacker JSON the linkage pointer can resolve to.
            try:
                expected = "sha256:" + sha256_hex(canonicalize(source_value))
            except (rfc8785.CanonicalizationError, UnicodeEncodeError):
                diags.append(
                    ValidationDiagnostic(
                        "ACEF-086",
                        (
                            f"Record {_record_id_of(rec)!r}: the hash-committed source value at "
                            f"{linked_pointer!r} is OUTSIDE the RFC-8785 / I-JSON / encodable domain "
                            f"(e.g. an integer with magnitude > 2^53, NaN/Infinity, or a string / "
                            f"object key holding a lone UTF-16 surrogate), so no valid "
                            f"sha256(JCS(source_value)) commitment can exist for it (§5.11 "
                            f"commitment-linkage). Bring the source value into the I-JSON domain "
                            f"(encode large integers as strings; remove NaN/Infinity; remove lone "
                            f"surrogates), or change the field's disposition so it is not "
                            f"hash-committed."
                        ),
                        path=f"/{_record_id_of(rec)}/{key}",
                    )
                )
                continue
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
    (sibling of ``payload``). This accessor returns it verbatim, defaulting to
    ``"public"`` when absent or non-string.

    Honest behavior note (audit finding F31): this default is fail-OPEN —
    ``"public"`` is the LEAST restrictive value, NOT a fail-closed posture. The
    confidentiality guarantee does NOT come from this function.

    For a SCHEMA-VALID record the fallback is unreachable: ``record-envelope``
    makes ``confidentiality`` a REQUIRED field with a closed enum, so every valid
    record carries a valid non-empty value and ``_record_confidentiality_of``
    returns it verbatim. For a SCHEMA-INVALID record the fallback IS reachable —
    the engine flushes the ``ACEF-004`` schema diagnostic but does NOT
    short-circuit, so ``run_incident_rules`` still inspects the same records
    (engine.py Phase-1 schema → Phase-3b incident rules, no early return). The
    fail-open default therefore cannot cause an INVALID bundle to be ACCEPTED:
    a record that is missing or mis-values ``confidentiality`` independently
    triggers a failing ``ACEF-004`` in the SAME assessment, so even if this gate
    mis-classifies it as public the bundle is still rejected. The schema layer is
    the safety net; this fallback is only a defensive default for a record the
    assessment is already failing."""
    conf = rec.get("confidentiality")
    return conf if isinstance(conf, str) and conf else "public"


# §5.5 dedupe-field SHAPE patterns — MIRRORED from incident_card.schema.json
# (#/properties/incident_dedupe_key.pattern and
# #/properties/incident_dedupe_key_hmac.pattern). The v1.1 incident_report schema
# has additionalProperties:true and does NOT define these two properties, so a
# malformed dedupe value on an incident_report payload is NOT caught at the schema
# phase — the rule enforces the shape for BOTH record types.
# End with an ABSOLUTE end-of-string assertion ``(?![\s\S])`` rather than ``$``: ``$``
# matches BEFORE a trailing ``\n``, so ``sha256:<64hex>\n`` would pass the §5.5 dedupe-key
# SHAPE check and corrupt the key's canonical bytes. Mirrors ``_SEV_VECTOR_PATTERN``.
_DEDUPE_KEY_SHAPE = re.compile(r"^sha256:[0-9a-f]{64}(?![\s\S])")
_DEDUPE_HMAC_SHAPE = re.compile(r"^hmac-sha256:[0-9a-f]{64}(?![\s\S])")


def check_dedupe_key_confidentiality(records: list[dict[str, Any]]) -> list[ValidationDiagnostic]:
    """ACEF-086: the §5.5 ``incident_dedupe_key`` confidentiality MUST + dedupe-field
    SHAPE validation on BOTH incident record types (resolves Q20, Finding 3).

    **Confidentiality (subject-bearing plaintext key).** The subject-bearing
    ``incident_dedupe_key`` MUST be emitted ONLY on a PUBLISHED/public record; on
    ANY non-public record it MUST be OMITTED. Three of the four dedupe inputs are
    low-entropy/enumerable, so a published unsalted key over a non-public (often
    guessable) subject would be offline-enumerable — a confidentiality leak. A
    non-public record (``confidentiality != public``) that EMITS
    ``incident_dedupe_key`` is a forged emit-on-non-public and FAILS validation
    with the reserved §5.11 publishability code ACEF-086 (NOT ACEF-022). This
    applies identically to an ``incident_report`` (which is non-public by nature):
    the report's dedupe path is the pepper-keyed hmac, not the plaintext key.

    The keyed ``incident_dedupe_key_hmac`` variant is the redacted-subject dedupe
    path; because it is pepper-keyed (held by the §5.3 resolver) it is NOT
    enumerable and is therefore NOT subject to this public-only omit rule — a
    non-public record MAY carry it.

    **Shape (both fields, both record types).** A PRESENT ``incident_dedupe_key``
    MUST match ``^sha256:[0-9a-f]{64}(?![\\s\\S])`` and a PRESENT
    ``incident_dedupe_key_hmac`` MUST match ``^hmac-sha256:[0-9a-f]{64}(?![\\s\\S])``
    (mirrored from incident_card.schema.json). The absolute end assertion
    ``(?![\\s\\S])`` (not ``$``) rejects a trailing newline, which ``$`` would admit
    before a final newline — a hash-corrupting ``sha256:<64hex>`` plus a newline. The
    ``incident_report`` schema's
    ``additionalProperties:true`` does not constrain these properties, so a
    malformed value on a report would otherwise pass unchecked; the rule enforces
    the shape for either record type (malformed -> ACEF-086).
    """
    diags: list[ValidationDiagnostic] = []
    for _idx, rec in _records_iter(records):
        if _record_type_of(rec) not in ("incident_card", "incident_report"):
            continue
        payload = _payload_of(rec)
        rid = _record_id_of(rec)
        confidentiality = _record_confidentiality_of(rec)

        # Confidentiality omit rule (subject-bearing plaintext key only).
        if "incident_dedupe_key" in payload and confidentiality != "public":
            diags.append(
                ValidationDiagnostic(
                    "ACEF-086",
                    (
                        f"Record {rid!r}: the subject-bearing incident_dedupe_key is "
                        f"emitted on a NON-public record (confidentiality={confidentiality!r}), violating "
                        f"the §5.5 confidentiality MUST. Three of the four dedupe inputs are low-entropy, "
                        f"so a published unsalted key over a non-public subject is offline-enumerable. Omit "
                        f"incident_dedupe_key on any non-public record; for redacted-subject dedupe emit the "
                        f"pepper-keyed incident_dedupe_key_hmac instead, or publish the record."
                    ),
                    path=f"/{rid}/incident_dedupe_key",
                )
            )

        # Shape validation (both fields, both record types). A non-string or a
        # pattern-mismatched value fails — the incident_report schema does not
        # constrain these properties (additionalProperties: true).
        for field, shape, sample in (
            ("incident_dedupe_key", _DEDUPE_KEY_SHAPE, "sha256:<64 lowercase hex>"),
            ("incident_dedupe_key_hmac", _DEDUPE_HMAC_SHAPE, "hmac-sha256:<64 lowercase hex>"),
        ):
            if field not in payload:
                continue
            value = payload[field]
            if not (isinstance(value, str) and shape.match(value)):
                diags.append(
                    ValidationDiagnostic(
                        "ACEF-086",
                        (
                            f"Record {rid!r}: {field} value {value!r} is malformed — it MUST match "
                            f"{sample} (§5.5, mirrored from incident_card.schema.json). The "
                            f"incident_report schema does not constrain this field, so the rule enforces "
                            f"its shape; recompute the value or remove it."
                        ),
                        path=f"/{rid}/{field}",
                    )
                )
    return diags


# ---------------------------------------------------------------------------
# ACEF-083 — public_projection_of edge SEMANTIC validation (§5.8 / §5.1)
# ---------------------------------------------------------------------------

# The §5.8 in-bundle incident graph edges added to the manifest relationship_type
# enum (§8 #4). Only ``public_projection_of`` carries a PRECISE endpoint contract
# (report→card, shared public_incident_id; §5.1/§5.8); the other four are general
# in-bundle record-graph edges (§5.8 leaves their endpoints unconstrained beyond
# the schema-level record/entity URN grammar and the reference checker's
# endpoint-existence check), so they are NOT semantically over-constrained here.
PUBLIC_PROJECTION_OF = "public_projection_of"
_INCIDENT_GRAPH_EDGES: frozenset[str] = frozenset(
    {PUBLIC_PROJECTION_OF, "caused_by", "harms", "mitigated_by", "transferable_to"}
)


# A relationship endpoint is a RECORD URN iff it matches the record_id grammar
# (``urn:acef:rec:<uuid>``; record-envelope.schema.json:24). An entity URN
# (``urn:acef:sub:/cmp:/dat:/act:``) — or any other URN — is NOT a record URN
# and therefore an invalid public_projection_of endpoint (the projection links
# two RECORDS, §5.1/§5.8).
_REC_URN_SHAPE = re.compile(r"^urn:acef:rec:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _is_record_urn(ref: str) -> bool:
    """True iff ``ref`` is a well-formed record URN (``urn:acef:rec:<uuid>``).

    ``fullmatch`` (NOT ``match``): a ``$``-anchored ``.match`` accepts ``urn:...<uuid>\\n``
    (``$`` matches before a final newline); the whole-string check rejects a §5.8 edge
    endpoint carrying a trailing newline.
    """
    return bool(_REC_URN_SHAPE.fullmatch(ref))


def _report_public_incident_id_of(payload: dict[str, Any]) -> str | None:
    """The AUTHORITATIVE ``public_incident_id`` of a confidential ``incident_report``:
    its ``card_source.public_incident_id`` (§5.7 — the report carries the shared id
    under ``card_source``, the block from which the public card is projected).

    A root-level ``public_incident_id`` on the report is NOT consulted: it must not
    be allowed to mask a divergent ``card_source`` id in the projection shared-id
    check. Returns ``None`` when ``card_source`` carries no non-empty string id."""
    cs = _as_dict(payload.get("card_source"))
    pid = cs.get("public_incident_id")
    return pid if isinstance(pid, str) and pid else None


def _card_public_incident_id_of(payload: dict[str, Any]) -> str | None:
    """The ``public_incident_id`` of a public ``incident_card``: its payload-ROOT
    ``public_incident_id`` (§5.1). Returns ``None`` when absent or non-string."""
    pid = payload.get("public_incident_id")
    return pid if isinstance(pid, str) and pid else None


def check_incident_edges(
    manifest: dict[str, Any],
    records: list[dict[str, Any]],
) -> list[ValidationDiagnostic]:
    """ACEF-083: SEMANTIC validation of the §5.8 ``public_projection_of`` edge.

    The reference checker (Phase 3) only verifies that a relationship's endpoints
    EXIST (entity URN or in-bundle record URN); it does not verify that a
    ``public_projection_of`` edge is semantically well-formed. Per §5.1/§5.8 the
    card is the deterministic public projection of the report, and the two are
    linked by a typed ``public_projection_of`` relationship whose direction is
    **report→card** and which shares a single ``public_incident_id``. A projection
    edge links two RECORDS; an entity URN endpoint (or any non-record URN) is a
    malformed projection. This rule enforces, for every ``public_projection_of``
    edge in ``manifest.entities.relationships[]``:

    - BOTH endpoints are RECORD URNs (``urn:acef:rec:<uuid>``) — an entity URN
      endpoint (``urn:acef:sub:`` / ``cmp:`` / ``dat:`` / ``act:``), or any other
      non-record URN, raises ACEF-083 (a projection edge between a record and an
      entity is malformed; it is NOT silently skipped just because the entity URN
      is absent from the record index);
    - each record-URN endpoint that is well-formed but DANGLING (not present in the
      bundle) is left to the reference checker's ACEF-020 (NOT double-reported);
    - the SOURCE record is an ``incident_report``;
    - the TARGET record is an ``incident_card``;
    - both records carry the SAME ``public_incident_id``, extracted BY RECORD TYPE:
      the report's AUTHORITATIVE id is its ``card_source.public_incident_id`` (§5.7;
      a root-level id on the report is NOT consulted, so it cannot mask a divergent
      ``card_source`` id), the card's is its public payload-ROOT
      ``public_incident_id``.

    Any violation raises ACEF-083 (id-trust/integrity band — the edge asserts the
    card is the projection of the report under a shared id; a wrong-type, reversed,
    mismatched-id, or non-record-endpoint edge is a public_incident_id-linkage
    integrity failure).

    The other four §5.8 incident edges (``caused_by`` / ``harms`` / ``mitigated_by``
    / ``transferable_to``) are general in-bundle record-graph edges; §5.8 does not
    pin their endpoint types, so they are NOT semantically constrained here (no
    over-constraint) — they are governed by the schema's URN grammar + the
    reference checker's endpoint-existence check.
    """
    relationships = _as_list(_as_dict(manifest.get("entities")).get("relationships"))
    if not relationships:
        return []

    # Index records by record URN for endpoint resolution.
    records_by_urn: dict[str, dict[str, Any]] = {}
    for _idx, rec in _records_iter(records):
        rid = _record_id_of(rec)
        if rid:
            records_by_urn[rid] = rec

    diags: list[ValidationDiagnostic] = []
    for i, rel in enumerate(relationships):
        if not isinstance(rel, dict):
            continue
        if rel.get("relationship_type") != PUBLIC_PROJECTION_OF:
            continue
        source_ref = rel.get("source_ref")
        target_ref = rel.get("target_ref")
        if not isinstance(source_ref, str) or not isinstance(target_ref, str):
            continue

        problems: list[str] = []

        # Endpoint grammar (Finding 1): a public_projection_of edge MUST link two
        # RECORD URNs. An entity URN endpoint (urn:acef:sub:/cmp:/dat:/act:) — or any
        # other non-record URN — is a malformed projection (record↔entity) → ACEF-083;
        # it is NOT silently skipped just because the entity URN is absent from the
        # record index. A WELL-FORMED but dangling record URN, however, is the
        # reference checker's ACEF-020 concern, so it is left to that checker (no
        # double-report) and the endpoint contributes no problem here.
        source_rec: dict[str, Any] | None = None
        target_rec: dict[str, Any] | None = None
        for ref, label in ((source_ref, "source"), (target_ref, "target")):
            resolved: dict[str, Any] | None = records_by_urn.get(ref)
            if resolved is not None:
                if label == "source":
                    source_rec = resolved
                else:
                    target_rec = resolved
                continue
            if _is_record_urn(ref):
                # Well-formed record URN with no in-bundle record: dangling →
                # ACEF-020 (reference checker), not ACEF-083. No problem added.
                continue
            problems.append(
                f"{label} endpoint {ref!r} is not a record URN (urn:acef:rec:<uuid>) — a "
                f"public_projection_of edge MUST link two in-bundle records, not an entity "
                f"(or other non-record) URN"
            )

        # Record-type + shared-id checks only for endpoints that resolved to an
        # in-bundle record. The report's AUTHORITATIVE id is its
        # card_source.public_incident_id (§5.7); the card's is its payload-root id
        # (Finding 2 — by-record-type extraction, so a root-level id on the report
        # cannot mask a divergent card_source id).
        src_type = _record_type_of(source_rec) if source_rec is not None else None
        tgt_type = _record_type_of(target_rec) if target_rec is not None else None
        src_pid = _report_public_incident_id_of(_payload_of(source_rec)) if source_rec is not None else None
        tgt_pid = _card_public_incident_id_of(_payload_of(target_rec)) if target_rec is not None else None

        if source_rec is not None and src_type != "incident_report":
            problems.append(
                f"source record {source_ref!r} is record_type {src_type!r}, not 'incident_report' "
                f"(the projection's SOURCE must be the private report)"
            )
        if target_rec is not None and tgt_type != "incident_card":
            problems.append(
                f"target record {target_ref!r} is record_type {tgt_type!r}, not 'incident_card' "
                f"(the projection's TARGET must be the public card)"
            )
        # Shared-id check only when both endpoints resolved to records and both ids
        # are present; a missing id on a resolved endpoint is reported as its own
        # problem so the diagnostic is actionable.
        if source_rec is not None and src_pid is None:
            problems.append(f"source record {source_ref!r} carries no card_source.public_incident_id")
        if target_rec is not None and tgt_pid is None:
            problems.append(f"target record {target_ref!r} carries no public_incident_id")
        if src_pid is not None and tgt_pid is not None and src_pid != tgt_pid:
            problems.append(
                f"the report's card_source.public_incident_id ({src_pid!r}) and the card's "
                f"public_incident_id ({tgt_pid!r}) differ — a public_projection_of edge MUST "
                f"link a report and card sharing ONE public_incident_id"
            )

        if problems:
            joined = "; ".join(problems)
            diags.append(
                ValidationDiagnostic(
                    "ACEF-083",
                    (
                        f"public_projection_of relationship {i} is semantically malformed (§5.1/§5.8): "
                        f"{joined}. The card is the deterministic public projection of the report; the "
                        f"edge MUST run report→card (source=incident_report, target=incident_card) and "
                        f"both records MUST share the same public_incident_id. Correct the edge endpoints, "
                        f"the record types, or the public_incident_id linkage."
                    ),
                    path=f"/entities/relationships/{i}",
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
    manifest_timestamp: str | None = None,
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

    ``manifest_timestamp`` is the bundle's ``metadata.timestamp`` (threaded from
    the engine). It anchors the x5c certificate-validity check in the ACEF-083 JWS
    self-consistency sub-check (spec §3.1.3 — cert expiry against the manifest
    timestamp, NOT wall-clock, for reproducible verification). The JWS sub-check is
    otherwise computed wholly from bundle bytes (attribution-free, no network).
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
    diags.extend(check_public_incident_id_offline(records, manifest=manifest, manifest_timestamp=manifest_timestamp))
    diags.extend(check_art73_clock(records, profiles=profiles))
    diags.extend(check_art73_existential(records, profiles=profiles))
    diags.extend(check_crosswalk_harm_core_consistency(records))
    diags.extend(check_incident_edges(manifest, records))
    diags.extend(check_publishability(records, source_backed=source_backed))
    diags.extend(check_dedupe_key_confidentiality(records))
    diags.extend(check_near_miss_marker(records))
    diags.extend(check_severity_band_consistency(records))
    return diags
