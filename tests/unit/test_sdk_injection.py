"""Unit tests for Package(clock=, urn_generator=) injection.

Fulfills:
- VAL-SDK-008: Default Package() (no injection) uses datetime.utcnow + uuid4;
  existing v0.3 test suite continues to pass.
- Sanity: injection actually replaces the default callables for records
  built via Package.record().
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

from acef.models.urns import URNType
from acef.package import Package

# Matches urn:acef:<type>:<uuid> per src/acef/models/urns.py:19-22
_URN_RE = re.compile(
    r"^urn:acef:(pkg|sub|cmp|dat|act|rec|asx):"
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
# Matches "YYYY-MM-DDTHH:MM:SSZ" per spec timestamp format
_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


# ---------------------------------------------------------------------------
# VAL-SDK-008 — default behavior unchanged
# ---------------------------------------------------------------------------


def test_val_sdk_008_default_package_uses_realtime_clock_and_uuid4() -> None:
    """Package() with no injection MUST use datetime.now(tz=utc) + uuid4-based
    URNs. Two records minted via Package.record() get distinct record_ids,
    and their timestamps are within a few seconds of now.
    """
    before = datetime.now(UTC)
    pkg = Package(producer={"name": "x", "version": "1.0.0"})

    rec1 = pkg.record(record_type="risk_register", payload={"k": 1})
    rec2 = pkg.record(record_type="risk_register", payload={"k": 2})
    after = datetime.now(UTC)

    # Distinct UUID-based record_ids
    assert rec1.record_id != rec2.record_id
    assert _URN_RE.match(rec1.record_id), f"record_id not URN-shaped: {rec1.record_id!r}"
    assert _URN_RE.match(rec2.record_id), f"record_id not URN-shaped: {rec2.record_id!r}"

    # Timestamps roughly equal "now"
    for rec in (rec1, rec2):
        assert _TS_RE.match(rec.timestamp), f"timestamp not ISO 8601 Z: {rec.timestamp!r}"
        ts = datetime.fromisoformat(rec.timestamp.replace("Z", "+00:00"))
        assert before.replace(microsecond=0) - _one_sec() <= ts <= after.replace(microsecond=0) + _one_sec(), (
            f"timestamp {ts} not within [before-1s, after+1s] window [{before}, {after}]"
        )

    # Package metadata timestamp + package_id also reflect runtime defaults
    assert _TS_RE.match(pkg.metadata.timestamp)
    assert _URN_RE.match(pkg.metadata.package_id)


def _one_sec():
    from datetime import timedelta

    return timedelta(seconds=1)


# ---------------------------------------------------------------------------
# Injection sanity — clock callable is honored
# ---------------------------------------------------------------------------


def test_injected_clock_is_used_for_record_timestamp() -> None:
    """Package(clock=fixed) — calling record() without explicit timestamp
    populates envelope.timestamp from the injected clock.
    """
    fixed = datetime(2020, 1, 1, 12, 0, 0, tzinfo=UTC)
    pkg = Package(
        producer={"name": "x", "version": "1.0.0"},
        clock=lambda: fixed,
    )
    rec = pkg.record(record_type="risk_register", payload={"k": 1})

    # Format: YYYY-MM-DDTHH:MM:SSZ (Z suffix, no microseconds)
    assert rec.timestamp == "2020-01-01T12:00:00Z", f"injected clock not honored; got {rec.timestamp!r}"

    # Package metadata timestamp also from injected clock
    assert pkg.metadata.timestamp == "2020-01-01T12:00:00Z"


def test_injected_urn_generator_is_used_for_record_id() -> None:
    """Package(urn_generator=fixed) — calling record() without explicit
    record_id mints record_id via the injected generator.
    """
    counter = {"n": 0}

    def gen(urn_type: URNType) -> str:
        counter["n"] += 1
        return f"urn:acef:{urn_type.value}:00000000-0000-0000-0000-{counter['n']:012x}"

    pkg = Package(
        producer={"name": "x", "version": "1.0.0"},
        urn_generator=gen,
    )
    rec1 = pkg.record(record_type="risk_register", payload={"k": 1})
    rec2 = pkg.record(record_type="risk_register", payload={"k": 2})

    # Package package_id consumed counter slot 1; rec1 = 2; rec2 = 3
    # (exact value depends on construction order; just assert they are
    # distinct and follow the injected pattern)
    assert rec1.record_id != rec2.record_id
    assert rec1.record_id.startswith("urn:acef:rec:00000000-0000-0000-0000-")
    assert rec2.record_id.startswith("urn:acef:rec:00000000-0000-0000-0000-")
    assert pkg.metadata.package_id.startswith("urn:acef:pkg:00000000-0000-0000-0000-")


def test_explicit_record_id_overrides_injection() -> None:
    """If the caller passes record_id explicitly to record(), it wins."""
    pkg = Package(
        producer={"name": "x", "version": "1.0.0"},
        urn_generator=lambda t: "urn:acef:rec:99999999-9999-9999-9999-999999999999",
    )
    rec = pkg.record(
        record_type="risk_register",
        payload={"k": 1},
        record_id="urn:acef:rec:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    )
    assert rec.record_id == "urn:acef:rec:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"


def test_explicit_timestamp_overrides_injection() -> None:
    """If the caller passes timestamp explicitly to record(), it wins."""
    pkg = Package(
        producer={"name": "x", "version": "1.0.0"},
        clock=lambda: datetime(1999, 1, 1, tzinfo=UTC),
    )
    rec = pkg.record(
        record_type="risk_register",
        payload={"k": 1},
        timestamp="2030-06-15T10:20:30Z",
    )
    assert rec.timestamp == "2030-06-15T10:20:30Z"


def test_clock_and_urn_generator_used_by_typed_builders() -> None:
    """The typed builders from F-M1-SDK-BUILDERS (record_scope_boundary_event,
    record_finding, record_delivery_verdict, attest) MUST also honor the
    injected clock + urn_generator when they internally mint URNs.
    """
    counter = {"n": 0}

    def gen(urn_type: URNType) -> str:
        counter["n"] += 1
        return f"urn:acef:{urn_type.value}:00000000-0000-0000-0000-{counter['n']:012x}"

    fixed = datetime(2024, 5, 1, 0, 0, 0, tzinfo=UTC)
    pkg = Package(
        producer={"name": "x", "version": "1.0.0"},
        clock=lambda: fixed,
        urn_generator=gen,
    )

    rec = pkg.record_finding(
        class_="safety_failure",
        subject_ref="urn:acef:sub:11111111-1111-1111-1111-111111111111",
        expected_behavior="agent refuses out-of-scope action",
        reproduction_steps_ref_content_hash="sha256:" + "0" * 64,
        severity={
            "severity_level": "high",
            "severity_rationale": "production-capable scope",
        },
        reproduction={
            "expected_behavior": "agent refuses out-of-scope action",
            "observed_behavior": "agent attempted unauthorized action",
            "reproduction_steps_ref": "urn:acef:rec:22222222-2222-2222-2222-222222222222",
            "evidence_commit_ref": "sha256:" + "a" * 64,
        },
        attribution={
            "persona_ref": "urn:acef:rec:33333333-3333-3333-3333-333333333333",
            "scenario_ref": "urn:acef:rec:33333333-3333-3333-3333-333333333334",
            "scope_ref": "urn:acef:rec:33333333-3333-3333-3333-333333333335",
        },
        discovered_at="2025-01-01T00:00:00Z",
        discovered_in_run_ref="urn:acef:rec:44444444-4444-4444-4444-444444444444",
    )

    # The envelope timestamp comes from injected clock
    assert rec.timestamp == "2024-05-01T00:00:00Z"
    # The envelope record_id is from injected generator (not uuid4-random)
    assert rec.record_id.startswith("urn:acef:rec:00000000-0000-0000-0000-")
    # The PAYLOAD finding_id is also from injected generator (not uuid4-random)
    assert rec.payload["finding_id"].startswith("urn:acef:rec:00000000-0000-0000-0000-"), (
        f"finding_id not from injected generator: {rec.payload['finding_id']!r}"
    )
