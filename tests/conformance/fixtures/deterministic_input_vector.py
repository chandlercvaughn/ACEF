"""Deterministic input vector for VAL-SDK-007 / VAL-SDK-DETERMINISM-ORDERING-001.

Provides a single :func:`build` entry point that, given a :class:`Package`
instance, appends a fixed sequence of subject, profile, and records.

Each record-add call passes an EXPLICIT ``timestamp`` and ``record_id``
derived from a stable per-record identifier. This guarantees that two
builds with shuffled add-order produce records whose
``(timestamp, record_id)`` tuples are paired identically with payload
content — so the export sort by ``(timestamp, record_id)`` per spec
§3.1.1 yields byte-equal output regardless of add-order.

Why explicit IDs: the spec mandates determinism (§3.1.1) and the
``Package(clock, urn_generator)`` injection (VAL-SDK-007) covers the
case where the caller has NOT supplied explicit values. For the
shuffled-add-order test we need to demonstrate that the export sort
itself is order-independent, which requires the (timestamp, record_id)
multiset to be identical across runs. Explicit IDs make that condition
mechanically obvious.
"""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from acef.package import Package


# Fixed input vector: each tuple is
#   (record_type, timestamp_iso, record_id_urn, provisions, payload).
# Sorted intentionally NOT by timestamp; the export sort is what
# normalizes order.
_RECORDS: tuple[tuple[str, str, str, list[str], dict], ...] = (
    (
        "risk_register",
        "2025-01-01T00:00:01Z",
        "urn:acef:rec:00000001-0000-0000-0000-000000000001",
        ["article-9"],
        {"risk_id": "R-001", "description": "Det risk A"},
    ),
    (
        "dataset_card",
        "2025-01-01T00:00:02Z",
        "urn:acef:rec:00000002-0000-0000-0000-000000000002",
        ["article-10"],
        {"name": "DetDataset", "size_records": 100},
    ),
    (
        "event_log",
        "2025-01-01T00:00:03Z",
        "urn:acef:rec:00000003-0000-0000-0000-000000000003",
        ["article-12"],
        {"event_type": "training", "summary": "Run #1"},
    ),
    (
        "event_log",
        "2025-01-01T00:00:04Z",
        "urn:acef:rec:00000004-0000-0000-0000-000000000004",
        ["article-12"],
        {"event_type": "training", "summary": "Run #2"},
    ),
    (
        "evaluation_report",
        "2025-01-01T00:00:05Z",
        "urn:acef:rec:00000005-0000-0000-0000-000000000005",
        ["article-15"],
        {"metric_name": "accuracy", "value": 0.95},
    ),
    (
        "conformity_declaration",
        "2025-01-01T00:00:06Z",
        "urn:acef:rec:00000006-0000-0000-0000-000000000006",
        ["article-16"],
        {"decision": "conform", "rationale": "All gates pass"},
    ),
)


def build(pkg: Package, *, shuffle: bool = False, shuffle_seed: int = 0) -> None:
    """Populate ``pkg`` with a deterministic input vector.

    Adds 1 subject, 1 profile, and 6 records with stable
    (timestamp, record_id) per logical record.

    Args:
        pkg: Target package.
        shuffle: If True, shuffle the record-add order.
        shuffle_seed: Deterministic shuffle seed.
    """
    pkg.add_subject(
        subject_type="ai_system",
        name="DetSystem",
        version="1.0.0",
        provider="acme",
        risk_classification="high-risk",
    )

    pkg.add_profile(
        profile_id="eu-ai-act-v1",
        provisions=["article-9", "article-10"],
    )

    records = list(_RECORDS)
    if shuffle:
        rng = random.Random(shuffle_seed)
        rng.shuffle(records)

    # The role-split record types (event_log here) require an explicit
    # obligation_role (spec §3.1 / audit envelope-manifest-5). Passing the
    # constant "provider" is byte-equivalent to the prior silent default, so
    # the deterministic output vector is unchanged.
    role_split = {"transparency_marking", "disclosure_labeling", "event_log"}
    for record_type, timestamp, record_id, provisions, payload in records:
        extra: dict[str, str] = {}
        if record_type in role_split:
            extra["obligation_role"] = "provider"
        pkg.record(
            record_type=record_type,
            provisions=provisions,
            payload=payload,
            timestamp=timestamp,
            record_id=record_id,
            **extra,
        )
