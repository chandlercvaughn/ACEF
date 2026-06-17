"""ACEF test fixtures and shared configuration.

Also owns the authoritative tier-marker auto-application hook (F-M1-TIER-INFRA,
VAL-TIER-002). Tests located under known top-level directories are tagged with
their tier marker by ``pytest_collection_modifyitems`` so that callers can use
``pytest -m plumbing``, ``pytest -m conformance``, ``pytest -m regression``,
and ``pytest -m integration`` selectors without touching every test file. The
auto-applied markers compose with any explicit ``@pytest.mark.<tier>``
decorators on individual tests (pytest deduplicates by marker name).
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from acef.models.enums import (
    ObligationRole,
)
from acef.models.records import EntityRefs, RecordEnvelope
from acef.package import Package


@pytest.fixture
def tmp_dir():
    """Provide a temporary directory for test output."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def minimal_package() -> Package:
    """Create a minimal valid package with one subject and one record."""
    pkg = Package(producer={"name": "test-tool", "version": "1.0.0"})
    system = pkg.add_subject(
        "ai_system",
        name="Test System",
        risk_classification="high-risk",
        modalities=["text"],
        lifecycle_phase="deployment",
    )
    pkg.record(
        "risk_register",
        provisions=["article-9"],
        # A SCHEMA-VALID risk_register payload: risk_id + description + category are
        # required, and likelihood/severity are closed enums (prior fixture used the
        # non-enum "medium"/"high", producing a schema-invalid record).
        payload={
            "risk_id": "RISK-001",
            "description": "Test risk",
            "category": "safety",
            "likelihood": "possible",
            "severity": "major",
        },
        obligation_role="provider",
        entity_refs={"subject_refs": [system.id]},
    )
    return pkg


@pytest.fixture
def full_package() -> Package:
    """Create a fully-featured package with multiple subjects, entities, and records."""
    pkg = Package(
        producer={"name": "acme-tool", "version": "2.0.0"},
        retention_policy={"min_retention_days": 3650},
    )

    # Subjects
    system = pkg.add_subject(
        "ai_system",
        name="Acme RAG Assistant",
        version="2.1.0",
        provider="Acme AI Corp",
        risk_classification="high-risk",
        modalities=["text"],
        lifecycle_phase="deployment",
    )
    model = pkg.add_subject(
        "ai_model",
        name="Acme LLM",
        version="3.0.0",
        provider="Acme AI Corp",
        risk_classification="gpai",
        modalities=["text"],
    )

    # Components
    retriever = pkg.add_component(
        name="Vector Retriever",
        type="retriever",
        version="3.1.0",
        subject_refs=[system.id],
    )
    pkg.add_component(
        name="Safety Filter",
        type="guardrail",
        version="1.4.0",
        subject_refs=[system.id],
    )

    # Datasets
    training_data = pkg.add_dataset(
        name="Training Data",
        source_type="licensed",
        modality="text",
        size={"records": 1000000, "size_gb": 100},
        subject_refs=[model.id],
    )

    # Actors
    pkg.add_actor(name="Jane Smith", role="provider", organization="Acme AI Corp")

    # Relationships
    pkg.add_relationship(system.id, model.id, "wraps")
    pkg.add_relationship(system.id, retriever.id, "calls")
    pkg.add_relationship(model.id, training_data.id, "trains_on")

    # Profiles
    pkg.add_profile("eu-ai-act-2024", provisions=["article-9", "article-10", "article-50.2"])

    # Records
    pkg.record(
        "risk_register",
        provisions=["article-9"],
        payload={"description": "Risk 1", "likelihood": "high", "severity": "high"},
        obligation_role="provider",
        entity_refs={"subject_refs": [system.id]},
    )
    pkg.record(
        "risk_treatment",
        provisions=["article-9"],
        payload={"treatment_type": "mitigate", "description": "Treatment 1"},
        obligation_role="provider",
        entity_refs={"subject_refs": [system.id]},
    )
    pkg.record(
        "data_provenance",
        provisions=["article-10"],
        payload={"acquisition_method": "licensed", "acquisition_date": "2025-09-01"},
        obligation_role="provider",
        entity_refs={"dataset_refs": [training_data.id]},
    )
    pkg.record(
        "transparency_marking",
        provisions=["article-50.2"],
        payload={
            "modality": "text",
            "marking_scheme_id": "c2pa-content-credentials",
            "scheme_version": "2.3",
            "metadata_container": "xmp/c2pa-manifest-store",
            "watermark_applied": True,
        },
        obligation_role="provider",
        entity_refs={"subject_refs": [system.id]},
    )
    pkg.record(
        "dataset_card",
        provisions=["article-10"],
        payload={"name": "Training Data", "description": "Licensed dataset"},
        obligation_role="provider",
        entity_refs={"dataset_refs": [training_data.id]},
    )
    pkg.record(
        "evaluation_report",
        provisions=["article-11"],
        payload={"methodology": "benchmark", "results": {"accuracy": 0.95}},
        obligation_role="provider",
        entity_refs={"subject_refs": [system.id]},
    )

    return pkg


@pytest.fixture
def sample_record() -> RecordEnvelope:
    """Create a sample RecordEnvelope."""
    return RecordEnvelope(
        record_type="risk_register",
        provisions_addressed=["article-9"],
        payload={"description": "Test risk"},
        obligation_role=ObligationRole.PROVIDER,
        entity_refs=EntityRefs(subject_refs=["urn:acef:sub:00000000-0000-0000-0000-000000000001"]),
    )


# ---------------------------------------------------------------------------
# Tier-marker auto-application (F-M1-TIER-INFRA, VAL-TIER-002 / VAL-TIER-003)
# ---------------------------------------------------------------------------
#
# pytest invokes ``pytest_collection_modifyitems`` once after collection. We
# walk each collected item's filesystem path and tag it with the tier markers
# its location implies:
#
#   tests/conformance/   -> plumbing + conformance
#   tests/unit/          -> plumbing
#   tests/integration/   -> integration
#
# ``item.add_marker`` is additive; explicit ``@pytest.mark.<tier>`` decorators
# on individual tests remain in place and are deduplicated by pytest. Tests
# located outside the three known directories receive no auto-applied tier
# marker (a future ``tests/perf/`` directory would not break this hook).
def pytest_collection_modifyitems(  # noqa: D401  (pytest hook signature)
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    """Auto-apply tier markers based on test file location.

    See module docstring and ``pyproject.toml`` ``[tool.pytest.ini_options]``
    for the tier model owned by F-M1-TIER-INFRA.
    """
    for item in items:
        parts = Path(str(item.fspath)).parts
        if "conformance" in parts and "tests" in parts:
            item.add_marker(pytest.mark.plumbing)
            item.add_marker(pytest.mark.conformance)
        elif "unit" in parts and "tests" in parts:
            item.add_marker(pytest.mark.plumbing)
        elif "integration" in parts and "tests" in parts:
            item.add_marker(pytest.mark.integration)
