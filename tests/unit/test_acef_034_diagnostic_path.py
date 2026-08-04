"""ACEF-034 must be a real, reachable diagnostic — not a string inside a traceback.

roborev finding on fd291ff (Medium): after the retention-provenance commit,
"ACEF-034" existed only inside a Pydantic ``ValueError`` message. It was absent
from the error taxonomy, ``load_template()`` let the raw ``ValidationError``
escape, and ``_evaluate_profiles`` catches only ``ACEFError`` — so a template
with a bad retention block ABORTED validation with an unhandled exception
instead of producing a diagnostic.

A second, pre-existing defect surfaced by the same analysis: the engine's
``except ACEFError`` block at engine.py discards the caught exception entirely
and hardcodes ``ACEF-030 "Template not found"``. A template that EXISTS but
contains malformed JSON therefore reports "not found" — a factually false
message about a file sitting on disk.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from acef.errors import (
    EXTENDED_ERROR_DETAILS,
    ACEFProfileError,
    ErrorCategory,
    Severity,
    resolve_error_meta,
)
from acef.templates import registry
from acef.templates.registry import load_template


@pytest.fixture
def template_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the registry at an isolated template directory."""
    monkeypatch.setattr(registry, "_get_template_dir", lambda: tmp_path)
    registry.clear_template_cache()
    yield tmp_path
    registry.clear_template_cache()


def _write(directory: Path, template_id: str, payload: dict) -> None:
    (directory / f"{template_id}.json").write_text(json.dumps(payload), encoding="utf-8")


def _minimal(provisions: list[dict]) -> dict:
    return {
        "template_id": "thirdparty",
        "template_name": "Third Party",
        "version": "1.0.0",
        "provisions": provisions,
    }


class TestACEF034IsRegistered:
    def test_acef_034_is_in_the_error_taxonomy(self) -> None:
        """A code that no registry knows about cannot be documented or looked up."""
        assert "ACEF-034" in EXTENDED_ERROR_DETAILS

    def test_acef_034_resolves_to_the_right_severity_and_category(self) -> None:
        """resolve_error_meta is the single source of truth for both emission paths.

        Without a registry entry it silently falls back to the conservative
        error/schema default, so an unsourced retention figure would serialize
        under the wrong category.
        """
        severity, category = resolve_error_meta("ACEF-034")
        assert (severity, category) == (Severity.ERROR, ErrorCategory.PROFILE), (
            f"ACEF-034 resolved to {severity}/{category}; it is a template/profile "
            "defect and must not fall through to the error/schema default"
        )

    def test_acef_034_carries_a_problem_and_a_fix(self) -> None:
        detail = EXTENDED_ERROR_DETAILS["ACEF-034"]
        assert detail.problem.strip()
        assert detail.fix.strip()


class TestACEF034ReachesCallers:
    def test_bare_retention_years_raises_acef_profile_error_not_validation_error(self, template_dir: Path) -> None:
        """The target population: a third-party template with an unsourced figure.

        Before the fix this escaped as a raw pydantic ValidationError, which no
        ACEF caller is expected to catch.
        """
        _write(
            template_dir,
            "thirdparty",
            _minimal([{"provision_id": "p1", "retention_years": 10}]),
        )
        with pytest.raises(ACEFProfileError) as exc:
            load_template("thirdparty")
        assert exc.value.code == "ACEF-034", (
            f"expected ACEF-034 for an unsourced retention figure, got {exc.value.code}"
        )
        assert "ACEF-034" in str(exc.value)

    def test_genuinely_missing_template_still_raises_acef_030(self, template_dir: Path) -> None:
        """Regression guard: do not swallow the real not-found case."""
        with pytest.raises(ACEFProfileError) as exc:
            load_template("does-not-exist")
        assert exc.value.code == "ACEF-030"

    def test_malformed_json_still_raises_acef_030(self, template_dir: Path) -> None:
        (template_dir / "badjson.json").write_text('{"template_id": bad}', encoding="utf-8")
        with pytest.raises(ACEFProfileError) as exc:
            load_template("badjson")
        assert exc.value.code == "ACEF-030"

    def test_a_conforming_template_still_loads(self, template_dir: Path) -> None:
        """The gate must not reject provisions that carry no figure at all."""
        _write(template_dir, "thirdparty", _minimal([{"provision_id": "p1"}]))
        tpl = load_template("thirdparty")
        assert tpl.provisions[0].retention is None
