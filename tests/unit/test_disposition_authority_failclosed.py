"""VAL-FIX-AUTH-005 / VAL-FIX-AUTH-006: disposition authority fails closed.

Audit findings (operation acef-audit-remediation):

- cross-record-authority-5 (HIGH/security): a disposition record carrying
  ``authority_check.authority_granted: true`` but a missing / typo'd /
  non-string / unrecognized ``authority_class`` silently skips the §14.5
  matrix — an authority-bypass false-green. The fix fails closed: such a
  record MUST emit ACEF-080 with a message naming the discriminator failure.

- cross-record-authority-6 (medium/security): when
  ``authority_check.actor_ref`` is absent, only ``entity_refs.actor_refs[0]``
  was evaluated — ordering a permitted actor first hid a denied actor. The
  fix evaluates EVERY ``actor_refs[]`` entry; ANY denied actor emits
  ACEF-080. An explicit ``authority_check.actor_ref`` keeps single-actor
  semantics (it is an explicit claim).

Legitimate silent-skip paths that MUST be preserved:

- record is not a disposition record (wrong type / wrong subtype);
- no ``authority_check`` block at all;
- ``authority_granted`` absent or not ``True`` (no authority is claimed).
"""

from __future__ import annotations

from typing import Any

from acef.validation.cross_record import enforce_disposition_authority

_DEPLOYER = "urn:acef:act:abc12345-0000-0000-0000-0000000000d1"
_PROVIDER = "urn:acef:act:abc12345-0000-0000-0000-0000000000c1"
_AUDITOR = "urn:acef:act:abc12345-0000-0000-0000-0000000000a1"
_UNDECLARED = "urn:acef:act:abc12345-0000-0000-0000-0000000000ee"
_REC_ID = "urn:acef:rec:abc12345-0000-0000-0000-000000000001"

_AUTHORITY_PHRASE = "authority matrix denies"


def _manifest(*actors: tuple[str, str]) -> dict[str, Any]:
    """Manifest stub with entities.actors built from (actor_id, role) pairs."""
    return {
        "entities": {
            "actors": [
                {
                    "actor_id": actor_id,
                    "role": role,
                    "name": "test-actor",
                    "organization": "test-org",
                }
                for actor_id, role in actors
            ]
        }
    }


def _disposition(
    *,
    authority_check: dict[str, Any] | None,
    actor_refs: list[Any] | None = None,
    record_type: str = "risk_treatment",
    treatment_subtype: str = "external_disposition",
) -> dict[str, Any]:
    """A risk_treatment/external_disposition record stub."""
    payload: dict[str, Any] = {"treatment_subtype": treatment_subtype}
    if authority_check is not None:
        payload["authority_check"] = authority_check
    rec: dict[str, Any] = {
        "record_id": _REC_ID,
        "record_type": record_type,
        "payload": payload,
    }
    if actor_refs is not None:
        rec["entity_refs"] = {"actor_refs": actor_refs}
    return rec


# ---------------------------------------------------------------------------
# VAL-FIX-AUTH-005: missing / typo'd / non-string / unrecognized
# authority_class fails CLOSED (ACEF-080), never a silent skip.
# ---------------------------------------------------------------------------


class TestAuthorityClassFailsClosed:
    def test_typo_authority_clas_key_emits_acef_080(self) -> None:
        """The audit's exact exploit: `authority_clas` (typo) carrying a
        matrix-DENIED value escapes the matrix with NO diagnostic."""
        manifest = _manifest((_PROVIDER, "provider"))
        rec = _disposition(
            authority_check={
                "authority_clas": "accepted_risk_request",  # typo'd key
                "authority_granted": True,
                "actor_ref": _PROVIDER,
            },
        )
        diags = enforce_disposition_authority(manifest, [rec])
        assert len(diags) == 1, f"typo'd authority_class must fail closed; got {diags!r}"
        assert diags[0].code == "ACEF-080"
        assert "authority_class" in diags[0].message
        assert "missing" in diags[0].message
        assert _REC_ID in diags[0].message

    def test_authority_class_key_absent_emits_acef_080(self) -> None:
        manifest = _manifest((_PROVIDER, "provider"))
        rec = _disposition(
            authority_check={"authority_granted": True, "actor_ref": _PROVIDER},
        )
        diags = enforce_disposition_authority(manifest, [rec])
        assert len(diags) == 1
        assert diags[0].code == "ACEF-080"
        assert "authority_class" in diags[0].message
        assert "missing" in diags[0].message

    def test_non_string_authority_class_emits_acef_080(self) -> None:
        manifest = _manifest((_PROVIDER, "provider"))
        rec = _disposition(
            authority_check={
                "authority_class": 42,
                "authority_granted": True,
                "actor_ref": _PROVIDER,
            },
        )
        diags = enforce_disposition_authority(manifest, [rec])
        assert len(diags) == 1
        assert diags[0].code == "ACEF-080"
        assert "authority_class" in diags[0].message

    def test_empty_string_authority_class_emits_acef_080(self) -> None:
        manifest = _manifest((_PROVIDER, "provider"))
        rec = _disposition(
            authority_check={
                "authority_class": "",
                "authority_granted": True,
                "actor_ref": _PROVIDER,
            },
        )
        diags = enforce_disposition_authority(manifest, [rec])
        assert len(diags) == 1
        assert diags[0].code == "ACEF-080"
        assert "authority_class" in diags[0].message

    def test_unrecognized_authority_class_names_the_value(self) -> None:
        """A non-empty string outside the five §14.5 classes must produce a
        PRECISE 'unrecognized authority_class' diagnostic (not the generic
        denied-pair message)."""
        manifest = _manifest((_PROVIDER, "provider"))
        rec = _disposition(
            authority_check={
                "authority_class": "self_certified_blanket_waiver",
                "authority_granted": True,
                "actor_ref": _PROVIDER,
            },
        )
        diags = enforce_disposition_authority(manifest, [rec])
        assert len(diags) == 1
        assert diags[0].code == "ACEF-080"
        assert "unrecognized" in diags[0].message
        assert "self_certified_blanket_waiver" in diags[0].message


# ---------------------------------------------------------------------------
# VAL-FIX-AUTH-006: EVERY entity_refs.actor_refs[] entry is evaluated when
# authority_check.actor_ref is absent — ANY denied actor fires ACEF-080.
# ---------------------------------------------------------------------------


class TestEveryActorEvaluated:
    def test_denied_actor_hidden_behind_permitted_first_actor(self) -> None:
        """The audit's exact exploit: deployer (permitted for
        accepted_risk_request) listed FIRST hides provider (DENIED) listed
        second — currently evaluated against actor_refs[0] only."""
        manifest = _manifest((_DEPLOYER, "deployer"), (_PROVIDER, "provider"))
        rec = _disposition(
            authority_check={
                "authority_class": "accepted_risk_request",
                "authority_granted": True,
                # no actor_ref → fallback must check ALL actor_refs
            },
            actor_refs=[_DEPLOYER, _PROVIDER],
        )
        diags = enforce_disposition_authority(manifest, [rec])
        assert len(diags) == 1, f"denied second actor must be caught; got {diags!r}"
        assert diags[0].code == "ACEF-080"
        assert _AUTHORITY_PHRASE in diags[0].message
        assert _PROVIDER in diags[0].message
        assert "provider" in diags[0].message

    def test_undeclared_actor_in_fallback_list_emits_acef_080(self) -> None:
        manifest = _manifest((_DEPLOYER, "deployer"))
        rec = _disposition(
            authority_check={
                "authority_class": "accepted_risk_request",
                "authority_granted": True,
            },
            actor_refs=[_DEPLOYER, _UNDECLARED],
        )
        diags = enforce_disposition_authority(manifest, [rec])
        assert len(diags) == 1
        assert diags[0].code == "ACEF-080"
        assert _UNDECLARED in diags[0].message
        assert "not declared" in diags[0].message

    def test_multiple_denied_actors_each_flagged(self) -> None:
        """All-errors-per-phase pattern: two denied actors → two diagnostics,
        each naming its actor."""
        manifest = _manifest((_PROVIDER, "provider"), (_AUDITOR, "auditor"))
        rec = _disposition(
            authority_check={
                "authority_class": "accepted_risk_request",
                "authority_granted": True,
            },
            actor_refs=[_PROVIDER, _AUDITOR],
        )
        diags = enforce_disposition_authority(manifest, [rec])
        assert len(diags) == 2
        assert all(d.code == "ACEF-080" for d in diags)
        assert all(_AUTHORITY_PHRASE in d.message for d in diags)
        messages = " | ".join(d.message for d in diags)
        assert _PROVIDER in messages
        assert _AUDITOR in messages

    def test_explicit_actor_ref_keeps_single_actor_semantics(self) -> None:
        """An explicit authority_check.actor_ref is an explicit claim: only
        that actor is evaluated, even if a denied actor appears in
        entity_refs.actor_refs."""
        manifest = _manifest((_DEPLOYER, "deployer"), (_PROVIDER, "provider"))
        rec = _disposition(
            authority_check={
                "authority_class": "accepted_risk_request",
                "authority_granted": True,
                "actor_ref": _DEPLOYER,  # permitted; explicit claim
            },
            actor_refs=[_DEPLOYER, _PROVIDER],
        )
        diags = enforce_disposition_authority(manifest, [rec])
        assert diags == [], f"explicit actor_ref must keep single-actor semantics; got {diags!r}"

    def test_explicit_denied_actor_ref_still_fires(self) -> None:
        manifest = _manifest((_DEPLOYER, "deployer"), (_PROVIDER, "provider"))
        rec = _disposition(
            authority_check={
                "authority_class": "accepted_risk_request",
                "authority_granted": True,
                "actor_ref": _PROVIDER,  # denied; explicit claim
            },
            actor_refs=[_DEPLOYER, _PROVIDER],
        )
        diags = enforce_disposition_authority(manifest, [rec])
        assert len(diags) == 1
        assert diags[0].code == "ACEF-080"
        assert _AUTHORITY_PHRASE in diags[0].message
        assert _PROVIDER in diags[0].message

    def test_granted_with_no_resolvable_actor_fails_closed(self) -> None:
        """No actor_ref AND no entity_refs.actor_refs: a granted disposition
        with no authorizing actor stays a §14.5 violation (fail closed)."""
        manifest = _manifest((_DEPLOYER, "deployer"))
        rec = _disposition(
            authority_check={
                "authority_class": "accepted_risk_request",
                "authority_granted": True,
            },
        )
        diags = enforce_disposition_authority(manifest, [rec])
        assert len(diags) == 1
        assert diags[0].code == "ACEF-080"


# ---------------------------------------------------------------------------
# Legitimate skip paths preserved (positives).
# ---------------------------------------------------------------------------


class TestLegitimateSkipsPreserved:
    def test_legit_granted_disposition_stays_clean(self) -> None:
        manifest = _manifest((_DEPLOYER, "deployer"))
        rec = _disposition(
            authority_check={
                "authority_class": "accepted_risk_request",
                "authority_granted": True,
                "actor_ref": _DEPLOYER,
            },
            actor_refs=[_DEPLOYER],
        )
        assert enforce_disposition_authority(manifest, [rec]) == []

    def test_multi_actor_all_permitted_stays_clean(self) -> None:
        manifest = _manifest((_DEPLOYER, "deployer"), (_AUDITOR, "auditor"))
        rec = _disposition(
            authority_check={
                "authority_class": "priority",
                "authority_granted": True,
            },
            actor_refs=[_DEPLOYER, _AUDITOR],
        )
        assert enforce_disposition_authority(manifest, [rec]) == []

    def test_no_authority_check_block_skipped_silently(self) -> None:
        manifest = _manifest((_PROVIDER, "provider"))
        rec = _disposition(authority_check=None, actor_refs=[_PROVIDER])
        assert enforce_disposition_authority(manifest, [rec]) == []

    def test_authority_granted_false_skipped_silently(self) -> None:
        manifest = _manifest((_PROVIDER, "provider"))
        rec = _disposition(
            authority_check={
                "authority_class": "accepted_risk_request",
                "authority_granted": False,
                "actor_ref": _PROVIDER,
            },
        )
        assert enforce_disposition_authority(manifest, [rec]) == []

    def test_authority_granted_absent_skipped_silently(self) -> None:
        """No authority_granted key = no authority claimed = legitimate
        silent skip, even with a typo'd/absent authority_class."""
        manifest = _manifest((_PROVIDER, "provider"))
        rec = _disposition(
            authority_check={"authority_clas": "accepted_risk_request"},
        )
        assert enforce_disposition_authority(manifest, [rec]) == []

    def test_non_disposition_subtype_skipped_silently(self) -> None:
        manifest = _manifest((_PROVIDER, "provider"))
        rec = _disposition(
            authority_check={
                "authority_granted": True,  # missing authority_class too
            },
            treatment_subtype="regression_definition",
        )
        assert enforce_disposition_authority(manifest, [rec]) == []

    def test_non_risk_treatment_record_skipped_silently(self) -> None:
        manifest = _manifest((_PROVIDER, "provider"))
        rec = _disposition(
            authority_check={"authority_granted": True},
            record_type="risk_register",
        )
        assert enforce_disposition_authority(manifest, [rec]) == []
