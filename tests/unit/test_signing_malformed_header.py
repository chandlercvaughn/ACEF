"""Stability-shakedown: ``verify_detached_jws`` must raise the structured
``ACEFSigningError`` (never a raw framework exception) for a malformed JWS
protected header — found by the whole-codebase review.

Two gaps (empirically reproduced against the public ``acef.verify`` /
``verify_detached_jws`` API, and reachable via ``acef doctor`` whose
``check_integrity`` call has no try/except):

* a truthy NON-LIST ``x5c`` (e.g. ``{"alg":"RS256","kid":"k","x5c":5}``) reached
  ``verify_x5c_chain`` -> ``_parse_x5c_chain`` -> ``enumerate(5)`` -> raw
  ``TypeError: 'int' object is not iterable``.
* a NON-DICT ``jwk`` (e.g. ``{"alg":"ES256","kid":"k","jwk":"notadict"}``) reached
  ``_load_public_key_from_jwk`` -> ``jwk.get("kty")`` -> raw
  ``AttributeError: 'str' object has no attribute 'get'``.

The ``verify_detached_jws`` contract documents ``Raises: ACEFSigningError`` only.
"""

from __future__ import annotations

import base64
import json

import pytest

from acef.errors import ACEFSigningError
from acef.signing import _load_public_key_from_jwk, verify_detached_jws, verify_x5c_chain


def _b64url(obj: object) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def _jws(header: dict) -> str:
    # detached JWS: <protected>..<sig>; the malformed header is rejected during
    # key resolution, before the signature is ever checked.
    return _b64url(header) + "..AAAA"


class TestMalformedX5cHeader:
    @pytest.mark.parametrize("x5c", [5, 1.5, True, "notalist", {"a": 1}])
    def test_non_list_x5c_raises_structured_not_typeerror(self, x5c: object) -> None:
        header = {"alg": "RS256", "kid": "k", "x5c": x5c}
        with pytest.raises(ACEFSigningError) as exc:
            verify_detached_jws(_jws(header), b"payload")
        assert exc.value.code == "ACEF-012"

    @pytest.mark.parametrize("x5c", [5, "notalist", {"a": 1}])
    def test_verify_x5c_chain_entry_guard(self, x5c: object) -> None:
        with pytest.raises(ACEFSigningError) as exc:
            verify_x5c_chain(x5c)  # type: ignore[arg-type]
        assert exc.value.code == "ACEF-012"


class TestMalformedJwkHeader:
    @pytest.mark.parametrize("jwk", ["notadict", 5, [1, 2], True])
    def test_non_dict_jwk_raises_structured_not_attributeerror(self, jwk: object) -> None:
        header = {"alg": "ES256", "kid": "k", "jwk": jwk}
        with pytest.raises(ACEFSigningError) as exc:
            verify_detached_jws(_jws(header), b"payload")
        assert exc.value.code == "ACEF-012"

    @pytest.mark.parametrize("jwk", ["notadict", 5, [1, 2]])
    def test_load_public_key_from_jwk_entry_guard(self, jwk: object) -> None:
        with pytest.raises(ACEFSigningError) as exc:
            _load_public_key_from_jwk(jwk)  # type: ignore[arg-type]
        assert exc.value.code == "ACEF-012"


class TestMalformedHeaderShape:
    """roborev follow-up: the protected header itself, when a valid JSON
    array/scalar (not an object), reached header.get() and leaked a raw
    AttributeError; and a JWK with a non-string Base64urlUInt member (n/e/x/y)
    reached _base64url_decode's regex and leaked a raw TypeError."""

    @pytest.mark.parametrize("hdr", [[], [1, 2], "x", 5, 1.5, True, None])
    def test_non_object_protected_header_raises_structured(self, hdr: object) -> None:
        jws = _b64url(hdr) + "..AAAA"
        with pytest.raises(ACEFSigningError) as exc:
            verify_detached_jws(jws, b"payload")
        assert exc.value.code == "ACEF-012"

    @pytest.mark.parametrize(
        "jwk",
        [
            {"kty": "RSA", "n": 5, "e": "AQAB"},
            {"kty": "RSA", "n": "AQAB", "e": [1]},
            {"kty": "EC", "crv": "P-256", "x": 5, "y": "abc"},
            {"kty": "EC", "crv": "P-256", "x": "abc", "y": {"k": 1}},
        ],
    )
    def test_jwk_with_non_string_base64url_member_raises_structured(self, jwk: dict) -> None:
        header = {"alg": "RS256" if jwk["kty"] == "RSA" else "ES256", "kid": "k", "jwk": jwk}
        with pytest.raises(ACEFSigningError) as exc:
            verify_detached_jws(_jws(header), b"payload")
        assert exc.value.code == "ACEF-012"


class TestUnhashableAlgHeader:
    """roborev follow-up: an object header with an unhashable `alg` value
    (`{"alg": []}`) reached `alg not in _ALLOWED_ALGORITHMS` (a frozenset) and
    leaked a raw TypeError. Type-check before membership."""

    @pytest.mark.parametrize("alg", [[], {}, [1, 2], {"k": "v"}, 5, 1.5, True, None])
    def test_non_string_alg_raises_structured_not_typeerror(self, alg: object) -> None:
        header = {"alg": alg, "kid": "k", "jwk": {"kty": "RSA"}}
        with pytest.raises(ACEFSigningError) as exc:
            verify_detached_jws(_jws(header), b"payload")
        assert exc.value.code == "ACEF-013"
