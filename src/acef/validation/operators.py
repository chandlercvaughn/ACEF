"""ACEF DSL operators — all 10 built-in operators per spec Section 3.5.

Each operator takes params and a list of records, returns (passed, evidence_refs).
Empty-set semantics:
  - Existential operators -> FAIL on zero records
  - Universal operators -> PASS (vacuous truth)
"""

from __future__ import annotations

import re
import signal
import sys
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import jsonpointer  # type: ignore[import-untyped]  # no published stubs / py.typed (no types-jsonpointer on PyPI)

from acef.errors import ACEFEvaluationError
from acef.integrity import canonicalize
from acef.models.records import RecordEnvelope
from acef.signing import verify_detached_jws

# Maximum allowed regex pattern length to mitigate ReDoS.
# Per ECMA-262 dialect requirement, patterns should be short rule-level matchers.
_MAX_REGEX_PATTERN_LENGTH = 1024

# Maximum allowed input string length for regex matching.
_MAX_REGEX_INPUT_LENGTH = 1_000_000

# Regex match timeout in seconds (only effective on Unix systems with SIGALRM).
_REGEX_TIMEOUT_SECONDS = 5


class _RegexTimeoutError(Exception):
    """Raised when a regex match exceeds the allowed timeout."""


def _regex_timeout_handler(signum: int, frame: Any) -> None:
    """Signal handler for regex timeout."""
    raise _RegexTimeoutError("Regex evaluation timed out")


# Pattern constructs that exist in Python's ``re`` module but are NOT
# valid ECMA-262 RegExp syntax. Spec §3.5 mandates ECMA-262; a strict
# implementation would require an embedded JS engine. As a pragmatic
# pre-validator we reject the constructs that most commonly diverge so
# templates that pass ACEF v1 validation will also parse under a future
# ECMA-262-true validator.
_NON_ECMA262_CONSTRUCTS = (
    # Python-only named group syntax — ECMA-262 uses (?<name>...)
    (re.compile(r"\(\?P<"), "Python-only named-group syntax (?P<name>...) — ECMA-262 uses (?<name>...)"),
    # Python-only named backreference
    (re.compile(r"\(\?P="), "Python-only named-backreference (?P=name) — ECMA-262 uses \\k<name>"),
    # Inline flags / scoped flags — ECMA-262 has no in-pattern flag syntax
    (
        re.compile(r"\(\?[aiLmsux]+(?:-[aiLmsux]+)?[:\)]"),
        "Python-only inline flag syntax — ECMA-262 has no in-pattern flags",
    ),
    # Comment groups
    (re.compile(r"\(\?#"), "Python-only comment group (?#...) — not part of ECMA-262"),
    # Possessive quantifiers added in Python 3.11 are NOT in ECMA-262
    (re.compile(r"[+*?]+\+"), "Possessive quantifier — not part of ECMA-262"),
    # Python-only anchors
    (re.compile(r"\\A"), "Python-only \\A anchor — ECMA-262 uses ^"),
    (re.compile(r"\\Z"), "Python-only \\Z anchor — ECMA-262 uses $"),
)


def _validate_ecma262_compatible(pattern: str) -> None:
    """Reject patterns that contain Python-specific (non-ECMA-262) constructs.

    Spec §3.5 requires patterns to be valid ECMA-262 RegExp; this is a
    static pre-validator for syntax constructs that have no ECMA-262
    equivalent (named-group spelling, inline flags, possessive quantifiers,
    ``\\A``/``\\Z`` anchors). Character-class SEMANTICS are aligned separately by
    :func:`_translate_ecma262_char_classes`: ``\\d``/``\\w`` become explicit ASCII
    classes while ``\\s``/``\\S`` become the explicit ECMA-262 whitespace class
    (which a blanket :data:`re.ASCII` would wrongly strip of its non-ASCII
    members), and the translated pattern keeps :data:`re.ASCII` only so
    ``\\b``/``\\B`` word boundaries stay ASCII — matching default (no ``u`` flag)
    ECMA-262 rather than Python's Unicode-by-default classes
    (validation-engine-dsl-5).
    """
    for compiled_check, message in _NON_ECMA262_CONSTRUCTS:
        if compiled_check.search(pattern):
            raise ACEFEvaluationError(
                f"Regex pattern is not valid ECMA-262: {message}. Pattern: {pattern!r}",
                code="ACEF-045",
            )


# ECMA-262 ``\s`` matches ``WhiteSpace`` ∪ ``LineTerminator`` (ECMA-262 §12.2 /
# §12.3): U+0009, U+000B, U+000C, U+0020, U+00A0, U+FEFF, every Unicode
# ``Space_Separator`` (general category Zs), plus the line terminators U+000A,
# U+000D, U+2028, U+2029. This explicit set is NEITHER Python's default ``\s``
# (which also matches U+001C–U+001F and U+0085 but NOT U+FEFF) NOR ASCII ``\s``
# (which drops every non-ASCII member). We translate ``\s``/``\S`` to this
# literal class so two conformant validators agree byte-for-byte
# (validation-engine-dsl-5 follow-up).
_ECMA262_WHITESPACE_CODEPOINTS: tuple[int, ...] = (
    0x0009,  # CHARACTER TABULATION
    0x000A,  # LINE FEED (LineTerminator)
    0x000B,  # LINE TABULATION
    0x000C,  # FORM FEED
    0x000D,  # CARRIAGE RETURN (LineTerminator)
    0x0020,  # SPACE
    0x00A0,  # NO-BREAK SPACE (Zs)
    0x1680,  # OGHAM SPACE MARK (Zs)
    0x2000,  # EN QUAD (Zs)
    0x2001,  # EM QUAD (Zs)
    0x2002,  # EN SPACE (Zs)
    0x2003,  # EM SPACE (Zs)
    0x2004,  # THREE-PER-EM SPACE (Zs)
    0x2005,  # FOUR-PER-EM SPACE (Zs)
    0x2006,  # SIX-PER-EM SPACE (Zs)
    0x2007,  # FIGURE SPACE (Zs)
    0x2008,  # PUNCTUATION SPACE (Zs)
    0x2009,  # THIN SPACE (Zs)
    0x200A,  # HAIR SPACE (Zs)
    0x2028,  # LINE SEPARATOR (LineTerminator)
    0x2029,  # PARAGRAPH SEPARATOR (LineTerminator)
    0x202F,  # NARROW NO-BREAK SPACE (Zs)
    0x205F,  # MEDIUM MATHEMATICAL SPACE (Zs)
    0x3000,  # IDEOGRAPHIC SPACE (Zs)
    0xFEFF,  # ZERO WIDTH NO-BREAK SPACE / BOM
)

# Bracket-class BODY (no surrounding ``[]``) for ECMA-262 ``\s``. Each member is
# a ``\uXXXX`` escape so the produced pattern is pure-ASCII source and immune to
# any source-encoding surprise; ``re.ASCII`` does NOT restrict explicit
# ``\uXXXX`` class members, only the ``\d``/``\w``/``\s``/``\b`` escapes.
_ECMA262_WHITESPACE_CLASS_BODY = "".join(f"\\u{cp:04x}" for cp in _ECMA262_WHITESPACE_CODEPOINTS)

# Highest code unit a non-``/u`` ECMA-262 regex can match: a UTF-16 code unit,
# i.e. the BMP ceiling. We translate negated shorthands to the EXPLICIT
# positive complement over [U+0000, U+FFFF] so the produced class is a literal
# range body (immune to ``re.ASCII``) that matches every code unit NOT in the
# excluded set — exactly what the OUTSIDE ``\D``→``[^0-9]`` / ``\W``→
# ``[^A-Za-z0-9_]`` forms already do (a literal ``[^…]`` is unaffected by
# ``re.ASCII``, so it spans the full BMP).
_BMP_MAX_CODE_UNIT = 0xFFFF


def _complement_class_body(excluded: tuple[int, ...]) -> str:
    r"""Return a class BODY matching every BMP code unit NOT in ``excluded``.

    Used to inline a NEGATED ECMA-262 shorthand (``\D``/``\W``/``\S``) inside a
    ``[...]`` character class, where Python ``re`` cannot nest a negated class.
    The result is a concatenation of ``\uXXXX`` / ``\uXXXX-\uYYYY`` ranges that
    is the positive complement of ``excluded`` over ``[U+0000, U+FFFF]``. Inside
    a positive class ``[…body…]`` this matches "not in excluded"; inside a
    negated class ``[^…body…]`` the regex engine composes the outer negation,
    yielding "in excluded" (so ``[^\S]`` correctly becomes ECMA-262 whitespace).
    """
    ordered = sorted(set(excluded))
    parts: list[str] = []
    start = 0x0000
    for cp in ordered:
        if cp > start:
            end = cp - 1
            parts.append(f"\\u{start:04x}" if start == end else f"\\u{start:04x}-\\u{end:04x}")
        start = cp + 1
    if start <= _BMP_MAX_CODE_UNIT:
        parts.append(
            f"\\u{start:04x}" if start == _BMP_MAX_CODE_UNIT else f"\\u{start:04x}-\\u{_BMP_MAX_CODE_UNIT:04x}"
        )
    return "".join(parts)


# Excluded sets for the three negated shorthands, as BMP code-unit tuples.
# ``\D`` excludes the ASCII digits [0-9]; ``\W`` excludes the ASCII word chars
# [A-Za-z0-9_]; ``\S`` excludes the ECMA-262 whitespace set. ``\d``/``\w`` stay
# ASCII to match the OUTSIDE positive translations and the DSL-5 invariant.
_ECMA262_DIGIT_CODEPOINTS: tuple[int, ...] = tuple(range(ord("0"), ord("9") + 1))
_ECMA262_WORD_CODEPOINTS: tuple[int, ...] = (
    *range(ord("0"), ord("9") + 1),
    *range(ord("A"), ord("Z") + 1),
    *range(ord("a"), ord("z") + 1),
    ord("_"),
)

# Class BODIES for the NEGATED shorthands — the positive complement of each
# excluded set over the BMP. Built once at import time.
_ECMA262_NON_DIGIT_CLASS_BODY = _complement_class_body(_ECMA262_DIGIT_CODEPOINTS)
_ECMA262_NON_WORD_CLASS_BODY = _complement_class_body(_ECMA262_WORD_CODEPOINTS)
_ECMA262_NON_WHITESPACE_CLASS_BODY = _complement_class_body(_ECMA262_WHITESPACE_CODEPOINTS)


def _translate_ecma262_char_classes(pattern: str) -> str:
    r"""Rewrite ``\d``/``\w``/``\s`` (and negations) to ECMA-262-faithful classes.

    Python's ``re`` matches Unicode by default; compiling with blanket
    :data:`re.ASCII` fixes ``\d``/``\w`` but *overcorrects* ``\s`` — ASCII ``\s``
    drops the many non-ASCII whitespace chars that ECMA-262 (no ``u`` flag)
    ``\s`` matches (U+00A0, U+1680, U+2000–U+200A, U+2028/9, U+202F, U+205F,
    U+3000, U+FEFF). So we translate per-class rather than flag the whole
    pattern (validation-engine-dsl-5 follow-up):

    * ``\d`` → ``[0-9]``        ``\D`` → ``[^0-9]``
    * ``\w`` → ``[A-Za-z0-9_]`` ``\W`` → ``[^A-Za-z0-9_]``
    * ``\s`` → ``[<ecma-262 ws>]``  ``\S`` → ``[^<ecma-262 ws>]``

    Inside a ``[...]`` character class the forms are inlined as bare class
    *bodies* (no nested brackets). POSITIVE shorthands inline their literal body
    (``\d`` → ``0-9``, …). NEGATED shorthands (``\D``/``\W``/``\S``) cannot nest a
    negated class in Python ``re``, so they inline the EXPLICIT positive
    complement over the BMP (``\S`` → every code unit NOT in the ECMA-262
    whitespace set, etc.) — see :func:`_complement_class_body`. This composes
    correctly: in a positive class ``[\S]`` it matches non-whitespace; in a
    negated class ``[^\S]`` the outer negation yields whitespace. The previous
    behavior left a negated shorthand inside a class at residual ASCII semantics,
    which DIVERGED from ECMA-262 (e.g. ``[\S]`` wrongly matched U+00A0 because
    ASCII ``\s`` drops it) — the roborev Finding-2 fix.

    ``\b``/``\B`` are NOT rewritten; they depend on ``\w`` and stay ASCII because
    the compiled pattern still carries ``re.ASCII`` (which no longer affects
    ``\s`` once ``\s`` is an explicit literal class).

    A backslash escapes the next character, so ``\\s`` (escaped backslash + literal
    ``s``) and ``\\d`` are passed through unchanged — only a *single* backslash
    immediately preceding ``d``/``w``/``s`` (any case) is a shorthand class.
    """
    # Per-position rewrites depending on whether we are inside a [...] class.
    outside = {
        "d": "[0-9]",
        "D": "[^0-9]",
        "w": "[A-Za-z0-9_]",
        "W": "[^A-Za-z0-9_]",
        "s": f"[{_ECMA262_WHITESPACE_CLASS_BODY}]",
        "S": f"[^{_ECMA262_WHITESPACE_CLASS_BODY}]",
    }
    # Inside a character class every shorthand is inlined as a bare class BODY.
    # POSITIVE shorthands use their literal body; NEGATED shorthands use the
    # EXPLICIT positive complement over the BMP so ``\D``/``\W``/``\S`` carry
    # ECMA-262 semantics inside a class (and compose under an outer ``[^…]``
    # negation) instead of falling back to divergent ASCII semantics.
    inside = {
        "d": "0-9",
        "D": _ECMA262_NON_DIGIT_CLASS_BODY,
        "w": "A-Za-z0-9_",
        "W": _ECMA262_NON_WORD_CLASS_BODY,
        "s": _ECMA262_WHITESPACE_CLASS_BODY,
        "S": _ECMA262_NON_WHITESPACE_CLASS_BODY,
    }

    out: list[str] = []
    in_class = False
    i = 0
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "\\" and i + 1 < n:
            nxt = pattern[i + 1]
            table = inside if in_class else outside
            if nxt in table:
                out.append(table[nxt])
            else:
                # Preserve any other escape verbatim (e.g. ``\.``, ``\\``, ``\b``,
                # negated shorthands inside a class).
                out.append(ch)
                out.append(nxt)
            i += 2
            continue
        if ch == "[" and not in_class:
            in_class = True
        elif ch == "]" and in_class:
            in_class = False
        out.append(ch)
        i += 1
    return "".join(out)


def _safe_regex_search(pattern: str, text: str) -> bool:
    """Execute a regex search with length limits and optional timeout.

    Mitigates ReDoS attacks by:
    1. Limiting pattern length to _MAX_REGEX_PATTERN_LENGTH characters
    2. Limiting input text length to _MAX_REGEX_INPUT_LENGTH characters
    3. Applying a SIGALRM-based timeout on Unix systems (main thread only)
    4. Pre-validating against known Python-only (non-ECMA-262) constructs
       per :func:`_validate_ecma262_compatible`

    ECMA-262 character-class SEMANTICS are aligned by
    :func:`_translate_ecma262_char_classes`: ``\\d``/``\\w`` become explicit ASCII
    classes and ``\\s``/``\\S`` become the explicit ECMA-262 whitespace class
    (which, unlike blanket :data:`re.ASCII`, keeps the non-ASCII whitespace chars
    ECMA-262 ``\\s`` matches). The translated pattern is still compiled with
    :data:`re.ASCII` so word boundaries ``\\b``/``\\B`` follow ASCII semantics —
    ``re.ASCII`` no longer affects ``\\s`` because it is now a literal class
    (validation-engine-dsl-5).

    Args:
        pattern: ECMA-262 regex pattern from DSL rule.
        text: The string value to match against.

    Returns:
        True if the pattern matches anywhere in the text.

    Raises:
        ACEFEvaluationError: If the pattern is too long, invalid, or times out.
    """
    _validate_ecma262_compatible(pattern)
    if len(pattern) > _MAX_REGEX_PATTERN_LENGTH:
        raise ACEFEvaluationError(
            f"Regex pattern exceeds maximum length ({len(pattern)} > {_MAX_REGEX_PATTERN_LENGTH})",
            code="ACEF-045",
        )

    if len(text) > _MAX_REGEX_INPUT_LENGTH:
        raise ACEFEvaluationError(
            f"Input string exceeds maximum length for regex matching ({len(text)} > {_MAX_REGEX_INPUT_LENGTH})",
            code="ACEF-045",
        )

    # Translate ECMA-262 shorthand classes BEFORE compiling. The original
    # ``pattern`` was length-checked above (the translation only expands it);
    # the compiled engine sees the ECMA-262-faithful form.
    compiled_pattern = _translate_ecma262_char_classes(pattern)

    # On Unix, use SIGALRM for timeout protection against catastrophic backtracking.
    # M-SCOUT-1: SIGALRM only works in the main thread of the main interpreter.
    use_alarm = (
        hasattr(signal, "SIGALRM") and sys.platform != "win32" and threading.current_thread() is threading.main_thread()
    )

    if use_alarm:
        old_handler = signal.signal(signal.SIGALRM, _regex_timeout_handler)
        signal.alarm(_REGEX_TIMEOUT_SECONDS)
        try:
            result = re.search(compiled_pattern, text, re.ASCII) is not None
        except _RegexTimeoutError:
            raise ACEFEvaluationError(
                f"Regex evaluation timed out after {_REGEX_TIMEOUT_SECONDS}s "
                f"(possible catastrophic backtracking): {pattern!r}",
                code="ACEF-045",
            )
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)
        return result
    else:
        # On non-Unix systems or non-main threads, rely on pattern and input length limits only.
        return re.search(compiled_pattern, text, re.ASCII) is not None


def _validate_pointer_syntax(pointer: str) -> None:
    """Validate that ``pointer`` is a syntactically well-formed JSON Pointer.

    Per RFC 6901 + spec §3.5: a JSON Pointer is either the empty string or
    begins with ``/``. The reference fragment form (``#/...``) is not
    accepted here because the spec uses bare pointers. Syntactically invalid
    pointers MUST emit ACEF-043 — distinct from the "missing-path" case
    handled by :func:`_resolve_pointer`.
    """
    if pointer == "":
        return
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise ACEFEvaluationError(
            f"Invalid JSON Pointer (must be empty or start with '/'): {pointer!r}",
            code="ACEF-043",
        )
    # Construct the parsed pointer to surface RFC 6901 syntax errors
    # (e.g., a stray ``~`` not followed by ``0`` or ``1``).
    try:
        jsonpointer.JsonPointer(pointer)
    except jsonpointer.JsonPointerException as exc:
        raise ACEFEvaluationError(
            f"Invalid JSON Pointer syntax: {pointer!r}: {exc}",
            code="ACEF-043",
        ) from exc


def _resolve_pointer(record_data: dict[str, Any], pointer: str) -> Any:
    """Resolve a JSON Pointer (RFC 6901) against a record dict.

    Returns None if the path doesn't exist (missing-path behavior per spec
    §3.5). Syntactically invalid pointers raise :class:`ACEFEvaluationError`
    with code ``ACEF-043`` — callers MUST call :func:`_validate_pointer_syntax`
    first on user-supplied pointers (typically once per rule), then this
    function for per-record resolution.
    """
    # Build a JsonPointer object explicitly so we can distinguish a parse
    # error (already raised by _validate_pointer_syntax) from a
    # "path didn't resolve" miss. jsonpointer.resolve_pointer raises
    # JsonPointerException for both cases, conflating them.
    try:
        ptr = jsonpointer.JsonPointer(pointer)
    except jsonpointer.JsonPointerException as exc:
        # Defensive: callers should have pre-validated, but raise ACEF-043
        # rather than silently returning None if they didn't.
        raise ACEFEvaluationError(
            f"Invalid JSON Pointer syntax: {pointer!r}: {exc}",
            code="ACEF-043",
        ) from exc
    try:
        return ptr.resolve(record_data)
    except jsonpointer.JsonPointerException:
        # Path is well-formed but does not exist in this record.
        return None


# The complete set of comparison operators ``_compare`` recognizes (spec §3.4).
# An ``op`` outside this set is a MALFORMED RULE, not a silent FALSE — see
# ``_validate_comparison_op`` (ACEF-046, audit finding F13).
_VALID_COMPARISON_OPS: frozenset[str] = frozenset({"eq", "ne", "gt", "gte", "lt", "lte", "in", "regex"})


def _validate_comparison_op(op: str) -> None:
    """Raise ACEF-046 when a rule's comparison ``op`` is not a recognized operator.

    Called UPFRONT by ``op_field_value`` / ``op_exists_where`` — before the
    empty-set short-circuit — so a typo'd ``op`` (e.g. ``"equals"``) is a LOUD
    malformed-rule error regardless of whether any record matches, mirroring the
    upfront ACEF-043 pointer-syntax check. Without it a typo'd op silently
    FALSE-FAILs the rule (non-empty set) or passes VACUOUSLY (zero records),
    turning a compliance check into a misleading verdict with no error code.
    """
    # ``op`` is checked for str-ness FIRST so a non-string op (e.g. a list/dict
    # from malformed JSON ``params``) raises a structured ACEF-046 rather than a
    # raw ``TypeError`` from set membership on an unhashable value.
    if not isinstance(op, str) or op not in _VALID_COMPARISON_OPS:
        raise ACEFEvaluationError(
            f"Unknown comparison operator {op!r} in rule. Valid operators: {', '.join(sorted(_VALID_COMPARISON_OPS))}.",
            code="ACEF-046",
        )


def _compare(actual: Any, op: str, expected: Any) -> bool:
    """Apply a comparison operator.

    For ordering operators (gt, gte, lt, lte), incompatible types
    (e.g., dict vs int) return False instead of raising TypeError (m6 Scout R2).

    Callers (``op_field_value`` / ``op_exists_where``) validate ``op`` upfront via
    ``_validate_comparison_op`` (ACEF-046). ``_compare`` re-validates at the TOP
    too — BEFORE the missing-path branch — so it is self-consistent for any
    caller: an unknown op never silently returns False, even when ``actual`` is
    None (the missing-path ``op == "ne"`` branch would otherwise mask it).
    """
    _validate_comparison_op(op)

    if actual is None:
        # Missing path: all comparisons false except ne
        return op == "ne"

    if op == "eq":
        return bool(actual == expected)
    elif op == "ne":
        return bool(actual != expected)
    elif op == "gt":
        try:
            return bool(actual > expected)
        except TypeError:
            return False
    elif op == "gte":
        try:
            return bool(actual >= expected)
        except TypeError:
            return False
    elif op == "lt":
        try:
            return bool(actual < expected)
        except TypeError:
            return False
    elif op == "lte":
        try:
            return bool(actual <= expected)
        except TypeError:
            return False
    elif op == "in":
        if isinstance(expected, list):
            return actual in expected
        return False
    elif op == "regex":
        if not isinstance(expected, str) or not isinstance(actual, str):
            return False
        try:
            return _safe_regex_search(expected, actual)
        except ACEFEvaluationError:
            raise
        except re.error as e:
            raise ACEFEvaluationError(
                f"Invalid regex pattern: {expected!r}: {e}",
                code="ACEF-045",
            ) from e
    # Defensive backstop: unreachable when callers validate ``op`` upfront, but
    # _compare must never SILENTLY return False for an unrecognized operator
    # (audit finding F13 — the prior ``return False`` masked typo'd ops).
    raise ACEFEvaluationError(
        f"Unknown comparison operator {op!r} in rule. Valid operators: {', '.join(sorted(_VALID_COMPARISON_OPS))}.",
        code="ACEF-046",
    )


def _filter_by_type(records: list[RecordEnvelope], record_type: str) -> list[RecordEnvelope]:
    """Filter records by record_type."""
    return [r for r in records if r.record_type == record_type]


# --- Operator implementations ---


def op_has_record_type(
    params: dict[str, Any],
    records: list[RecordEnvelope],
) -> tuple[bool, list[str]]:
    """has_record_type: At least min_count records of given type exist.

    Existential operator -> FAIL on zero matching records if min_count > 0.
    """
    record_type = params["type"]
    min_count = params.get("min_count", 1)
    matching = _filter_by_type(records, record_type)
    evidence_refs = [r.record_id for r in matching]
    return len(matching) >= min_count, evidence_refs


def op_field_present(
    params: dict[str, Any],
    records: list[RecordEnvelope],
) -> tuple[bool, list[str]]:
    """field_present: Every record of given type has non-null value at path.

    Universal operator -> PASS vacuously on zero records.
    """
    record_type = params["record_type"]
    field = params["field"]
    # Validate the pointer ONCE before the empty-set short-circuit so a
    # malformed ``field`` raises ACEF-043 regardless of how many records match
    # (validation-engine-dsl-3/-7). ACEF-043 is a property of the rule's field
    # parameter, not contingent on data presence (spec §3.6 line 1265).
    _validate_pointer_syntax(field)
    matching = _filter_by_type(records, record_type)

    if not matching:
        return True, []  # Vacuous truth

    evidence_refs: list[str] = []
    all_present = True
    for rec in matching:
        data = rec.to_jsonl_dict()
        value = _resolve_pointer(data, field)
        if value is not None:
            evidence_refs.append(rec.record_id)
        else:
            all_present = False

    return all_present, evidence_refs


def op_field_value(
    params: dict[str, Any],
    records: list[RecordEnvelope],
) -> tuple[bool, list[str]]:
    """field_value: Field value satisfies comparison for every record of given type.

    Universal operator -> PASS vacuously on zero records.
    """
    record_type = params["record_type"]
    field = params["field"]
    op = params["op"]
    value = params["value"]
    # Validate the pointer ONCE before the empty-set short-circuit
    # (validation-engine-dsl-3/-7); ACEF-043 is not contingent on data presence.
    _validate_pointer_syntax(field)
    # Likewise validate the comparison op upfront (ACEF-046, F13): a typo'd op is
    # a malformed rule regardless of data presence — it must NOT pass vacuously
    # on zero records nor silently FALSE-FAIL on a non-empty set.
    _validate_comparison_op(op)
    matching = _filter_by_type(records, record_type)

    if not matching:
        return True, []  # Vacuous truth

    evidence_refs: list[str] = []
    all_match = True
    for rec in matching:
        data = rec.to_jsonl_dict()
        actual = _resolve_pointer(data, field)
        if _compare(actual, op, value):
            evidence_refs.append(rec.record_id)
        else:
            all_match = False

    return all_match, evidence_refs


def op_evidence_freshness(
    params: dict[str, Any],
    records: list[RecordEnvelope],
    *,
    evaluation_instant: str = "",
    package_timestamp: str = "",
    provision_effective_date: str = "",
) -> tuple[bool, list[str]]:
    """evidence_freshness: All records within scope have timestamp within max_days.

    Universal operator -> PASS vacuously on zero records.

    Per spec Section 3.7: all date-sensitive rule logic MUST use
    evaluation_instant as the single reference time. MUST NOT use
    wall-clock time during evaluation.

    Args:
        params: Operator parameters (max_days, reference_date).
        records: Records to evaluate.
        evaluation_instant: ISO 8601 evaluation timestamp.
        package_timestamp: ISO 8601 package creation timestamp.
        provision_effective_date: ISO 8601 provision effective date (M6 Implementer R2).
    """
    if not records:
        return True, []  # Vacuous truth

    max_days = params["max_days"]
    reference_date_type = params.get("reference_date", "validation_time")

    # Determine reference date per spec Section 3.7:
    # - validation_time -> evaluation_instant
    # - package_time -> metadata.timestamp
    # - obligation_effective_date -> provision effective_date (M6 Implementer R2)
    if reference_date_type == "validation_time":
        ref_str = evaluation_instant
    elif reference_date_type == "package_time":
        ref_str = package_timestamp
    elif reference_date_type == "obligation_effective_date":
        # M6 (Implementer R2): Resolve to provision's effective_date
        ref_str = provision_effective_date if provision_effective_date else evaluation_instant
    else:
        # Unknown type, fall back to evaluation_instant per spec
        ref_str = evaluation_instant

    if not ref_str:
        # Per spec Section 3.7: MUST NOT use wall-clock time during evaluation.
        # If no reference date is available, the rule cannot be evaluated.
        return True, []

    try:
        ref_dt = datetime.fromisoformat(ref_str.replace("Z", "+00:00"))
        # F12: a BARE-DATE reference (e.g. the obligation_effective_date "2026-08-02") parses
        # NAIVE, while Z-suffixed record timestamps parse AWARE — comparing the two raised
        # TypeError. Normalize a naive reference to UTC (a bare date denotes a UTC calendar
        # day; the spec forbids wall-clock, so no local-zone ambiguity).
        if ref_dt.tzinfo is None:
            ref_dt = ref_dt.replace(tzinfo=UTC)
    except ValueError as exc:
        # The reference date was supplied but is malformed. Spec §3.5 lists
        # ACEF-045 (invalid pattern parameter) and ACEF-043 (invalid pointer)
        # as the per-parameter validation errors; for evidence_freshness the
        # closest match is ACEF-045 because the value is a malformed pattern
        # of a date string. Raising surfaces the problem rather than
        # silently passing the rule.
        raise ACEFEvaluationError(
            f"evidence_freshness reference date is not valid ISO 8601: {ref_str!r}: {exc}",
            code="ACEF-045",
        ) from exc

    cutoff = ref_dt - timedelta(days=max_days)

    evidence_refs: list[str] = []
    all_fresh = True
    for rec in records:
        try:
            rec_dt = datetime.fromisoformat(rec.timestamp.replace("Z", "+00:00"))
            # F12: normalize a naive record timestamp to UTC too, so the comparison below
            # never mixes naive and aware datetimes regardless of the input forms.
            if rec_dt.tzinfo is None:
                rec_dt = rec_dt.replace(tzinfo=UTC)
        except ValueError as exc:
            # A record with a malformed timestamp cannot satisfy a freshness
            # check; surface the bad data as ACEF-050 (malformed JSONL
            # content) rather than silently flipping the rule to FAILED.
            raise ACEFEvaluationError(
                f"Record {rec.record_id} has invalid timestamp {rec.timestamp!r}: {exc}",
                code="ACEF-050",
            ) from exc
        if rec_dt >= cutoff:
            evidence_refs.append(rec.record_id)
        else:
            all_fresh = False

    return all_fresh, evidence_refs


def op_attachment_exists(
    params: dict[str, Any],
    records: list[RecordEnvelope],
) -> tuple[bool, list[str]]:
    """attachment_exists: At least one record of given type has an attachment.

    Existential operator -> FAIL on zero matching records.
    """
    record_type = params["record_type"]
    media_type = params.get("media_type")
    matching = _filter_by_type(records, record_type)

    evidence_refs: list[str] = []
    for rec in matching:
        for att in rec.attachments:
            if media_type is None or att.media_type == media_type:
                evidence_refs.append(rec.record_id)
                break

    return len(evidence_refs) > 0, evidence_refs


def op_entity_linked(
    params: dict[str, Any],
    records: list[RecordEnvelope],
) -> tuple[bool, list[str]]:
    """entity_linked: Every record of given type has at least one entity ref of given type.

    Universal operator -> PASS vacuously on zero records.
    """
    record_type = params["record_type"]
    entity_type = params["entity_type"]
    matching = _filter_by_type(records, record_type)

    if not matching:
        return True, []

    ref_field_map = {
        "subject": "subject_refs",
        "component": "component_refs",
        "dataset": "dataset_refs",
        "actor": "actor_refs",
    }
    ref_field = ref_field_map.get(entity_type)
    if ref_field is None:
        raise ACEFEvaluationError(
            f"Unknown entity_type: {entity_type!r}",
            code="ACEF-045",
        )

    evidence_refs: list[str] = []
    all_linked = True
    for rec in matching:
        refs = getattr(rec.entity_refs, ref_field, [])
        if refs:
            evidence_refs.append(rec.record_id)
        else:
            all_linked = False

    return all_linked, evidence_refs


def op_exists_where(
    params: dict[str, Any],
    records: list[RecordEnvelope],
) -> tuple[bool, list[str]]:
    """exists_where: At least min_count records exist where field satisfies comparison.

    Existential operator -> FAIL on zero matching records if min_count > 0.
    """
    record_type = params["record_type"]
    field = params["field"]
    op = params["op"]
    value = params["value"]
    min_count = params.get("min_count", 1)

    # Validate the pointer ONCE up front so a malformed ``field`` raises
    # ACEF-043 even when zero records match and the per-record loop below never
    # runs (validation-engine-dsl-3/-7).
    _validate_pointer_syntax(field)
    # And the comparison op upfront (ACEF-046, F13): an unknown op on an
    # existential rule must raise, not pass/fail silently.
    _validate_comparison_op(op)
    matching = _filter_by_type(records, record_type)

    evidence_refs: list[str] = []
    for rec in matching:
        data = rec.to_jsonl_dict()
        actual = _resolve_pointer(data, field)
        if _compare(actual, op, value):
            evidence_refs.append(rec.record_id)

    return len(evidence_refs) >= min_count, evidence_refs


def op_attachment_kind_exists(
    params: dict[str, Any],
    records: list[RecordEnvelope],
) -> tuple[bool, list[str]]:
    """attachment_kind_exists: Records of given type have attachments with matching attachment_type.

    Existential operator -> FAIL on zero matching.
    """
    record_type = params["record_type"]
    attachment_type = params["attachment_type"]
    min_count = params.get("min_count", 1)

    matching = _filter_by_type(records, record_type)

    evidence_refs: list[str] = []
    for rec in matching:
        for att in rec.attachments:
            if att.attachment_type == attachment_type:
                evidence_refs.append(rec.record_id)
                break

    return len(evidence_refs) >= min_count, evidence_refs


def op_bundle_signed(
    params: dict[str, Any],
    records: list[RecordEnvelope],
    *,
    signature_count: int = 0,
    signature_algorithms: list[str] | None = None,
) -> tuple[bool, list[str]]:
    """bundle_signed: Bundle has at least min_signatures valid signatures.

    Existential operator on signatures (not records).
    """
    min_signatures = params.get("min_signatures", 1)
    required_alg = params.get("required_alg")

    effective_count = signature_count
    if required_alg is not None:
        # Validate ``required_alg`` WHENEVER it is present, independent of
        # whether any signatures exist. The previous ``and signature_algorithms``
        # guard let a malformed ``required_alg`` (e.g. ``123`` or
        # ``["RS256", 5]``) be silently treated as absent — and PASS — when there
        # were zero verified signatures (notably ``min_signatures: 0``). The
        # parameter is specified as ``string[]`` (spec §3.5 bundle_signed); accept
        # a bare string (normalized to a single-element set so membership is
        # EXACT, not substring — validation-engine-dsl-6) OR a list of strings,
        # and reject anything else with ACEF-045 (validation-engine-dsl-6 follow-up).
        if isinstance(required_alg, str):
            required_set = {required_alg}
        elif isinstance(required_alg, list):
            for member in required_alg:
                if not isinstance(member, str):
                    raise ACEFEvaluationError(
                        f"bundle_signed required_alg list members must be strings, got {type(member).__name__}",
                        code="ACEF-045",
                    )
            required_set = set(required_alg)
        else:
            raise ACEFEvaluationError(
                f"bundle_signed required_alg must be a string or list of strings, got {type(required_alg).__name__}",
                code="ACEF-045",
            )
        # Apply the validated algorithm set to the membership test. With zero
        # verified signatures this yields effective_count == 0, which is the
        # correct count — the param was still validated above.
        effective_count = sum(1 for a in (signature_algorithms or []) if a in required_set)

    return effective_count >= min_signatures, []


def _attestation_verifies(
    rec: RecordEnvelope,
    *,
    manifest_timestamp: str | None = None,
) -> bool:
    """Return True iff the record's attestation block cryptographically verifies.

    Normative recipe (spec §3.5 record_attested row + §3.1 attestation block):

    1. ``method`` MUST be ``"jws"`` — v1 restricts record attestation to JWS
       only (C2PA is deferred to a future profile); any other method does
       NOT count.
    2. ``signed_fields`` MUST include ``"/payload"`` (spec §3.1) — a signature
       scope that excludes the payload attests nothing about the evidence.
    3. Extract each ``signed_fields`` JSON Pointer (RFC 6901) from the
       record's serialized form (:meth:`RecordEnvelope.to_jsonl_dict`).
    4. RFC 8785-canonicalize the ``{pointer: extracted_value}`` object.
    5. Verify the detached JWS over those canonical bytes.
       :func:`acef.signing.verify_detached_jws` enforces RS256/ES256 only
       (ACEF-013 for anything else), requires ``kid``, and resolves the
       verification key from the header's embedded ``jwk`` / ``x5c``. For
       x5c-backed attestations, ``manifest_timestamp`` (the bundle's
       ``metadata.timestamp``) anchors the certificate-validity check per
       spec §3.1.3 — expiry is checked against the manifest timestamp, NOT
       wall-clock — so an expired or not-yet-valid chain does NOT count.

    Fail-closed: any failure (forged or tampered signature, unsupported
    algorithm, out-of-validity x5c chain, unresolvable pointer,
    non-canonicalizable content) means the record is NOT counted. A forged
    attestation is a non-match for the existential operator, never an
    evaluation-engine error, so this helper never raises.
    """
    att = rec.attestation
    if att is None or not att.signature:
        return False
    if att.method != "jws":
        return False
    if "/payload" not in att.signed_fields:
        return False
    try:
        record_dict = rec.to_jsonl_dict()
        subset = {pointer: jsonpointer.resolve_pointer(record_dict, pointer) for pointer in att.signed_fields}
        canonical = canonicalize(subset)
        verify_detached_jws(att.signature, canonical, manifest_timestamp=manifest_timestamp)
    except Exception:
        # Intentionally broad: a record carrying ANY unverifiable attestation
        # (ACEFSigningError, JsonPointerException, rfc8785 domain errors, …)
        # must be treated as not-attested rather than crash rule evaluation.
        return False
    return True


def op_record_attested(
    params: dict[str, Any],
    records: list[RecordEnvelope],
    *,
    manifest_timestamp: str | None = None,
) -> tuple[bool, list[str]]:
    """record_attested: At least min_count records have VERIFIED attestation blocks.

    Existential operator -> FAIL on zero matching.

    Per spec §3.5, a record counts only when its non-null attestation block
    carries a *valid* JWS signature: extract the fields listed in
    ``signed_fields``, canonicalize via RFC 8785, verify the detached JWS
    (see :func:`_attestation_verifies` for the full normative recipe).
    Presence of a signature string is NOT sufficient.

    ``manifest_timestamp`` is the bundle's ``metadata.timestamp``, threaded
    in by the rule engine the same way ``bundle_signed`` receives signature
    context. It anchors x5c certificate-validity checks (spec §3.1.3: cert
    expiry is checked against the manifest timestamp, NOT wall-clock).
    """
    record_type = params["record_type"]
    min_count = params.get("min_count", 1)

    matching = _filter_by_type(records, record_type)

    evidence_refs: list[str] = []
    for rec in matching:
        if _attestation_verifies(rec, manifest_timestamp=manifest_timestamp):
            evidence_refs.append(rec.record_id)

    return len(evidence_refs) >= min_count, evidence_refs


# --- Operator registry ---

OperatorFunc = Callable[..., tuple[bool, list[str]]]

OPERATOR_REGISTRY: dict[str, OperatorFunc] = {
    "has_record_type": op_has_record_type,
    "field_present": op_field_present,
    "field_value": op_field_value,
    "evidence_freshness": op_evidence_freshness,
    "attachment_exists": op_attachment_exists,
    "entity_linked": op_entity_linked,
    "exists_where": op_exists_where,
    "attachment_kind_exists": op_attachment_kind_exists,
    "bundle_signed": op_bundle_signed,
    "record_attested": op_record_attested,
}
