"""ACEF DSL operators — all 10 built-in operators per spec Section 3.5.

Each operator takes params and a list of records, returns (passed, evidence_refs).
Empty-set semantics:
  - Existential operators -> FAIL on zero records
  - Universal operators -> PASS (vacuous truth)
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, NamedTuple

if TYPE_CHECKING:
    from cryptography.x509 import Certificate

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


def _brace_is_unbounded(pattern: str, brace_idx: int) -> bool:
    """True if ``pattern[brace_idx] == '{'`` opens an UNBOUNDED quantifier ``{n,}``
    (no upper bound). ``{n}`` / ``{n,m}`` are *bounded*, but bounded does NOT mean
    safe: a bounded counted repetition of an ambiguous body (``(a?){n}``,
    ``(a{0,n}){0,n}``) still backtracks exponentially — that family is caught by
    :func:`_has_catastrophic_group_repetition`, not here."""
    close = pattern.find("}", brace_idx)
    if close == -1:
        return False
    inner = pattern[brace_idx + 1 : close]
    if "," not in inner:
        return False  # {n} — exact, bounded
    upper = inner.split(",", 1)[1].strip()
    return upper == ""  # {n,} unbounded; {n,m} bounded


def _segment_has_unbounded_quantifier(segment: str) -> bool:
    """True if ``segment`` contains an unbounded quantifier (``*``, ``+``, or
    ``{n,}``) at the regex level — skipping escaped chars and ``[...]`` classes."""
    i, n = 0, len(segment)
    while i < n:
        c = segment[i]
        if c == "\\":
            i += 2
            continue
        if c == "[":
            i += 1
            while i < n and segment[i] != "]":
                if segment[i] == "\\":
                    i += 1
                i += 1
            i += 1
            continue
        if c in ("*", "+"):
            return True
        if c == "{" and _brace_is_unbounded(segment, i):
            return True
        i += 1
    return False


def _segment_has_alternation(segment: str) -> bool:
    """True if ``segment`` contains a ``|`` at ANY nesting depth (skipping ``\\``
    escapes and ``[...]`` classes). Checking at any depth — not only the top
    level — is deliberate: a quantified group's alternation-overlap ReDoS can be
    WRAPPED in an inner group (``((a|aa))+``, ``(?:(a(?:|a)))+``) and still
    backtrack catastrophically. This is conservative (it also flags safe nested
    alternations like ``(a(b|c)d)+``); for the short rule-level DSL matchers that
    trade is acceptable, and a future linear-time engine would accept them."""
    i, n = 0, len(segment)
    while i < n:
        c = segment[i]
        if c == "\\":
            i += 2
            continue
        if c == "[":
            i += 1
            while i < n and segment[i] != "]":
                if segment[i] == "\\":
                    i += 1
                i += 1
            i += 1
            continue
        if c == "|":
            return True
        i += 1
    return False


def _has_nested_unbounded_quantifier(pattern: str) -> bool:
    """Detect catastrophic-backtracking signatures DETERMINISTICALLY: an
    UNBOUNDED-quantified group (`(…)*`, `(…)+`, `(…){n,}`) whose body either
    contains an unbounded quantifier (the **nested-quantifier** class — `(a+)+`,
    `(a*)*`, `(.*)+`, `(\\d+){2,}`) OR a top-level alternation (the
    **alternation-overlap** class — `(a|aa)+`, `(a|a)*`).

    This is a conservative, platform-independent static check (no wall clock):
    it rejects the two main ReDoS classes so two validators on ANY platform
    reach the SAME verdict, replacing the old Unix-main-thread-only SIGALRM
    timeout whose outcome was platform-dependent (finding 11; roborev on
    6147931 added the alternation-overlap class). It over-rejects some safe
    quantified alternations (e.g. `(a|b)+`) — acceptable for the short
    rule-level matchers the DSL uses, and a future linear-time engine would
    accept them precisely.
    """
    stack: list[int] = []  # indices of '(' opens
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "\\":
            i += 2
            continue
        if c == "[":
            i += 1
            while i < n and pattern[i] != "]":
                if pattern[i] == "\\":
                    i += 1
                i += 1
            i += 1
            continue
        if c == "(":
            stack.append(i)
            i += 1
            continue
        if c == ")":
            if stack:
                start = stack.pop()
                q = pattern[i + 1] if i + 1 < n else ""
                group_unbounded = q in ("*", "+") or (q == "{" and _brace_is_unbounded(pattern, i + 1))
                if group_unbounded:
                    body = pattern[start + 1 : i]
                    if _segment_has_unbounded_quantifier(body) or _segment_has_alternation(body):
                        return True
            i += 1
            continue
        i += 1
    return False


# --- Sequential / adjacent-quantifier ReDoS detection (PhD re-review) ----------
# The nested-quantifier check above is GROUP-anchored: it only inspects a body
# wrapped in an unbounded-quantified group. It therefore MISSES the third
# catastrophic-backtracking family — two or more UNBOUNDED quantifiers applied to
# adjacent atoms whose character sets OVERLAP, with no mandatory disjoint
# separator between them (``a*a*…c``, ``.*.*x``, ``[a-z]+[a-z]+$``, ``\d+\d+x``).
# These carry no group, so the group walker returns immediately; ``re.search``
# then runs the backtracking engine with no time guard (degree-k polynomial /
# superpolynomial blow-up). The analyzer below is a deterministic,
# platform-independent static over-approximation that rejects this family too,
# completing the spec §3.5 resource bound. It is conservative (it can over-reject
# some safe constructs, e.g. ``a.*b.*c`` which is genuinely quadratic, or two
# adjacent quantified groups), which is acceptable for the short rule-level DSL
# matchers — a future linear-time engine would accept the safe ones precisely.

_RE_DIGITS: frozenset[str] = frozenset("0123456789")
_RE_WORD: frozenset[str] = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
# ``\s`` for the adjacency scanner MUST be the SAME set ``_safe_regex_search``
# compiles (``_translate_ecma262_char_classes`` -> ECMA-262 whitespace, which
# includes non-ASCII members like NBSP U+00A0). Modelling ``\s`` as bare ASCII
# whitespace would miss ``^\s+ +$``-style adjacency (roborev HIGH on 192082f).
_RE_SPACE: frozenset[str] = frozenset(chr(cp) for cp in _ECMA262_WHITESPACE_CODEPOINTS)


class _Atom(NamedTuple):
    """One regex atom plus its quantifier, as seen by the adjacency scanner.

    ``wildcard`` True means the atom's class is treated as matching ANYTHING
    (``.``, ``\\D``/``\\W``/``\\S``, a negated/shorthand-bearing ``[...]``, or a
    group whose first set could not be pinned) — it overlaps every other class.
    ``charset`` is the concrete ASCII set otherwise. ``zero_width`` marks anchors
    / lookarounds (``^``, ``$``, ``\\b``), which are transparent to adjacency.
    ``body`` is the inner pattern of a group, for recursion.
    """

    wildcard: bool
    charset: frozenset[str]
    unbounded: bool
    nullable: bool
    zero_width: bool
    body: str | None


def _charsets_overlap(a: tuple[bool, frozenset[str]], b: tuple[bool, frozenset[str]]) -> bool:
    """True if two ``(wildcard, charset)`` classes can match a common character."""
    if a[0] or b[0]:
        return True
    return bool(a[1] & b[1])


def _matching_paren(segment: str, i: int) -> int:
    """Index of the ``)`` that matches the ``(`` at ``segment[i]`` (skipping
    escapes and ``[...]`` classes). Returns the last index if unbalanced — the
    invalid pattern will be rejected later by ``re.compile`` regardless."""
    depth, j, n = 0, i, len(segment)
    while j < n:
        c = segment[j]
        if c == "\\":
            j += 2
            continue
        if c == "[":
            j += 1
            while j < n and segment[j] != "]":
                if segment[j] == "\\":
                    j += 1
                j += 1
            j += 1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return j
        j += 1
    return n - 1


def _strip_group_prefix(inner: str) -> tuple[str, bool]:
    """Strip a group's ``(?:`` / ``(?<name>`` / lookaround prefix, returning the
    body to analyze and whether the group is ZERO-WIDTH (a lookaround)."""
    if inner.startswith("?:"):
        return inner[2:], False
    if inner.startswith("?=") or inner.startswith("?!"):
        return inner[2:], True
    if inner.startswith("?<=") or inner.startswith("?<!"):
        return inner[3:], True
    if inner.startswith("?P<") or inner.startswith("?<"):
        gt = inner.find(">")
        if gt != -1:
            return inner[gt + 1 :], False
    return inner, False


def _split_top_level_alternation(segment: str) -> list[str]:
    """Split ``segment`` on ``|`` at group-depth 0 (skipping escapes and classes).
    Each branch is an independent sequence for adjacency analysis."""
    parts: list[str] = []
    depth, start, j, n = 0, 0, 0, len(segment)
    while j < n:
        c = segment[j]
        if c == "\\":
            j += 2
            continue
        if c == "[":
            j += 1
            while j < n and segment[j] != "]":
                if segment[j] == "\\":
                    j += 1
                j += 1
            j += 1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            if depth > 0:
                depth -= 1
        elif c == "|" and depth == 0:
            parts.append(segment[start:j])
            start = j + 1
        j += 1
    parts.append(segment[start:])
    return parts


_HEX = frozenset("0123456789abcdefABCDEF")

# ECMA-262 ControlEscape letters -> the control character each compiles to.
_CONTROL_ESCAPE_CHARS: dict[str, str] = {"t": "\t", "n": "\n", "r": "\r", "f": "\f", "v": "\v"}


def _consume_escape(segment: str, i: int) -> tuple[bool, frozenset[str], bool, int]:
    """Consume the escape sequence at ``segment[i] == '\\'`` exactly as the regex
    engine compiles it, returning ``(wildcard, charset, zero_width, next_index)``.

    Hex/unicode escapes are RESOLVED to their actual character (``\\x61`` -> ``a``,
    ``\\u0061`` -> ``a``) so the adjacency scanner sees the same atom the compiled
    engine does — otherwise ``^\\x61+\\x61+$`` would be mis-tokenized as disjoint
    literals and ``a+a+`` would slip through (roborev HIGH on 849ac31). Escapes
    that cannot be resolved to one concrete character (``\\cX``, octal,
    backreferences, ``\\u{...}``, ``\\N{...}``) are treated as ``wildcard`` so they
    overlap any neighbor (conservative). Consuming the FULL length is essential so
    the quantifier attaches to the right atom and a class is not closed early."""
    n = len(segment)
    if i + 1 >= n:
        return False, frozenset({"\\"}), False, i + 1
    esc = segment[i + 1]
    if esc in ("b", "B", "A", "Z"):
        return False, frozenset(), True, i + 2  # zero-width assertion
    if esc == "d":
        return False, _RE_DIGITS, False, i + 2
    if esc == "w":
        return False, _RE_WORD, False, i + 2
    if esc == "s":
        return False, _RE_SPACE, False, i + 2
    if esc in ("D", "W", "S"):
        return True, frozenset(), False, i + 2
    if esc in _CONTROL_ESCAPE_CHARS:
        # ECMA-262 ControlEscape \t \n \r \f \v -> the actual control character the
        # engine matches (NOT the literal letter t/n/r/f/v). Missing these left
        # bypasses like ^\s+\t+$ (TAB is in the \s set) — roborev HIGH on 192082f.
        return False, frozenset({_CONTROL_ESCAPE_CHARS[esc]}), False, i + 2
    if esc == "x":
        h = segment[i + 2 : i + 4]
        if len(h) == 2 and all(ch in _HEX for ch in h):
            return False, frozenset({chr(int(h, 16))}), False, i + 4
        return True, frozenset(), False, i + 2
    if esc == "u":
        if i + 2 < n and segment[i + 2] == "{":  # \u{...} (u-flag form) — unresolved
            close = segment.find("}", i + 2)
            return True, frozenset(), False, (close + 1 if close != -1 else i + 2)
        h = segment[i + 2 : i + 6]
        if len(h) == 4 and all(ch in _HEX for ch in h):
            return False, frozenset({chr(int(h, 16))}), False, i + 6
        return True, frozenset(), False, i + 2
    if esc == "N" and i + 2 < n and segment[i + 2] == "{":  # \N{NAME}
        close = segment.find("}", i + 2)
        return True, frozenset(), False, (close + 1 if close != -1 else i + 2)
    if esc == "c" and i + 2 < n:  # \cX control escape
        return True, frozenset(), False, i + 3
    if esc in "01234567":  # octal escape or backreference — unresolved
        j = i + 1
        while j < n and j < i + 4 and segment[j] in "01234567":
            j += 1
        return True, frozenset(), False, j
    if esc in "89":  # backreference
        return True, frozenset(), False, i + 2
    # Simple escaped literal: \. \+ \\ \/ \( … -> the literal character itself.
    return False, frozenset({esc}), False, i + 2


def _parse_char_class(pattern: str, i: int) -> tuple[bool, frozenset[str], int]:
    """Parse a ``[...]`` class starting at ``pattern[i]``. Returns
    ``(wildcard, members, next_index_past_])``. A negated class or one containing
    a shorthand (``\\d`` etc.) or unresolved escape is treated as ``wildcard=True``
    (conservative)."""
    n = len(pattern)
    j = i + 1
    negated = False
    if j < n and pattern[j] == "^":
        negated = True
        j += 1
    members: set[str] = set()
    shorthand = False
    prev: str | None = None
    first = True
    while j < n and (first or pattern[j] != "]"):
        first = False
        c = pattern[j]
        if c == "\\" and j + 1 < n:
            w, cset, _zw, j = _consume_escape(pattern, j)
            if w or len(cset) != 1:
                # A shorthand (\d) or unresolved escape (\x{bad}, \cX, octal,
                # backref) — make the whole class conservatively wildcard. (Also
                # covers a zero-width escape, which cannot meaningfully appear in
                # a class; flagging wildcard is safe.)
                shorthand = True
                prev = None
            else:
                ch = next(iter(cset))
                members.add(ch)
                prev = ch
            continue
        if c == "-" and prev is not None and j + 1 < n and pattern[j + 1] != "]":
            # The range's UPPER endpoint may itself be an escape (``[\x61-\x7a]`` is
            # ``[a-z]``). Resolve it the same way the engine compiles it; an
            # unresolved escape upper bound makes the whole class wildcard (roborev
            # HIGH on 192082f).
            if pattern[j + 1] == "\\":
                hw, hcset, _hzw, j_after = _consume_escape(pattern, j + 1)
                if hw or len(hcset) != 1:
                    shorthand = True
                    prev = None
                    j = j_after
                    continue
                hi = next(iter(hcset))
            else:
                hi = pattern[j + 1]
                j_after = j + 2
            lo_o, hi_o = ord(prev), ord(hi)
            if lo_o <= hi_o:
                for o in range(lo_o, hi_o + 1):
                    members.add(chr(o))
            prev = None
            j = j_after
            continue
        members.add(c)
        prev = c
        j += 1
    next_i = j + 1 if j < n else n
    if negated or shorthand:
        return True, frozenset(), next_i
    return False, frozenset(members), next_i


def _first_charset(segment: str) -> tuple[bool, frozenset[str]]:
    """The ``(wildcard, charset)`` of the first CONSUMING atom of ``segment``,
    unioned across top-level alternation branches. An empty or anchor-only branch
    yields ``wildcard=True`` (conservative)."""
    acc: set[str] = set()
    for branch in _split_top_level_alternation(segment):
        got = False
        for atom in _iter_atoms(branch):
            if atom.zero_width:
                continue
            if atom.wildcard:
                return True, frozenset()
            acc |= atom.charset
            got = True
            break
        if not got:
            return True, frozenset()
    return False, frozenset(acc)


def _iter_atoms(segment: str) -> Iterator[_Atom]:
    """Yield each atom of ``segment`` (one group-nesting level) with its
    quantifier classification. Groups are yielded with their ``body`` for
    recursion and a first-set charset for outer adjacency."""
    i, n = 0, len(segment)
    while i < n:
        c = segment[i]
        wildcard = False
        charset: frozenset[str] = frozenset()
        zero_width = False
        body: str | None = None
        if c == "\\":
            wildcard, charset, zero_width, i = _consume_escape(segment, i)
        elif c == "[":
            wildcard, charset, i = _parse_char_class(segment, i)
        elif c == "(":
            close = _matching_paren(segment, i)
            inner = segment[i + 1 : close]
            body_inner, zw = _strip_group_prefix(inner)
            body = body_inner
            if zw:
                zero_width = True
            else:
                wildcard, charset = _first_charset(body_inner)
            i = close + 1
        elif c == ".":
            wildcard = True
            i += 1
        elif c in ("^", "$"):
            zero_width = True
            i += 1
        elif c in (")", "]"):
            i += 1
            continue
        else:
            charset = frozenset({c})
            i += 1
        unbounded = False
        nullable = False
        if i < n and not zero_width:
            q = segment[i]
            if q == "*":
                unbounded, nullable = True, True
                i += 1
            elif q == "+":
                unbounded, nullable = True, False
                i += 1
            elif q == "?":
                unbounded, nullable = False, True
                i += 1
            elif q == "{":
                cb = segment.find("}", i)
                if cb != -1:
                    inner_b = segment[i + 1 : cb]
                    unbounded = _brace_is_unbounded(segment, i)
                    lo = inner_b.split(",", 1)[0].strip()
                    nullable = lo in ("", "0")
                    i = cb + 1
            if i < n and segment[i] in ("?", "+"):  # lazy / possessive marker
                i += 1
        yield _Atom(wildcard, charset, unbounded, nullable, zero_width, body)


def _scan_branch_adjacent(branch: str) -> bool:
    """True if ``branch`` (one alternation branch) contains two unbounded
    quantifiers over overlapping classes that are *reachable* from each other —
    i.e. with no mandatory atom of a disjoint class forced between them.

    ``pending`` is the SET of unbounded-quantified classes still reachable at the
    current position. A nullable unbounded atom (``a*``, ``a{0,}``) can match
    empty, so it ADDS its class without dropping earlier pending ones — that is
    what catches ``a*b*a*`` (the middle ``b*`` matches empty, leaving the two
    ``a*`` adjacent; roborev HIGH on 849ac31). A NON-nullable unbounded atom
    (``a+``) must consume ≥1 char, so it breaks earlier reachability and becomes
    the sole pending class. A mandatory atom disjoint from all pending classes is
    a real separator and clears the set (``\\d+-\\d+``)."""
    pending: list[tuple[bool, frozenset[str]]] = []
    for atom in _iter_atoms(branch):
        if atom.body is not None and _has_adjacent_unbounded_quantifiers(atom.body):
            return True
        if atom.zero_width:
            continue
        cs = (atom.wildcard, atom.charset)
        if atom.unbounded and any(_charsets_overlap(p, cs) for p in pending):
            return True
        if atom.unbounded:
            if atom.nullable:
                pending.append(cs)  # matches empty -> earlier classes stay reachable
            else:
                pending = [cs]  # consumes >=1 -> earlier classes no longer reachable
        elif atom.nullable:
            # A nullable BOUNDED atom (``x?``, ``x{0,m}``) can match empty: it does
            # NOT break adjacency, and is not itself an unbounded source.
            continue
        elif pending and all(not _charsets_overlap(p, cs) for p in pending):
            # A MANDATORY atom whose class is disjoint from EVERY pending unbounded
            # class is a real separator — it removes the ambiguity.
            pending = []
    return False


def _has_adjacent_unbounded_quantifiers(pattern: str) -> bool:
    """Detect the SEQUENTIAL / adjacent-quantifier catastrophic-backtracking class
    DETERMINISTICALLY (no wall clock): two or more unbounded quantifiers over
    overlapping atoms in sequence (``a*a*…c``, ``.*.*x``, ``[a-z]+[a-z]+$``),
    including the form wrapped inside a group (``(a*a*)b``). Complements the
    group-anchored :func:`_has_nested_unbounded_quantifier`; together they cover
    the nested, alternation-overlap, and sequential ReDoS families the spec §3.5
    resource bound rejects."""
    for branch in _split_top_level_alternation(pattern):
        if _scan_branch_adjacent(branch):
            return True
    return False


# --- Bounded/nullable group-repetition ReDoS (fresh systems committee) ---------
# The three families above are all defined over UNBOUNDED quantifiers (*, +, {n,}).
# But a group repeated MORE THAN ONCE — by an unbounded quantifier OR a BOUNDED
# counted quantifier whose upper bound is >= 2 ({n} n>=2, {n,m} m>=2) — whose body
# is NULLABLE (matches empty), has an ALTERNATION, or contains a nested unbounded
# quantifier also backtracks exponentially: (a?){28}a{28}, (a|a){24}b, (.?){24}x,
# (a{0,n}){0,n}$, and even (a?)+ (nullable body under +) which the nested-only
# check missed because `a?` carries no unbounded quantifier. These use only small,
# length-cap-safe patterns, so neither the pattern- nor input-length cap mitigates
# them; they must be rejected statically.


_REP_INF = 1 << 30  # sentinel "unbounded" upper repetition bound (so hi >= 2 is uniform)


def _group_repetition_hi(pattern: str, idx: int) -> int | None:
    """For a quantifier at ``pattern[idx]`` (the char immediately after a group's
    ``)``), return its UPPER repetition bound: a positive int for ``{n}``/``{n,m}``,
    a large sentinel for an unbounded ``*``/``+``/``{n,}``, ``1`` for ``?``, or
    ``None`` when there is no quantifier. The sentinel ``_REP_INF`` stands in for
    'unbounded' so callers test ``hi >= 2`` uniformly."""
    if idx >= len(pattern):
        return None
    q = pattern[idx]
    if q in ("*", "+"):
        return _REP_INF
    if q == "?":
        return 1
    if q == "{":
        close = pattern.find("}", idx)
        if close == -1:
            return None
        inner = pattern[idx + 1 : close]
        if "," not in inner:
            try:
                return int(inner)  # {n}
            except ValueError:
                return None
        lo, hi = inner.split(",", 1)
        hi = hi.strip()
        if hi == "":
            return _REP_INF  # {n,} unbounded
        try:
            return int(hi)  # {n,m}
        except ValueError:
            return None
    return None


def _atom_is_nullable(atom: _Atom) -> bool:
    """True if ``atom`` can match the empty string: a zero-width anchor, a
    nullable quantifier (``*``, ``?``, ``{0,…}``), or a group whose body is
    recursively nullable (e.g. ``(a?)`` with no outer quantifier)."""
    if atom.zero_width or atom.nullable:
        return True
    if atom.body is not None:
        return _segment_is_nullable(atom.body)
    return False


def _segment_is_nullable(segment: str) -> bool:
    """True if ``segment`` can match the empty string — i.e. some top-level
    alternation branch consists entirely of nullable atoms (an empty branch is
    nullable)."""
    for branch in _split_top_level_alternation(segment):
        if all(_atom_is_nullable(a) for a in _iter_atoms(branch)):
            return True
    return False


def _has_catastrophic_group_repetition(pattern: str) -> bool:
    """Detect catastrophic GROUP repetition the unbounded-only checks miss: a group
    repeated more than once (unbounded quantifier OR a bounded counted quantifier
    with upper bound >= 2) whose body is NULLABLE, contains a top-level
    ALTERNATION, or contains a nested unbounded quantifier. Deterministic and
    platform-independent (no wall clock)."""
    stack: list[int] = []  # indices of '(' opens
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "\\":
            i += 2
            continue
        if c == "[":
            i += 1
            while i < n and pattern[i] != "]":
                if pattern[i] == "\\":
                    i += 1
                i += 1
            i += 1
            continue
        if c == "(":
            stack.append(i)
            i += 1
            continue
        if c == ")":
            if stack:
                start = stack.pop()
                hi = _group_repetition_hi(pattern, i + 1)
                repeats_multiply = hi is not None and hi >= 2  # _REP_INF >= 2
                if repeats_multiply:
                    # Strip a group prefix (``?:``, ``?<name>``, lookaround) so a
                    # non-capturing nullable group ``(?:a?){28}`` / ``(?:a?)+`` is
                    # normalized to its body ``a?`` before the ambiguity checks —
                    # otherwise the raw ``?:a?`` reads as non-nullable and evades
                    # the rule (roborev High on 468db1c).
                    body, _zw = _strip_group_prefix(pattern[start + 1 : i])
                    if (
                        _segment_is_nullable(body)
                        or _segment_has_alternation(body)
                        or _segment_has_unbounded_quantifier(body)
                    ):
                        return True
            i += 1
            continue
        i += 1
    return False


def _safe_regex_search(pattern: str, text: str) -> bool:
    """Execute a regex search under a DETERMINISTIC, platform-independent bound.

    Mitigates ReDoS attacks by:
    1. Limiting pattern length to _MAX_REGEX_PATTERN_LENGTH characters
    2. Limiting input text length to _MAX_REGEX_INPUT_LENGTH characters
    3. Rejecting BEFORE matching — as ACEF-045 — every catastrophic-backtracking
       signature: the nested-quantifier and alternation-overlap families
       (:func:`_has_nested_unbounded_quantifier`), the sequential /
       adjacent-quantifier family (:func:`_has_adjacent_unbounded_quantifiers`),
       AND the bounded/nullable group-repetition family
       (:func:`_has_catastrophic_group_repetition`). This static rejection is the
       portable resource bound (spec §3.5); it replaced the old SIGALRM wall-clock
       timeout, which only fired on the Unix main thread and gave a
       platform-DEPENDENT provision verdict.
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

    # DETERMINISTIC resource bound (finding 11): reject the nested-quantifier
    # catastrophic-backtracking class up front, BEFORE matching, so the ACEF-045
    # decision is identical on every platform and thread. This replaces the old
    # SIGALRM wall-clock timeout, which only worked on the Unix main thread —
    # giving a platform-DEPENDENT provision verdict (ACEF-045 on one platform,
    # complete/hang on another). The static check + the pattern/input length caps
    # are the normative, portable resource bound (spec §3.5).
    if _has_nested_unbounded_quantifier(pattern):
        raise ACEFEvaluationError(
            "Regex pattern has a nested unbounded quantifier (catastrophic-backtracking risk); "
            f"rejected deterministically per the spec §3.5 resource bound: {pattern!r}",
            code="ACEF-045",
        )

    # Sequential / adjacent-quantifier ReDoS (e.g. ``a*a*…c``, ``.*.*x``,
    # ``[a-z]+[a-z]+$``): two unbounded quantifiers over overlapping atoms with no
    # disjoint mandatory separator. The group-anchored check above does not see
    # these (no quantified group), so without this the validator would run the
    # backtracking engine unbounded. Rejected statically, identically on every
    # platform — completing the spec §3.5 deterministic resource bound.
    if _has_adjacent_unbounded_quantifiers(pattern):
        raise ACEFEvaluationError(
            "Regex pattern has adjacent unbounded quantifiers over overlapping classes "
            "(catastrophic-backtracking risk); rejected deterministically per the spec "
            f"§3.5 resource bound: {pattern!r}",
            code="ACEF-045",
        )

    # Bounded/nullable group-repetition ReDoS (e.g. ``(a?){n}a{n}``, ``(a|a){n}b``,
    # ``(a{0,n}){0,n}$``, ``(a?)+``): a group repeated more than once — by an
    # unbounded quantifier OR a bounded counted quantifier with upper bound >= 2 —
    # whose body is nullable / overlapping-alternation / nested-unbounded. These
    # carry no unbounded quantifier of their own (or hide a nullable body), so the
    # two checks above miss them; they backtrack exponentially on inputs far under
    # the length caps. Rejected statically, completing the §3.5 resource bound.
    if _has_catastrophic_group_repetition(pattern):
        raise ACEFEvaluationError(
            "Regex pattern repeats a nullable/overlapping/nested group (counted or unbounded) "
            "(catastrophic-backtracking risk); rejected deterministically per the spec "
            f"§3.5 resource bound: {pattern!r}",
            code="ACEF-045",
        )

    # Translate ECMA-262 shorthand classes BEFORE compiling. The original
    # ``pattern`` was length-checked above (the translation only expands it);
    # the compiled engine sees the ECMA-262-faithful form. The match is now run
    # directly (no SIGALRM): on the bounded input, a pattern that passed the
    # static check above runs in bounded time identically on all platforms.
    compiled_pattern = _translate_ecma262_char_classes(pattern)
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


# Distinguishes "the pointer path does not exist" from "the path exists and holds
# JSON null". Both resolve to None, and conflating them makes `ne` count records
# where nothing resolved at all: _compare(None, "ne", 999) is True, so a rule
# asserting "some record has a value other than 999" was satisfied by records
# that have no such field. Existential rules must only count a record when the
# pointer RESOLVES and the comparison holds.
_MISSING = object()


def _resolve_or_missing(record_data: dict[str, Any], pointer: str) -> Any:
    """Resolve a pointer, returning :data:`_MISSING` when the path is absent."""
    node: Any = record_data
    for raw in pointer.split("/")[1:]:
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict):
            if token not in node:
                return _MISSING
            node = node[token]
        elif isinstance(node, list):
            if not token.isdigit():
                return _MISSING
            idx = int(token)
            if idx >= len(node):
                return _MISSING
            node = node[idx]
        else:
            return _MISSING
    return node


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


def _validate_regex_operand(op: str, value: Any) -> None:
    """Raise ACEF-045 when a ``regex`` rule's operand is not a usable pattern.

    Called UPFRONT, mirroring :func:`_validate_comparison_op`. Without it an
    invalid pattern such as ``"("`` is never compiled when zero records match or
    no pointer resolves, so a malformed rule yields an ordinary failure rather
    than the rule error the spec requires.
    """
    if op != "regex":
        return
    if not isinstance(value, str):
        raise ACEFEvaluationError(
            f"regex comparison operand must be a string pattern, got {type(value).__name__}",
            code="ACEF-045",
        )
    # Reuse the hardened checker so length/ReDoS rejection is identical to the
    # per-record path; matching against the empty string is side-effect free.
    # A syntactically invalid pattern surfaces from ``re`` as a raw error, which
    # is not an ACEF diagnostic — translate it.
    try:
        _safe_regex_search(value, "")
    except re.error as exc:
        raise ACEFEvaluationError(
            f"invalid ECMA-262 regex pattern {value!r}: {exc}",
            code="ACEF-045",
        ) from exc


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
    # Same reasoning for the regex OPERAND (ACEF-045): a malformed pattern must
    # raise even when zero records match or no pointer resolves, otherwise a
    # broken rule reports an ordinary failure instead of a rule error.
    _validate_regex_operand(op, value)
    matching = _filter_by_type(records, record_type)

    evidence_refs: list[str] = []
    for rec in matching:
        data = rec.to_jsonl_dict()
        actual = _resolve_or_missing(data, field)
        if actual is _MISSING:
            continue
        if _compare(actual, op, value):
            evidence_refs.append(rec.record_id)

    return len(evidence_refs) >= min_count, evidence_refs


def op_exists_where_any(
    params: dict[str, Any],
    records: list[RecordEnvelope],
) -> tuple[bool, list[str]]:
    """exists_where_any: like ``exists_where`` but over ALTERNATIVE pointers.

    At least ``min_count`` records exist for which **any** pointer in ``fields``
    resolves and satisfies the comparison. Existential -> FAIL on zero matching
    records when ``min_count`` > 0, matching :func:`op_exists_where`.

    Motivation: ACEF states record retention on two distinct surfaces — the
    envelope (``/retention/min_retention_days``) and the ``logging_spec`` payload
    (``/payload/retention_policy_summary/min_days``). A single-pointer rule
    cannot express "either surface satisfies the floor", so enforcing the
    Art. 19(1) / Art. 26(6) six-month duty with ``exists_where`` fails records
    that legitimately use only one of them — including ACEF's own canonical
    logging record.

    A record satisfying several listed pointers still counts ONCE: the
    disjunction selects records, it does not multiply them.
    """
    record_type = params["record_type"]
    fields = params["fields"]
    op = params["op"]
    value = params["value"]
    min_count = params.get("min_count", 1)

    if not isinstance(fields, list) or not fields:
        raise ACEFEvaluationError(
            "exists_where_any requires a non-empty 'fields' list — a disjunction over no pointers is not a rule",
            code="ACEF-043",
        )
    # Validate EVERY pointer and the comparison op up front, so a malformed rule
    # raises even when zero records match and the loop below never runs
    # (validation-engine-dsl-3/-7), and so a bad pointer in any position is
    # caught rather than only the first.
    for field in fields:
        _validate_pointer_syntax(field)
    _validate_comparison_op(op)
    _validate_regex_operand(op, value)
    matching = _filter_by_type(records, record_type)

    evidence_refs: list[str] = []
    for rec in matching:
        data = rec.to_jsonl_dict()
        resolved = [v for v in (_resolve_or_missing(data, field) for field in fields) if v is not _MISSING]
        if any(_compare(v, op, value) for v in resolved):
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
    trust_anchors: list[Certificate] | None = None,
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
        header = verify_detached_jws(
            att.signature, canonical, manifest_timestamp=manifest_timestamp, trust_anchors=trust_anchors
        )
        # Trust-posture symmetry with the harness verifier and bundle signatures:
        # when trust anchors ARE configured, only an ANCHORED x5c chain counts. A
        # jwk-only attestation is self-attested — an attacker can re-sign a tampered
        # record with their own auto-embedded key — so it does NOT satisfy
        # record_attested under configured anchors (verify_detached_jws ignores
        # anchors for a jwk-only signature, so an anchor set alone is not a secure
        # path). With NO anchors (trust_anchors is None), a jwk-only attestation is
        # self-attested and counts (spec §3.5 record_attested row). A non-None EMPTY
        # anchor list is an explicit anchoring request no chain can satisfy, so use
        # ``is not None`` (not truthiness) — trust_anchors=[] fails closed.
        if trust_anchors is not None and not header.get("x5c"):
            return False
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
    trust_anchors: list[Certificate] | None = None,
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

    ``trust_anchors`` is the SAME locally-configured x5c trust-anchor set the
    Phase-2 integrity check ran under (spec §3.5 record_attested trust-anchoring
    consistency clause). When non-empty and an attestation carries an ``x5c``
    chain, that chain MUST terminate at a configured anchor to count — so a
    self-issued x5c rejected as a bundle signature (ACEF-012) does NOT satisfy
    ``record_attested`` in the same anchored run. ``None`` (default) preserves
    the historical ``self-attested`` behavior exactly (no anchoring enforced).
    """
    record_type = params["record_type"]
    min_count = params.get("min_count", 1)

    matching = _filter_by_type(records, record_type)

    evidence_refs: list[str] = []
    for rec in matching:
        if _attestation_verifies(rec, manifest_timestamp=manifest_timestamp, trust_anchors=trust_anchors):
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
    "exists_where_any": op_exists_where_any,
    "attachment_kind_exists": op_attachment_kind_exists,
    "bundle_signed": op_bundle_signed,
    "record_attested": op_record_attested,
}
