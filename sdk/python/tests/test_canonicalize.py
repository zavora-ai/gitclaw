"""
Property-based tests for JCS Canonicalization.

Feature: gitclaw-sdk
Property 2: JCS canonicalization round-trip
Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5 | Design: DR-2
"""

import json

from hypothesis import given, settings
from hypothesis import strategies as st

from gitclaw.canonicalize import canonicalize

# Strategy for generating JSON-compatible values
# Constrain floats to a safe range that won't overflow when round-tripped through JSON
# Values near sys.float_info.max can become infinity after JSON parsing
json_primitives = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**53), max_value=2**53),  # Safe integer range
    st.floats(
        min_value=-1e308,
        max_value=1e308,
        allow_nan=False,
        allow_infinity=False,
        allow_subnormal=False,
    ),
    st.text(max_size=100),
)

# Recursive strategy for nested JSON structures
json_values = st.recursive(
    json_primitives,
    lambda children: st.one_of(
        st.lists(children, max_size=5),
        st.dictionaries(st.text(max_size=20), children, max_size=5),
    ),
    max_leaves=20,
)


@given(value=json_values)
@settings(max_examples=100)
def test_jcs_canonicalization_round_trip(value: object) -> None:
    """
    Property 2: JCS canonicalization round-trip

    For any valid JSON object, canonicalizing the object, parsing the result
    back to a data structure, and canonicalizing again SHALL produce an
    identical string.

    Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5 | Design: DR-2
    """
    # First canonicalization
    canonical1 = canonicalize(value)

    # Parse back to Python object
    parsed = json.loads(canonical1)

    # Second canonicalization
    canonical2 = canonicalize(parsed)

    # Must be identical
    assert canonical1 == canonical2, (
        f"Round-trip failed:\n"
        f"  Original: {value!r}\n"
        f"  First canonical: {canonical1}\n"
        f"  Parsed: {parsed!r}\n"
        f"  Second canonical: {canonical2}"
    )


@given(obj=st.dictionaries(st.text(max_size=20), json_primitives, max_size=10))
@settings(max_examples=100)
def test_keys_are_sorted(obj: dict[str, object]) -> None:
    """
    Verify that object keys are sorted lexicographically.

    Validates: Requirement 3.1
    """
    canonical = canonicalize(obj)
    parsed = json.loads(canonical)

    keys = list(parsed.keys())
    sorted_keys = sorted(keys)

    assert keys == sorted_keys, f"Keys not sorted: {keys} vs {sorted_keys}"


@given(s=st.text(max_size=100))
@settings(max_examples=100)
def test_string_escaping_produces_valid_json(s: str) -> None:
    """
    Verify that string escaping produces valid JSON.

    Validates: Requirement 3.4
    """
    canonical = canonicalize(s)

    # Must be valid JSON
    parsed = json.loads(canonical)

    # Must round-trip correctly
    assert parsed == s, f"String round-trip failed: {s!r} -> {canonical} -> {parsed!r}"


def test_no_whitespace_between_tokens() -> None:
    """
    Verify that canonical output has no whitespace between tokens.

    Validates: Requirement 3.2
    """
    obj = {"a": 1, "b": [1, 2, 3], "c": {"nested": True}}
    canonical = canonicalize(obj)

    # Should not contain spaces outside of strings
    # Parse and check structure
    assert " " not in canonical.replace('"nested"', "").replace('"', "")


def test_negative_zero_becomes_zero() -> None:
    """
    Verify that -0.0 is canonicalized as "0".

    Validates: Requirement 3.3 (shortest representation)
    """
    assert canonicalize(-0.0) == "0"
    assert canonicalize(0.0) == "0"


def test_integers_have_no_decimal() -> None:
    """
    Verify that integers don't have decimal points.

    Validates: Requirement 3.3 (shortest representation)
    """
    assert canonicalize(42) == "42"
    assert canonicalize(-100) == "-100"
    assert canonicalize(0) == "0"
