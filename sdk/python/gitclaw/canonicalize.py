"""
JSON Canonicalization Scheme (JCS) implementation per RFC 8785.

This module provides deterministic JSON serialization for signature generation.
"""

import math
from typing import Any


class JCSCanonicalizer:
    """
    JSON Canonicalization Scheme (RFC 8785) implementation.

    Produces deterministic JSON output by:
    1. Sorting object keys lexicographically by UTF-16 code units
    2. Using no whitespace between tokens
    3. Using shortest numeric representation
    4. Using minimal string escaping
    """

    def canonicalize(self, value: Any) -> str:
        """
        Canonicalize a Python value to a JCS-compliant JSON string.

        Args:
            value: Any JSON-serializable Python value

        Returns:
            Canonical JSON string per RFC 8785
        """
        return self._canonicalize_value(value)

    def _canonicalize_value(self, value: Any) -> str:
        """Canonicalize any JSON value."""
        if value is None:
            return "null"
        elif isinstance(value, bool):
            return "true" if value else "false"
        elif isinstance(value, str):
            return self._canonicalize_string(value)
        elif isinstance(value, int):
            return self._canonicalize_integer(value)
        elif isinstance(value, float):
            return self._canonicalize_float(value)
        elif isinstance(value, dict):
            return self._canonicalize_object(value)
        elif isinstance(value, (list, tuple)):
            return self._canonicalize_array(value)
        else:
            raise TypeError(f"Cannot canonicalize type: {type(value).__name__}")

    def _canonicalize_object(self, obj: dict[str, Any]) -> str:
        """
        Canonicalize a dictionary with keys sorted by UTF-16 code units.

        Per RFC 8785, keys are sorted lexicographically by their UTF-16
        code unit representation.
        """
        # Sort keys by UTF-16 code units (Python's default string comparison
        # works correctly for this since Python 3 strings are Unicode)
        sorted_keys = sorted(obj.keys(), key=lambda k: [ord(c) for c in k])

        pairs = []
        for key in sorted_keys:
            canonical_key = self._canonicalize_string(key)
            canonical_value = self._canonicalize_value(obj[key])
            pairs.append(f"{canonical_key}:{canonical_value}")

        return "{" + ",".join(pairs) + "}"

    def _canonicalize_array(self, arr: list[Any] | tuple[Any, ...]) -> str:
        """Canonicalize an array."""
        elements = [self._canonicalize_value(item) for item in arr]
        return "[" + ",".join(elements) + "]"

    def _canonicalize_string(self, s: str) -> str:
        """
        Escape and quote a string according to JSON spec with minimal escaping.

        Only escapes characters that MUST be escaped per JSON spec:
        - Control characters (U+0000 to U+001F)
        - Backslash and double quote
        """
        result = ['"']
        for char in s:
            code = ord(char)
            if char == '"':
                result.append('\\"')
            elif char == '\\':
                result.append('\\\\')
            elif code == 0x08:  # backspace
                result.append('\\b')
            elif code == 0x09:  # tab
                result.append('\\t')
            elif code == 0x0A:  # newline
                result.append('\\n')
            elif code == 0x0C:  # form feed
                result.append('\\f')
            elif code == 0x0D:  # carriage return
                result.append('\\r')
            elif code < 0x20:  # other control characters
                result.append(f'\\u{code:04x}')
            else:
                result.append(char)
        result.append('"')
        return ''.join(result)

    def _canonicalize_integer(self, n: int) -> str:
        """Format an integer."""
        return str(n)

    def _canonicalize_float(self, n: float) -> str:
        """
        Format a float using shortest representation per RFC 8785.

        Special cases:
        - NaN and Infinity are not valid JSON
        - -0.0 becomes "0"
        - Uses exponential notation when shorter
        """
        if math.isnan(n) or math.isinf(n):
            raise ValueError(f"Cannot canonicalize {n}: not valid JSON")

        # Handle negative zero
        if n == 0.0:
            return "0"

        # Try different representations and pick shortest
        # Standard decimal
        decimal_repr = self._format_decimal(n)

        # Exponential notation
        exp_repr = self._format_exponential(n)

        # Return shortest representation
        if len(exp_repr) < len(decimal_repr):
            return exp_repr
        return decimal_repr

    def _format_decimal(self, n: float) -> str:
        """Format float as decimal, removing trailing zeros."""
        # Use repr for full precision, then clean up
        s = repr(n)

        # repr might give exponential notation for very large/small numbers
        if 'e' in s or 'E' in s:
            # Fall back to format with high precision
            s = f"{n:.17g}"

        return s

    def _format_exponential(self, n: float) -> str:
        """Format float in exponential notation."""
        # Get the exponent
        if n == 0:
            return "0"

        exp = math.floor(math.log10(abs(n)))
        mantissa = n / (10 ** exp)

        # Format mantissa without trailing zeros
        mantissa_str = f"{mantissa:.15g}"

        # Remove unnecessary decimal point
        if '.' in mantissa_str:
            mantissa_str = mantissa_str.rstrip('0').rstrip('.')

        if exp == 0:
            return mantissa_str

        return f"{mantissa_str}e{exp:+d}" if exp < 0 else f"{mantissa_str}e+{exp}"


# Module-level convenience function
_canonicalizer = JCSCanonicalizer()


def canonicalize(value: Any) -> str:
    """
    Canonicalize a Python value to a JCS-compliant JSON string.

    This is a convenience function that uses a module-level JCSCanonicalizer.

    Args:
        value: Any JSON-serializable Python value

    Returns:
        Canonical JSON string per RFC 8785
    """
    return _canonicalizer.canonicalize(value)
