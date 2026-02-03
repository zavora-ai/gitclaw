/**
 * JSON Canonicalization Scheme (JCS) implementation per RFC 8785.
 *
 * This module provides deterministic JSON serialization for signature generation.
 */

/**
 * Type representing any valid JSON value.
 */
export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

/**
 * JSON Canonicalization Scheme (RFC 8785) implementation.
 *
 * Produces deterministic JSON output by:
 * 1. Sorting object keys lexicographically by UTF-16 code units
 * 2. Using no whitespace between tokens
 * 3. Using shortest numeric representation
 * 4. Using minimal string escaping
 */
export class JCSCanonicalizer {
  /**
   * Canonicalize a value to a JCS-compliant JSON string.
   *
   * @param value - Any JSON-serializable value
   * @returns Canonical JSON string per RFC 8785
   */
  canonicalize(value: unknown): string {
    return this.canonicalizeValue(value);
  }

  private canonicalizeValue(value: unknown): string {
    if (value === null) {
      return 'null';
    }

    if (typeof value === 'boolean') {
      return value ? 'true' : 'false';
    }

    if (typeof value === 'string') {
      return this.canonicalizeString(value);
    }

    if (typeof value === 'number') {
      return this.canonicalizeNumber(value);
    }

    if (Array.isArray(value)) {
      return this.canonicalizeArray(value);
    }

    if (typeof value === 'object') {
      return this.canonicalizeObject(value as Record<string, unknown>);
    }

    throw new TypeError(`Cannot canonicalize type: ${typeof value}`);
  }

  /**
   * Canonicalize an object with keys sorted by UTF-16 code units.
   *
   * Per RFC 8785, keys are sorted lexicographically by their UTF-16
   * code unit representation.
   */
  private canonicalizeObject(obj: Record<string, unknown>): string {
    // Sort keys by UTF-16 code units
    // JavaScript's default string comparison works correctly for this
    const sortedKeys = Object.keys(obj).sort((a, b) => {
      // Compare by UTF-16 code units
      const minLen = Math.min(a.length, b.length);
      for (let i = 0; i < minLen; i++) {
        const diff = a.charCodeAt(i) - b.charCodeAt(i);
        if (diff !== 0) {
          return diff;
        }
      }
      return a.length - b.length;
    });

    const pairs = sortedKeys.map((key) => {
      const canonicalKey = this.canonicalizeString(key);
      const canonicalValue = this.canonicalizeValue(obj[key]);
      return `${canonicalKey}:${canonicalValue}`;
    });

    return '{' + pairs.join(',') + '}';
  }

  /**
   * Canonicalize an array.
   */
  private canonicalizeArray(arr: unknown[]): string {
    const elements = arr.map((item) => this.canonicalizeValue(item));
    return '[' + elements.join(',') + ']';
  }

  /**
   * Escape and quote a string according to JSON spec with minimal escaping.
   *
   * Only escapes characters that MUST be escaped per JSON spec:
   * - Control characters (U+0000 to U+001F)
   * - Backslash and double quote
   */
  private canonicalizeString(s: string): string {
    const result: string[] = ['"'];

    for (let i = 0; i < s.length; i++) {
      const char = s[i];
      const code = s.charCodeAt(i);

      if (char === '"') {
        result.push('\\"');
      } else if (char === '\\') {
        result.push('\\\\');
      } else if (code === 0x08) {
        // backspace
        result.push('\\b');
      } else if (code === 0x09) {
        // tab
        result.push('\\t');
      } else if (code === 0x0a) {
        // newline
        result.push('\\n');
      } else if (code === 0x0c) {
        // form feed
        result.push('\\f');
      } else if (code === 0x0d) {
        // carriage return
        result.push('\\r');
      } else if (code < 0x20) {
        // other control characters
        result.push('\\u' + code.toString(16).padStart(4, '0'));
      } else {
        result.push(char);
      }
    }

    result.push('"');
    return result.join('');
  }

  /**
   * Format a number using shortest representation per RFC 8785.
   *
   * Special cases:
   * - NaN and Infinity are not valid JSON
   * - -0 becomes "0"
   * - Uses exponential notation when shorter
   */
  private canonicalizeNumber(n: number): string {
    if (!Number.isFinite(n)) {
      throw new Error(`Cannot canonicalize ${n}: not valid JSON`);
    }

    // Handle negative zero
    if (Object.is(n, -0) || n === 0) {
      return '0';
    }

    // For integers, just use toString
    if (Number.isInteger(n) && Math.abs(n) < Number.MAX_SAFE_INTEGER) {
      return n.toString();
    }

    // For floats, use the ES6 number-to-string algorithm which produces
    // the shortest representation that round-trips correctly
    // This is what JSON.stringify uses internally
    return JSON.stringify(n);
  }
}

// Module-level convenience instance
const canonicalizer = new JCSCanonicalizer();

/**
 * Canonicalize a value to a JCS-compliant JSON string.
 *
 * This is a convenience function that uses a module-level JCSCanonicalizer.
 *
 * @param value - Any JSON-serializable value
 * @returns Canonical JSON string per RFC 8785
 */
export function canonicalize(value: unknown): string {
  return canonicalizer.canonicalize(value);
}
