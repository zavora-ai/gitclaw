/**
 * Property-based tests for JCS Canonicalization.
 *
 * Feature: gitclaw-sdk
 * Property 2: JCS canonicalization round-trip
 * Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5 | Design: DR-2
 */

import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import { canonicalize } from '../src/canonicalize.js';

// Strategy for generating JSON-compatible values
// Constrain floats to a safe range that won't overflow when round-tripped through JSON
const jsonPrimitives = fc.oneof(
  fc.constant(null),
  fc.boolean(),
  fc.integer({ min: -(2 ** 53), max: 2 ** 53 }), // Safe integer range
  fc.double({
    min: -1e100,
    max: 1e100,
    noNaN: true,
    noDefaultInfinity: true,
  }),
  fc.string({ maxLength: 100 })
);

// Recursive strategy for nested JSON structures
const jsonValues: fc.Arbitrary<unknown> = fc.letrec((tie) => ({
  value: fc.oneof(
    { depthSize: 'small', withCrossShrink: true },
    jsonPrimitives,
    fc.array(tie('value'), { maxLength: 5 }),
    fc.dictionary(fc.string({ maxLength: 20 }), tie('value'), { maxKeys: 5 })
  ),
})).value;

describe('JCS Canonicalization', () => {
  /**
   * Property 2: JCS canonicalization round-trip
   *
   * For any valid JSON object, canonicalizing the object, parsing the result
   * back to a data structure, and canonicalizing again SHALL produce an
   * identical string.
   *
   * **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5** | **Design: DR-2**
   */
  it('round-trip property: canonicalize -> parse -> canonicalize produces identical output', () => {
    fc.assert(
      fc.property(jsonValues, (value) => {
        // First canonicalization
        const canonical1 = canonicalize(value);

        // Parse back to JavaScript object
        const parsed = JSON.parse(canonical1);

        // Second canonicalization
        const canonical2 = canonicalize(parsed);

        // Must be identical
        expect(canonical1).toBe(canonical2);
      }),
      { numRuns: 100 }
    );
  });

  /**
   * Verify that object keys are sorted lexicographically in the output.
   *
   * Validates: Requirement 3.1
   */
  it('keys are sorted lexicographically by UTF-16 code units', () => {
    // Use a custom arbitrary that excludes __proto__ to avoid JavaScript prototype pollution
    const safeKey = fc.string({ maxLength: 20 }).filter((s) => s !== '__proto__');

    fc.assert(
      fc.property(fc.dictionary(safeKey, jsonPrimitives, { maxKeys: 10 }), (obj) => {
        const canonical = canonicalize(obj);

        // Sort the original keys by UTF-16 code units
        const sortedKeys = Object.keys(obj).sort((a, b) => {
          const minLen = Math.min(a.length, b.length);
          for (let i = 0; i < minLen; i++) {
            const diff = a.charCodeAt(i) - b.charCodeAt(i);
            if (diff !== 0) return diff;
          }
          return a.length - b.length;
        });

        // Build expected canonical output with sorted keys
        const sortedObj: Record<string, unknown> = {};
        for (const key of sortedKeys) {
          sortedObj[key] = obj[key];
        }
        const expectedCanonical = canonicalize(sortedObj);

        // The canonical output should match
        expect(canonical).toBe(expectedCanonical);
      }),
      { numRuns: 100 }
    );
  });

  /**
   * Verify that string escaping produces valid JSON.
   *
   * Validates: Requirement 3.4
   */
  it('string escaping produces valid JSON that round-trips correctly', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 100 }), (s) => {
        const canonical = canonicalize(s);

        // Must be valid JSON
        const parsed = JSON.parse(canonical);

        // Must round-trip correctly
        expect(parsed).toBe(s);
      }),
      { numRuns: 100 }
    );
  });

  /**
   * Verify that canonical output has no whitespace between tokens.
   *
   * Validates: Requirement 3.2
   */
  it('no whitespace between tokens', () => {
    const obj = { a: 1, b: [1, 2, 3], c: { nested: true } };
    const canonical = canonicalize(obj);

    // Should not contain spaces outside of strings
    // Remove all string content and check for spaces
    const withoutStrings = canonical.replace(/"[^"]*"/g, '""');
    expect(withoutStrings).not.toContain(' ');
    expect(withoutStrings).not.toContain('\n');
    expect(withoutStrings).not.toContain('\t');
  });

  /**
   * Verify that -0 is canonicalized as "0".
   *
   * Validates: Requirement 3.3 (shortest representation)
   */
  it('negative zero becomes zero', () => {
    expect(canonicalize(-0)).toBe('0');
    expect(canonicalize(0)).toBe('0');
  });

  /**
   * Verify that integers don't have decimal points.
   *
   * Validates: Requirement 3.3 (shortest representation)
   */
  it('integers have no decimal point', () => {
    expect(canonicalize(42)).toBe('42');
    expect(canonicalize(-100)).toBe('-100');
    expect(canonicalize(0)).toBe('0');
  });

  /**
   * Verify that NaN and Infinity throw errors.
   */
  it('throws on NaN and Infinity', () => {
    expect(() => canonicalize(NaN)).toThrow();
    expect(() => canonicalize(Infinity)).toThrow();
    expect(() => canonicalize(-Infinity)).toThrow();
  });

  /**
   * Verify control characters are properly escaped.
   */
  it('control characters are properly escaped', () => {
    const str = 'hello\nworld\ttab\r\n';
    const canonical = canonicalize(str);
    expect(canonical).toBe('"hello\\nworld\\ttab\\r\\n"');
  });

  /**
   * Verify backslash and quote are escaped.
   */
  it('backslash and quote are escaped', () => {
    const str = 'say "hello" \\ world';
    const canonical = canonicalize(str);
    expect(canonical).toBe('"say \\"hello\\" \\\\ world"');
  });
});
