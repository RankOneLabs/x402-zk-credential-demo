import { describe, it, expect } from 'vitest';
import {
  FIELD_MODULUS,
  toField,
  hexToBigInt,
  bigIntToHex,
  randomFieldElement,
  stringToField,
  bytesToField,
  fieldToBytes,
} from '../src/utils.js';

describe('toField', () => {
  it('returns value unchanged when in range', () => {
    expect(toField(0n)).toBe(0n);
    expect(toField(1n)).toBe(1n);
    expect(toField(12345n)).toBe(12345n);
  });

  it('reduces values >= FIELD_MODULUS', () => {
    expect(toField(FIELD_MODULUS)).toBe(0n);
    expect(toField(FIELD_MODULUS + 1n)).toBe(1n);
    expect(toField(FIELD_MODULUS * 2n)).toBe(0n);
    expect(toField(FIELD_MODULUS * 2n + 5n)).toBe(5n);
  });

  it('handles negative values', () => {
    expect(toField(-1n)).toBe(FIELD_MODULUS - 1n);
    expect(toField(-FIELD_MODULUS)).toBe(0n);
    expect(toField(-5n)).toBe(FIELD_MODULUS - 5n);
  });
});

describe('hexToBigInt', () => {
  it('converts hex with 0x prefix', () => {
    expect(hexToBigInt('0x0')).toBe(0n);
    expect(hexToBigInt('0x1')).toBe(1n);
    expect(hexToBigInt('0xff')).toBe(255n);
    expect(hexToBigInt('0x100')).toBe(256n);
  });

  it('converts hex without 0x prefix', () => {
    expect(hexToBigInt('0')).toBe(0n);
    expect(hexToBigInt('ff')).toBe(255n);
    expect(hexToBigInt('deadbeef')).toBe(0xdeadbeefn);
  });

  it('handles large values', () => {
    const largeHex = '0x' + 'ff'.repeat(32);
    expect(hexToBigInt(largeHex)).toBe((1n << 256n) - 1n);
  });
});

describe('bigIntToHex', () => {
  it('converts to padded hex string', () => {
    expect(bigIntToHex(0n)).toBe('0x' + '0'.repeat(64));
    expect(bigIntToHex(1n)).toBe('0x' + '0'.repeat(63) + '1');
    expect(bigIntToHex(255n)).toBe('0x' + '0'.repeat(62) + 'ff');
  });

  it('respects custom padding', () => {
    expect(bigIntToHex(255n, 1)).toBe('0xff');
    expect(bigIntToHex(255n, 2)).toBe('0x00ff');
    expect(bigIntToHex(256n, 2)).toBe('0x0100');
  });

  it('handles values larger than padding', () => {
    expect(bigIntToHex(0xdeadbeefn, 2)).toBe('0xdeadbeef');
  });
});

describe('randomFieldElement', () => {
  it('returns value in valid range', () => {
    for (let i = 0; i < 10; i++) {
      const r = randomFieldElement();
      expect(r).toBeGreaterThanOrEqual(0n);
      expect(r).toBeLessThan(FIELD_MODULUS);
    }
  });

  it('returns different values', () => {
    const values = new Set<bigint>();
    for (let i = 0; i < 10; i++) {
      values.add(randomFieldElement());
    }
    // Should have at least 9 unique values (astronomically unlikely to have collision)
    expect(values.size).toBeGreaterThanOrEqual(9);
  });
});

describe('stringToField', () => {
  it('converts empty string to 0', () => {
    expect(stringToField('')).toBe(0n);
  });

  it('produces consistent output', () => {
    expect(stringToField('hello')).toBe(stringToField('hello'));
    expect(stringToField('world')).toBe(stringToField('world'));
  });

  it('produces different output for different inputs', () => {
    expect(stringToField('hello')).not.toBe(stringToField('world'));
    expect(stringToField('a')).not.toBe(stringToField('b'));
  });

  it('handles unicode', () => {
    const result = stringToField('こんにちは');
    expect(result).toBeGreaterThanOrEqual(0n);
    expect(result).toBeLessThan(FIELD_MODULUS);
  });
});

describe('bytesToField', () => {
  it('converts empty array to 0', () => {
    expect(bytesToField(new Uint8Array([]))).toBe(0n);
  });

  it('converts single byte', () => {
    expect(bytesToField(new Uint8Array([0]))).toBe(0n);
    expect(bytesToField(new Uint8Array([1]))).toBe(1n);
    expect(bytesToField(new Uint8Array([255]))).toBe(255n);
  });

  it('converts multiple bytes big-endian', () => {
    expect(bytesToField(new Uint8Array([1, 0]))).toBe(256n);
    expect(bytesToField(new Uint8Array([1, 0, 0]))).toBe(65536n);
    expect(bytesToField(new Uint8Array([0xde, 0xad, 0xbe, 0xef]))).toBe(0xdeadbeefn);
  });

  it('reduces values >= FIELD_MODULUS', () => {
    // 32 bytes of 0xff is larger than FIELD_MODULUS
    const maxBytes = new Uint8Array(32).fill(0xff);
    const result = bytesToField(maxBytes);
    expect(result).toBeGreaterThanOrEqual(0n);
    expect(result).toBeLessThan(FIELD_MODULUS);
  });
});

describe('fieldToBytes', () => {
  it('converts 0 to 32 zero bytes', () => {
    const bytes = fieldToBytes(0n);
    expect(bytes.length).toBe(32);
    expect(bytes.every(b => b === 0)).toBe(true);
  });

  it('converts 1 to bytes with trailing 1', () => {
    const bytes = fieldToBytes(1n);
    expect(bytes[31]).toBe(1);
    expect(bytes.slice(0, 31).every(b => b === 0)).toBe(true);
  });

  it('round-trips with bytesToField', () => {
    const values = [0n, 1n, 255n, 256n, 0xdeadbeefn, FIELD_MODULUS - 1n];
    for (const v of values) {
      expect(bytesToField(fieldToBytes(v))).toBe(v);
    }
  });

  it('converts large values correctly', () => {
    const bytes = fieldToBytes(FIELD_MODULUS - 1n);
    expect(bytes.length).toBe(32);
    expect(bytesToField(bytes)).toBe(FIELD_MODULUS - 1n);
  });
});
