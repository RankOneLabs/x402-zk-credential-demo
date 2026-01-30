import { describe, it, expect } from 'vitest';
import { ZkVerifier, parseProofFromRequest } from '../src/verifier.js';

describe('ZkVerifier', () => {
  describe('initialization', () => {
    it('should create verifier with default config', () => {
      const verifier = new ZkVerifier();
      expect(verifier.isInitialized()).toBe(false);
    });

    it('should create verifier with skipVerification', () => {
      const verifier = new ZkVerifier({ skipVerification: true });
      expect(verifier.isInitialized()).toBe(false);
    });
  });

  describe('verify with skipVerification', () => {
    it('should return valid in skip mode', async () => {
      const verifier = new ZkVerifier({ skipVerification: true });
      
      const result = await verifier.verify({
        proof: new Uint8Array([1, 2, 3]),
        publicInputs: [
          '0x1', '0x2', '0x3', '0x4', '0x5',  // 5 public inputs
          '0xabc',  // origin_token
          '0x1',    // tier
        ],
      });
      
      expect(result.valid).toBe(true);
      expect(result.outputs?.originToken).toBe('0xabc');
      expect(result.outputs?.tier).toBe(1);
    });

    it('should extract tier correctly in skip mode', async () => {
      const verifier = new ZkVerifier({ skipVerification: true });
      
      const result = await verifier.verify({
        proof: new Uint8Array([1, 2, 3]),
        publicInputs: ['0x1', '0x2', '0x3', '0x4', '0x5', '0xdef', '0x2'],
      });
      
      expect(result.outputs?.tier).toBe(2);
    });
  });
});

describe('parseProofFromRequest', () => {
  it('should parse valid proof JSON', () => {
    const proofData = {
      proof: Buffer.from([1, 2, 3, 4]).toString('base64'),
      publicInputs: ['0x1', '0x2', '0x3'],
    };
    const encoded = Buffer.from(JSON.stringify(proofData)).toString('base64');
    
    const result = parseProofFromRequest(encoded);
    
    expect(result).not.toBeNull();
    expect(result?.publicInputs).toEqual(['0x1', '0x2', '0x3']);
    expect(result?.proof.length).toBe(4);
  });

  it('should return null for invalid base64', () => {
    const result = parseProofFromRequest('not-valid-base64!!!');
    expect(result).toBeNull();
  });

  it('should return null for invalid JSON', () => {
    const encoded = Buffer.from('not json').toString('base64');
    const result = parseProofFromRequest(encoded);
    expect(result).toBeNull();
  });

  it('should return null for missing proof field', () => {
    const encoded = Buffer.from(JSON.stringify({ publicInputs: ['0x1'] })).toString('base64');
    const result = parseProofFromRequest(encoded);
    expect(result).toBeNull();
  });

  it('should return null for missing publicInputs field', () => {
    const encoded = Buffer.from(JSON.stringify({ proof: 'abc' })).toString('base64');
    const result = parseProofFromRequest(encoded);
    expect(result).toBeNull();
  });

  it('should return null for non-array publicInputs', () => {
    const encoded = Buffer.from(JSON.stringify({ proof: 'abc', publicInputs: 'not-array' })).toString('base64');
    const result = parseProofFromRequest(encoded);
    expect(result).toBeNull();
  });
});
