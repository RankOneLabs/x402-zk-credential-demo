import { describe, it, expect, beforeAll } from 'vitest';
import {
  pedersenCommit,
  pedersenCommitSync,
  verifyCommitment,
  initPedersen,
} from '../src/pedersen.js';

describe('Pedersen Commitment', () => {
  // Initialize Barretenberg before tests
  beforeAll(async () => {
    await initPedersen();
  });

  it('should create a deterministic commitment', async () => {
    const secret = 12345n;
    const blinding = 67890n;
    
    const c1 = await pedersenCommit(secret, blinding);
    const c2 = await pedersenCommit(secret, blinding);
    
    expect(c1.point.x).toBe(c2.point.x);
    expect(c1.point.y).toBe(c2.point.y);
  });
  
  it('should verify a valid commitment', async () => {
    const secret = 12345n;
    const blinding = 67890n;
    
    const commitment = await pedersenCommit(secret, blinding);
    const valid = await verifyCommitment(commitment.point, secret, blinding);
    
    expect(valid).toBe(true);
  });
  
  it('should reject invalid opening', async () => {
    const secret = 12345n;
    const blinding = 67890n;
    
    const commitment = await pedersenCommit(secret, blinding);
    const valid = await verifyCommitment(commitment.point, secret + 1n, blinding);
    
    expect(valid).toBe(false);
  });
  
  it('different secrets should produce different commitments', async () => {
    const blinding = 12345n;
    
    const c1 = await pedersenCommit(1n, blinding);
    const c2 = await pedersenCommit(2n, blinding);
    
    expect(c1.point.x !== c2.point.x || c1.point.y !== c2.point.y).toBe(true);
  });
  
  it('should match known Barretenberg test vector', async () => {
    // Test vector from Barretenberg: commit([1, 1]) 
    // Expected: (0x2f7a8f9a6c96926682205fb73ee43215bf13523c19d7afe36f12760266cdfe15, 
    //            0x01916b316adbbf0e10e39b18c1d24b33ec84b46daddf72f43878bcc92b6057e6)
    const commitment = await pedersenCommit(1n, 1n);
    
    expect(commitment.point.x.toString(16)).toBe(
      '2f7a8f9a6c96926682205fb73ee43215bf13523c19d7afe36f12760266cdfe15'
    );
    expect(commitment.point.y.toString(16)).toBe(
      '1916b316adbbf0e10e39b18c1d24b33ec84b46daddf72f43878bcc92b6057e6'
    );
  });
});

describe('pedersenCommitSync', () => {
  // Note: beforeAll in the previous describe already initialized BB
  
  it('should produce same result as async version', async () => {
    const secret = 12345n;
    const blinding = 67890n;
    
    const asyncResult = await pedersenCommit(secret, blinding);
    const syncResult = pedersenCommitSync(secret, blinding);
    
    expect(syncResult.point.x).toBe(asyncResult.point.x);
    expect(syncResult.point.y).toBe(asyncResult.point.y);
    expect(syncResult.secret).toBe(asyncResult.secret);
    expect(syncResult.blinding).toBe(asyncResult.blinding);
  });
  
  it('should work with test vector', () => {
    const commitment = pedersenCommitSync(1n, 1n);
    
    expect(commitment.point.x.toString(16)).toBe(
      '2f7a8f9a6c96926682205fb73ee43215bf13523c19d7afe36f12760266cdfe15'
    );
    expect(commitment.point.y.toString(16)).toBe(
      '1916b316adbbf0e10e39b18c1d24b33ec84b46daddf72f43878bcc92b6057e6'
    );
  });
});
