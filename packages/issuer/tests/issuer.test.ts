import { describe, it, expect, beforeAll } from 'vitest';
import { CredentialIssuer, type IssuerConfig } from '../src/issuer.js';
import {
  pedersenCommit,
  schnorrVerify,
  poseidonHash7,
  hexToBigInt,
  randomFieldElement,
} from '@zk-session/crypto';

describe('CredentialIssuer', () => {
  const issuerConfig: IssuerConfig = {
    serviceId: 12345n,
    secretKey: randomFieldElement(),
    tiers: [
      { minAmountCents: 0, tier: 0, maxPresentations: 100, durationSeconds: 3600 },
      { minAmountCents: 100, tier: 1, maxPresentations: 1000, durationSeconds: 86400 },
    ],
    allowMockPayments: true,
  };

  let issuer: CredentialIssuer;

  beforeAll(async () => {
    // Initialize crypto (Pedersen needs WASM init)
    await pedersenCommit(1n, 1n);
    issuer = new CredentialIssuer(issuerConfig);
  });

  it('should issue a credential for mock payment', async () => {
    const commitment = await pedersenCommit(123n, 456n);

    const response = await issuer.issueCredential({
      paymentProof: {
        mock: { amountUSDC: 1.0, payer: '0xTestUser' },
      },
      userCommitment: {
        x: '0x' + commitment.point.x.toString(16),
        y: '0x' + commitment.point.y.toString(16),
      },
    });

    expect(response.credential).toBeDefined();
    expect(response.credential.tier).toBe(1); // $1.00 >= $1.00 tier
    expect(response.credential.maxPresentations).toBe(1000);
  });

  it('should assign correct tier based on payment amount', async () => {
    const commitment = await pedersenCommit(123n, 456n);

    // Small payment -> tier 0
    const response = await issuer.issueCredential({
      paymentProof: {
        mock: { amountUSDC: 0.5, payer: '0xTestUser' },
      },
      userCommitment: {
        x: '0x' + commitment.point.x.toString(16),
        y: '0x' + commitment.point.y.toString(16),
      },
    });

    expect(response.credential.tier).toBe(0);
    expect(response.credential.maxPresentations).toBe(100);
  });

  it('should produce verifiable signatures', async () => {
    const commitment = await pedersenCommit(123n, 456n);

    const response = await issuer.issueCredential({
      paymentProof: {
        mock: { amountUSDC: 1.0, payer: '0xTestUser' },
      },
      userCommitment: {
        x: '0x' + commitment.point.x.toString(16),
        y: '0x' + commitment.point.y.toString(16),
      },
    });

    const cred = response.credential;

    // Reconstruct the message that was signed
    const message = poseidonHash7(
      hexToBigInt(cred.serviceId),
      BigInt(cred.tier),
      BigInt(cred.maxPresentations),
      BigInt(cred.issuedAt),
      BigInt(cred.expiresAt),
      hexToBigInt(cred.userCommitment.x),
      hexToBigInt(cred.userCommitment.y),
    );

    // Verify signature
    const valid = schnorrVerify(
      {
        x: hexToBigInt(cred.issuerPubkey.x),
        y: hexToBigInt(cred.issuerPubkey.y),
      },
      message,
      {
        r: {
          x: hexToBigInt(cred.signature.r.x),
          y: hexToBigInt(cred.signature.r.y),
        },
        s: hexToBigInt(cred.signature.s),
      }
    );

    expect(valid).toBe(true);
  });

  it('should reject when mock payments disabled', async () => {
    const strictIssuer = new CredentialIssuer({
      ...issuerConfig,
      allowMockPayments: false,
    });

    const commitment = await pedersenCommit(123n, 456n);

    await expect(
      strictIssuer.issueCredential({
        paymentProof: {
          mock: { amountUSDC: 1.0, payer: '0xTestUser' },
        },
        userCommitment: {
          x: '0x' + commitment.point.x.toString(16),
          y: '0x' + commitment.point.y.toString(16),
        },
      })
    ).rejects.toThrow('Invalid payment proof');
  });
});
