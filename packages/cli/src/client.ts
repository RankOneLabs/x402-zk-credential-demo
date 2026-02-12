/**
 * ZK Credential Client
 * 
 * Manages credentials and generates authenticated requests.
 * Compliant with x402 zk-credential spec v0.1.0
 */

import {
  pedersenCommit,
  randomFieldElement,
  poseidonHash3,
  stringToField,
  bigIntToHex,
  hexToBigInt,
  addSchemePrefix,
  parseSchemePrefix,
  type X402WithZKCredentialResponse,
  type X402PaymentRequest,
  type X402PaymentResponse,
  type CredentialWireFormat,
  type PaymentPayload,
  type PaymentRequirements,
  bytesToPoint,
  toBase64Url,
  fromBase64Url,
  pointToBytes,
  fieldToBytes,
  bytesToField,
} from '@demo/crypto';

/** Settlement request for x402 v2 */
interface SettlementRequest {
  payment: PaymentPayload;
  paymentRequirements: PaymentRequirements;
  extensions: {
    'zk-credential': {
      commitment: string;
    };
  };
}

/** Settlement response from facilitator */
interface SettlementResponse {
  payment_receipt: {
    status: 'settled';
    txHash?: string;
    amountUSDC: number;
  };
  extensions: {
    'zk-credential': {
      credential: CredentialWireFormat;
    };
  };
}
import { Noir } from '@noir-lang/noir_js';
import { UltraHonkBackend } from '@aztec/bb.js';
import { CompiledCircuit } from '@noir-lang/types';
import { CredentialStorage, type StoredCredential } from './storage.js';
import x402Circuit from './circuits/x402_zk_credential.json' with { type: 'json' };
import { ProofCache, type CachedProof } from './cache.js';

export type IdentityStrategy =
  | 'max-privacy'      // Always increment index
  | 'max-performance'  // Always reuse index=0
  | 'per-origin'       // One index per origin
  | 'time-bucketed';   // New index every N seconds

export interface ClientConfig {
  /** Presentation strategy */
  strategy: IdentityStrategy;
  /** Time bucket size in seconds (for time-bucketed strategy) */
  timeBucketSeconds: number;
  /** Enable proof caching */
  enableProofCache: boolean;
  /** Storage path (optional) */
  storagePath?: string;
}

const DEFAULT_CONFIG: ClientConfig = {
  strategy: 'time-bucketed',
  timeBucketSeconds: 300, // 5 minutes
  enableProofCache: true,
};

/** Parsed 402 response with zk-credential extension */
export interface Parsed402Response {
  issuerUrl: string;
  issuerPubkey: { x: string; y: string };
  issuerPubkeyB64: string;
  issuerSuite: string;
  serviceId: string;
  paymentAmount: string;
  paymentAsset: string;
  credentialSuites: string[];
}

export class ZkCredentialClient {
  private readonly config: ClientConfig;
  private readonly storage: CredentialStorage;
  private readonly proofCache: ProofCache;
  private readonly originIndices: Map<string, number> = new Map();

  // Cache issuer pubkey from 402 response
  private issuerPubkeyCache: Map<string, { x: string; y: string; b64: string }> = new Map();

  constructor(config: Partial<ClientConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.storage = new CredentialStorage(this.config.storagePath);
    this.proofCache = new ProofCache();
  }

  /**
   * Parse a 402 Payment Required response (spec §6)
   * Parses x402 PaymentRequired format with accepts[] array
   */
  parse402Response(body: X402WithZKCredentialResponse): Parsed402Response {
    // Validate zk-credential extension exists
    if (!body.extensions?.['zk-credential']) {
      throw new Error('Response does not contain zk-credential extension');
    }

    const zkCredential = body.extensions['zk-credential'];
    if (!zkCredential.info) {
      throw new Error('Response does not contain zk-credential.info');
    }
    const info = zkCredential.info;

    // Get first payment option from accepts array
    if (!body.accepts || body.accepts.length === 0) {
      throw new Error('Response does not contain any payment options');
    }
    const payment = body.accepts[0];

    const pubkeyB64 = info.issuer_pubkey;

    // Decode base64url to bytes (0x04 + x + y)
    const pubkeyBytes = fromBase64Url(pubkeyB64);
    if (pubkeyBytes[0] !== 0x04 || pubkeyBytes.length !== 65) {
      throw new Error('Invalid issuer pubkey format: expected 65 bytes starting with 0x04');
    }

    const pubkeyPoint = bytesToPoint(pubkeyBytes);
    const pubkeyX = bigIntToHex(pubkeyPoint.x);
    const pubkeyY = bigIntToHex(pubkeyPoint.y);

    const issuerUrl = payment.payTo;

    return {
      issuerUrl,
      issuerPubkey: { x: pubkeyX, y: pubkeyY },
      issuerPubkeyB64: pubkeyB64,
      issuerSuite: info.issuer_suite,
      serviceId: info.service_id,
      paymentAmount: payment.amount,
      paymentAsset: payment.asset,
      credentialSuites: info.credential_suites,
    };
  }

  /**
   * Discover zk-credential requirements by making a request to a protected endpoint
   * and parsing the 402 response (spec §5.2, step 1-2)
   */
  async discover(url: string): Promise<Parsed402Response> {
    const response = await fetch(url, { method: 'GET' });

    if (response.status !== 402) {
      throw new Error(`Expected 402 response, got ${response.status}`);
    }

    const body = await response.json() as X402WithZKCredentialResponse;
    const parsed = this.parse402Response(body);

    // Cache the issuer pubkey for later use
    this.issuerPubkeyCache.set(parsed.issuerUrl, { ...parsed.issuerPubkey, b64: parsed.issuerPubkeyB64 });

    return parsed;
  }

  getCachedIssuerPubkey(issuerUrl: string): { x: string; y: string; b64: string } | undefined {
    return this.issuerPubkeyCache.get(issuerUrl);
  }

  /**
   * Generate a payment request with ZK credential commitment (spec §8.2)
   * Client generates secrets locally and computes commitment
   */
  async generatePaymentRequest(
    paymentProof: unknown
  ): Promise<{
    request: X402PaymentRequest;
    secrets: {
      nullifierSeed: bigint;
      blindingFactor: bigint;
    };
  }> {
    // Generate secrets locally (never sent to facilitator)
    const nullifierSeed = randomFieldElement();
    const blindingFactor = randomFieldElement();

    // Compute commitment (async - uses Barretenberg)
    const commitment = await pedersenCommit(nullifierSeed, blindingFactor);

    // Format commitment as suite-prefixed string (spec §8.2)
    // Format: "pedersen-schnorr-poseidon-ultrahonk:<base64url(0x04 + x + y)>"
    const commitmentBytes = pointToBytes(commitment.point);
    const commitmentB64 = toBase64Url(commitmentBytes);
    const commitmentPrefixed = addSchemePrefix('pedersen-schnorr-poseidon-ultrahonk', commitmentB64);

    return {
      request: {
        x402Version: 2,
        payment: paymentProof,
        extensions: {
          'zk-credential': {
            commitment: commitmentPrefixed,
          },
        },
      },
      secrets: {
        nullifierSeed,
        blindingFactor,
      },
    };
  }

  /**
   * Handle payment response and extract credential (spec §8.4)
   */
  async handlePaymentResponse(
    response: X402PaymentResponse,
    secrets: { nullifierSeed: bigint; blindingFactor: bigint },
    issuerUrl: string
  ): Promise<StoredCredential> {
    if (!response.extensions?.['zk-credential']?.credential) {
      throw new Error('Payment response missing zk-credential credential');
    }

    const { credential } = response.extensions['zk-credential'];

    // Verify the returned commitment matches what we sent
    // Recompute commitment from secrets to verify
    const expectedCommitment = await pedersenCommit(secrets.nullifierSeed, secrets.blindingFactor);
    const expectedCommitmentBytes = pointToBytes(expectedCommitment.point);
    const expectedCommitmentB64 = toBase64Url(expectedCommitmentBytes);

    const { value: returnedCommitmentB64 } = parseSchemePrefix(credential.commitment);

    if (returnedCommitmentB64 !== expectedCommitmentB64) {
      throw new Error(
        'Commitment mismatch: facilitator returned credential with different commitment. ' +
        'This could indicate a malicious facilitator.'
      );
    }

    // Parse credential wire format into stored format
    const stored = this.parseCredentialWireFormat(
      credential,
      secrets.nullifierSeed,
      secrets.blindingFactor,
      issuerUrl
    );

    this.storage.set(stored);
    console.log(`[Client] Credential obtained: tier=${credential.tier}, identity_limit=${credential.identity_limit}`);

    return stored;
  }

  /**
   * Parse credential wire format from facilitator into stored format
   */
  private parseCredentialWireFormat(
    wire: CredentialWireFormat,
    nullifierSeed: bigint,
    blindingFactor: bigint,
    issuerUrl: string
  ): StoredCredential {
    // Parse commitment point from suite-prefixed base64url
    const { value: commitmentB64 } = parseSchemePrefix(wire.commitment);
    const commitmentBytes = fromBase64Url(commitmentB64);
    const commitmentPoint = bytesToPoint(commitmentBytes);

    const commitmentX = commitmentPoint.x;
    const commitmentY = commitmentPoint.y;

    // Parse suite-typed signature: <suite>:<base64url>
    const { value: sigB64 } = parseSchemePrefix(wire.signature);
    const sigBytes = fromBase64Url(sigB64);
    if (sigBytes.length !== 96) {
      throw new Error(`Invalid signature length: expected 96 bytes, got ${sigBytes.length}`);
    }
    const sigRX = bigIntToHex(bytesToField(sigBytes.slice(0, 32)));
    const sigRY = bigIntToHex(bytesToField(sigBytes.slice(32, 64)));
    const sigS = bigIntToHex(bytesToField(sigBytes.slice(64, 96)));

    return {
      serviceId: wire.service_id,
      tier: wire.tier,
      identityLimit: wire.identity_limit,
      expiresAt: wire.expires_at,
      userCommitment: {
        x: bigIntToHex(commitmentX),
        y: bigIntToHex(commitmentY),
      },
      signature: {
        r: { x: sigRX, y: sigRY },
        s: sigS,
      },
      issuerPubkey: { x: '0x0', y: '0x0' }, // Populated from discovery
      nullifierSeed: bigIntToHex(nullifierSeed),
      blindingFactor: bigIntToHex(blindingFactor),
      identityCount: 0,
      obtainedAt: Date.now(),
      issuerUrl,
    };
  }

  /**
   * Settle payment and obtain credential using x402 v2 signed payload
    * Uses standard settlement body extensions for commitment and credential.
   * 
    * @param issuerUrl - URL of the issuer/facilitator /settle endpoint
   * @param paymentPayload - x402 v2 PaymentPayload with signed EIP-3009 authorization
   * @param paymentRequirements - Payment requirements from the 402 response
   */
  async settleAndObtainCredential(
    issuerUrl: string,
    paymentPayload: PaymentPayload,
    paymentRequirements: PaymentRequirements
  ): Promise<StoredCredential> {
    // Generate secrets locally (never sent to facilitator)
    const nullifierSeed = randomFieldElement();
    const blindingFactor = randomFieldElement();

    // Compute commitment
    const commitment = await pedersenCommit(nullifierSeed, blindingFactor);

    const commitmentBytes = pointToBytes(commitment.point);
    const commitmentB64 = toBase64Url(commitmentBytes);
    const commitmentPrefixed = addSchemePrefix('pedersen-schnorr-poseidon-ultrahonk', commitmentB64);

    // Build settlement request body with standard extension commitment
    const request = {
      payment: paymentPayload,
      paymentRequirements,
      extensions: {
        'zk-credential': {
          commitment: commitmentPrefixed,
        },
      },
    };

    const response = await fetch(issuerUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(request),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: 'Unknown error' })) as { error?: string };
      throw new Error(`Settlement failed: ${error.error || response.statusText}`);
    }

    const settlement = await response.json() as SettlementResponse;
    const credential = settlement.extensions?.['zk-credential']?.credential;
    if (!credential) {
      throw new Error('Settlement response missing extensions.zk-credential.credential');
    }

    // Verify the returned commitment matches what we sent
    // This prevents a malicious facilitator from issuing credentials with wrong commitments
    const { value: returnedCommitmentB64 } = parseSchemePrefix(credential.commitment);
    const expectedCommitmentBytes = pointToBytes(commitment.point);
    const expectedCommitmentB64 = toBase64Url(expectedCommitmentBytes);

    if (returnedCommitmentB64 !== expectedCommitmentB64) {
      throw new Error(
        'Commitment mismatch: facilitator returned credential with different commitment. ' +
        'This could indicate a malicious facilitator.'
      );
    }

    // Parse and store credential
    const stored = this.parseCredentialWireFormat(
      credential,
      nullifierSeed,
      blindingFactor,
      issuerUrl
    );

    this.storage.set(stored);
    console.log(`[Client] Credential obtained: tier=${credential.tier}, identity_limit=${credential.identity_limit}`);

    return stored;
  }

  /**
   * Make an authenticated request using x402_zk_credential body envelope.
   */
  async makeAuthenticatedRequest(
    url: string,
    options: RequestInit & {
      forceUnlinkable?: boolean;
      issuerPubkey?: { x: string; y: string };  // Required for proof generation
      issuerPubkeyB64?: string;
    } = {}
  ): Promise<Response> {
    const urlObj = new URL(url);
    const scheme = urlObj.protocol.replace(':', '').toLowerCase();
    const hostname = urlObj.hostname.toLowerCase();
    const port = urlObj.port;
    const defaultPort = scheme === 'https' ? '443' : scheme === 'http' ? '80' : '';
    const host = port && port !== defaultPort ? `${hostname}:${port}` : hostname;
    const pathname = urlObj.pathname || '/';
    const canonicalOrigin = `${scheme}://${host}${pathname}`;
    const originId = stringToField(canonicalOrigin);

    // Find credential for this service
    // For demo, use the first available credential
    const credentials = this.storage.list();
    if (credentials.length === 0) {
      throw new Error('No credentials available. Obtain one first.');
    }

    const credential = credentials[0];

    // Check expiration
    const now = Math.floor(Date.now() / 1000);
    if (credential.expiresAt < now) {
      throw new Error('Credential expired. Obtain a new one.');
    }

    let issuerPubkey = options.issuerPubkey;
    let issuerPubkeyB64 = options.issuerPubkeyB64;

    if (!issuerPubkey || !issuerPubkeyB64) {
      const cached = this.issuerPubkeyCache.get(credential.issuerUrl);
      if (cached) {
        issuerPubkey = { x: cached.x, y: cached.y };
        issuerPubkeyB64 = cached.b64;
      }
    }

    if (!issuerPubkey && credential.issuerPubkey && credential.issuerPubkey.x !== '0x0') {
      issuerPubkey = credential.issuerPubkey;
      issuerPubkeyB64 = toBase64Url(pointToBytes({ x: hexToBigInt(issuerPubkey.x), y: hexToBigInt(issuerPubkey.y) }));
    }

    if (!issuerPubkey || !issuerPubkeyB64) {
      throw new Error('Issuer public key not available. Call discover() first or provide options.issuerPubkey and options.issuerPubkeyB64');
    }

    credential.issuerPubkey = issuerPubkey;
    // Select presentation index based on strategy
    const { index, timeBucket } = this.selectIdentityIndex(
      credential,
      originId,
      options.forceUnlinkable
    );

    // Check if we have a cached proof
    const cachedProof = this.config.enableProofCache
      ? this.proofCache.get(
        credential.serviceId,
        originId.toString(),
        index,
        timeBucket
      )
      : undefined;

    let proof: CachedProof;

    if (cachedProof) {
      console.log('[Client] Cache hit, reusing proof');
      proof = cachedProof;
    } else {
      console.log('[Client] Generating new proof...');
      proof = await this.generateProof(credential, originId, index, timeBucket);

      // Cache the proof
      if (this.config.enableProofCache) {
        this.proofCache.set(
          credential.serviceId,
          originId.toString(),
          index,
          proof,
          timeBucket
        );
      }
    }

    const headers = new Headers(options.headers);
    headers.set('Content-Type', 'application/json');
    // Extract original application payload from options.body
    let appPayload: unknown = null;
    if (options.body) {
      if (typeof options.body === 'string') {
        try {
          appPayload = JSON.parse(options.body);
        } catch {
          throw new Error('makeAuthenticatedRequest only supports JSON string bodies');
        }
      } else if (typeof options.body === 'object') {
        appPayload = options.body;
      }
    }

    // Build body envelope: { x402_zk_credential, payload }
    const body = JSON.stringify({
      x402_zk_credential: {
        version: '0.1.0',
        suite: 'pedersen-schnorr-poseidon-ultrahonk',
        issuer_pubkey: issuerPubkeyB64,
        proof: proof.proof,
        current_time: proof.currentTime,
        public_outputs: {
          origin_token: proof.originToken,
          tier: proof.tier,
        },
      },
      payload: appPayload,
    });

    return fetch(url, { ...options, method: options.method ?? 'POST', headers, body });
  }

  /**
   * Generate a ZK proof
   */
  private async generateProof(
    credential: StoredCredential,
    originId: bigint,
    identityIndex: number,
    timeBucket?: number
  ): Promise<CachedProof> {
    const circuit = x402Circuit as any;
    // Use UltraHonk backend matching the verifier
    const backend = new UltraHonkBackend(circuit.bytecode);
    const noir = new Noir(circuit);

    const currentTime = BigInt(Math.floor(Date.now() / 1000));
    // Helper to format as hex string for Noir (0x prefix)
    const fmt = (n: bigint | number | string) => bigIntToHex(BigInt(n));

    // Prepare inputs matching circuit ABI
    const input = {
      // Public inputs
      // Note: Noir expects these to be part of the witness generation
      // Convert service_id from base64url to BigInt
      service_id: fmt(bytesToField(fromBase64Url(credential.serviceId))),
      current_time: fmt(currentTime),
      origin_id: fmt(originId),
      facilitator_pubkey_x: fmt(credential.issuerPubkey.x),
      facilitator_pubkey_y: fmt(credential.issuerPubkey.y),

      // Private inputs
      cred_service_id: fmt(bytesToField(fromBase64Url(credential.serviceId))),
      cred_tier: fmt(credential.tier),
      cred_identity_limit: fmt(credential.identityLimit),
      cred_expires_at: fmt(credential.expiresAt),
      cred_commitment_x: fmt(credential.userCommitment.x),
      cred_commitment_y: fmt(credential.userCommitment.y),

      sig_r_x: fmt(credential.signature.r.x),
      sig_r_y: fmt(credential.signature.r.y),
      sig_s_lo: fmt(hexToBigInt(credential.signature.s) & ((1n << 128n) - 1n)),
      sig_s_hi: fmt(hexToBigInt(credential.signature.s) >> 128n),

      nullifier_seed: fmt(credential.nullifierSeed),
      blinding_factor: fmt(credential.blindingFactor),

      identity_index: fmt(identityIndex),
    };

    try {
      console.log('[Client] Generating witness with Noir...');
      const { witness } = await noir.execute(input);

      console.log('[Client] Generating proof with Barretenberg...');
      const proofData = await backend.generateProof(witness);
      console.log('[Client] Proof generation successful');

      const { proof, publicInputs } = proofData;
      console.log(`[Client] Proof size: ${proof.length} bytes, ${publicInputs.length} public inputs`);

      // Extract outputs from public inputs
      // Layout: [service_id, current_time, origin_id, facilitator_pubkey_x, facilitator_pubkey_y, origin_token, tier]
      const originToken = publicInputs[5];
      const tier = publicInputs[6];

      const proofBytes = typeof proof === 'string' ? fromBase64Url(proof) : proof;
      const proofB64 = toBase64Url(proofBytes);

      return {
        proof: proofB64,
        originToken: originToken,
        tier: Number(hexToBigInt(tier)),
        currentTime: Number(currentTime),
        cachedUntil: Math.min(credential.expiresAt, Number(currentTime) + 60),
        meta: {
          serviceId: credential.serviceId,
          originId: originId.toString(),
          identityIndex,
          timeBucket,
        },
      };
    } finally {
      // Cleanup to prevent memory leaks/hanging processes
      await backend.destroy();
    }
  }

  /**
   * Select presentation index based on strategy
   */
  private selectIdentityIndex(
    credential: StoredCredential,
    originId: bigint,
    forceUnlinkable?: boolean
  ): { index: number; timeBucket?: number } {
    // Force unlinkable overrides strategy
    if (forceUnlinkable) {
      const index = this.storage.incrementIdentityCount(credential.serviceId) - 1;
      return { index };
    }

    switch (this.config.strategy) {
      case 'max-privacy': {
        const index = this.storage.incrementIdentityCount(credential.serviceId) - 1;
        return { index };
      }

      case 'max-performance':
        return { index: 0 };

      case 'per-origin': {
        const originKey = originId.toString();
        if (!this.originIndices.has(originKey)) {
          const index = this.storage.incrementIdentityCount(credential.serviceId) - 1;
          this.originIndices.set(originKey, index);
        }
        return { index: this.originIndices.get(originKey)! };
      }

      case 'time-bucketed': {
        const now = Math.floor(Date.now() / 1000);
        const bucket = Math.floor(now / this.config.timeBucketSeconds);
        const timeBucket = bucket * this.config.timeBucketSeconds;

        // Use hash(timeBucket, serviceId, obtainedAt) for deterministic but unpredictable index
        const hash = poseidonHash3(
          BigInt(timeBucket),
          bytesToField(fromBase64Url(credential.serviceId)),
          BigInt(credential.obtainedAt)
        );

        const index = Number(hash % BigInt(credential.identityLimit));
        return { index, timeBucket };
      }

      default:
        return { index: 0 };
    }
  }

  /**
   * List stored credentials
   */
  listCredentials(): StoredCredential[] {
    return this.storage.list();
  }

  /**
   * Get credential status
   */
  getCredentialStatus(serviceId?: string): {
    credential: StoredCredential;
    status: 'valid' | 'expired' | 'exhausted';
    remainingIdentities: number;
    expiresIn: number;
  } | undefined {
    const credentials = this.storage.list();
    const credential = serviceId
      ? credentials.find(c => c.serviceId === serviceId)
      : credentials[0];

    if (!credential) {
      return undefined;
    }

    const now = Math.floor(Date.now() / 1000);
    const expiresIn = credential.expiresAt - now;
    const remaining = credential.identityLimit - credential.identityCount;

    let status: 'valid' | 'expired' | 'exhausted';
    if (expiresIn <= 0) {
      status = 'expired';
    } else if (remaining <= 0) {
      status = 'exhausted';
    } else {
      status = 'valid';
    }

    return {
      credential,
      status,
      remainingIdentities: Math.max(0, remaining),
      expiresIn: Math.max(0, expiresIn),
    };
  }

  /**
   * Clear all stored credentials
   */
  clearCredentials(): void {
    this.storage.clear();
    this.proofCache.clear();
    this.originIndices.clear();
  }
}
