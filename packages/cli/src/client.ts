/**
 * ZK Session Client
 * 
 * Manages credentials and generates authenticated requests.
 * Compliant with x402 zk-session spec v0.1.0
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
  type X402WithZKSessionResponse,
  type X402PaymentRequest,
  type X402PaymentResponse,
  type CredentialWireFormat,
  type PaymentPayload,
  type PaymentRequirements,
} from '@demo/crypto';

/** Settlement request for x402 v2 */
interface SettlementRequest {
  payment: PaymentPayload;
  paymentRequirements: PaymentRequirements;
  zk_session: {
    commitment: string;
  };
}

/** Settlement response from facilitator */
interface SettlementResponse {
  payment_receipt: {
    status: 'settled';
    txHash?: string;
    amountUSDC: number;
  };
  zk_session: {
    credential: CredentialWireFormat;
  };
}
import { Noir } from '@noir-lang/noir_js';
import { UltraHonkBackend } from '@aztec/bb.js';
import { CompiledCircuit } from '@noir-lang/types';
import { CredentialStorage, type StoredCredential } from './storage.js';
import x402Circuit from './circuits/x402_zk_session.json' with { type: 'json' };
import { ProofCache, type CachedProof } from './cache.js';

export type PresentationStrategy =
  | 'max-privacy'      // Always increment index
  | 'max-performance'  // Always reuse index=0
  | 'per-origin'       // One index per origin
  | 'time-bucketed';   // New index every N seconds

export interface ClientConfig {
  /** Presentation strategy */
  strategy: PresentationStrategy;
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

/** Parsed 402 response with zk_session extension */
export interface Parsed402Response {
  facilitatorUrl: string;
  facilitatorPubkey: { x: string; y: string };
  paymentAmount: string;
  paymentAsset: string;
  schemes: string[];
}

export class ZkSessionClient {
  private readonly config: ClientConfig;
  private readonly storage: CredentialStorage;
  private readonly proofCache: ProofCache;
  private readonly originIndices: Map<string, number> = new Map();

  // Cache facilitator pubkey from 402 response
  private facilitatorPubkeyCache: Map<string, { x: string; y: string }> = new Map();

  constructor(config: Partial<ClientConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.storage = new CredentialStorage(this.config.storagePath);
    this.proofCache = new ProofCache();
  }

  /**
   * Parse a 402 Payment Required response (spec §6)
   * Parses x402 PaymentRequired format with accepts[] array
   */
  parse402Response(body: X402WithZKSessionResponse): Parsed402Response {
    // Validate zk_session extension exists
    if (!body.extensions?.zk_session) {
      throw new Error('Response does not contain zk_session extension');
    }

    const zkSession = body.extensions.zk_session;

    // Get first payment option from accepts array
    if (!body.accepts || body.accepts.length === 0) {
      throw new Error('Response does not contain any payment options');
    }
    const payment = body.accepts[0];

    // Parse scheme-prefixed facilitator pubkey
    const { scheme, value: pubkeyHex } = parseSchemePrefix(zkSession.facilitator_pubkey);
    if (scheme !== 'pedersen-schnorr-bn254') {
      throw new Error(`Unsupported scheme: ${scheme}`);
    }

    // Parse pubkey from uncompressed point format (0x04 + x + y)
    const pubkeyBytes = pubkeyHex.startsWith('0x') ? pubkeyHex.slice(2) : pubkeyHex;
    if (!pubkeyBytes.startsWith('04') || pubkeyBytes.length !== 130) {
      throw new Error('Invalid facilitator pubkey format');
    }

    const pubkeyX = '0x' + pubkeyBytes.slice(2, 66);
    const pubkeyY = '0x' + pubkeyBytes.slice(66, 130);

    // Get facilitator URL from extension (spec §6) or fall back to payTo
    const facilitatorUrl = zkSession.facilitator_url || payment.payTo;

    return {
      facilitatorUrl,
      facilitatorPubkey: { x: pubkeyX, y: pubkeyY },
      paymentAmount: payment.amount,
      paymentAsset: payment.asset,
      schemes: zkSession.schemes,
    };
  }

  /**
   * Discover zk_session requirements by making a request to a protected endpoint
   * and parsing the 402 response (spec §5.2, step 1-2)
   */
  async discover(url: string): Promise<Parsed402Response> {
    const response = await fetch(url, { method: 'GET' });

    if (response.status !== 402) {
      throw new Error(`Expected 402 response, got ${response.status}`);
    }

    const body = await response.json() as X402WithZKSessionResponse;
    const parsed = this.parse402Response(body);

    // Cache the facilitator pubkey for later use
    this.facilitatorPubkeyCache.set(parsed.facilitatorUrl, parsed.facilitatorPubkey);

    return parsed;
  }

  /**
   * Get cached facilitator pubkey
   */
  getCachedFacilitatorPubkey(facilitatorUrl: string): { x: string; y: string } | undefined {
    return this.facilitatorPubkeyCache.get(facilitatorUrl);
  }

  /**
   * Generate a payment request with ZK session commitment (spec §7.2)
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

    // Format commitment as scheme-prefixed string (spec §7.2)
    // Format: "pedersen-schnorr-bn254:0x04" + x (64 hex) + y (64 hex)
    const commitmentHex = '0x04' +
      commitment.point.x.toString(16).padStart(64, '0') +
      commitment.point.y.toString(16).padStart(64, '0');
    const commitmentPrefixed = addSchemePrefix('pedersen-schnorr-bn254', commitmentHex);

    return {
      request: {
        x402Version: 2,
        payment: paymentProof,
        extensions: {
          zk_session: {
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
   * Handle payment response and extract credential (spec §7.3)
   */
  async handlePaymentResponse(
    response: X402PaymentResponse,
    secrets: { nullifierSeed: bigint; blindingFactor: bigint },
    facilitatorUrl: string
  ): Promise<StoredCredential> {
    if (!response.extensions?.zk_session?.credential) {
      throw new Error('Payment response missing zk_session credential');
    }

    const { credential } = response.extensions.zk_session;

    // Verify the returned commitment matches what we sent
    // Recompute commitment from secrets to verify
    const expectedCommitment = await pedersenCommit(secrets.nullifierSeed, secrets.blindingFactor);
    const expectedCommitmentHex = '0x04' +
      expectedCommitment.point.x.toString(16).padStart(64, '0') +
      expectedCommitment.point.y.toString(16).padStart(64, '0');
    
    const expectedCommitmentNormalized = expectedCommitmentHex.toLowerCase();
    const returnedCommitment = credential.commitment.toLowerCase();
    if (returnedCommitment !== expectedCommitmentNormalized) {
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
      facilitatorUrl
    );

    this.storage.set(stored);
    console.log(`[Client] Credential obtained: tier=${credential.tier}, max_presentations=${credential.max_presentations}`);

    return stored;
  }

  /**
   * Parse credential wire format from facilitator into stored format
   */
  private parseCredentialWireFormat(
    wire: CredentialWireFormat,
    nullifierSeed: bigint,
    blindingFactor: bigint,
    facilitatorUrl: string
  ): StoredCredential {
    // Parse commitment point from hex (0x04 + 64 hex x + 64 hex y)
    const commitmentHex = wire.commitment.startsWith('0x') ? wire.commitment.slice(2) : wire.commitment;
    if (!commitmentHex.startsWith('04') || commitmentHex.length !== 130) {
      throw new Error('Invalid commitment format in credential');
    }
    const commitmentX = hexToBigInt('0x' + commitmentHex.slice(2, 66));
    const commitmentY = hexToBigInt('0x' + commitmentHex.slice(66, 130));

    // Parse signature (r.x + r.y + s, each 64 hex = 192 total)
    const sigHex = wire.signature.startsWith('0x') ? wire.signature.slice(2) : wire.signature;
    if (sigHex.length !== 192) {
      throw new Error('Invalid signature format in credential');
    }
    const sigRX = '0x' + sigHex.slice(0, 64);
    const sigRY = '0x' + sigHex.slice(64, 128);
    const sigS = '0x' + sigHex.slice(128, 192);

    return {
      serviceId: wire.service_id,
      tier: wire.tier,
      maxPresentations: wire.max_presentations,
      issuedAt: wire.issued_at,
      expiresAt: wire.expires_at,
      userCommitment: {
        x: bigIntToHex(commitmentX),
        y: bigIntToHex(commitmentY),
      },
      signature: {
        r: { x: sigRX, y: sigRY },
        s: sigS,
      },
      // Facilitator pubkey is obtained from 402 response, not stored here
      // The client must get it from the 402 response each time
      issuerPubkey: { x: '0x0', y: '0x0' }, // Placeholder - updated when making requests
      nullifierSeed: bigIntToHex(nullifierSeed),
      blindingFactor: bigIntToHex(blindingFactor),
      presentationCount: 0,
      obtainedAt: Date.now(),
      issuerUrl: facilitatorUrl,
    };
  }

  /**
   * Settle payment and obtain credential using x402 v2 signed payload (spec §7.2, §7.3)
   * 
   * This method:
   * 1. Generates secrets and commitment locally
   * 2. Creates EIP-3009 signed payment authorization
   * 3. Sends to facilitator for settlement
   * 4. Stores and returns the credential
   * 
   * @param facilitatorUrl - URL of the facilitator's /settle endpoint
   * @param paymentPayload - x402 v2 PaymentPayload with signed EIP-3009 authorization
   * @param paymentRequirements - Payment requirements from the 402 response
   */
  async settleAndObtainCredential(
    facilitatorUrl: string,
    paymentPayload: PaymentPayload,
    paymentRequirements: PaymentRequirements
  ): Promise<StoredCredential> {
    // Generate secrets locally (never sent to facilitator)
    const nullifierSeed = randomFieldElement();
    const blindingFactor = randomFieldElement();

    // Compute commitment
    const commitment = await pedersenCommit(nullifierSeed, blindingFactor);
    const commitmentHex = '0x04' +
      commitment.point.x.toString(16).padStart(64, '0') +
      commitment.point.y.toString(16).padStart(64, '0');
    const commitmentPrefixed = addSchemePrefix('pedersen-schnorr-bn254', commitmentHex);

    // Build x402 v2 settlement request
    const request: SettlementRequest = {
      payment: paymentPayload,
      paymentRequirements,
      zk_session: {
        commitment: commitmentPrefixed,
      },
    };

    // Send to facilitator
    const response = await fetch(facilitatorUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: 'Unknown error' })) as { error?: string };
      throw new Error(`Settlement failed: ${error.error || response.statusText}`);
    }

    const data = await response.json() as SettlementResponse;
    
    // Extract credential from response
    const credential = data.zk_session?.credential;
    if (!credential) {
      throw new Error('Settlement response missing zk_session.credential');
    }

    // Verify the returned commitment matches what we sent
    // This prevents a malicious facilitator from issuing credentials with wrong commitments
    const returnedCommitment = credential.commitment.toLowerCase();
    const expectedCommitment = commitmentHex.toLowerCase();
    if (returnedCommitment !== expectedCommitment) {
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
      facilitatorUrl
    );

    this.storage.set(stored);
    console.log(`[Client] Credential obtained: tier=${credential.tier}, max_presentations=${credential.max_presentations}`);

    return stored;
  }

  /**
   * Make an authenticated request using Authorization: ZKSession header (spec §8.1)
   * 
   * If the request receives a 402 response, this method will NOT automatically
   * handle payment - the caller must obtain a credential first.
   */
  async makeAuthenticatedRequest(
    url: string,
    options: RequestInit & {
      forceUnlinkable?: boolean;
      issuerPubkey?: { x: string; y: string };  // Required for proof generation
    } = {}
  ): Promise<Response> {
    const urlObj = new URL(url);
    // Normalize origin_id: lowercase, strip trailing slash, strip query params
    let pathname = urlObj.pathname.toLowerCase();
    if (pathname.endsWith('/') && pathname.length > 1) {
      pathname = pathname.slice(0, -1);
    }
    const originId = stringToField(pathname);

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

    // Ensure we have issuer pubkey (either from stored credential or options)
    const storedIssuerPubkey =
      credential.issuerPubkey && credential.issuerPubkey.x !== '0x0'
        ? credential.issuerPubkey
        : undefined;

    const issuerPubkey = options.issuerPubkey ?? storedIssuerPubkey;

    if (!issuerPubkey) {
      throw new Error(
        'Issuer public key not available. Provide it via options.issuerPubkey'
      );
    }

    // Persist the resolved issuer pubkey so future requests don't need options.issuerPubkey
    credential.issuerPubkey = issuerPubkey;
    // Select presentation index based on strategy
    const { index, timeBucket } = this.selectPresentationIndex(
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

    // Format Authorization header (spec §8.1)
    // Format: Authorization: ZKSession <scheme>:<base64-proof>
    const headers = new Headers(options.headers);
    const authValue = `ZKSession pedersen-schnorr-bn254:${proof.proof}`;
    headers.set('Authorization', authValue);

    return fetch(url, { ...options, headers });
  }

  /**
   * Generate a ZK proof
   */
  private async generateProof(
    credential: StoredCredential,
    originId: bigint,
    presentationIndex: number,
    timeBucket?: number
  ): Promise<CachedProof> {
    const circuit = x402Circuit as any;
    // Use UltraHonk backend matching the verifier
    const backend = new UltraHonkBackend(circuit.bytecode);
    const noir = new Noir(circuit);

    const currentTime = BigInt(Math.floor(Date.now() / 1000));
    const expiresAt = timeBucket
      ? timeBucket + this.config.timeBucketSeconds
      : Number(currentTime) + 60;

    // Helper to format as hex string for Noir (0x prefix)
    const fmt = (n: bigint | number | string) => bigIntToHex(BigInt(n));

    // Prepare inputs matching circuit ABI
    const input = {
      // Public inputs
      // Note: Noir expects these to be part of the witness generation
      service_id: fmt(credential.serviceId),
      current_time: fmt(currentTime),
      origin_id: fmt(originId),
      issuer_pubkey_x: fmt(credential.issuerPubkey.x),
      issuer_pubkey_y: fmt(credential.issuerPubkey.y),

      // Private inputs
      cred_service_id: fmt(credential.serviceId),
      cred_tier: fmt(credential.tier),
      cred_max_presentations: fmt(credential.maxPresentations),
      cred_issued_at: fmt(credential.issuedAt),
      cred_expires_at: fmt(credential.expiresAt),
      cred_commitment_x: fmt(credential.userCommitment.x),
      cred_commitment_y: fmt(credential.userCommitment.y),

      sig_r_x: fmt(credential.signature.r.x),
      sig_r_y: fmt(credential.signature.r.y),
      sig_s_lo: fmt(hexToBigInt(credential.signature.s) & ((1n << 128n) - 1n)),
      sig_s_hi: fmt(hexToBigInt(credential.signature.s) >> 128n),

      nullifier_seed: fmt(credential.nullifierSeed),
      blinding_factor: fmt(credential.blindingFactor),

      presentation_index: fmt(presentationIndex),
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
      // Layout: [service_id, current_time, origin_id, issuer_pubkey_x, issuer_pubkey_y, origin_token, tier]
      // We need last 2
      const originToken = publicInputs[5];
      const tier = publicInputs[6];

      // Format proof data for transmission (JSON with base64 proof)
      const transmissionData = {
        proof: Buffer.from(proof).toString('base64'),
        publicInputs
      };

      const proofB64 = Buffer.from(JSON.stringify(transmissionData)).toString('base64');

      return {
        proof: proofB64,
        originToken: originToken,
        tier: Number(hexToBigInt(tier)),
        expiresAt,
        meta: {
          serviceId: credential.serviceId,
          originId: originId.toString(),
          presentationIndex,
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
  private selectPresentationIndex(
    credential: StoredCredential,
    originId: bigint,
    forceUnlinkable?: boolean
  ): { index: number; timeBucket?: number } {
    // Force unlinkable overrides strategy
    if (forceUnlinkable) {
      const index = this.storage.incrementPresentationCount(credential.serviceId) - 1;
      return { index };
    }

    switch (this.config.strategy) {
      case 'max-privacy': {
        const index = this.storage.incrementPresentationCount(credential.serviceId) - 1;
        return { index };
      }

      case 'max-performance':
        return { index: 0 };

      case 'per-origin': {
        const originKey = originId.toString();
        if (!this.originIndices.has(originKey)) {
          const index = this.storage.incrementPresentationCount(credential.serviceId) - 1;
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
          BigInt(credential.serviceId),
          BigInt(credential.obtainedAt)
        );

        const index = Number(hash % BigInt(credential.maxPresentations));
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
    remainingPresentations: number;
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
    const remaining = credential.maxPresentations - credential.presentationCount;

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
      remainingPresentations: Math.max(0, remaining),
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
