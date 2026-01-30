/**
 * ZK Proof Verifier
 * 
 * Verifies Noir ZK proofs using Barretenberg.
 */

import { UltraHonkBackend } from '@aztec/bb.js';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

// Resolve paths relative to this file
const __dirname = dirname(fileURLToPath(import.meta.url));

export interface VerifierConfig {
  /** Path to compiled circuit JSON (default: auto-detect from circuits/target/) */
  circuitPath?: string;
  /** Skip proof verification (for development) */
  skipVerification?: boolean;
}

export interface ProofData {
  /** The proof bytes (base64 encoded when transmitted) */
  proof: Uint8Array;
  /** Public inputs for verification */
  publicInputs: string[];
}

export interface ProofVerificationResult {
  valid: boolean;
  /** Extracted public outputs: [origin_token, tier] */
  outputs?: {
    originToken: string;
    tier: number;
  };
  error?: string;
}

/**
 * ZK Proof Verifier using UltraHonk
 */
export class ZkVerifier {
  private backend: UltraHonkBackend | null = null;
  private circuitBytecode: string | null = null;
  private initialized = false;
  private initPromise: Promise<void> | null = null;
  
  constructor(private config: VerifierConfig = {}) {}
  
  /**
   * Initialize the verifier with the circuit
   */
  async initialize(): Promise<void> {
    // Return existing init promise if already initializing
    if (this.initPromise) {
      return this.initPromise;
    }
    
    if (this.initialized) {
      return;
    }
    
    this.initPromise = this._doInitialize();
    return this.initPromise;
  }
  
  private async _doInitialize(): Promise<void> {
    try {
      // Find circuit path
      const circuitPath = this.config.circuitPath ?? this.findCircuitPath();
      
      if (!circuitPath || !existsSync(circuitPath)) {
        throw new Error(`Circuit not found at ${circuitPath}. Run 'nargo compile' first.`);
      }
      
      console.log(`[ZkVerifier] Loading circuit from ${circuitPath}`);
      
      // Load the compiled circuit JSON
      const circuitJson = JSON.parse(readFileSync(circuitPath, 'utf-8'));
      this.circuitBytecode = circuitJson.bytecode;
      
      if (!this.circuitBytecode) {
        throw new Error('Circuit JSON does not contain bytecode');
      }
      
      // Create the UltraHonk backend
      console.log('[ZkVerifier] Initializing UltraHonk backend...');
      this.backend = new UltraHonkBackend(this.circuitBytecode);
      
      this.initialized = true;
      console.log('[ZkVerifier] Initialized successfully');
    } catch (error) {
      // Clean up any partially initialized resources
      await this.destroy();
      this.initPromise = null;
      throw error;
    }
  }
  
  /**
   * Clean up resources (destroy backend if created)
   */
  async destroy(): Promise<void> {
    if (this.backend) {
      try {
        await this.backend.destroy();
      } catch {
        // Ignore errors during cleanup
      }
      this.backend = null;
    }
    this.circuitBytecode = null;
    this.initialized = false;
    this.initPromise = null;
  }
  
  /**
   * Find the circuit path by searching common locations
   */
  private findCircuitPath(): string | null {
    const searchPaths = [
      // Relative to this file (api/src/)
      join(__dirname, '../../../circuits/target/x402_zk_session.json'),
      // Relative to project root
      join(process.cwd(), 'circuits/target/x402_zk_session.json'),
    ];
    
    for (const path of searchPaths) {
      if (existsSync(path)) {
        return path;
      }
    }
    
    return searchPaths[0]; // Return first path for error message
  }
  
  /**
   * Verify a ZK proof
   * 
   * @param proofData - The proof and public inputs
   * @returns Verification result with extracted outputs
   */
  async verify(proofData: ProofData): Promise<ProofVerificationResult> {
    // Validate publicInputs has enough elements for outputs
    // Circuit layout: 5 public inputs + 2 public outputs (origin_token, tier)
    const NUM_PUBLIC_INPUTS = 5;
    const NUM_PUBLIC_OUTPUTS = 2;
    const REQUIRED_LENGTH = NUM_PUBLIC_INPUTS + NUM_PUBLIC_OUTPUTS;
    
    if (proofData.publicInputs.length < REQUIRED_LENGTH) {
      return { 
        valid: false, 
        error: `Invalid publicInputs length: expected >= ${REQUIRED_LENGTH}, got ${proofData.publicInputs.length}` 
      };
    }
    
    // Extract outputs (after the public inputs)
    const originToken = proofData.publicInputs[NUM_PUBLIC_INPUTS];
    const tierHex = proofData.publicInputs[NUM_PUBLIC_INPUTS + 1];
    
    // Validate extracted values exist (TypeScript narrowing)
    if (originToken === undefined || tierHex === undefined) {
      return { valid: false, error: 'Missing origin_token or tier in publicInputs' };
    }
    
    const tier = parseInt(tierHex, 16);
    if (isNaN(tier)) {
      return { valid: false, error: 'Invalid tier value in publicInputs' };
    }
    
    // Skip verification in dev mode
    if (this.config.skipVerification) {
      console.log('[ZkVerifier] Skipping verification (dev mode)');
      return {
        valid: true,
        outputs: { originToken, tier },
      };
    }
    
    // Ensure initialized
    await this.initialize();
    
    if (!this.backend) {
      return { valid: false, error: 'Verifier not initialized' };
    }
    
    try {
      // Verify the proof
      // Public inputs order: service_id, current_time, origin_id, issuer_pubkey_x, issuer_pubkey_y
      // Public outputs: origin_token, tier
      const isValid = await this.backend.verifyProof({
        proof: proofData.proof,
        publicInputs: proofData.publicInputs,
      });
      
      if (!isValid) {
        return { valid: false, error: 'Proof verification failed' };
      }
      
      // Outputs already extracted and validated above
      return {
        valid: true,
        outputs: { originToken, tier },
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error('[ZkVerifier] Verification error:', message);
      return { valid: false, error: message };
    }
  }
  
  /**
   * Check if the verifier is initialized
   */
  isInitialized(): boolean {
    return this.initialized;
  }
}

/**
 * Parse a base64-encoded proof into ProofData
 * 
 * Expected format: JSON with { proof: base64, publicInputs: string[] }
 */
export function parseProofFromRequest(proofB64: string): ProofData | null {
  try {
    const decoded = Buffer.from(proofB64, 'base64').toString('utf-8');
    const parsed = JSON.parse(decoded);
    
    // Validate proof field exists and is non-empty
    if (!parsed.proof) {
      return null;
    }
    
    // Validate publicInputs is an array
    if (!Array.isArray(parsed.publicInputs)) {
      return null;
    }
    
    // Parse proof bytes
    let proofBytes: Uint8Array;
    if (typeof parsed.proof === 'string') {
      // Validate non-empty string
      if (parsed.proof.length === 0) {
        return null;
      }
      proofBytes = Buffer.from(parsed.proof, 'base64');
      // Validate decoded bytes are non-empty (catches invalid base64)
      if (proofBytes.length === 0) {
        return null;
      }
    } else if (Array.isArray(parsed.proof)) {
      // Validate non-empty array before conversion
      if (parsed.proof.length === 0) {
        return null;
      }
      proofBytes = new Uint8Array(parsed.proof);
    } else {
      return null;
    }
    
    return {
      proof: proofBytes,
      publicInputs: parsed.publicInputs,
    };
  } catch {
    return null;
  }
}
