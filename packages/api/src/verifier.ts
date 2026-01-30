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

export interface VerificationResult {
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
      this.initPromise = null;
      throw error;
    }
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
  async verify(proofData: ProofData): Promise<VerificationResult> {
    // Skip verification in dev mode
    if (this.config.skipVerification) {
      console.log('[ZkVerifier] Skipping verification (dev mode)');
      return {
        valid: true,
        outputs: {
          originToken: proofData.publicInputs[proofData.publicInputs.length - 2] ?? '0x0',
          tier: parseInt(proofData.publicInputs[proofData.publicInputs.length - 1] ?? '0', 16),
        },
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
      
      // Extract public outputs (last 2 elements)
      // The circuit returns (origin_token, tier)
      const numPublicInputs = 5; // service_id, current_time, origin_id, issuer_pk_x, issuer_pk_y
      const originToken = proofData.publicInputs[numPublicInputs];
      const tierHex = proofData.publicInputs[numPublicInputs + 1];
      
      return {
        valid: true,
        outputs: {
          originToken: originToken ?? '0x0',
          tier: tierHex ? parseInt(tierHex, 16) : 0,
        },
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
  
  /**
   * Destroy the backend and free resources
   */
  async destroy(): Promise<void> {
    if (this.backend) {
      await this.backend.destroy();
      this.backend = null;
    }
    this.initialized = false;
    this.initPromise = null;
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
    
    if (!parsed.proof || !Array.isArray(parsed.publicInputs)) {
      return null;
    }
    
    return {
      proof: typeof parsed.proof === 'string' 
        ? Buffer.from(parsed.proof, 'base64')
        : new Uint8Array(parsed.proof),
      publicInputs: parsed.publicInputs,
    };
  } catch {
    return null;
  }
}
