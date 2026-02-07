
import { UltraHonkBackend } from '@aztec/bb.js';
import { Noir } from '@noir-lang/noir_js';
import x402Circuit from '../src/circuits/x402_zk_credential.json' with { type: 'json' };
import {
    pedersenCommit,
    generateKeypair,
    schnorrSign,
    poseidonHash7,
    hexToBigInt,
    bigIntToHex
} from '@demo/crypto';

async function main() {
    console.log('Initializing backend...');
    const circuit = x402Circuit as any;
    // Use UltraHonk backend matching the verifier
    const backend = new UltraHonkBackend(circuit.bytecode);
    const noir = new Noir(circuit);

    console.log('Generating valid inputs...');

    // 1. Setup
    const nullifierSeed = 12345n;
    const blindingFactor = 67890n;
    const serviceId = 1n;
    const currentTime = BigInt(Math.floor(Date.now() / 1000));
    const originId = 12345n;
    const credTier = 1n;
    const credIdentityLimit = 1000n;
    const credIssuedAt = currentTime - 1000n;
    const credExpiresAt = currentTime + 86400n;
    const identityIndex = 0n;

    // 2. Crypto
    const { secretKey, publicKey } = await generateKeypair();
    const commitment = await pedersenCommit(nullifierSeed, blindingFactor);

    const message = poseidonHash7(
        serviceId,
        credTier,
        credIdentityLimit,
        credIssuedAt,
        credExpiresAt,
        commitment.point.x,
        commitment.point.y
    );

    const signature = await schnorrSign(secretKey, message);

    const s = signature.s;
    const s_lo = s & ((1n << 128n) - 1n);
    const s_hi = s >> 128n;

    const fmt = (n: bigint | number) => bigIntToHex(BigInt(n));

    const input = {
        service_id: fmt(serviceId),
        current_time: fmt(currentTime),
        origin_id: fmt(originId),
        facilitator_pubkey_x: fmt(publicKey.x),
        facilitator_pubkey_y: fmt(publicKey.y),

        cred_service_id: fmt(serviceId),
        cred_tier: fmt(credTier),
        cred_identity_limit: fmt(credIdentityLimit),
        cred_issued_at: fmt(credIssuedAt),
        cred_expires_at: fmt(credExpiresAt),
        cred_commitment_x: fmt(commitment.point.x),
        cred_commitment_y: fmt(commitment.point.y),

        sig_r_x: fmt(signature.r.x),
        sig_r_y: fmt(signature.r.y),
        sig_s_lo: fmt(s_lo),
        sig_s_hi: fmt(s_hi),

        nullifier_seed: fmt(nullifierSeed),
        blinding_factor: fmt(blindingFactor),

        identity_index: fmt(identityIndex),
    };

    console.log('Generating witness...');
    const { witness } = await noir.execute(input);
    console.log('Witness generated. Size:', witness.length);

    console.log('Generating proof...');
    const proofFn = async () => {
        try {
            const proof = await backend.generateProof(witness);
            console.log('Proof generated successfully!');
            console.log('Proof length:', proof.proof.length);
        } catch (e) {
            console.error('Proof generation failed:', e);
            throw e;
        }
    };

    await proofFn();
}

main().catch(err => {
    console.error('Fatal error:', err);
    process.exit(1);
});
