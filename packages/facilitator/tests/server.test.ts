import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createFacilitatorServer } from '../src/server.js';
import type { ZKCredentialErrorResponse } from '@demo/crypto';

describe('Facilitator Server', () => {
    const port = 3002; // Use a different port to avoid conflicts
    const serverConfig = {
        port,
        serviceId: 123n,
        secretKey: 123456789n,
        tiers: [
            { minAmountCents: 10, tier: 1, identityLimit: 10, durationSeconds: 3600 }
        ]
    };

    let server: ReturnType<typeof createFacilitatorServer>;

    beforeAll(async () => {
        server = createFacilitatorServer(serverConfig);
        await server.start();
    });

    afterAll(async () => {
        await server.stop();
    });

    it('should expose issuer info endpoint', async () => {
        const response = await fetch(`http://localhost:${port}/info`);
        expect(response.status).toBe(200);

        const data = await response.json() as {
            service_id: string;
            issuer_suite: string;
            issuer_pubkey: string;
            credential_suites: string[];
        };

        expect(data.service_id).toBeTypeOf('string');
        expect(data.issuer_suite).toBe('pedersen-schnorr-poseidon-ultrahonk');
        expect(data.issuer_pubkey).toMatch(/^[A-Za-z0-9_-]+$/);
        expect(data.credential_suites).toContain('pedersen-schnorr-poseidon-ultrahonk');
    });

    it('should return 404 with structured error for unknown endpoints', async () => {
        const response = await fetch(`http://localhost:${port}/unknown`);
        expect(response.status).toBe(404);
        const error = await response.json() as ZKCredentialErrorResponse;
        expect(error.error).toBe('not_found');
        expect(error.message).toBe('Not Found');
    });

    it('should return structured error for invalid settle request', async () => {
        const response = await fetch(`http://localhost:${port}/settle`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
        });
        expect(response.status).toBe(400);
        const error = await response.json() as ZKCredentialErrorResponse;
        expect(error.error).toBe('invalid_proof');
        expect(error.message).toContain('Missing extensions.zk-credential.commitment');
    });
});
