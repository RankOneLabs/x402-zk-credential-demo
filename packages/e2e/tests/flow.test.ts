import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn, ChildProcess } from 'child_process';
import { createPublicClient, createWalletClient, http, defineChain } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { createApiServer } from '../../api/src/server.js';
import { ZkCredentialClient } from '../../cli/src/client.js';
import { createFacilitatorServer } from '../../facilitator/src/server.js';
import { hexToBigInt, parseSchemePrefix, type X402WithZKCredentialResponse, type PaymentPayload, type PaymentRequirements } from '@demo/crypto';
// Import x402 client libs for payment payload creation
import { x402Client } from '@x402/core/client';
import { registerExactEvmScheme } from '@x402/evm/exact/client';
import path from 'path';
import fs from 'fs';
import os from 'os';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// --- Configuration ---
const ANVIL_PORT = 8545;
const FACILITATOR_PORT = 3001;
const API_PORT = 3002;
const ANVIL_RPC = `http://127.0.0.1:${ANVIL_PORT}`;

// Set SKIP_PROOF_VERIFICATION=true to skip proof verification (e.g., in CI without CRS)
const SKIP_PROOF_VERIFICATION = process.env.SKIP_PROOF_VERIFICATION === 'true';

// Default Anvil account #0 (Private Key)
const ANVIL_PK_0 = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'; // Account 0
// Account #1 (User)
const ANVIL_PK_1 = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d'; // Account 1

// Chain Definition (Anvil)
const anvilChain = defineChain({
    id: 31337,
    name: 'Local Anvil',
    nativeCurrency: { decimals: 18, name: 'Ether', symbol: 'ETH' },
    rpcUrls: { default: { http: [ANVIL_RPC] } },
});

// Clients
const userAccount = privateKeyToAccount(ANVIL_PK_1);
const publicClient = createPublicClient({ chain: anvilChain, transport: http(ANVIL_RPC) });

describe('End-to-End Flow', () => {
    let anvilProcess: ChildProcess;
    let usdcAddress: `0x${string}`;
    let facilitatorServer: ReturnType<typeof createFacilitatorServer>;
    let apiServer: ReturnType<typeof createApiServer>;
    let facilitatorAddress: `0x${string}`;
    let facilitatorPubkey: { x: string; y: string };

    // Start Anvil
    beforeAll(async () => {
        console.log('Starting Anvil...');
        anvilProcess = spawn('anvil', ['--port', String(ANVIL_PORT), '--block-time', '1'], {
            stdio: 'ignore', // Keep logs clean
            detached: true,
        });

        // Wait for Anvil to be ready
        await new Promise((resolve) => setTimeout(resolve, 3000));
    });

    // Cleanup
    afterAll(async () => {
        // Stop servers first (with error handling for servers that may not have started)
        if (apiServer) {
            try {
                await apiServer.stop();
            } catch {
                // Server may not have started
            }
        }
        if (facilitatorServer) {
            try {
                await facilitatorServer.stop();
            } catch {
                // Server may not have started
            }
        }
        // Then kill Anvil
        if (anvilProcess) {
            try {
                if (process.platform !== 'win32' && anvilProcess.pid !== undefined) {
                    process.kill(-anvilProcess.pid); // Kill process group on POSIX
                } else {
                    anvilProcess.kill(); // Fallback for Windows or missing PID
                }
            } catch {
                // Process may already be dead
            }
        }
    });

    // Deploy Contracts
    it('should deploy MockUSDC', async () => {
        // We'll use forge to deploy using a shell command for simplicity
        // rather than implementing deployment logic in JS
        console.log('Deploying MockUSDC...');

        // Using default Anvil key #0 to deploy
        const cmd = `forge script script/Deploy.s.sol:Deploy --rpc-url ${ANVIL_RPC} --broadcast --private-key ${ANVIL_PK_0}`;

        // Resolve contracts path relative to this test file
        // tests/flow.test.ts -> packages/e2e/tests -> packages/e2e -> packages -> root -> contracts (down)
        // relative: ../../../contracts
        const contractsDir = path.resolve(__dirname, '../../../contracts');
        console.log(`Forge working directory: ${contractsDir}`);

        // Execute forge script
        await new Promise<void>((resolve, reject) => {
            const p = spawn(cmd, { shell: true, cwd: contractsDir });

            // Pipe output for debugging
            p.stdout.on('data', (d) => console.log(`[Forge] ${d}`));
            p.stderr.on('data', (d) => console.error(`[Forge Err] ${d}`));

            p.on('close', (code) => code === 0 ? resolve() : reject(new Error(`Forge deployment failed: ${code}`)));
        });

        // Extract address from strict run-latest.json or broadcast file
        // For simplicity in this demo, we'll PREDICT the address.
        // Anvil resets state, so address is deterministic if nonce is 0.
        // Account 0 (deployer) nonce 0 -> Deployer Contract
        // Wait... scripts use CREATE.
        // Let's just grab the broadcast artifact which is reliable.
        const broadcastPath = path.join(contractsDir, 'broadcast/Deploy.s.sol/31337/run-latest.json');
        const broadcast = JSON.parse(fs.readFileSync(broadcastPath, 'utf-8'));

        usdcAddress = broadcast.receipts[0].contractAddress;
        console.log(`MockUSDC deployed at: ${usdcAddress}`);
        expect(usdcAddress).toBeDefined();
        expect(usdcAddress).toMatch(/^0x[a-fA-F0-9]{40}$/);
    }, 30000); // extensive timeout for compilation

    it('should start Facilitator and API servers', async () => {
        // 1. Start Facilitator
        facilitatorAddress = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'; // Account 0 (Deployer/Receiver)

        facilitatorServer = createFacilitatorServer({
            port: FACILITATOR_PORT,
            serviceId: 1001n,
            secretKey: 123456789n,
            kid: 'e2e-test-key',
            tiers: [
                { minAmountCents: 10, tier: 1, identityLimit: 10, durationSeconds: 3600 }
            ],
            evmPayment: {
                chainId: 31337,
                rpcUrl: ANVIL_RPC,
                facilitatorPrivateKey: ANVIL_PK_0 as `0x${string}`,
                usdcAddress,
                usdcDecimals: 6,
            },
            allowMockPayments: false,
        });

        await facilitatorServer.start();

        // Fetch facilitator's public key from /info endpoint (new spec format)
        const infoResponse = await fetch(`http://localhost:${FACILITATOR_PORT}/info`);
        const infoData = await infoResponse.json() as {
            facilitator_pubkey: string;
            service_id: string;
            credential_suites: string[];
        };

        // Parse scheme-prefixed pubkey
        const { value: pubkeyHex } = parseSchemePrefix(infoData.facilitator_pubkey);
        const pubkeyBytes = pubkeyHex.startsWith('0x') ? pubkeyHex.slice(2) : pubkeyHex;
        facilitatorPubkey = {
            x: '0x' + pubkeyBytes.slice(2, 66),
            y: '0x' + pubkeyBytes.slice(66, 130),
        };
        console.log('Facilitator pubkey:', facilitatorPubkey);

        // Verify /.well-known/zk-credential-keys
        const wkResponse = await fetch(`http://localhost:${FACILITATOR_PORT}/.well-known/zk-credential-keys`);
        expect(wkResponse.status).toBe(200);
        const wkData = await wkResponse.json() as any;
        expect(wkData.keys).toBeDefined();
        expect(wkData.keys[0].kid).toBe('e2e-test-key');
        expect(wkData.keys[0].x).toBe(facilitatorPubkey.x);

        // 2. Start API
        console.log('Starting API Server...');
        apiServer = createApiServer({
            port: API_PORT,
            zkCredential: {
                serviceId: 1001n,
                facilitatorPubkey: {
                    x: hexToBigInt(facilitatorPubkey.x),
                    y: hexToBigInt(facilitatorPubkey.y),
                },
                rateLimit: { maxRequestsPerToken: 10, windowSeconds: 60 },
                skipProofVerification: SKIP_PROOF_VERIFICATION,
                facilitatorUrl: `http://localhost:${FACILITATOR_PORT}/settle`,
                paymentAmount: '100000',
                paymentAsset: usdcAddress, // Use deployed contract address
                paymentRecipient: facilitatorAddress,
                network: 'eip155:31337', // Anvil chain ID
            }
        });

        // Start listening
        await apiServer.start();
    });

    it('should execute full flow: Discovery -> Mint -> Sign Authorization -> Settle -> Verify', async () => {
        // 0. Discovery Phase: Try to access protected resource unauthenticated
        console.log('Attempting unauthenticated access (Discovery)...');
        const discoveryResponse = await fetch(`http://localhost:${API_PORT}/api/whoami`);
        expect(discoveryResponse.status).toBe(402);

        const discoveryData = await discoveryResponse.json() as X402WithZKCredentialResponse;
        console.log('Discovery Data (x402 format):', JSON.stringify(discoveryData, null, 2));

        // Verify x402 PaymentRequired format (spec v2)
        expect(discoveryData.x402Version).toBe(2);
        expect(discoveryData.accepts).toBeDefined();
        expect(discoveryData.accepts.length).toBeGreaterThan(0);
        expect(discoveryData.accepts[0].scheme).toBe('exact');
        expect(discoveryData.accepts[0].asset).toBe(usdcAddress);

        // Verify zk_credential extension
        expect(discoveryData.extensions?.zk_credential).toBeDefined();
        expect(discoveryData.extensions!.zk_credential!.version).toBe('0.2.0');
        expect(discoveryData.extensions!.zk_credential!.credential_suites).toContain('pedersen-schnorr-poseidon-ultrahonk');

        // Parse facilitator URL and payment details from 402 response
        const zkCredential = discoveryData.extensions!.zk_credential!;
        const paymentReqs = discoveryData.accepts[0];
        const facilitatorUrl = zkCredential.facilitator_url || `http://localhost:${FACILITATOR_PORT}/settle`;

        // 1. Mint USDC to User
        const mintAbi = [{
            name: 'mint',
            type: 'function',
            stateMutability: 'nonpayable',
            inputs: [{ name: 'to', type: 'address' }, { name: 'amount', type: 'uint256' }],
            outputs: []
        }] as const;

        const amount = 2_000_000n; // 2 USDC
        const deployerAccount = privateKeyToAccount(ANVIL_PK_0);
        const deployerWalletClient = createWalletClient({
            chain: anvilChain,
            transport: http(ANVIL_RPC),
            account: deployerAccount
        });

        console.log('Minting USDC to user...');
        const mintTxHash = await deployerWalletClient.writeContract({
            address: usdcAddress,
            abi: mintAbi,
            functionName: 'mint',
            args: [userAccount.address, amount]
        });
        // Wait for mint to be confirmed
        await publicClient.waitForTransactionReceipt({ hash: mintTxHash });
        console.log('Minted USDC, tx:', mintTxHash.slice(0, 16) + '...');

        // 2. Create payment payload using x402 client library
        // This handles EIP-3009 authorization and EIP-712 signing automatically
        console.log('Creating payment payload via x402Client...');

        // Build PaymentRequirements from the 402 response
        // @x402/evm requires extra.name and extra.version for EIP-712 domain
        const paymentRequirements: PaymentRequirements = {
            scheme: paymentReqs.scheme,
            network: paymentReqs.network,
            asset: paymentReqs.asset,
            amount: paymentReqs.amount,
            payTo: paymentReqs.payTo,
            maxTimeoutSeconds: paymentReqs.maxTimeoutSeconds,
            extra: {
                ...paymentReqs.extra,
                // EIP-712 domain info for USDC (required by @x402/evm)
                name: 'USD Coin',
                version: '1',
            },
        };

        // Create x402 client with EVM exact scheme
        // userAccount satisfies ClientEvmSigner interface (has address + signTypedData)
        const x402 = new x402Client();
        registerExactEvmScheme(x402, { signer: userAccount });

        // Create payment payload - handles EIP-3009/EIP-712 automatically
        const { x402Version, payload } = await x402.createPaymentPayload({
            x402Version: 2,
            accepts: [paymentRequirements],
            resource: discoveryData.resource,
        });

        const paymentPayload: PaymentPayload = {
            x402Version,
            resource: discoveryData.resource,
            accepted: paymentRequirements,
            payload,
        };

        console.log('Payment payload created via x402Client');

        // 4. Settle and obtain credential via Client (spec §7.2, §7.3)
        console.log('Settling payment and obtaining credential...');
        // Use temp storage to avoid conflicts with previous test runs
        const tempStoragePath = path.join(os.tmpdir(), `zk-credential-test-${Date.now()}`, 'credentials.json');
        const client = new ZkCredentialClient({
            strategy: 'time-bucketed',
            timeBucketSeconds: 60,
            storagePath: tempStoragePath,
        });

        const storedCredential = await client.settleAndObtainCredential(
            facilitatorUrl,
            paymentPayload,
            paymentRequirements
        );

        expect(storedCredential).toBeDefined();
        expect(storedCredential.tier).toBe(1);
        console.log('Credential obtained:', {
            serviceId: storedCredential.serviceId,
            kid: storedCredential.kid,
            tier: storedCredential.tier,
        });
        expect(storedCredential.kid).toBe('e2e-test-key');

        // 5. Access Protected API with zk_credential body presentation
        console.log('Accessing protected API with ZK proof...');
        const response = await client.makeAuthenticatedRequest(
            `http://localhost:${API_PORT}/api/whoami`
        );

        console.log('Response status:', response.status);
        const data = await response.json();
        console.log('API Response:', data);
        expect(response.status).toBe(200);
        expect(data.tier).toBe(1);
        expect(data.message).toContain('valid ZK credentials');
    }, 120000); // Proof generation can take 60+ seconds
});
