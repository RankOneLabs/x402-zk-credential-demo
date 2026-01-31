import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn, ChildProcess } from 'child_process';
import { createPublicClient, createWalletClient, http, defineChain, parseEther, parseUnits } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { createApiServer, ZkSessionMiddleware } from '@demo/api';
import { ZkSessionClient } from '@demo/cli';
import { createIssuerServer } from '@demo/issuer';
import { hexToBigInt } from '@demo/crypto';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// --- Configuration ---
const ANVIL_PORT = 8545;
const ISSUER_PORT = 3001;
const API_PORT = 3002;
const ANVIL_RPC = `http://127.0.0.1:${ANVIL_PORT}`;

// In CI, skip real proof verification (CRS download fails due to network)
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
const walletClient = createWalletClient({ chain: anvilChain, transport: http(ANVIL_RPC), account: userAccount });

describe('End-to-End Flow', () => {
    let anvilProcess: ChildProcess;
    let usdcAddress: `0x${string}`;
    let issuerServer: ReturnType<typeof createIssuerServer>;
    let apiServer: ReturnType<typeof createApiServer>;
    let issuerAddress: `0x${string}`;

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
    afterAll(() => {
        if (anvilProcess) {
            if (process.platform !== 'win32' && anvilProcess.pid !== undefined) {
                process.kill(-anvilProcess.pid); // Kill process group on POSIX
            } else {
                anvilProcess.kill(); // Fallback for Windows or missing PID
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

    it('should start Issuer and API servers', async () => {
        // 1. Start Issuer
        issuerAddress = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'; // Account 0 (Deployer/Receiver)

        issuerServer = createIssuerServer({
            port: ISSUER_PORT,
            serviceId: 1001n,
            secretKey: 123456789n,
            tiers: [
                { minAmountCents: 100, tier: 1, maxPresentations: 10, durationSeconds: 3600 }
            ],
            paymentVerification: {
                chainId: 31337,
                rpcUrl: ANVIL_RPC,
                recipientAddress: issuerAddress,
                usdcDecimals: 6,
                usdcAddress, // PASS THE DEPLOYED ADDRESS
            },
            allowMockPayments: false,
        });

        await issuerServer.start();

        // Fetch issuer's public key from /info endpoint
        const infoResponse = await fetch(`http://localhost:${ISSUER_PORT}/info`);
        const infoData = await infoResponse.json() as { issuerPubkey: { x: string, y: string } };
        const issuerPubkey = {
            x: hexToBigInt(infoData.issuerPubkey.x),
            y: hexToBigInt(infoData.issuerPubkey.y),
        };
        console.log('Issuer pubkey:', infoData.issuerPubkey);

        // 2. Start API
        console.log('Starting API Server...');
        apiServer = createApiServer({
            port: API_PORT,
            zkSession: {
                serviceId: 1001n,
                issuerPubkey, // Use real issuer public key
                rateLimit: { maxRequestsPerToken: 10, windowSeconds: 60 },
                skipProofVerification: SKIP_PROOF_VERIFICATION,
                issuerUrl: `http://localhost:${ISSUER_PORT}`,
                priceInfo: '1.00 USDC'
            }
        });

        // Start listening
        await apiServer.start();
    });

    it('should execute full flow: Discovery -> Mint -> Pay -> Issue -> Verify', async () => {
        // 0. Discovery Phase: Try to access protected resource unauthenticated
        console.log('Attempting unauthenticated access (Discovery)...');
        const discoveryResponse = await fetch(`http://localhost:${API_PORT}/api/whoami`);
        expect(discoveryResponse.status).toBe(402);

        const discoveryData = await discoveryResponse.json();
        console.log('Discovery Data:', discoveryData);

        expect(discoveryData.error).toBe('Payment Required');
        expect(discoveryData.discovery).toBeDefined();
        expect(discoveryData.discovery.issuerUrl).toBe(`http://localhost:${ISSUER_PORT}`);
        expect(discoveryData.discovery.price).toBe('1.00 USDC');

        // Parse price (simple logic for test)
        // In reality client parses "1.00 USDC" -> 1_000_000 units
        const requiredAmount = 1_000_000n; // 1 USDC

        // 1. Mint USDC to User
        // ABI for mint(address, uint256)
        const mintAbi = [{
            name: 'mint',
            type: 'function',
            stateMutability: 'nonpayable',
            inputs: [{ name: 'to', type: 'address' }, { name: 'amount', type: 'uint256' }],
            outputs: []
        }];

        const amount = 2_000_000n; // 2 USDC
        const deployerAccount = privateKeyToAccount(ANVIL_PK_0);

        console.log('Minting USDC to user...');
        const { request: mintRequest } = await publicClient.simulateContract({
            account: deployerAccount, // Pass Account object, not PK string
            address: usdcAddress,
            abi: mintAbi,
            functionName: 'mint',
            args: [userAccount.address, amount]
        });
        await walletClient.writeContract(mintRequest);

        // 2. User transfers USDC to Issuer
        // ERC20 Transfer ABI
        const transferAbi = [{
            name: 'transfer',
            type: 'function',
            stateMutability: 'nonpayable',
            inputs: [{ name: 'to', type: 'address' }, { name: 'value', type: 'uint256' }],
            outputs: [{ name: '', type: 'bool' }]
        }];

        console.log('Transferring USDC to issuer...');
        // We need the hash for the proof
        const hash = await walletClient.writeContract({
            address: usdcAddress,
            abi: transferAbi,
            functionName: 'transfer',
            args: [issuerAddress, requiredAmount], // Pay the discovered amount
            account: userAccount
        });

        console.log(`Payment TX: ${hash}`);

        // Wait for confirmation
        await publicClient.waitForTransactionReceipt({ hash });

        // 3. Request Credential via Client (HTTP)
        console.log('Requesting credential...');
        const client = new ZkSessionClient({
            issuerUrl: `http://localhost:${ISSUER_PORT}`, // Fix: Property 'issuerUrl' is missing in type
            mockProofs: SKIP_PROOF_VERIFICATION
        });

        const storedCredential = await client.obtainCredential(
            `http://localhost:${ISSUER_PORT}`,
            { txHash: hash }
        );

        expect(storedCredential).toBeDefined();
        expect(storedCredential.tier).toBe(1);

        // 4. Access Protected API
        console.log('Accessing protected API...');
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
