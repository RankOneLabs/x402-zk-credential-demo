/**
 * Demo: Make a real USDC payment and obtain credential
 * 
 * This script demonstrates the full x402 zk-credential payment flow:
 * 1. Discovery: Fetch 402 response with zk_credential extension
 * 2. Payment: Create EIP-3009 signed authorization via x402Client
 * 3. Settlement: Submit payment to facilitator and obtain credential
 * 4. Access: Make authenticated requests with ZK proofs
 * 
 * Run with: npx tsx packages/cli/src/demo.ts
 */

import { parseSchemePrefix, type PaymentRequirements, type PaymentPayload, fromBase64Url, bytesToPoint, bigIntToHex } from '@demo/crypto';
import { privateKeyToAccount } from 'viem/accounts';
import { x402Client } from '@x402/core/client';
import { registerExactEvmScheme } from '@x402/evm/exact/client';
import { ZkCredentialClient } from './client.js';

// Configuration
const API_URL = process.env.API_URL ?? 'http://localhost:3002';
const PRIVATE_KEY = (process.env.PRIVATE_KEY ?? '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d') as `0x${string}`;

async function main() {
  console.log('=== ZK Credential Client Demo ===\n');

  const account = privateKeyToAccount(PRIVATE_KEY);
  console.log(`Using account: ${account.address}\n`);

  // === PHASE 1: Discovery (spec §6) ===
  console.log('━━━ PHASE 1: Discovery (402 Response) ━━━\n');

  console.log(`Requesting protected resource: ${API_URL}/api/whoami`);
  console.log('Expected: 402 Payment Required with zk_credential extension\n');

  const discoveryResponse = await fetch(`${API_URL}/api/whoami`);

  if (discoveryResponse.status === 200) {
    console.log('✓ API returned 200 OK (Auth disabled?) - Demo complete.\n');
    process.exit(0);
  }

  if (discoveryResponse.status !== 402) {
    console.error(`✗ Expected 402, got ${discoveryResponse.status}`);
    console.log('\n   Make sure the API server is running:');
    console.log('   $ npm run api\n');
    process.exit(1);
  }

  const discoveryData = await discoveryResponse.json() as any;

  if (!discoveryData.extensions?.['zk-credential']) {
    console.error('✗ Missing zk-credential extension in 402 response');
    process.exit(1);
  }

  const paymentReqs = discoveryData.accepts[0];
  const zkCredential = discoveryData.extensions['zk-credential'];
  const facilitatorUrl = zkCredential.facilitator_url;
  const facilitatorPubkeyString = zkCredential.facilitator_pubkey;

  console.log('✓ Received 402 response:\n');
  console.log('  Payment Requirements:');
  console.log(`    - scheme: ${paymentReqs.scheme}`);
  console.log(`    - network: ${paymentReqs.network}`);
  console.log(`    - amount: ${paymentReqs.amount}`);
  console.log(`    - asset: ${paymentReqs.asset}`);
  console.log(`    - payTo: ${paymentReqs.payTo}`);
  console.log('  ZK Credential Extension:');
  console.log(`    - credential_suites: [${zkCredential.credential_suites.join(', ')}]`);
  console.log(`    - facilitator_pubkey: ${facilitatorPubkeyString.slice(0, 40)}...`);
  console.log(`    - facilitator_url: ${facilitatorUrl}\n`);

  // === PHASE 2: Payment & Settlement (spec §7) ===
  console.log('━━━ PHASE 2: Payment & Settlement ━━━\n');

  // Build PaymentRequirements with EIP-712 domain info
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

  console.log('1. Creating payment payload via x402Client...');

  // Create x402 client with EVM exact scheme
  const x402 = new x402Client();
  registerExactEvmScheme(x402, { signer: account });

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

  console.log('   ✓ EIP-3009 authorization signed\n');

  console.log('2. Settling payment and obtaining credential...');

  const client = new ZkCredentialClient({
    strategy: 'time-bucketed',
    timeBucketSeconds: 60,
  });

  const credential = await client.settleAndObtainCredential(
    facilitatorUrl,
    paymentPayload,
    paymentRequirements
  );

  console.log('\n✓ Settlement complete!\n');
  console.log('   Credential:');
  console.log(`   - service_id: ${credential.serviceId.slice(0, 20)}...`);
  console.log(`   - tier: ${credential.tier}`);
  console.log(`   - identity_limit: ${credential.identityLimit}`);
  console.log(`   - expires_at: ${new Date(credential.expiresAt * 1000).toLocaleString()}\n`);

  // === PHASE 3: Anonymous API Access ===
  console.log('━━━ PHASE 3: Anonymous API Access ━━━\n');

  // Parse facilitator pubkey (base64url)
  const parsedPubkeyB64 = parseSchemePrefix(facilitatorPubkeyString).value;
  const pubkeyBytes = fromBase64Url(parsedPubkeyB64);
  const pubkeyPoint = bytesToPoint(pubkeyBytes);

  const facilitatorPubkey = {
    x: bigIntToHex(pubkeyPoint.x),
    y: bigIntToHex(pubkeyPoint.y),
  };

  console.log('Making authenticated requests with ZK proofs...\n');

  // Test /api/whoami
  console.log('1. GET /api/whoami');
  const whoamiResp = await client.makeAuthenticatedRequest(`${API_URL}/api/whoami`, {
    facilitatorPubkey,
  });
  const whoamiData = await whoamiResp.json() as any;
  console.log(`   Status: ${whoamiResp.status}`);
  console.log(`   Response: ${JSON.stringify(whoamiData)}\n`);

  // Test /api/chat
  const messages = ['Hello!', 'How does this work?', 'Is this really anonymous?'];

  for (const [i, msg] of messages.entries()) {
    console.log(`${i + 2}. POST /api/chat { message: "${msg}" }`);

    const response = await client.makeAuthenticatedRequest(`${API_URL}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: msg }),
      facilitatorPubkey,
    });

    const body = await response.json() as any;

    if (response.ok) {
      console.log(`   Status: 200 OK`);
      console.log(`   Response: "${body.response}"`);
      const remaining = response.headers.get('x-ratelimit-remaining');
      if (remaining) console.log(`   Rate Limit: ${remaining} remaining`);
    } else {
      console.log(`   Status: ${response.status}`);
      console.log(`   Error: ${body.error}`);
    }
    console.log();
  }

  console.log('✓ Demo complete!\n');
}

main().catch((err: Error) => {
  console.error('\nError:', err.message);
  process.exit(1);
});
