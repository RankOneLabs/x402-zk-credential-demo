/**
 * Demo: Make a real USDC payment and obtain credential
 * 
 * This script demonstrates the full x402 payment flow:
 * 1. Transfer USDC to the issuer's payment address
 * 2. Submit the transaction hash to obtain a credential
 * 
 * Run with: npx tsx scripts/demo-payment.ts
 */

import {
  hexToBigInt,
  addSchemePrefix,
  parseSchemePrefix,
  randomFieldElement,
  pedersenCommit,
} from '@demo/crypto';
import { privateKeyToAccount } from 'viem/accounts';
import { TransferEvmScheme } from './schemes/TransferEvmScheme.js';
import { ZkSessionClient } from './client.js';

// Configuration
const API_URL = process.env.API_URL ?? 'http://localhost:3002';
const RPC_URL = process.env.RPC_URL ?? 'http://localhost:8545';
const USE_REAL_PAYMENTS = process.env.USE_REAL_PAYMENTS !== 'false'; // Default to true

// USDC on Base Sepolia (and Anvil fork)
const USDC_ADDRESS = '0x036CbD53842c5426634e7929541eC2318f3dCF7e';

// Anvil's first test account (User)
const PRIVATE_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';

async function main() {
  console.log('=== ZK Session Client Demo ===');
  const client = new ZkSessionClient();

  // === PHASE 1: Discovery (spec §6) ===
  console.log('━━━ PHASE 1: Discovery (402 Response) ━━━\n');

  console.log(`Requesting protected resource: ${API_URL}/api/whoami`);
  console.log('Expected: 402 Payment Required with zk_session extension\n');

  const discoveryResponse = await fetch(`${API_URL}/api/whoami`);

  let payTo: string | undefined;
  let paymentAmount: string | undefined;
  let facilitatorUrl: string | undefined;
  let facilitatorPubkeyString: string | undefined;

  if (discoveryResponse.status === 402 && discoveryResponse.headers.get('content-type')?.includes('json')) {
    const data = await discoveryResponse.json() as any;
    console.log('✓ Received 402 response with zk_session extension:\n');
    console.log('  accepts[0] (payment requirements):');
    const note = data.accepts[0];
    console.log(`    - amount: ${note.amount}`);
    console.log(`    - asset: ${note.asset}`);
    console.log(`    - facilitator: ${note.payTo}`);

    payTo = note.payTo;
    paymentAmount = note.amount;

    console.log('  extensions.zk_session:');
    const ext = data.extensions.zk_session;
    console.log(`    - schemes: [${ext.schemes.join(', ')}]`);
    console.log(`    - facilitator_pubkey: ${ext.facilitator_pubkey.slice(0, 20)}...`);

    facilitatorUrl = ext.facilitator_url || payTo;
    facilitatorPubkeyString = ext.facilitator_pubkey;
    console.log();
  } else {
    // Demo success bypass if auth disabled
    if (discoveryResponse.status === 200) {
      console.log('✓ API returned 200 OK (Auth disabled?) - Demo complete.\n');
      process.exit(0);
    }
    console.error('✗ Discovery failed: ' + discoveryResponse.status);
    console.log('\n   Make sure the API server is running:');
    console.log('   $ npm run api\n');
    process.exit(1);
  }

  // === PHASE 2: Settlement (spec §5.2 steps 3-5) ===
  console.log('━━━ PHASE 2: Settlement (via API Mediator) ━━━\n');

  console.log(`Facilitator: ${facilitatorUrl}`);
  console.log(`Payment: ${paymentAmount} USDC\n`);

  console.log('1. Client generates secrets & commitment locally\n');

  // 2. Generate payment request
  let paymentProof: any = { mock: { amountUSDC: 1.00, payer: '0xdemouser' } };

  if (USE_REAL_PAYMENTS && payTo && paymentAmount) {
    try {
      console.log('   (Using Real Payments on Anvil via TransferEvmScheme)');

      const account = privateKeyToAccount(PRIVATE_KEY);
      const scheme = new TransferEvmScheme(account, RPC_URL, USDC_ADDRESS as `0x${string}`);

      const payload = await scheme.createPaymentPayload(2, {
        amount: paymentAmount,
        asset: 'USDC',
        payTo: payTo,
        scheme: 'exact',
        network: 'eip155:84532',
        maxTimeoutSeconds: 300,
        extra: {}
      });

      paymentProof = payload.payload; // { txHash: ... }
      console.log(`   Payment Proof generated:`, paymentProof);

    } catch (e) {
      console.warn('   ! Real payment failed:', (e as Error).message);
      console.warn('   Falling back to mock payment.');
    }
  }

  const { request, secrets } = await client.generatePaymentRequest(paymentProof);

  console.log('2. Client sends PAYMENT-SIGNATURE to API Server');
  console.log(`   - commitment: ${request.extensions.zk_session.commitment}\n`);

  console.log('3. API Server proxies to/from Facilitator...');

  let credential;
  try {
    const paymentSigJson = JSON.stringify(request);
    const paymentSigB64 = Buffer.from(paymentSigJson).toString('base64');

    const paymentResponse = await fetch(`${API_URL}/api/whoami`, {
      method: 'GET',
      headers: {
        'PAYMENT-SIGNATURE': paymentSigB64,
        'Content-Type': 'application/json',
      },
    });

    if (paymentResponse.status !== 200) {
      throw new Error(`Payment failed: ${paymentResponse.status} ${paymentResponse.statusText}`);
    }

    const paymentResponseHeader = paymentResponse.headers.get('PAYMENT-RESPONSE');
    if (!paymentResponseHeader) {
      throw new Error('Missing PAYMENT-RESPONSE header from API');
    }

    const paymentResponsePayload = JSON.parse(Buffer.from(paymentResponseHeader, 'base64').toString('utf-8'));

    console.log('\n✓ Payment accepted by API Server\n');

    if (!facilitatorUrl) facilitatorUrl = 'http://localhost:3001/settle'; // Final fallback

    // 5. Handle response and store credential
    credential = await client.handlePaymentResponse(
      paymentResponsePayload,
      secrets,
      facilitatorUrl
    );

    console.log('\n✓ Settlement complete!\n');
    console.log('   Credential (CredentialWireFormat):');
    console.log(`   - scheme: pedersen-schnorr-bn254`);
    console.log(`   - service_id: ${credential.serviceId.slice(0, 20)}...`);
    console.log(`   - tier: ${credential.tier} (Pro)`);
    console.log(`   - max_presentations: ${credential.maxPresentations}`);
    console.log(`   - expires_at: ${new Date(credential.expiresAt * 1000).toLocaleString()}\n`);

  } catch (err) {
    console.error('\n✗ Settlement failed:', (err as Error).message);
    process.exit(1);
  }

  console.log('━━━ PHASE 3: Anonymous API Access ━━━\n');

  console.log(`API Server: ${API_URL}`);
  console.log('Making 3 requests to /api/chat...\n');

  const messages = ['Hello!', 'How does this work?', 'Is this really anonymous?'];

  // Parse pubkey for Phase 3
  let issuerPubkey = undefined;
  if (facilitatorPubkeyString) {
    const parsedPubkey = parseSchemePrefix(facilitatorPubkeyString).value; // "0x04..."
    const x = parsedPubkey.slice(4, 68); // 32 bytes = 64 hex chars
    const y = parsedPubkey.slice(68, 132);
    issuerPubkey = {
      x: "0x" + x,
      y: "0x" + y
    };
  }

  for (const [i, msg] of messages.entries()) {
    console.log(`${i + 1}. POST /api/chat { message: "${msg}" }`);

    try {
      const response = await client.makeAuthenticatedRequest(`${API_URL}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: msg }),
        issuerPubkey
      });

      const body = await response.json() as any;

      if (response.ok) {
        console.log(`   Status: 200 OK`);
        console.log(`   Response: "${body.response}"`);
        console.log(`   Rate Limit: ${response.headers.get('x-ratelimit-remaining')} remaining`);
      } else {
        console.log(`   Status: ${response.status} ${response.statusText}`);
        console.log(`   Error: ${body.error}`);
      }
    } catch (err) {
      console.error(`   Failed: ${(err as Error).message}`);
    }
    console.log();
  }
}

main().catch((err: Error) => {
  console.error('\nError:', err.message);
  process.exit(1);
});
