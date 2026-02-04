/**
 * Demo Script
 * 
 * Runs the full ZK Session demo flow per x402 zk-session spec v0.1.0:
 * 1. Request protected resource → receive 402 with zk_session extension
 * 2. Parse facilitator URL and pubkey from 402 response  
 * 3. Generate secrets and compute commitment
 * 4. POST to facilitator /settle with payment + commitment
 * 5. Receive payment_receipt + credential
 * 6. Generate proof and access resource with Authorization: ZKSession header
 */

import { ZkSessionClient } from './client.js';

const API_URL = process.env.API_URL ?? 'http://localhost:3002';

async function main() {
  console.log('╔═══════════════════════════════════════════════════════════════╗');
  console.log('║       ZK Session Demo (x402 spec v0.1.0 compliant)            ║');
  console.log('╚═══════════════════════════════════════════════════════════════╝\n');
  
  const client = new ZkSessionClient({
    strategy: 'time-bucketed',
    timeBucketSeconds: 60,
  });
  
  // Clear any existing credentials
  client.clearCredentials();
  
  // === PHASE 1: Discovery (spec §5.2 steps 1-2) ===
  console.log('━━━ PHASE 1: Discovery (402 Response) ━━━\n');
  
  console.log(`Requesting protected resource: ${API_URL}/api/whoami`);
  console.log('Expected: 402 Payment Required with zk_session extension\n');
  
  let facilitatorUrl: string;
  let facilitatorPubkey: { x: string; y: string };
  
  try {
    const discovery = await client.discover(`${API_URL}/api/whoami`);
    
    console.log('✓ Received 402 response with zk_session extension:\n');
    console.log('  accepts[0] (payment requirements):');
    console.log(`    - amount: ${discovery.paymentAmount}`);
    console.log(`    - asset: ${discovery.paymentAsset}`);
    console.log(`    - facilitator: ${discovery.facilitatorUrl}`);
    console.log('  extensions.zk_session:');
    console.log(`    - schemes: [${discovery.schemes.join(', ')}]`);
    console.log(`    - facilitator_pubkey: ${discovery.facilitatorPubkey.x.slice(0, 20)}...`);
    console.log();
    
    facilitatorUrl = discovery.facilitatorUrl;
    facilitatorPubkey = discovery.facilitatorPubkey;
  } catch (err) {
    console.error('✗ Discovery failed:', (err as Error).message);
    console.log('\n   Make sure the API server is running:');
    console.log('   $ npm run api\n');
    process.exit(1);
  }
  
  // === PHASE 2: Settlement (spec §5.2 steps 3-5) ===
  console.log('━━━ PHASE 2: Settlement (/settle) ━━━\n');
  
  console.log(`Facilitator: ${facilitatorUrl}`);
  console.log('Payment: $1.00 USDC (mock)\n');
  
  console.log('1. Client generates secrets locally:');
  console.log('   - nullifier_seed = random()');
  console.log('   - blinding_factor = random()');
  console.log('   - commitment = Pedersen(nullifier_seed, blinding_factor)\n');
  
  console.log('2. Client sends {payment, zk_session: {commitment}} to facilitator\n');
  
  console.log('3. Facilitator verifies payment and signs credential...');
  
  try {
    const credential = await client.settleAndObtainCredential(facilitatorUrl, {
      mock: { amountUSDC: 1.00, payer: '0xdemouser' },
    });
    
    console.log('\n✓ Settlement complete!\n');
    console.log('   Credential (CredentialWireFormat):');
    console.log(`   - scheme: pedersen-schnorr-bn254`);
    console.log(`   - service_id: ${credential.serviceId.slice(0, 20)}...`);
    console.log(`   - tier: ${credential.tier} (Pro)`);
    console.log(`   - max_presentations: ${credential.maxPresentations}`);
    console.log(`   - expires_at: ${new Date(credential.expiresAt * 1000).toLocaleString()}\n`);
  } catch (err) {
    console.error('\n✗ Settlement failed:', (err as Error).message);
    console.log('\n   Make sure the facilitator is running:');
    console.log('   $ npm run facilitator\n');
    process.exit(1);
  }
  
  // === PHASE 3: Presentation (spec §5.2 steps 6-7) ===
  console.log('━━━ PHASE 3: Anonymous API Access ━━━\n');
  
  console.log(`API Server: ${API_URL}`);
  console.log('Authorization: ZKSession pedersen-schnorr-bn254:<base64-proof>');
  console.log('Strategy: time-bucketed (60s windows)\n');
  
  console.log('Making authenticated requests...\n');
  
  const requests = [
    { name: 'Identity check', method: 'GET', path: '/api/whoami' },
    { name: 'Chat message', method: 'POST', path: '/api/chat', body: { message: 'Hello from ZK!' } },
    { name: 'Fetch data', method: 'GET', path: '/api/data' },
  ];
  
  for (const req of requests) {
    const url = `${API_URL}${req.path}`;
    console.log(`→ ${req.name}: ${req.method} ${req.path}`);
    
    try {
      const startTime = Date.now();
      
      const response = await client.makeAuthenticatedRequest(url, {
        method: req.method,
        body: req.body ? JSON.stringify(req.body) : undefined,
        headers: req.body ? { 'Content-Type': 'application/json' } : undefined,
        issuerPubkey: facilitatorPubkey,
      });
      
      const elapsed = Date.now() - startTime;
      const body = await response.json();
      
      console.log(`  Status: ${response.status} (${elapsed}ms)`);
      console.log(`  Rate limit remaining: ${response.headers.get('X-RateLimit-Remaining')}`);
      console.log(`  Response: ${JSON.stringify(body).slice(0, 60)}...`);
    } catch (err) {
      console.log(`  ✗ Error: ${(err as Error).message}`);
    }
    console.log();
  }
  
  // === PHASE 4: Privacy Demonstration ===
  console.log('━━━ PHASE 4: Privacy Demonstration ━━━\n');
  
  console.log('Making multiple requests to show origin_token behavior...\n');
  
  const tokens: string[] = [];
  
  for (let i = 0; i < 3; i++) {
    const response = await client.makeAuthenticatedRequest(`${API_URL}/api/whoami`, {
      issuerPubkey: facilitatorPubkey,
    });
    const rateLimitRemaining = response.headers.get('X-RateLimit-Remaining');
    const body = await response.json() as { originToken: string };
    const zkToken = body.originToken;
    tokens.push(zkToken);
    console.log(`  Request ${i + 1}: origin_token = ${zkToken} (rate limit: ${rateLimitRemaining ?? '?'})`);
  }
  
  const allSame = tokens.every(t => t === tokens[0]);
  console.log(`\n  All tokens same (within time bucket): ${allSame ? '✓ Yes' : '✗ No'}`);
  console.log('  → Same presentation_index produces same origin_token (linkable within window)\n');
  
  // Force unlinkable request
  console.log('Making unlinkable request (new presentation_index)...');
  const unlinkableResponse = await client.makeAuthenticatedRequest(
    `${API_URL}/api/whoami`,
    { forceUnlinkable: true, issuerPubkey: facilitatorPubkey }
  );
  const unlinkableBody = await unlinkableResponse.json() as { originToken: string };
  const unlinkableToken = unlinkableBody.originToken;
  console.log(`  Unlinkable origin_token: ${unlinkableToken}`);
  console.log(`  Different from previous: ${unlinkableToken !== tokens[0] ? '✓ Yes (unlinkable!)' : '✗ No'}\n`);
  
  // === Summary ===
  console.log('━━━ Summary ━━━\n');
  
  const status = client.getCredentialStatus();
  if (status) {
    console.log('Credential Status:');
    console.log(`  - State: ${status.status.toUpperCase()}`);
    console.log(`  - Presentations used: ${status.credential.presentationCount}`);
    console.log(`  - Remaining: ${status.remainingPresentations}`);
    console.log(`  - Expires in: ${Math.round(status.expiresIn / 60)} minutes`);
  }
  
  console.log('\n╔═══════════════════════════════════════════════════════════════╗');
  console.log('║                    Demo Complete! 🎉                          ║');
  console.log('╚═══════════════════════════════════════════════════════════════╝\n');
  
  console.log('Key takeaways (x402 zk-session spec):');
  console.log('  • 402 response advertises zk_session extension with facilitator info');
  console.log('  • Settlement bundles payment + commitment → credential');
  console.log('  • Authorization: ZKSession header carries proof');
  console.log('  • origin_token = hash(nullifier_seed, origin_id, presentation_index)');
  console.log('  • Client controls linkability via presentation_index');
}

main().catch(console.error);
