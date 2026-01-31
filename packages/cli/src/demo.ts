/**
 * Demo Script
 * 
 * Runs the full ZK Session demo flow programmatically.
 */

import { ZkSessionClient } from './client.js';

const ISSUER_URL = process.env.ISSUER_URL ?? 'http://localhost:3001';
const API_URL = process.env.API_URL ?? 'http://localhost:3002';

async function main() {
  console.log('╔═══════════════════════════════════════════════════════════════╗');
  console.log('║            ZK Session Credential Demo                         ║');
  console.log('╚═══════════════════════════════════════════════════════════════╝\n');
  
  const client = new ZkSessionClient({
    strategy: 'time-bucketed',
    timeBucketSeconds: 60,
  });
  
  // Clear any existing credentials
  client.clearCredentials();
  
  // === PHASE 1: Issuance ===
  console.log('━━━ PHASE 1: Credential Issuance ━━━\n');
  
  console.log(`Issuer: ${ISSUER_URL}`);
  console.log('Payment: $1.00 USDC (mock)\n');
  
  console.log('1. Client generates secrets locally:');
  console.log('   - nullifier_seed = random()');
  console.log('   - blinding_factor = random()');
  console.log('   - commitment = nullifier_seed * G + blinding * H\n');
  
  console.log('2. Client sends {payment_proof, commitment} to issuer\n');
  
  console.log('3. Issuer verifies payment and signs credential...');
  
  try {
    const credential = await client.obtainCredential(ISSUER_URL, {
      mock: { amountUSDC: 1.00, payer: '0xdemouser' },
    });
    
    console.log('\n✓ Credential obtained!\n');
    console.log('   Credential details:');
    console.log(`   - Service ID: ${credential.serviceId.slice(0, 20)}...`);
    console.log(`   - Tier: ${credential.tier} (Pro)`);
    console.log(`   - Max Presentations: ${credential.maxPresentations}`);
    console.log(`   - Expires: ${new Date(credential.expiresAt * 1000).toLocaleString()}\n`);
  } catch (err) {
    console.error('\n✗ Failed to obtain credential:', (err as Error).message);
    console.log('\n   Make sure the issuer is running:');
    console.log('   $ npm run issuer\n');
    process.exit(1);
  }
  
  // === PHASE 2: Presentation ===
  console.log('━━━ PHASE 2: Anonymous API Access ━━━\n');
  
  console.log(`API Server: ${API_URL}`);
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
  
  // === PHASE 3: Privacy Demonstration ===
  console.log('━━━ PHASE 3: Privacy Demonstration ━━━\n');
  
  console.log('Making multiple requests to show token behavior...\n');
  
  const tokens: string[] = [];
  
  for (let i = 0; i < 3; i++) {
    const response = await client.makeAuthenticatedRequest(`${API_URL}/api/whoami`);
    const rateLimitRemaining = response.headers.get('X-RateLimit-Remaining');
    const body = await response.json() as { originToken: string };
    const zkToken = body.originToken;
    tokens.push(zkToken);
    console.log(`  Request ${i + 1}: token = ${zkToken} (rate limit remaining: ${rateLimitRemaining ?? 'unknown'})`);
  }
  
  const allSame = tokens.every(t => t === tokens[0]);
  console.log(`\n  All tokens same (within time bucket): ${allSame ? '✓ Yes' : '✗ No'}`);
  console.log('  This demonstrates proof caching within the time window.\n');
  
  // Force unlinkable request
  console.log('Making unlinkable request (bypasses cache)...');
  const unlinkableResponse = await client.makeAuthenticatedRequest(
    `${API_URL}/api/whoami`,
    { forceUnlinkable: true }
  );
  const unlinkableBody = await unlinkableResponse.json() as { originToken: string };
  const unlinkableToken = unlinkableBody.originToken;
  console.log(`  Unlinkable token: ${unlinkableToken}`);
  console.log(`  Different from cached: ${unlinkableToken !== tokens[0] ? '✓ Yes' : '✗ No'}\n`);
  
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
  
  console.log('Key takeaways:');
  console.log('  • Client generates ZK proof → server never sees credential');
  console.log('  • origin_token enables rate limiting without linking requests');
  console.log('  • Proof caching optimizes performance within time windows');
  console.log('  • forceUnlinkable bypasses cache for sensitive operations');
}

main().catch(console.error);
