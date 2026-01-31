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
  createPublicClient,
  createWalletClient,
  http,
  parseAbi,
  formatUnits,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { baseSepolia } from 'viem/chains';
import { pedersenCommit, randomFieldElement, bigIntToHex } from '@demo/crypto';

// Configuration
const ISSUER_URL = process.env.ISSUER_URL ?? 'http://localhost:3001';
const RPC_URL = process.env.RPC_URL ?? 'http://localhost:8545';

// USDC on Base Sepolia
const USDC_ADDRESS = '0x036CbD53842c5426634e7929541eC2318f3dCF7e';
const USDC_ABI = parseAbi([
  'function transfer(address to, uint256 amount) returns (bool)',
  'function balanceOf(address account) view returns (uint256)',
  'function approve(address spender, uint256 amount) returns (bool)',
]);

// Anvil's first test account
const PRIVATE_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';

async function main() {
  console.log('╔═══════════════════════════════════════════════════════════════╗');
  console.log('║          Real x402 Payment Demo                               ║');
  console.log('╚═══════════════════════════════════════════════════════════════╝\n');

  // Get issuer info
  console.log('1. Fetching issuer info...');
  const infoRes = await fetch(`${ISSUER_URL}/info`);
  if (!infoRes.ok) {
    throw new Error(`Failed to fetch issuer info: ${infoRes.statusText}`);
  }
  const issuerInfo = await infoRes.json();
  console.log(`   Service ID: ${issuerInfo.serviceId}`);
  console.log(`   Tiers: ${issuerInfo.tiers.map((t: any) => `$${t.priceUSDC}`).join(', ')}`);

  // We need the recipient address from env since issuer doesn't expose it
  const recipientAddress = process.env.RECIPIENT_ADDRESS;
  if (!recipientAddress) {
    console.error('\n   ERROR: RECIPIENT_ADDRESS not set');
    console.log('   Run the issuer with RECIPIENT_ADDRESS=0x... to enable on-chain verification');
    console.log('   Or use mock payments (default behavior)');
    process.exit(1);
  }

  // Setup viem clients
  console.log('\n2. Setting up wallet...');
  const account = privateKeyToAccount(PRIVATE_KEY);
  console.log(`   Address: ${account.address}`);

  const publicClient = createPublicClient({
    chain: baseSepolia,
    transport: http(RPC_URL),
  });

  const walletClient = createWalletClient({
    account,
    chain: baseSepolia,
    transport: http(RPC_URL),
  });

  // Check USDC balance
  console.log('\n3. Checking USDC balance...');
  const balance = await publicClient.readContract({
    address: USDC_ADDRESS,
    abi: USDC_ABI,
    functionName: 'balanceOf',
    args: [account.address],
  });
  console.log(`   Balance: ${formatUnits(balance, 6)} USDC`);

  if (balance < 100000n) { // Less than $0.10
    console.error('\n   ERROR: Insufficient USDC balance');
    console.log('   Get testnet USDC from: https://faucet.circle.com/');
    process.exit(1);
  }

  // Transfer USDC to issuer
  const paymentAmount = 1000000n; // $1.00 USDC (6 decimals)
  console.log(`\n4. Sending $${formatUnits(paymentAmount, 6)} USDC to issuer...`);
  console.log(`   Recipient: ${recipientAddress}`);

  const txHash = await walletClient.writeContract({
    address: USDC_ADDRESS,
    abi: USDC_ABI,
    functionName: 'transfer',
    args: [recipientAddress as `0x${string}`, paymentAmount],
  });
  console.log(`   Transaction: ${txHash}`);

  // Wait for confirmation
  console.log('\n5. Waiting for confirmation...');
  const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
  console.log(`   Block: ${receipt.blockNumber}`);
  console.log(`   Status: ${receipt.status}`);

  // Generate commitment
  console.log('\n6. Generating credential commitment...');
  const nullifierSeed = randomFieldElement();
  const blindingFactor = randomFieldElement();
  const commitment = await pedersenCommit(nullifierSeed, blindingFactor);
  console.log(`   Commitment: (${bigIntToHex(commitment.point.x).slice(0, 20)}...)`);

  // Request credential with txHash
  console.log('\n7. Requesting credential from issuer...');
  const credentialRes = await fetch(`${ISSUER_URL}/credentials/issue`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      paymentProof: { txHash },
      userCommitment: {
        x: bigIntToHex(commitment.point.x),
        y: bigIntToHex(commitment.point.y),
      },
    }),
  });

  if (!credentialRes.ok) {
    const error = await credentialRes.json();
    throw new Error(`Failed to obtain credential: ${error.error}`);
  }

  const { credential } = await credentialRes.json();
  console.log('\n   ✓ Credential obtained!');
  console.log(`   Tier: ${credential.tier}`);
  console.log(`   Max Presentations: ${credential.maxPresentations}`);
  console.log(`   Expires: ${new Date(credential.expiresAt * 1000).toLocaleString()}`);

  console.log('\n╔═══════════════════════════════════════════════════════════════╗');
  console.log('║                 Payment Demo Complete! 🎉                     ║');
  console.log('╚═══════════════════════════════════════════════════════════════╝');
}

main().catch((err) => {
  console.error('\nError:', err.message);
  process.exit(1);
});
