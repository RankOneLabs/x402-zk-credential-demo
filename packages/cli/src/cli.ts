#!/usr/bin/env node
/**
 * ZK Session CLI
 * 
 * Command-line interface for managing ZK session credentials.
 */

import { Command } from 'commander';
import { ZkSessionClient, type PresentationStrategy } from './client.js';

const program = new Command();

program
  .name('zk-session')
  .description('CLI for ZK Session credentials')
  .version('0.1.0');

// Credential commands
const credentialCmd = program
  .command('credential')
  .description('Manage credentials');

credentialCmd
  .command('obtain')
  .description('Obtain a new credential from an issuer')
  .requiredOption('--issuer <url>', 'Issuer URL')
  .option('--amount <usdc>', 'Payment amount in USDC', '0.10')
  .option('--payer <address>', 'Payer address', '0xdemo')
  .action(async (options) => {
    const client = new ZkSessionClient();
    
    console.log(`Obtaining credential from ${options.issuer}...`);
    console.log(`Payment: $${options.amount} USDC (mock)`);
    
    try {
      const credential = await client.obtainCredential(options.issuer, {
        mock: {
          amountUSDC: parseFloat(options.amount),
          payer: options.payer,
        },
      });
      
      console.log('\n✓ Credential obtained successfully!\n');
      console.log(`  Service ID: ${credential.serviceId}`);
      console.log(`  Tier: ${credential.tier}`);
      console.log(`  Max Presentations: ${credential.maxPresentations}`);
      console.log(`  Expires: ${new Date(credential.expiresAt * 1000).toISOString()}`);
    } catch (err) {
      console.error('Failed to obtain credential:', (err as Error).message);
      process.exit(1);
    }
  });

credentialCmd
  .command('list')
  .description('List stored credentials')
  .action(() => {
    const client = new ZkSessionClient();
    const credentials = client.listCredentials();
    
    if (credentials.length === 0) {
      console.log('No credentials stored.');
      return;
    }
    
    console.log(`Found ${credentials.length} credential(s):\n`);
    
    for (const cred of credentials) {
      const status = client.getCredentialStatus(cred.serviceId);
      console.log(`Service: ${cred.serviceId}`);
      console.log(`  Tier: ${cred.tier}`);
      console.log(`  Status: ${status?.status}`);
      console.log(`  Used: ${cred.presentationCount}/${cred.maxPresentations}`);
      console.log(`  Expires in: ${Math.round((status?.expiresIn ?? 0) / 60)} minutes`);
      console.log(`  Issuer: ${cred.issuerUrl}`);
      console.log();
    }
  });

credentialCmd
  .command('status')
  .description('Check credential status')
  .option('--service <id>', 'Service ID (optional)')
  .action((options) => {
    const client = new ZkSessionClient();
    const status = client.getCredentialStatus(options.service);
    
    if (!status) {
      console.log('No credential found.');
      return;
    }
    
    console.log(`Credential Status: ${status.status.toUpperCase()}\n`);
    console.log(`  Service: ${status.credential.serviceId}`);
    console.log(`  Tier: ${status.credential.tier}`);
    console.log(`  Remaining: ${status.remainingPresentations} presentations`);
    console.log(`  Expires in: ${Math.round(status.expiresIn / 60)} minutes`);
  });

credentialCmd
  .command('clear')
  .description('Clear all stored credentials')
  .action(() => {
    const client = new ZkSessionClient();
    client.clearCredentials();
    console.log('All credentials cleared.');
  });

// Request command
program
  .command('request')
  .description('Make an authenticated request')
  .argument('<method>', 'HTTP method (GET, POST, etc.)')
  .argument('<url>', 'Request URL')
  .option('--data <json>', 'Request body (JSON)')
  .option('--strategy <strategy>', 'Presentation strategy', 'time-bucketed')
  .option('--force-unlinkable', 'Force unlinkable request')
  .action(async (method: string, url: string, options) => {
    const client = new ZkSessionClient({
      strategy: options.strategy as PresentationStrategy,
    });
    
    console.log(`${method} ${url}`);
    console.log(`Strategy: ${options.strategy}`);
    
    try {
      const fetchOptions: RequestInit = {
        method: method.toUpperCase(),
      };
      
      if (options.data) {
        fetchOptions.body = options.data;
        fetchOptions.headers = { 'Content-Type': 'application/json' };
      }
      
      const response = await client.makeAuthenticatedRequest(url, {
        ...fetchOptions,
        forceUnlinkable: options.forceUnlinkable,
      });
      
      console.log(`\nStatus: ${response.status} ${response.statusText}`);
      console.log(`Rate Limit Remaining: ${response.headers.get('X-RateLimit-Remaining')}`);
      
      const body = await response.json().catch(() => response.text());
      console.log('\nResponse:');
      console.log(JSON.stringify(body, null, 2));
    } catch (err) {
      console.error('Request failed:', (err as Error).message);
      process.exit(1);
    }
  });

// Demo command
program
  .command('demo')
  .description('Run full demo flow')
  .option('--issuer <url>', 'Issuer URL', 'http://localhost:3001')
  .option('--api <url>', 'API URL', 'http://localhost:3002')
  .action(async (options) => {
    console.log('=== ZK Session Demo ===\n');
    
    const client = new ZkSessionClient({
      strategy: 'time-bucketed',
      timeBucketSeconds: 60, // 1 minute for demo
    });
    
    // Step 1: Obtain credential
    console.log('Step 1: Obtaining credential...');
    try {
      const credential = await client.obtainCredential(options.issuer, {
        mock: { amountUSDC: 1.00, payer: '0xdemo' },
      });
      console.log(`✓ Got tier ${credential.tier} credential with ${credential.maxPresentations} presentations\n`);
    } catch (err) {
      console.error('Failed:', (err as Error).message);
      console.log('\nMake sure the issuer is running: npm run issuer');
      process.exit(1);
    }
    
    // Step 2: Make authenticated requests
    console.log('Step 2: Making authenticated requests...\n');
    
    const endpoints = [
      { method: 'GET', path: '/api/whoami' },
      { method: 'POST', path: '/api/chat', body: { message: 'Hello, ZK!' } },
      { method: 'GET', path: '/api/data' },
    ];
    
    for (const endpoint of endpoints) {
      const url = `${options.api}${endpoint.path}`;
      console.log(`  ${endpoint.method} ${endpoint.path}`);
      
      try {
        const response = await client.makeAuthenticatedRequest(url, {
          method: endpoint.method,
          body: endpoint.body ? JSON.stringify(endpoint.body) : undefined,
          headers: endpoint.body ? { 'Content-Type': 'application/json' } : undefined,
        });
        
        const body = await response.json();
        console.log(`    Status: ${response.status}, Remaining: ${response.headers.get('X-RateLimit-Remaining')}`);
        console.log(`    Response: ${JSON.stringify(body).slice(0, 80)}...`);
      } catch (err) {
        console.log(`    Error: ${(err as Error).message}`);
      }
      console.log();
    }
    
    // Step 3: Show credential status
    console.log('Step 3: Credential status');
    const status = client.getCredentialStatus();
    if (status) {
      console.log(`  Status: ${status.status}`);
      console.log(`  Remaining: ${status.remainingPresentations} presentations`);
      console.log(`  Expires in: ${Math.round(status.expiresIn / 60)} minutes`);
    }
    
    console.log('\n=== Demo Complete ===');
  });

program.parse();
