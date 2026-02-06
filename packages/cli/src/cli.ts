#!/usr/bin/env node
/**
 * ZK Credential CLI
 * 
 * Command-line interface for managing ZK credentials.
 */

import { Command } from 'commander';
import { ZkCredentialClient, type PresentationStrategy } from './client.js';

const program = new Command();

program
  .name('zk-credential')
  .description('CLI for ZK credentials')
  .version('0.1.0');

// Credential commands
const credentialCmd = program
  .command('credential')
  .description('Manage credentials');

// credential obtain command removed (deprecated flow)
// Use the demo script or update to use API mediation
// credentialCmd.command('obtain')...

credentialCmd
  .command('list')
  .description('List stored credentials')
  .action(() => {
    const client = new ZkCredentialClient();
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
      console.log(`  Used: ${cred.presentationCount}/${cred.presentationBudget}`);
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
    const client = new ZkCredentialClient();
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
    const client = new ZkCredentialClient();
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
    const client = new ZkCredentialClient({
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
// demo command removed (deprecated flow)
// Use 'npm run demo' to run src/demo.ts
// program.command('demo')...

program.parse();
