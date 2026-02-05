
import {
    SchemeNetworkClient,
    PaymentRequirements,
    PaymentPayload,
    Network
} from '@x402/core/types';
import {
    createWalletClient,
    createPublicClient,
    http,
    parseAbi,
    Account,
    PublicClient,
    WalletClient,
    Transport,
    Chain
} from 'viem';
import { baseSepolia } from 'viem/chains';

/**
 * A custom EVM scheme that performs a simple ERC20 transfer and returns the txHash.
 * Compatible with the current Facilitator implementation.
 */
export class TransferEvmScheme implements SchemeNetworkClient {
    public readonly scheme = 'exact'; // Reusing 'exact' as the facilitator expects this scheme name in 402?
    // Actually, standard says 'exact' usually. 
    // But our facilitator v2 might default to 'exact'.
    // Let's use 'transfer-evm' or similar if distinct, 
    // but for compatibility with "ExactEvmScheme" replacement, we might need 'exact' 
    // IF the server asks for 'exact'.
    // The demo server asks for 'exact' in the 402 response (Step 307: expect...scheme).toBe('exact')).

    private publicClient: PublicClient<Transport, Chain>;
    private walletClient: WalletClient<Transport, Chain, Account>;
    private usdcAddress: `0x${string}`;

    // ERC20 ABI (minimal)
    private static ABI = parseAbi([
        'function transfer(address to, uint256 amount) returns (bool)',
    ]);

    constructor(
        account: Account,
        rpcUrl: string,
        usdcAddress: `0x${string}`
    ) {
        this.usdcAddress = usdcAddress;
        // Use 'as any' to bypass viem chain type incompatibility between baseSepolia and generic Chain
        this.publicClient = createPublicClient({
            chain: baseSepolia,
            transport: http(rpcUrl)
        }) as any;
        this.walletClient = createWalletClient({
            account,
            chain: baseSepolia,
            transport: http(rpcUrl)
        }) as any;
    }

    async createPaymentPayload(
        x402Version: number,
        requirements: PaymentRequirements
    ): Promise<Pick<PaymentPayload, 'x402Version' | 'payload'> & { scheme: string }> {

        console.log(`[TransferEvmScheme] Paying ${requirements.amount} ${requirements.asset} to ${requirements.payTo}`);

        // Check if asset matches (simple check)
        if (requirements.asset !== 'USDC') {
            throw new Error(`Unsupported asset: ${requirements.asset}`);
        }

        const txHash = await this.walletClient.writeContract({
            address: this.usdcAddress,
            abi: TransferEvmScheme.ABI,
            functionName: 'transfer',
            args: [requirements.payTo as `0x${string}`, BigInt(requirements.amount)]
        });

        console.log(`[TransferEvmScheme] Tx Sent: ${txHash}`);

        await this.publicClient.waitForTransactionReceipt({ hash: txHash });
        console.log(`[TransferEvmScheme] Tx Confirmed`);

        return {
            x402Version,
            scheme: this.scheme,
            payload: {
                txHash,
                // Facilitator v2 expects 'paymentPayload' structure, 
                // x402Client usually puts 'payload' into the body.
                // We match the 'SettlementRequest' shape: { paymentPayload: { txHash } }
                // Wait, standard x402Client might wrap it differently?
                // Standard x402Client sends: { payment: payload, ... }
                // Our facilitator expects: { paymentPayload: { txHash } }
                // So payload should be { txHash }
            }
        };
    }
}
