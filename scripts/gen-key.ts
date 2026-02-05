
import { derivePublicKey } from '../packages/crypto/src/schnorr.js';
import { bigIntToHex } from '../packages/crypto/src/utils.js';

async function main() {
    const secretKey = BigInt('0x1234567890abcdef');
    const publicKey = await derivePublicKey(secretKey);
    console.log('Secret Key:', bigIntToHex(secretKey));
    console.log('Public Key X:', bigIntToHex(publicKey.x));
    console.log('Public Key Y:', bigIntToHex(publicKey.y));
}

main().catch(console.error);
