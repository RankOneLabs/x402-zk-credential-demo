// Test bb.js poseidon hash
import { Barretenberg, Fr } from '@aztec/bb.js';

const bb = await Barretenberg.new({ threads: 1 });

// Check available methods on bb
const proto = Object.getPrototypeOf(bb);
const methods = Object.getOwnPropertyNames(proto);
console.log('Methods containing "poseidon" or "hash":');
console.log(methods.filter(m => m.toLowerCase().includes('poseidon') || m.toLowerCase().includes('hash')));

// Try poseidon2Hash if available
const testInputs = [new Fr(1n), new Fr(2n), new Fr(3n), new Fr(4n), new Fr(5n)];
console.log('\nTest inputs:', testInputs.map(f => f.toString()));

// Check wasm exports
const wasm = bb.getWasm();
if (wasm.exports) {
    const poseidonExports = Object.keys(wasm.exports).filter(k => k.toLowerCase().includes('poseidon'));
    console.log('\nWasm exports with poseidon:', poseidonExports);
}

await bb.destroy();
