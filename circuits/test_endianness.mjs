import { Fr } from '@aztec/bb.js';

const one = new Fr(1n);
console.log('Fr(1) value:', one.value);

// Check first and last byte
const first = one.value[0];
const last = one.value[31];

if (first === 0 && last === 1) {
    console.log('Byte order: Big Endian (0...1)');
} else if (first === 1 && last === 0) {
    console.log('Byte order: Little Endian (1...0)');
} else {
    console.log('Unknown byte order');
}
