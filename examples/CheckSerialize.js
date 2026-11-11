/* global console */
import {bls12_381 as bls} from '@noble/curves/bls12-381.js';
import {bytesToHex} from '../lib/BBS.js';
import {expand_message_xmd} from '@noble/curves/abstract/hash-to-curve.js';
import {sha256} from '@noble/hashes/sha2.js';

console.log(bls.G1.Point.BASE);
console.log(bls.G1.Point.BASE.toHex(true));
console.log(bls.G1.Point.BASE.toHex(false));

const result = expand_message_xmd(new Uint8Array([1, 2]),
  new Uint8Array([3, 4, 5]), 64, sha256);
console.log('Expand message xmd result:');
console.log(bytesToHex(result));
