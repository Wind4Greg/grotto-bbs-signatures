/*global TextEncoder, console*/
/* eslint-disable max-len */
import { hexToBytes } from '@noble/hashes/utils';
import {bytesToHex, calculate_random_scalars, concat, hash_to_scalar, messages_to_scalars,
    octets_to_sig, octets_to_proof, os2ip,  numberToHex}
    from '../lib/BBS.js';
import {hash_to_curve_g1} from '../lib/PseudonymBBS.js';
import {bls12_381 as bls} from '@noble/curves/bls12-381';
import { API_ID_PSEUDONYM_BBS_SHA } from '../lib/BBS.js';

// OP is the verifier_id as a curve point
const OP = bls.G1.ProjectivePoint.fromHex(hexToBytes('83f72c76d9bdc5765d0bc3bd4e1c5fc0428cb894fe53a62fdad80c28d295005b0f378d637bda32c1aa3df77c6d3ab884'));
// pseudonym should be OP raised to the pid_scalar
const pseudonym = bls.G1.ProjectivePoint.fromHex(hexToBytes('a48177347fd65ec55ebaf18a40e82292cfc9de91003dd9db2cfdceaf956ec3c1c096f8995d8b1f11800b20c5b62af5a4'));
const pid = hexToBytes('6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418');
const verifier_id = hexToBytes('bbb4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a');
const OPCheck = await hash_to_curve_g1(verifier_id, API_ID_PSEUDONYM_BBS_SHA);
const Ut = bls.G1.ProjectivePoint.fromHex(hexToBytes('b125c1eec25365b285d078a29820b11b94edda3371480d858c544538fb229b892ba3090e5a1613a1102058d43b05ffc2'));
console.log(`OPCheck: ${bytesToHex(OPCheck.toRawBytes(true))}`);
const [pid_scalar] = await messages_to_scalars([pid], API_ID_PSEUDONYM_BBS_SHA);
const challenge = BigInt('0x' + '48609481c50893e50834e54724279645a2149830d2151bcbc642438e5e4a0c4c');
// check pidHat calculation
const pidTilde = BigInt('0x' + '4c583e5e4fc913aa71989afc50cfd8c2024d64df96ed12c7ef82d50ed4d8bb1b');
const pidHat = bls.fields.Fr.add(pidTilde,
    bls.fields.Fr.mul(pid_scalar, challenge));
console.log(`pidHat: ${numberToHex(pidHat, 32)}`);
const pseudoCheck = OP.multiply(pid_scalar);
// const pidHat = BigInt('0x' + '2fe88334bfeb16b0b48262ecbe4bb511875948d11a8abc86380f11a8d130b639');
// console.log(`pidHat: ${pidHat}`);

let Uv = OP.multiply(pidHat);
Uv = Uv.subtract(pseudonym.multiply(challenge));
console.log(`Uv: ${bytesToHex(Uv.toRawBytes(true))}`);
console.log(`confirm pseudonym: ${pseudoCheck.equals(pseudonym)}`);
console.log(`pseudocheck: ${bytesToHex(pseudoCheck.toRawBytes(true))}`);