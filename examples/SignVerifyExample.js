/*global console*/
/*eslint max-len: ["error", { "ignoreStrings": true, "ignoreComments": true }]*/
import {bytesToHex, hexToBytes, messages_to_scalars, prepareGenerators,
  publicFromPrivate, sign, verify} from '../lib/BBS.js';

const hex_msgs = [
  '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
  'c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80',
  '7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73',
  '77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c',
  '496694774c5604ab1b2544eababcf0f53278ff50',
  '515ae153e22aae04ad16f759e07237b4',
  'd183ddc6e2665aa4e2f088af',
  'ac55fb33a75909ed',
  '96012096',
  ''
];

const test_msgs = hex_msgs.map(hex => hexToBytes(hex)); // Convert to byte array

const msg_scalars = await messages_to_scalars(test_msgs);

const gens = await prepareGenerators(test_msgs.length); // Generate enough for all messages

// Prepare private and public keys
const sk_bytes = hexToBytes('60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc');
const pk_bytes = publicFromPrivate(sk_bytes);

const header = hexToBytes('11223344556677889900aabbccddeeff');

// Try signing with a single message
let L = 1;
let signature = await sign(sk_bytes, pk_bytes, header, msg_scalars.slice(0, L),
  gens);
console.log('Complete signature single message:');
let resultString = bytesToHex(signature);
console.log(resultString);
// From https://github.com/decentralized-identity/bbs-signature/blob/main/tooling/fixtures/fixture_data/bls12-381-sha-256/signature/signature001.json
let expected = '88c0eb3bc1d97610c3a66d8a3a73f260f95a3028bccf7fff7d9851e2acd9f3f32fdf58a5b34d12df8177adf37aa318a20f72be7d37a8e8d8441d1bc0bc75543c681bf061ce7e7f6091fe78c1cb8af103';
console.log(`Test vector verified: ${resultString === expected}`);
let verified = await verify(pk_bytes, signature, header,
  msg_scalars.slice(0, L), gens);
console.log(`Algorithm verified: ${verified}`);

L = 10; // Try with all 10 messages
signature = await sign(sk_bytes, pk_bytes, header, msg_scalars.slice(0, L),
  gens);
console.log('Complete signature 10 messages:');
resultString = bytesToHex(signature);
console.log(resultString);
// From https://github.com/decentralized-identity/bbs-signature/blob/main/tooling/fixtures/fixture_data/bls12-381-sha-256/signature/signature004.json
expected = '895cd9c0ccb9aca4de913218655346d718711472f2bf1f3e68916de106a0d93cf2f47200819b45920bbda541db2d91480665df253fedab2843055bdc02535d83baddbbb2803ec3808e074f71f199751e';
console.log(`Test vector verified: ${resultString === expected}`);
verified = await verify(pk_bytes, signature, header, msg_scalars.slice(0, L),
  gens);
console.log(`Algorithm verified: ${verified}`);
