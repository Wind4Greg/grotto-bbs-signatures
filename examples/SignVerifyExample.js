/*global console*/
/*eslint max-len: ["error", { "ignoreStrings": true, "ignoreComments": true }]*/
import {bytesToHex, hexToBytes, messages_to_scalars, prepareGenerators,
  publicFromPrivate, sign, verify} from '../lib/BBS.js';

const test_msgs = [
  hexToBytes('9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02'),
  hexToBytes('87a8bd656d49ee07b8110e1d8fd4f1dcef6fb9bc368c492d9bc8c4f98a739ac6'),
  hexToBytes('96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90'),
  hexToBytes('ac55fb33a75909edac8994829b250779298aa75d69324a365733f16c333fa943'),
  hexToBytes('d183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151'),
  hexToBytes('515ae153e22aae04ad16f759e07237b43022cb1ced4c176e0999c6a8ba5817cc'),
  hexToBytes('496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2'),
  hexToBytes('77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c23364568523f8b91'),
  hexToBytes('7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b7320912416'),
  hexToBytes('c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80')
];

const msg_scalars = await messages_to_scalars(test_msgs);

const gens = await prepareGenerators(test_msgs.length); // Generate enough for all messages

// Prepare private and public keys
const sk_bytes = hexToBytes('57887f6e42cbf2a76fae89370474abe3d0f2e9db5d66c3f60b13e4fc724cde4e');
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
let expected = '997e314ef7aba8c416719faafd2ec389a6d6fcc224a8a679a1f504f141242287a87166c3c90c1aacc989f08e303fde125977bc9cfbdbc4beb12ae4b12af757a75b1b8e245f2595b191078741bb533064';
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
expected = '8f34cef031ce533fc060186a11ae01816499753e654cae2ec22158555e9a0e6fadb963661c73a0ccb1d3786702b1cad70bd529fafdc3ceff1ee5471091f7565f6f01324b7f08c546a4531a5ed722283e';
console.log(`Test vector verified: ${resultString === expected}`);
verified = await verify(pk_bytes, signature, header, msg_scalars.slice(0, L),
  gens);
console.log(`Algorithm verified: ${verified}`);
