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
const sk_bytes = hexToBytes('4a39afffd624d69e81808b2e84385cc80bf86adadf764e030caa46c231f2a8d7');
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
let expected = '8fb17415378ec4462bc167be75583989e0528913da142239848ae88309805bfb3656bcff322e5d8fd1a7e40a660a62266099f27fa81ff5010443f36285f6f0758e4d701c444b20447cded906a3f2001714087f165f760369b901ccbe5173438b32ad195b005e2747492cf002cf51e498';
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
expected = 'b058678021dba2313c65fadc469eb4f030264719e40fb93bbf68bdf79079317a0a36193288b7dcb983fae0bc3e4c077f145f99a66794c5d0510cb0e12c0441830817822ad4ba74068eb7f34eb11ce3ee606d86160fecd844dda9d04bed759a676b0c8868d3f97fbe2e8b574169bd73a3';
console.log(`Test vector verified: ${resultString === expected}`);
verified = await verify(pk_bytes, signature, header, msg_scalars.slice(0, L),
  gens);
console.log(`Algorithm verified: ${verified}`);
