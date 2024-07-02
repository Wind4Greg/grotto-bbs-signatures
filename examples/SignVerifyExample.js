/*global console*/
/*eslint max-len: ["error", { "ignoreStrings": true, "ignoreComments": true }]*/
import {API_ID_BBS_SHAKE, bytesToHex, hexToBytes, messages_to_scalars,
  prepareGenerators, publicFromPrivate, sign, verify} from '../lib/BBS.js';

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

const msg_scalars = await messages_to_scalars(test_msgs, API_ID_BBS_SHAKE);

const gens = await prepareGenerators(test_msgs.length + 1, API_ID_BBS_SHAKE); // Generate enough for all messages

// Prepare private and public keys
const sk_bytes = hexToBytes('2eee0f60a8a3a8bec0ee942bfd46cbdae9a0738ee68f5a64e7238311cf09a079');
const pk_bytes = publicFromPrivate(sk_bytes);

const header = hexToBytes('11223344556677889900aabbccddeeff');

// Try signing with a single message
let L = 1;
let signature = await sign(sk_bytes, pk_bytes, header, msg_scalars.slice(0, L),
  gens, API_ID_BBS_SHAKE);
console.log('Complete signature single message:');
let resultString = bytesToHex(signature);
console.log(resultString);
// From https://github.com/decentralized-identity/bbs-signature/blob/main/tooling/fixtures/fixture_data/bls12-381-shake-256/signature/signature001.json
let expected = 'b9a622a4b404e6ca4c85c15739d2124a1deb16df750be202e2430e169bc27fb71c44d98e6d40792033e1c452145ada95030832c5dc778334f2f1b528eced21b0b97a12025a283d78b7136bb9825d04ef';
console.log(`Test vector verified: ${resultString === expected}`);
let verified = await verify(pk_bytes, signature, header,
  msg_scalars.slice(0, L), gens, API_ID_BBS_SHAKE);
console.log(`Algorithm verified: ${verified}`);

L = 10; // Try with all 10 messages
signature = await sign(sk_bytes, pk_bytes, header, msg_scalars.slice(0, L),
  gens, API_ID_BBS_SHAKE);
console.log('Complete signature 10 messages:');
resultString = bytesToHex(signature);
console.log(resultString);
// From https://github.com/decentralized-identity/bbs-signature/blob/main/tooling/fixtures/fixture_data/bls12-381-shake-256/signature/signature004.json
expected = '956a3427b1b8e3642e60e6a7990b67626811adeec7a0a6cb4f770cdd7c20cf08faabb913ac94d18e1e92832e924cb6e202912b624261fc6c59b0fea801547f67fb7d3253e1e2acbcf90ef59a6911931e';
console.log(`Test vector verified: ${resultString === expected}`);
verified = await verify(pk_bytes, signature, header, msg_scalars.slice(0, L),
  gens, API_ID_BBS_SHAKE);
console.log(`Algorithm verified: ${verified}`);
