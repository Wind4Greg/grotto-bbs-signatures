/*global console*/
import {bytesToHex, hexToBytes, messages_to_scalars, prepareGenerators,
  proofGen, proofVerify, publicFromPrivate} from '../lib/BBS.js';
// Some test messages in hex string format from draft
const hex_msgs = [
  '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
  '87a8bd656d49ee07b8110e1d8fd4f1dcef6fb9bc368c492d9bc8c4f98a739ac6',
  '96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90',
  'ac55fb33a75909edac8994829b250779298aa75d69324a365733f16c333fa943',
  'd183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151',
  '515ae153e22aae04ad16f759e07237b43022cb1ced4c176e0999c6a8ba5817cc',
  '496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2',
  '77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c23364568523f8b91',
  '7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b7320912416',
  'c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80'
];

const test_msgs = hex_msgs.map(hex => hexToBytes(hex)); // Convert to byte array
const msg_scalars = await messages_to_scalars(test_msgs); // hash to scalars
const gens = await prepareGenerators(test_msgs.length); // Enough for all msgs

const sk_bytes = hexToBytes(
  '4a39afffd624d69e81808b2e84385cc80bf86adadf764e030caa46c231f2a8d7');
const pk_bytes = publicFromPrivate(sk_bytes);
const header = hexToBytes('11223344556677889900aabbccddeeff');
/*eslint max-len: ["error", { "ignoreStrings": true, "ignoreComments": true }]*/
// From https://github.com/decentralized-identity/bbs-signature/blob/main/tooling/fixtures/fixture_data/bls12-381-sha-256/signature/signature004.json
const signature = hexToBytes('b058678021dba2313c65fadc469eb4f030264719e40fb93bbf68bdf79079317a0a36193288b7dcb983fae0bc3e4c077f145f99a66794c5d0510cb0e12c0441830817822ad4ba74068eb7f34eb11ce3ee606d86160fecd844dda9d04bed759a676b0c8868d3f97fbe2e8b574169bd73a3');
const ph = new Uint8Array();
const disclosed_indexes = [0, 1, 2, 3, 6, 7, 8, 9];
let result = await proofGen(pk_bytes, signature, header, ph, msg_scalars,
  disclosed_indexes, gens);
// console.log(`result length: ${result.length}`);
// console.log(`expected length: ${3*48 + 5*32 + 32*(msg_scalars.length - disclosed_indexes.length)}`);
console.log('Proof');
console.log(bytesToHex(result));
// Create proof bundle: pk_bytes, header, ph, disclosed msgs, disclosed indexes, proof, total messages
const disclosedMsgs = hex_msgs.filter(
  (msg, i) => disclosed_indexes.includes(i)
);
const proofBundle = {
  pk: bytesToHex(pk_bytes),
  header: bytesToHex(header),
  ph: bytesToHex(ph),
  disclosedIndexes: disclosed_indexes,
  disclosedMsgs,
  proof: bytesToHex(result)
};

console.log(proofBundle);

// Verify proof
const pk = hexToBytes(proofBundle.pk);
const proof = hexToBytes(proofBundle.proof);
const headerV = hexToBytes(proofBundle.header);
const phV = hexToBytes(proofBundle.ph);

// In the proof bundle messages are hex strings, need scalars
const dis_msg_octets = proofBundle.disclosedMsgs.map(hex => hexToBytes(hex));
const disclosed_msgs = await messages_to_scalars(dis_msg_octets);
const disclosed_indexesV = proofBundle.disclosedIndexes;
result = await proofVerify(pk, proof, headerV, phV, disclosed_msgs,
  disclosed_indexesV, gens);
console.log(`Proof verified: ${result}`);
