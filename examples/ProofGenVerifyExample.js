/*global console*/
import {bytesToHex, hexToBytes, messages_to_scalars, prepareGenerators,
  proofGen, proofVerify, publicFromPrivate} from '../lib/BBS.js';
// Some test messages in hex string format from draft
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
const msg_scalars = await messages_to_scalars(test_msgs); // hash to scalars
const gens = await prepareGenerators(test_msgs.length); // Enough for all msgs

const sk_bytes = hexToBytes(
  '60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc');
const pk_bytes = publicFromPrivate(sk_bytes);
const header = hexToBytes('11223344556677889900aabbccddeeff');
/*eslint max-len: ["error", { "ignoreStrings": true, "ignoreComments": true }]*/
// From https://github.com/decentralized-identity/bbs-signature/blob/main/tooling/fixtures/fixture_data/bls12-381-sha-256/signature/signature004.json
const signature = hexToBytes('895cd9c0ccb9aca4de913218655346d718711472f2bf1f3e68916de106a0d93cf2f47200819b45920bbda541db2d91480665df253fedab2843055bdc02535d83baddbbb2803ec3808e074f71f199751e');
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
