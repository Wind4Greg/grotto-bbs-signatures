
import { sign, verify, messages_to_scalars, prepareGenerators, os2ip, hexToBytes, bytesToHex } from '../lib/BBS.js';
import {bls12_381 as bls} from '@noble/curves/bls12-381';

let test_msgs = [
    hexToBytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"),
    hexToBytes("87a8bd656d49ee07b8110e1d8fd4f1dcef6fb9bc368c492d9bc8c4f98a739ac6"),
    hexToBytes("96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90"),
    hexToBytes("ac55fb33a75909edac8994829b250779298aa75d69324a365733f16c333fa943"),
    hexToBytes("d183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151"),
    hexToBytes("515ae153e22aae04ad16f759e07237b43022cb1ced4c176e0999c6a8ba5817cc"),
    hexToBytes("496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2"),
    hexToBytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c23364568523f8b91"),
    hexToBytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b7320912416"),
    hexToBytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80")
];

let msg_scalars = await messages_to_scalars(test_msgs);

let gens = await prepareGenerators(test_msgs.length); // Generate enough for all messages

// Prepare private and public keys
let sk_bytes = hexToBytes("4a39afffd624d69e81808b2e84385cc80bf86adadf764e030caa46c231f2a8d7");
let pointPk = bls.G2.ProjectivePoint.fromPrivateKey(sk_bytes);
let pk_bytes = pointPk.toRawBytes(true);
let sk_scalar = os2ip(sk_bytes);

let header = hexToBytes("11223344556677889900aabbccddeeff");

// Try signing with a single message
let L = 1;
let signature = await sign(sk_scalar, pk_bytes, header, msg_scalars.slice(0, L), gens);
console.log("Complete signature single message:")
let resultString = bytesToHex(signature);
console.log(resultString);
// From https://github.com/decentralized-identity/bbs-signature/blob/main/tooling/fixtures/fixture_data/bls12-381-sha-256/signature/signature001.json
let expected = "8e65ee0ea2d5f8ccb5fe03e1f985960dab25cfd1f4035cddd74f1b48d12fe24c621c5f9f56f23845ecee82ae207371ac39f37eb451b7a1ea7e41afb1436d28eef1016674ff320f70ab1537d3da8ed48d201594558a35a8503b12abbe02b5ed805baec5d20c263134934f1991dd4d3125";
console.log(`Test vector verified: ${resultString === expected}`);
let verified = await verify(pk_bytes, signature, header, msg_scalars.slice(0,L), gens);
console.log(`Algorithm verified: ${verified}`);

L = 10; // Try with all 10 messages
signature = await sign(sk_scalar, pk_bytes, header, msg_scalars.slice(0, L), gens);
console.log("Complete signature 10 messages:")
resultString = bytesToHex(signature);
console.log(resultString);
// From https://github.com/decentralized-identity/bbs-signature/blob/main/tooling/fixtures/fixture_data/bls12-381-sha-256/signature/signature004.json
expected = "b13ae29b49e313b1c0983056e80cfb8d84a81985ca7488557aaf9b923f1e67994cab0e5ab05c75ffcf3fde1c23207ce5218dcfec42e9cc0063ff488100f89ba08296ced4923052e597279e1f775b157c55ed6b32ba777c3eec754bda4ab096e4147f2587248ba47b22226aee2aeafd85";
console.log(`Test vector verified: ${resultString === expected}`);
verified = await verify(pk_bytes, signature, header, msg_scalars.slice(0,L), gens);
console.log(`Algorithm verified: ${verified}`);
