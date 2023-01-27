/* 
  Checks the generation of proofs and their subsequent verification.
  This checks various different subsets of disclosed indices. Since during development
  we had some funky issues that arose with edge cases.
*/
import { assert } from 'chai';
import { bytesToHex, hexToBytes, proofGen, proofVerify, prepareGenerators, messages_to_scalars } from '../lib/BBS.js';


const sigBundle = {
  "signerKeyPair": {
    "secretKey": "47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56",
    "publicKey": "b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7"
  },
  "header": "11223344556677889900aabbccddeeff",
  "messages": [
    "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
    "87a8bd656d49ee07b8110e1d8fd4f1dcef6fb9bc368c492d9bc8c4f98a739ac6",
    "96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90",
    "ac55fb33a75909edac8994829b250779298aa75d69324a365733f16c333fa943",
    "d183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151",
    "515ae153e22aae04ad16f759e07237b43022cb1ced4c176e0999c6a8ba5817cc",
    "496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2",
    "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c23364568523f8b91",
    "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b7320912416",
    "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"
  ],
  "signature": "b9c68aa75ed3510d2c3dd06d962106b888073b9468db2bde45c42ed32d3a04ffc14e0854ce219b77ce845fe7b06e200f66f64cb709e83a367586a70dc080b0fe242444b7cfd08977d74d91be64b468485774792526992181bc8b2d40a913c9bf561b2eeb0e149bfb7dc05d3607903513",
};

let L = sigBundle.messages.length;

const ph = hexToBytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");

// A selection of different choices of disclosed messages
const disclosureTests = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [0],
  [9],
  [0, 1, 2],
  [7, 8, 9],
  [0, 2, 4, 6, 8],
  [1, 3, 5, 7, 9],
  [0, 1, 8, 9]
];

describe('Proof Generation', function () {
  let gens, msg_scalars, headerBytes, publicBytes, signature;
  before(async function () {
    gens = await prepareGenerators(L); // precompute generators
    let messagesOctets = sigBundle.messages.map(msg => hexToBytes(msg));
    msg_scalars = await messages_to_scalars(messagesOctets);
    headerBytes = hexToBytes(sigBundle.header);
    publicBytes = hexToBytes(sigBundle.signerKeyPair.publicKey);
    signature = hexToBytes(sigBundle.signature);
  });

  for (let disclosed of disclosureTests) {
    it(`Messages disclosed: ${disclosed}`, async function () {
      let proof = await proofGen(publicBytes, signature, headerBytes, ph, msg_scalars, disclosed, gens);
      let disclosedMsgScalars = msg_scalars.filter((msg, i) => disclosed.includes(i));
      // console.log(`proof: ${bytesToHex(proof)}`);
      let result = await proofVerify(publicBytes, proof, L, headerBytes, ph, disclosedMsgScalars,
        disclosed, gens);
      assert.isTrue(result);
    });
  }
});
