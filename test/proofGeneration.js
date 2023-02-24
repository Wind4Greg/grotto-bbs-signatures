/* 
  Checks the generation of proofs and their subsequent algorithmic verification.
  This checks various different subsets of disclosed indices. Since during development
  we had some funky issues that arose with edge cases.
  Does NOT check generated proofs against test vectors. See proofGenSeeded.js for that.
*/
import { assert } from 'chai';
import { bytesToHex, hexToBytes, proofGen, proofVerify, prepareGenerators, messages_to_scalars } from '../lib/BBS.js';


const sigBundleSHA = {
  "signerKeyPair": {
    "secretKey": "4a39afffd624d69e81808b2e84385cc80bf86adadf764e030caa46c231f2a8d7",
    "publicKey": "aaff983278257afc45fa9d44d156c454d716fb1a250dfed132d65b2009331f618c623c14efa16245f50cc92e60334051087f1ae92669b89690f5feb92e91568f95a8e286d110b011e9ac9923fd871238f57d1295395771331ff6edee43e4ccc6"
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
  "signature": "b13ae29b49e313b1c0983056e80cfb8d84a81985ca7488557aaf9b923f1e67994cab0e5ab05c75ffcf3fde1c23207ce5218dcfec42e9cc0063ff488100f89ba08296ced4923052e597279e1f775b157c55ed6b32ba777c3eec754bda4ab096e4147f2587248ba47b22226aee2aeafd85",
};

const sigBundleSHAKE = {
  "signerKeyPair": {
    "secretKey": "4a39afffd624d69e81808b2e84385cc80bf86adadf764e030caa46c231f2a8d7",
    "publicKey": "aaff983278257afc45fa9d44d156c454d716fb1a250dfed132d65b2009331f618c623c14efa16245f50cc92e60334051087f1ae92669b89690f5feb92e91568f95a8e286d110b011e9ac9923fd871238f57d1295395771331ff6edee43e4ccc6"
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
  "signature": "816da6afb697e0de28e765753977c5b46211d8db85b03f189a8869b80eeae766b7e99aae2553a148b0e4fcee76b17d801c88ec4ef8c6a1edb08eb0422ae8c8162f71c9407e0eea81f3705cb433542e9569a47a7c70e1578fbf67c788685a292f4715375246ce3f61c65513242f411978",
}



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

for (let hashType of ["SHA-256", "SHAKE-256"]) {
  let sigBundle = sigBundleSHA;
  if (hashType == "SHAKE-256") {
    sigBundle = sigBundleSHAKE;
  }
  let L = sigBundle.messages.length;
  describe('Proof Generation/Verification Random Scalars ' + hashType, function () {
    let gens, msg_scalars, headerBytes, publicBytes, signature;
    before(async function () {
      gens = await prepareGenerators(L, hashType); // precompute generators
      let messagesOctets = sigBundle.messages.map(msg => hexToBytes(msg));
      msg_scalars = await messages_to_scalars(messagesOctets, hashType);
      headerBytes = hexToBytes(sigBundle.header);
      publicBytes = hexToBytes(sigBundle.signerKeyPair.publicKey);
      signature = hexToBytes(sigBundle.signature);
    });

    for (let disclosed of disclosureTests) {
      it(`Messages disclosed: ${disclosed}`, async function () {
        let proof = await proofGen(publicBytes, signature, headerBytes, ph, msg_scalars, disclosed, gens, hashType);
        let disclosedMsgScalars = msg_scalars.filter((msg, i) => disclosed.includes(i));
        // console.log(`proof: ${bytesToHex(proof)}`);
        let result = await proofVerify(publicBytes, proof, L, headerBytes, ph, disclosedMsgScalars,
          disclosed, gens, hashType);
        assert.isTrue(result);
      });
    }
  });
}