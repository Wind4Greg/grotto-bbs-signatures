/* global describe, it, before */
/*eslint max-len: ["error", { "ignoreStrings": true, "ignoreComments": true }]*/
/*
  Checks the generation of proofs and their subsequent algorithmic verification.
  This checks various different subsets of disclosed indices. Since during
  development we had some funky issues that arose with edge cases.
  Does NOT check generated proofs against test vectors. See proofGenSeeded.js
  for that.
*/
import {hexToBytes, messages_to_scalars, prepareGenerators,
  proofGen, proofVerify} from '../lib/BBS.js';
import {assert} from 'chai';

const sigBundleSHA = {
  signerKeyPair: {
    secretKey: '57887f6e42cbf2a76fae89370474abe3d0f2e9db5d66c3f60b13e4fc724cde4e',
    publicKey: 'a9df410a06798fafcc2a1cc004441c3cb831ffdc408500eb3c24f876714317798ec4ec7cfee653a4c3c44f6158ebebf70a0484cd7d8984a3325c154b7f39f8b1b97ab087e5218ab343011456953219b91cca6c5eb37613b2963e588691a42ec1'
  },
  header: '11223344556677889900aabbccddeeff',
  messages: [
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
  ],
  signature: '8f34cef031ce533fc060186a11ae01816499753e654cae2ec22158555e9a0e6fadb963661c73a0ccb1d3786702b1cad70bd529fafdc3ceff1ee5471091f7565f6f01324b7f08c546a4531a5ed722283e'
};

const sigBundleSHAKE = {
  signerKeyPair: {
    secretKey: '63bf6d84ff9dc4822dafb362189b5ef63bd89b8f44f6cefe3dd2dadfa9732e39',
    publicKey: 'acac86a688f260a1fda6291505e68c36df49684c65abb302b0527c77d1392a7b32954e553e910e93b6cc6c613dc25ed0070dba3a671f82dca905c9a8f2605d2b78a142896e849ce0cbe01f098c14d64809645c87d2b788c198e41db2b862199d'
  },
  header: '11223344556677889900aabbccddeeff',
  messages: [
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
  ],
  signature: '8a5fbcf75a54dc2b91c070610ad89fa89d32566baaa83a80cf901950dda5bce723d8d2aafe550a8b36a8dfe9a5f0affc1a1114341a2ecba3b575cfe0038c3e5f9487d32bf4cfe01d79acc9436c3e9bb7',
};

const ph = hexToBytes('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501');

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

for(const hashType of ['SHA-256', 'SHAKE-256']) {
  let sigBundle = sigBundleSHA;
  if(hashType == 'SHAKE-256') {
    sigBundle = sigBundleSHAKE;
  }
  const L = sigBundle.messages.length;
  describe('Proof Generation/Verification Random Scalars ' + hashType, function() {
    let gens; let msg_scalars; let headerBytes; let publicBytes; let signature;
    before(async function() {
      gens = await prepareGenerators(L, hashType); // precompute generators
      const messagesOctets = sigBundle.messages.map(msg => hexToBytes(msg));
      msg_scalars = await messages_to_scalars(messagesOctets, hashType);
      headerBytes = hexToBytes(sigBundle.header);
      publicBytes = hexToBytes(sigBundle.signerKeyPair.publicKey);
      signature = hexToBytes(sigBundle.signature);
    });

    for(const disclosed of disclosureTests) {
      it(`Messages disclosed: ${disclosed}`, async function() {
        const proof = await proofGen(publicBytes, signature, headerBytes,
          ph, msg_scalars, disclosed, gens, hashType);
        const disclosedMsgScalars = msg_scalars.filter(
          (msg, i) => disclosed.includes(i));
        // console.log(`proof: ${bytesToHex(proof)}`);
        const result = await proofVerify(publicBytes, proof, headerBytes,
          ph, disclosedMsgScalars, disclosed, gens, hashType);
        assert.isTrue(result);
      });
    }
  });
}
