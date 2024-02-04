/* global describe, it, before */
/*eslint max-len: ["error", { "ignoreStrings": true, "ignoreComments": true }]*/
/*
  Checks the generation of proofs and their subsequent algorithmic verification.
  This checks various different subsets of disclosed indices. Since during
  development we had some funky issues that arose with edge cases.
  Does NOT check generated proofs against test vectors. See proofGenSeeded.js
  for that.
*/
import {API_ID_BBS_SHA, API_ID_BBS_SHAKE, hexToBytes, messages_to_scalars,
  prepareGenerators, proofGen, proofVerify} from '../lib/BBS.js';
import {assert} from 'chai';
import {readFile} from 'fs/promises';

// These are signature files for 10 messages
const SHA_PATH = './test/fixture_data/bls12-381-sha-256/signature/signature004.json';
const SHAKE_PATH = './test/fixture_data/bls12-381-shake-256/signature/signature004.json';

const sigBundleSHA = JSON.parse(await readFile(SHA_PATH));
// console.log(testFiles);

const sigBundleSHAKE = JSON.parse(await readFile(SHAKE_PATH));

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

for(const api_id of [API_ID_BBS_SHA, API_ID_BBS_SHAKE]) {
  let sigBundle = sigBundleSHA;
  if(api_id.includes('SHAKE-256')) {
    sigBundle = sigBundleSHAKE;
  }
  const L = sigBundle.messages.length;
  describe('Proof Generation/Verification Random Scalars ' + api_id, function() {
    let gens; let msg_scalars; let headerBytes; let publicBytes; let signature;
    before(async function() {
      gens = await prepareGenerators(L + 1, api_id); // precompute generators
      const messagesOctets = sigBundle.messages.map(msg => hexToBytes(msg));
      msg_scalars = await messages_to_scalars(messagesOctets, api_id);
      headerBytes = hexToBytes(sigBundle.header);
      publicBytes = hexToBytes(sigBundle.signerKeyPair.publicKey);
      signature = hexToBytes(sigBundle.signature);
    });

    for(const disclosed of disclosureTests) {
      it(`Messages disclosed: ${disclosed}`, async function() {
        const proof = await proofGen(publicBytes, signature, headerBytes,
          ph, msg_scalars, disclosed, gens, api_id);
        const disclosedMsgScalars = msg_scalars.filter(
          (msg, i) => disclosed.includes(i));
        // console.log(`proof: ${bytesToHex(proof)}`);
        const result = await proofVerify(publicBytes, proof, headerBytes,
          ph, disclosedMsgScalars, disclosed, gens, api_id);
        assert.isTrue(result);
      });
    }
  });
}
