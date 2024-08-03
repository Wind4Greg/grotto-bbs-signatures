/* global describe, it, TextEncoder */
/* eslint-disable max-len */
import {API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE, hexToBytes,
  seeded_random_scalars} from '../lib/BBS.js';
import {readdir, readFile} from 'fs/promises';
import {assert} from 'chai';
import {ProofGenWithPseudonym} from '../lib/PseudonymBBS.js';
import {bytesToHex} from '@noble/hashes/utils';

import {dirname} from 'path';
import {fileURLToPath} from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

const SHA_PATH = __dirname + '/fixture_data/bls12-381-sha-256/proof/';
const SHAKE_PATH = __dirname + '/fixture_data/bls12-381-shake-256/proof/';
const allMessagesFile = __dirname + '/fixture_data/messages.json';

const allMessages = JSON.parse(await readFile(allMessagesFile));
const messages = allMessages.map(hexMsg => hexToBytes(hexMsg));
for(const api_id of [API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE]) { //  
  let path = SHA_PATH;
  if(api_id.includes('SHAKE-256')) {
    path = SHAKE_PATH;
  }
  const files = await readdir(path);
  // get all the test vectors in the dir
  const testVectors = [];
  for(const fn of files) {
    testVectors.push(JSON.parse(await readFile(path + fn)));
  }

  describe('Proof generation for ' + api_id, async function() {
    for(let i = 0; i < testVectors.length; i++) { // testVectors.length
      const proofFixture = testVectors[i];
      it(`case: ${proofFixture.caseName}`, async function() {
        const PK = hexToBytes(proofFixture.signerPublicKey);
        const signature = hexToBytes(proofFixture.signature);
        const header = hexToBytes(proofFixture.header);
        const ph = hexToBytes(proofFixture.presentationHeader);
        const pseudonym = hexToBytes(proofFixture.pseudonym);
        const verifier_id = hexToBytes(proofFixture.verifier_id);
        const pid = hexToBytes(proofFixture.pid);
        const disclosedIndexes = proofFixture.disclosedIndexes;
        // Pseudo random (deterministic) scalar generation seed and function
        const rngParams = proofFixture.mockRngParameters;
        const te = new TextEncoder();
        const seed = te.encode(rngParams.SEED);
        const rng_dst = rngParams.proof.DST;
        const rand_scalar_func = seeded_random_scalars.bind(null, seed, rng_dst);

        const proof = await ProofGenWithPseudonym(PK, signature, pseudonym, verifier_id,
          pid, header, ph, messages, disclosedIndexes, api_id, rand_scalar_func);
        // console.log(`proof: ${bytesToHex(proof)}`);
        assert.equal(bytesToHex(proof), proofFixture.proof);
      });
    }
  });
}
