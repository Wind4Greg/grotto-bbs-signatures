/*
  Verifies all Blind proof test vectors, but does not test proof generation.
*/
/*global describe, before, it*/
/* eslint-disable max-len */
import {API_ID_BLIND_BBS_SHA, API_ID_BLIND_BBS_SHAKE, hexToBytes, messages_to_scalars,
  prepareGenerators, proofVerify} from '../lib/BBS.js';
import {readdir, readFile} from 'fs/promises';
import {assert} from 'chai';
import {dirname} from 'path';
import {fileURLToPath} from 'url';

const maxL = 20; // Use when precomputing the generators
const __dirname = dirname(fileURLToPath(import.meta.url));
const SHA_PATH = __dirname + '/fixture_data/bls12-381-sha-256/proof/';
const SHAKE_PATH = __dirname + '/fixture_data/bls12-381-shake-256/proof/';

for(const api_id of [API_ID_BLIND_BBS_SHA, API_ID_BLIND_BBS_SHAKE]) {
  let path = SHA_PATH;
  if(api_id.includes('SHAKE-256')) {
    path = SHAKE_PATH;
  }
  // Read all the proof test files into JavaScript objects
  const vectorPath = path;
  const testFiles = await readdir(vectorPath);
  // console.log(testFiles);
  const testVectors = [];
  for(const fn of testFiles) {
    const testVector = JSON.parse(await readFile(vectorPath + fn));
    testVectors.push(testVector);
    // for debugging only remove
    // if(fn === 'proof003.json') {
    //   break;
    // }
    // console.log(testVector);
  }

  describe('Proof Verification ' + api_id, function() {
    let gens;
    before(async function() {
      gens = await prepareGenerators(maxL + 1, api_id); // precompute generators
    });

    for(const vector of testVectors) {
      // Create test name
      let testName = vector.caseName;
      if(vector.result.valid) {
        testName += ':valid';
      } else {
        testName += ':invalid:' + vector.result.reason;
      }

      it(testName + ' ' + api_id, async function() {
        // From the test vector get the disclosed indices and messages
        const disclosedData = vector.disclosedData;
        const disclosedIndexes = Object.keys(disclosedData).map(s => parseInt(s));
        const messagesOctets = Object.values(disclosedData).map(msg => hexToBytes(msg));
        // console.log(disclosedIndexes);
        // console.log(messagesOctets);
        const disclosedMsgScalars = await messages_to_scalars(messagesOctets,
          api_id);
        const headerBytes = hexToBytes(vector.header);
        const publicBytes = hexToBytes(vector.signerPublicKey);
        const proof = hexToBytes(vector.proof);
        const ph = hexToBytes(vector.presentationHeader);
        const result = await proofVerify(publicBytes, proof, headerBytes, ph,
          disclosedMsgScalars, disclosedIndexes, gens, api_id);
        assert.equal(result, vector.result.valid);
      });
    }
  });
}
