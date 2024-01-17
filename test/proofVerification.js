/*
  Verifies all proof test vectors, but does not test proof generation.
*/
/*global describe, before, it*/
import {API_ID_BBS_SHA, API_ID_BBS_SHAKE, hexToBytes, messages_to_scalars,
  prepareGenerators, proofVerify} from '../lib/BBS.js';
import {readdir, readFile} from 'fs/promises';
import {assert} from 'chai';

const maxL = 20; // Use when precomputing the generators

const SHA_PATH = './test/fixture_data/bls12-381-sha-256/';
const SHAKE_PATH = './test/fixture_data/bls12-381-shake-256/';

for(const api_id of [API_ID_BBS_SHA, API_ID_BBS_SHAKE]) {
  let path = SHA_PATH;
  if(api_id.includes('SHAKE-256')) {
    path = SHAKE_PATH;
  }
  // Read all the proof test files into JavaScript objects
  const vectorPath = path + 'proof/';
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
      gens = await prepareGenerators(maxL, api_id); // precompute generators
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
        const disclosedIndexes = vector.disclosedIndexes;
        // Test vector contains all the messages, NOT just the disclosed
        // messages!!!
        const disclosed_messages = vector.messages.filter((msg, i) =>
          disclosedIndexes.includes(i)
        );
        const messagesOctets = disclosed_messages.map(msg => hexToBytes(msg));
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
