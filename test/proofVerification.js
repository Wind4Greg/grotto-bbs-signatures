/*
  Verifies all proof test vectors, but does not test proof generation.
*/
/*global describe, before, it*/
import {hexToBytes, messages_to_scalars, prepareGenerators, proofVerify}
  from '../lib/BBS.js';
import {readdir, readFile} from 'fs/promises';
import {assert} from 'chai';

const maxL = 20; // Use when precomputing the generators

const SHA_PATH = './test/fixture_data/bls12-381-sha-256/';
const SHAKE_PATH = './test/fixture_data/bls12-381-shake-256/';

for(const hashType of ['SHA-256', 'SHAKE-256']) {
  let path = SHA_PATH;
  if(hashType == 'SHAKE-256') {
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
    // console.log(testVector);
  }

  describe('Proof Verification ' + hashType, function() {
    let gens;
    before(async function() {
      gens = await prepareGenerators(maxL, hashType); // precompute generators
    });

    for(const vector of testVectors) {
      // Create test name
      let testName = vector.caseName;
      if(vector.result.valid) {
        testName += ':valid';
      } else {
        testName += ':invalid:' + vector.result.reason;
      }

      it(testName + ' ' + hashType, async function() {
        // From the test vector get the disclosed indices and messages
        const msgsObject = vector.revealedMessages;
        const disclosedIndexes = [];
        const messagesOctets = [];
        for(const field in msgsObject) {
          disclosedIndexes.push(parseInt(field));
          messagesOctets.push(hexToBytes(msgsObject[field]));
        }
        // console.log(disclosedIndexes);
        // console.log(messagesOctets);
        const disclosedMsgScalars = await messages_to_scalars(messagesOctets,
          hashType);
        const headerBytes = hexToBytes(vector.header);
        const publicBytes = hexToBytes(vector.signerPublicKey);
        const proof = hexToBytes(vector.proof);
        const ph = hexToBytes(vector.presentationHeader);
        const result = await proofVerify(publicBytes, proof, headerBytes, ph,
          disclosedMsgScalars, disclosedIndexes, gens, hashType);
        assert.equal(result, vector.result.valid);
      });
    }
  });
}
