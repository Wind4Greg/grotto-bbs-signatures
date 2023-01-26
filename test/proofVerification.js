/* 
  Verifies all proof test vectors, but does not test proof generation.
*/
import { assert } from 'chai';
import { hexToBytes, proofVerify, prepareGenerators, messages_to_scalars } from '../lib/BBS.js';
import { readFile, readdir } from 'fs/promises';

const maxL = 20; // Use when precomputing the generators

// Read all the proof test files into JavaScript objects
const vectorPath = './test/fixture_data/bls12-381-sha-256/proof/';
let testFiles = await readdir(vectorPath);
// console.log(testFiles);
let testVectors = [];
for (let fn of testFiles) {
  let testVector = JSON.parse(await readFile(vectorPath + fn));
  testVectors.push(testVector);
  // console.log(testVector);
}

describe('Proof Verification', function () {
  let gens;
  before(async function () {
    gens = await prepareGenerators(maxL); // precompute generators
  })

  for (let vector of testVectors) {
    // Create test name
    let testName = vector.caseName;
    if (vector.result.valid) {
      testName += ":valid";
    } else {
      testName += ":invalid:" + vector.result.reason;
    }

    it(testName, async function () {
      // From the test vector get the disclosed indices and messages
      let msgsObject = vector.revealedMessages;
      let disclosedIndexes = [];
      let messagesOctets = [];
      for (let field in msgsObject) {
        disclosedIndexes.push(parseInt(field));
        messagesOctets.push(hexToBytes(msgsObject[field]));
      }
      // console.log(disclosedIndexes);
      // console.log(messagesOctets);
      let disclosedMsgScalars = await messages_to_scalars(messagesOctets);
      let headerBytes = hexToBytes(vector.header);
      let publicBytes = hexToBytes(vector.signerPublicKey);
      let L = vector.totalMessageCount;
      let proof = hexToBytes(vector.proof);
      let ph = hexToBytes(vector.presentationHeader);
      let result = await proofVerify(publicBytes, proof, L, headerBytes, ph, disclosedMsgScalars, 
          disclosedIndexes, gens);
      assert.equal(result, vector.result.valid);
    });
  }
});
