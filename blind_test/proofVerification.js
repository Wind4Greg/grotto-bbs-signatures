/*
  Verifies all Blind proof test vectors, but does not test proof generation.
*/
/*global describe, before, it*/
/* eslint-disable max-len */
import {API_ID_BLIND_BBS_SHA, API_ID_BLIND_BBS_SHAKE, hexToBytes, messages_to_scalars,
  prepareGenerators} from '../lib/BBS.js';
import {readdir, readFile} from 'fs/promises';
import {assert} from 'chai';
import { BlindProofVerify } from '../lib/BlindBBS.js';
import {dirname} from 'path';
import {fileURLToPath} from 'url';

const maxL = 20; // Use when precomputing the generators
const __dirname = dirname(fileURLToPath(import.meta.url));
const SHA_PATH = __dirname + '/fixture_data/bls12-381-sha-256/proof/';
const SHAKE_PATH = __dirname + '/fixture_data/bls12-381-shake-256/proof/';

for(const api_id of [API_ID_BLIND_BBS_SHA, API_ID_BLIND_BBS_SHAKE]) { // , API_ID_BLIND_BBS_SHAKE
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
    testVectors.push(testVector); // Uncomment for regular testing
    // for debugging only remove
    // if(fn === 'proof008.json') { // Ca use to focus on a particular case
    //   testVectors.push(testVector);
    //   break;
    // }
    // console.log(testVector);
  }

  describe('Proof Verification ' + api_id, function() {


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
        const revealedMessages = vector.revealedMessages;
        const disclosedIndexes = Object.keys(revealedMessages).map(s => parseInt(s));
        const messagesOctets = Object.values(revealedMessages).map(msg => hexToBytes(msg));
        // Get the disclosed committed messages and indexes
        let revealedCommittedMessages = [];
        let disclosedCommittedIndexes = [];
        let committedMessageOctets = [];
        if(vector.revealedCommittedMessages) {
          revealedCommittedMessages = vector.revealedCommittedMessages;
          disclosedCommittedIndexes = Object.keys(revealedCommittedMessages).map(s => parseInt(s));
          committedMessageOctets = Object.values(revealedCommittedMessages).map(msg => hexToBytes(msg));
        }
        // console.log(disclosedIndexes);
        // console.log(messagesOctets);
        const headerBytes = hexToBytes(vector.header);
        const publicBytes = hexToBytes(vector.signerPublicKey);
        const proof = hexToBytes(vector.proof);
        const ph = hexToBytes(vector.presentationHeader);
        const result = await BlindProofVerify(publicBytes, proof, headerBytes,
          ph, vector.L, messagesOctets, committedMessageOctets, disclosedIndexes,
          disclosedCommittedIndexes, api_id);
        assert.equal(result, vector.result.valid);
      });
    }
  });
}
