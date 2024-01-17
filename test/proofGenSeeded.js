/* global describe, it, before */
/*eslint max-len: ["error", { "ignoreStrings": true, "ignoreComments": true }]*/
/*
  Uses seeded random pseudo random generator in proof generation to check
  against generated proof test vectors.
*/
import {API_ID_BBS_SHA, API_ID_BBS_SHAKE, bytesToHex, hexToBytes,
  messages_to_scalars, prepareGenerators, proofGen, seeded_random_scalars}
  from '../lib/BBS.js';
import {assert} from 'chai';
import {readFile} from 'fs/promises';

const maxL = 20; // Use when precomputing the generators

// Need the signatures that go with the proofs.
const testFiles = ['proof001.json', 'proof002.json', 'proof003.json',
  'proof014.json', 'proof015.json'];

const SHA_PATH = './test/fixture_data/bls12-381-sha-256/';
const SHAKE_PATH = './test/fixture_data/bls12-381-shake-256/';

for(const api_id of [API_ID_BBS_SHA, API_ID_BBS_SHAKE]) {
  let path = SHA_PATH;
  if(api_id.includes('SHAKE-256')) {
    path = SHAKE_PATH;
  }
  // Pseudo random (deterministic) scalar generation seed and function
  const seed = hexToBytes('332e313431353932363533353839373933323338343632363433333833323739');
  const rand_scalar_func = seeded_random_scalars.bind(null, seed, api_id);
  // Read all the proof test files into JavaScript objects
  const proofPath = path + 'proof/';
  // console.log(testFiles);
  const testVectors = [];
  for(const filename of testFiles) {
    const proofBundle = JSON.parse(await readFile(proofPath + filename));
    testVectors.push(proofBundle);
  }
  // console.log(testVectors);

  describe('Proof Generation Seeded Validation ' + api_id, function() {
    let gens;
    before(async function() {
      gens = await prepareGenerators(maxL, api_id); // precompute generators
    });

    for(const proofBundle of testVectors) {
      // Create test name
      const testName = proofBundle.caseName;

      it(testName + ' ' + api_id, async function() {
        // Get all the signature related stuff
        const messagesOctets = proofBundle.messages.map(msg => hexToBytes(msg));
        const msg_scalars = await messages_to_scalars(messagesOctets, api_id);
        const headerBytes = hexToBytes(proofBundle.header);
        const publicBytes = hexToBytes(proofBundle.signerPublicKey);
        const signature = hexToBytes(proofBundle.signature);

        // From the test vector get the disclosed indices and messages

        const disclosedIndexes = proofBundle.disclosedIndexes;

        const ph = hexToBytes(proofBundle.presentationHeader);
        const proof = await proofGen(publicBytes, signature, headerBytes, ph,
          msg_scalars, disclosedIndexes, gens, api_id, rand_scalar_func);
        // console.log("Computed Proof:");
        // console.log(bytesToHex(proof));
        // console.log("Test vector Proof:");
        // console.log(proofBundle.proof);
        // console.log(`is equal?: ${bytesToHex(proof) === proofBundle.proof}`);
        // console.log('Computed proof raw values:');
        // console.log(octets_to_proof(proof));
        // console.log('Test Vector proof raw values:');
        // console.log(octets_to_proof(hexToBytes(proofBundle.proof)));
        assert.equal(bytesToHex(proof), proofBundle.proof);
      });
    }
  });
}
