/* global describe, it, before */
/*eslint max-len: ["error", { "ignoreStrings": true, "ignoreComments": true }]*/
/*
  Uses seeded random pseudo random generator in proof generation to check
  against generated proof test vectors.
*/
import {bytesToHex, hexToBytes, messages_to_scalars, octets_to_proof,
  prepareGenerators, proofGen, seeded_random_scalars} from '../lib/BBS.js';
import {assert} from 'chai';
import {readFile} from 'fs/promises';

const maxL = 20; // Use when precomputing the generators

// Need the signatures that go with the proofs.
const testPairs = [
  {proofFile: 'proof001.json', signatureFile: 'signature001.json'},
  {proofFile: 'proof002.json', signatureFile: 'signature004.json'},
  {proofFile: 'proof003.json', signatureFile: 'signature004.json'},
];

const SHA_PATH = './test/fixture_data/bls12-381-sha-256/';
const SHAKE_PATH = './test/fixture_data/bls12-381-shake-256/';

for(const hashType of ['SHA-256', 'SHAKE-256']) {
  let path = SHA_PATH;
  if(hashType == 'SHAKE-256') {
    path = SHAKE_PATH;
  }
  // Pseudo random (deterministic) scalar generation seed and function
  const seed = hexToBytes('332e313431353932363533353839373933323338343632363433333833323739');
  const rand_scalar_func = seeded_random_scalars.bind(null, seed, hashType);
  // Read all the proof test files into JavaScript objects
  const sigPath = path + 'signature/';
  const proofPath = path + 'proof/';
  // console.log(testFiles);
  const testVectors = [];
  for(const pair of testPairs) {
    const proofBundle = JSON.parse(await readFile(proofPath + pair.proofFile));
    const sigBundle = JSON.parse(await readFile(sigPath + pair.signatureFile));
    testVectors.push({proofBundle, sigBundle});
  }
  // console.log(testVectors);

  describe('Proof Generation Seeded Validation ' + hashType, function() {
    let gens;
    before(async function() {
      gens = await prepareGenerators(maxL, hashType); // precompute generators
    });

    for(const vector of testVectors) {
      // Create test name
      const testName = vector.proofBundle.caseName;

      it(testName + ' ' + hashType, async function() {
        // Get all the signature related stuff
        const sigBundle = vector.sigBundle;
        const messagesOctets = sigBundle.messages.map(msg => hexToBytes(msg));
        const msg_scalars = await messages_to_scalars(messagesOctets, hashType);
        const headerBytes = hexToBytes(sigBundle.header);
        const publicBytes = hexToBytes(sigBundle.signerKeyPair.publicKey);
        const signature = hexToBytes(sigBundle.signature);

        // From the test vector get the disclosed indices and messages
        const proofBundle = vector.proofBundle;
        const msgsObject = proofBundle.revealedMessages;
        const disclosedIndexes = [];
        for(const field in msgsObject) {
          disclosedIndexes.push(parseInt(field));
        }

        const ph = hexToBytes(proofBundle.presentationHeader);
        const proof = await proofGen(publicBytes, signature, headerBytes, ph,
          msg_scalars, disclosedIndexes, gens, hashType, rand_scalar_func);
        // console.log(bytesToHex(proof));
        // console.log('Computed proof raw values:');
        // console.log(octets_to_proof(proof));
        // console.log('Test Vector proof raw values:');
        // console.log(octets_to_proof(hexToBytes(proofBundle.proof)));
        assert.equal(bytesToHex(proof), proofBundle.proof);
      });
    }
  });
}
