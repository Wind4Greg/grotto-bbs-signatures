/*
  Uses seeded random pseudo random generator in proof generation to check
  against generated proof test vectors.
*/
import { assert } from 'chai';
import { hexToBytes, proofGen, prepareGenerators, messages_to_scalars, bytesToHex, seeded_random_scalars } from '../lib/BBS.js';
import { readFile, readdir } from 'fs/promises';



const maxL = 20; // Use when precomputing the generators

// Need the signatures that go with the proofs.
const testPairs = [
  { proofFile: "proof001.json", signatureFile: "signature001.json" },
  { proofFile: "proof002.json", signatureFile: "signature004.json" },
  { proofFile: "proof003.json", signatureFile: "signature004.json" },
];

const SHA_PATH = './test/fixture_data/bls12-381-sha-256/';
const SHAKE_PATH = './test/fixture_data/bls12-381-shake-256/';

for (let hashType of ["SHA-256", "SHAKE-256"]) {
  let path = SHA_PATH;
  if (hashType == "SHAKE-256") {
    path = SHAKE_PATH;
  }
  // Pseudo random (deterministic) scalar generation seed and function
  let seed = hexToBytes("332e313431353932363533353839373933323338343632363433333833323739");
  let rand_scalar_func = seeded_random_scalars.bind(null, seed, hashType);
  // Read all the proof test files into JavaScript objects
  const sigPath = path + 'signature/';
  const proofPath = path + 'proof/';
  // console.log(testFiles);
  let testVectors = [];
  for (let pair of testPairs) {
    let proofBundle = JSON.parse(await readFile(proofPath + pair.proofFile));
    let sigBundle = JSON.parse(await readFile(sigPath + pair.signatureFile));
    testVectors.push({ proofBundle: proofBundle, sigBundle: sigBundle });
  }
  // console.log(testVectors);

  describe('Proof Generation Seeded Validation ' + hashType, function () {
    let gens;
    before(async function () {
      gens = await prepareGenerators(maxL, hashType); // precompute generators
    })

    for (let vector of testVectors) {
      // Create test name
      let testName = vector.proofBundle.caseName;


      it(testName + " " + hashType, async function () {
        let msg_scalars, headerBytes, publicBytes, signature;
        // Get all the signature related stuff
        let sigBundle = vector.sigBundle;
        let messagesOctets = sigBundle.messages.map(msg => hexToBytes(msg));
        msg_scalars = await messages_to_scalars(messagesOctets, hashType);
        headerBytes = hexToBytes(sigBundle.header);
        publicBytes = hexToBytes(sigBundle.signerKeyPair.publicKey);
        signature = hexToBytes(sigBundle.signature);

        // From the test vector get the disclosed indices and messages
        let proofBundle = vector.proofBundle;
        let msgsObject = proofBundle.revealedMessages;
        let disclosedIndexes = [];
        for (let field in msgsObject) {
          disclosedIndexes.push(parseInt(field));
        }

        let ph = hexToBytes(proofBundle.presentationHeader);
        let proof = await proofGen(publicBytes, signature, headerBytes, ph, msg_scalars, disclosedIndexes,
          gens, hashType, rand_scalar_func);
        // console.log(bytesToHex(proof));
        assert.equal(bytesToHex(proof), proofBundle.proof);
      });
    }
  });
}
