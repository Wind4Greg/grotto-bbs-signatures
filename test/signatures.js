import { assert } from 'chai';
import { bytesToHex, hexToBytes, sign, verify, prepareGenerators, messages_to_scalars } from '../lib/BBS.js';
import { readFile, readdir } from 'fs/promises';

const maxL = 20; // Use when precomputing the generators

// Read all the signature test files into JavaScript objects
const vectorPath = './test/fixture_data/bls12-381-sha-256/signature/';
let testFiles = await readdir(vectorPath);
// console.log(testFiles);
let testVectors = [];
for (let fn of testFiles) {
  let testVector = JSON.parse(await readFile(vectorPath + fn));
  testVectors.push(testVector);
  // console.log(testVector);
}

describe('Signatures', function () {
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

    // We only check signature generation for "valid" test signatures
    if (vector.result.valid) {
      it("signature:" + testName, async function () {
        let messagesOctets = vector.messages.map(msg => hexToBytes(msg));
        let msg_scalars = await messages_to_scalars(messagesOctets);
        let headerBytes = hexToBytes(vector.header);
        let secretScalar = BigInt("0x" + vector.signerKeyPair.secretKey);
        let publicBytes = hexToBytes(vector.signerKeyPair.publicKey)
        let result = await sign(secretScalar, publicBytes, headerBytes, msg_scalars, gens);
        assert.equal(bytesToHex(result), vector.signature, 'signatures should match');
      });
    }
    // We verify against all signatures whether valid or invalid
    it("verify:" + testName, async function () {
      let messagesOctets = vector.messages.map(msg => hexToBytes(msg));
      let msg_scalars = await messages_to_scalars(messagesOctets);
      let gens = await prepareGenerators(vector.messages.length); // Generate enough for all messages
      let headerBytes = hexToBytes(vector.header);
      let publicBytes = hexToBytes(vector.signerKeyPair.publicKey)
      let signature = hexToBytes(vector.signature);
      let verified = await verify(publicBytes, signature, headerBytes, msg_scalars, gens);
      assert.equal(verified, vector.result.valid);
    });
  }
});
