/*global before, describe, it */
import {API_ID_BBS_SHA, API_ID_BBS_SHAKE, bytesToHex, hexToBytes,
  messages_to_scalars, prepareGenerators, sign, verify} from '../lib/BBS.js';
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

  // Read all the signature test files into JavaScript objects
  const vectorPath = path + 'signature/';
  const testFiles = await readdir(vectorPath);
  // console.log(testFiles);
  const testVectors = [];
  for(const fn of testFiles) {
    const testVector = JSON.parse(await readFile(vectorPath + fn));
    testVectors.push(testVector);
    // console.log(testVector);
  }

  describe('Signatures ' + api_id, function() {
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

      // We only check signature generation for "valid" test signatures
      if(vector.result.valid) {
        it('signature ' + api_id + ': ' + testName, async function() {
          const messagesOctets = vector.messages.map(msg => hexToBytes(msg));
          const msg_scalars = await messages_to_scalars(messagesOctets, api_id);
          const headerBytes = hexToBytes(vector.header);
          const secretScalar = BigInt('0x' + vector.signerKeyPair.secretKey);
          const publicBytes = hexToBytes(vector.signerKeyPair.publicKey);
          const result = await sign(secretScalar, publicBytes, headerBytes,
            msg_scalars, gens, api_id);
          // let computeSig = octets_to_sig(result);
          // console.log('Computed raw signature:');
          // console.log(computeSig);
          // console.log('Computed e value in hex:');
          // console.log(computeSig.e.toString(16));
          // let testVectSigBytes = hexToBytes(vector.signature);
          // let testVectSig = octets_to_sig(testVectSigBytes);
          // console.log('Raw test vector signature:');
          // console.log(testVectSig);
          assert.equal(bytesToHex(result), vector.signature,
            'signatures should match');

        });
      }
      // We verify against all signatures whether valid or invalid
      it('verify ' + api_id + ': ' + testName, async function() {
        const messagesOctets = vector.messages.map(msg => hexToBytes(msg));
        const msg_scalars = await messages_to_scalars(messagesOctets, api_id);
        const gens = await prepareGenerators(vector.messages.length, api_id);
        const headerBytes = hexToBytes(vector.header);
        const publicBytes = hexToBytes(vector.signerKeyPair.publicKey);
        const signature = hexToBytes(vector.signature);
        const verified = await verify(publicBytes, signature, headerBytes,
          msg_scalars, gens, api_id);
        assert.equal(verified, vector.result.valid);
      });
    }
  });
}
