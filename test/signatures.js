/*global before, describe, it, console*/
import {bytesToHex, hexToBytes, messages_to_scalars, prepareGenerators, sign,
  verify, octets_to_sig} from '../lib/BBS.js';
import {readdir, readFile} from 'fs/promises';
import {assert} from 'chai';

const maxL = 20; // Use when precomputing the generators

const SHA_PATH = './test/fixture_data/bls12-381-sha-256/';
const SHAKE_PATH = './test/fixture_data/bls12-381-shake-256/';

for(const hash of ['SHA-256', 'SHAKE-256']) {
  let path = SHA_PATH;
  if(hash == 'SHAKE-256') {
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

  describe('Signatures ' + hash, function() {
    let gens;
    before(async function() {
      gens = await prepareGenerators(maxL, hash); // precompute generators
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
        it('signature ' + hash + ': ' + testName, async function() {
          const messagesOctets = vector.messages.map(msg => hexToBytes(msg));
          const msg_scalars = await messages_to_scalars(messagesOctets, hash);
          const headerBytes = hexToBytes(vector.header);
          const secretScalar = BigInt('0x' + vector.signerKeyPair.secretKey);
          const publicBytes = hexToBytes(vector.signerKeyPair.publicKey);
          const result = await sign(secretScalar, publicBytes, headerBytes,
            msg_scalars, gens, hash);
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
      // it('verify ' + hash + ': ' + testName, async function() {
      //   const messagesOctets = vector.messages.map(msg => hexToBytes(msg));
      //   const msg_scalars = await messages_to_scalars(messagesOctets, hash);
      //   const gens = await prepareGenerators(vector.messages.length, hash);
      //   const headerBytes = hexToBytes(vector.header);
      //   const publicBytes = hexToBytes(vector.signerKeyPair.publicKey);
      //   const signature = hexToBytes(vector.signature);
      //   const verified = await verify(publicBytes, signature, headerBytes,
      //     msg_scalars, gens, hash);
      //   assert.equal(verified, vector.result.valid);
      // });
    }
  });
}
