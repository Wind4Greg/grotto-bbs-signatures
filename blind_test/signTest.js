/* global describe, URL, it, before, TextEncoder*/
/* eslint-disable max-len */
import {API_ID_BLIND_BBS_SHA, API_ID_BLIND_BBS_SHAKE, hexToBytes,
  seeded_random_scalars} from '../lib/BBS.js';
import {BlindSign} from '../lib/BlindBBS.js';
import {readdir, readFile} from 'fs/promises';
import {assert} from 'chai';
import {bytesToHex} from '@noble/hashes/utils';

import {dirname} from 'path';
import {fileURLToPath} from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

const SHA_PATH = __dirname + '/fixture_data/bls12-381-sha-256/signature/';
const SHAKE_PATH = __dirname + '/fixture_data/bls12-381-shake-256/signature/';

for(const api_id of [API_ID_BLIND_BBS_SHA, API_ID_BLIND_BBS_SHAKE]) {
  let path = SHA_PATH;
  if(api_id.includes('SHAKE-256')) {
    path = SHAKE_PATH;
  }
  const files = await readdir(path);
  // get all the test vectors in the dir
  const testVectors = [];
  for(const fn of files) {
    testVectors.push(JSON.parse(await readFile(path + fn)));
  }

  describe('Signature generation for ' + api_id, async function() {
    for(let i = 0; i < 1; i++) { // testVectors.length
      const commitFixture = testVectors[i];
      it(`case: ${commitFixture.caseName}`, async function() {
        console.log('Starting test');
        const SK = BigInt('0x' + commitFixture.signerKeyPair.secretKey);
        const PK = hexToBytes(commitFixture.signerKeyPair.publicKey);
        const commitment_with_proof = hexToBytes(commitFixture.commitmentWithProof);
        const header = hexToBytes(commitFixture.header);
        const messages = commitFixture.messages.map(hexMsg => hexToBytes(hexMsg));
        const signerBlind = BigInt('0x' + commitFixture.signerBlind);
        const sig = await BlindSign(SK, PK, commitment_with_proof, header, messages, signerBlind, api_id);
        // console.log(`commit with proof (hex): ${bytesToHex(commit_with_proof_octs)}`);
        // console.log(`secret prover blind (hex): ${secret_prover_blind.toString(16)}`);
        assert.equal(bytesToHex(sig), commitFixture.signature);
      });
    }
  });
}
