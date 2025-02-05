/* global describe, it */
/* eslint-disable max-len */
import {API_ID_BLIND_BBS_SHA, API_ID_BLIND_BBS_SHAKE, hexToBytes} from '../lib/BBS.js';
import {readdir, readFile} from 'fs/promises';
import {assert} from 'chai';
import {BlindSign} from '../lib/BlindBBS.js';
import {bytesToHex} from '@noble/hashes/utils';

import {dirname} from 'path';
import {fileURLToPath} from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

const SHA_PATH = __dirname + '/fixture_data/bls12-381-sha-256/signature/';
const SHAKE_PATH = __dirname + '/fixture_data/bls12-381-shake-256/signature/';

for(const api_id of [API_ID_BLIND_BBS_SHA, API_ID_BLIND_BBS_SHAKE]) { // API_ID_BLIND_BBS_SHA, API_ID_BLIND_BBS_SHAKE
  let path = SHA_PATH;
  if(api_id.includes('SHAKE-256')) {
    path = SHAKE_PATH;
  }
  const files = await readdir(path);
  // get all the test vectors in the dir
  const testVectors = [];
  for(const fn of files) {
    const vectorObj = JSON.parse(await readFile(path + fn));
    vectorObj.filename = fn;
    testVectors.push(vectorObj);
  }

  describe('Signature generation for ' + api_id, async function() {
    for(let i = 0; i < testVectors.length; i++) { // testVectors.length
      const commitFixture = testVectors[i];
      it(`file: ${commitFixture.filename}, case: ${commitFixture.caseName}`, async function() {
        const SK = BigInt('0x' + commitFixture.signerKeyPair.secretKey);
        const PK = hexToBytes(commitFixture.signerKeyPair.publicKey);
        let commitment_with_proof = null;
        if(commitFixture.commitmentWithProof) {
          commitment_with_proof = hexToBytes(commitFixture.commitmentWithProof);
        }
        const header = hexToBytes(commitFixture.header);
        const messages = commitFixture.messages.map(hexMsg => hexToBytes(hexMsg));
        // BlindSign(SK, PK, commitment_with_proof, header, messages,  api_id)
        const sig = await BlindSign(SK, PK, commitment_with_proof, header, messages, api_id);
        assert.equal(bytesToHex(sig), commitFixture.signature);
      });
    }
  });
}
