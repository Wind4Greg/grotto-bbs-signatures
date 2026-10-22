/* global describe, it */
/* eslint-disable max-len */
import {API_ID_BLIND_BBS_SHA, API_ID_BLIND_BBS_SHAKE, hexToBytes} from '../lib/BBS.js';
import {readdir, readFile} from 'fs/promises';
import {assert} from 'chai';
import {BlindSign} from '../lib/BlindBBS.js';
import {bytesToHex} from '@noble/hashes/utils.js';

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
      const sigFixture = testVectors[i];
      it(`file: ${sigFixture.filename}, case: ${sigFixture.caseName}`, async function() {
        const SK = BigInt('0x' + sigFixture.signerKeyPair.secretKey);
        const PK = hexToBytes(sigFixture.signerKeyPair.publicKey);
        let commitment_with_proof = null;
        if(sigFixture.commitmentWithProof) {
          commitment_with_proof = hexToBytes(sigFixture.commitmentWithProof);
        }
        const header = hexToBytes(sigFixture.header);

        const messages = sigFixture.messages.map(msg => [msg[0], hexToBytes(msg[1])]);
        // BlindSign(SK, PK, commitment_with_proof, header, messages,  api_id)
        const sig = await BlindSign(SK, PK, commitment_with_proof, header, messages, api_id);
        assert.equal(bytesToHex(sig), sigFixture.signature);
      });
    }
  });
}
