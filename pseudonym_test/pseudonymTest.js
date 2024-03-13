/* global describe, it */
/* eslint-disable max-len */
import {API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE, hexToBytes} from '../lib/BBS.js';
import {readdir, readFile} from 'fs/promises';
import {assert} from 'chai';
import {CalculatePseudonym} from '../lib/PseudonymBBS.js';
import {bytesToHex} from '@noble/hashes/utils';

import {dirname} from 'path';
import {fileURLToPath} from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SHA_PATH = __dirname + '/fixture_data/bls12-381-sha-256/pseudonym/';
const SHAKE_PATH = __dirname + '/fixture_data/bls12-381-shake-256/pseudonym/';

for(const api_id of [API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE]) {
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

  describe('Pseudonym generation for ' + api_id, async function() {
    for(let i = 0; i < testVectors.length; i++) { // testVectors.length
      const sigFixture = testVectors[i];
      it(`case: ${sigFixture.caseName}`, async function() {
        const pid = hexToBytes(sigFixture.pid);
        const verifier_id = hexToBytes(sigFixture.verifier_id);
        const pseudonym = sigFixture.pseudonym;
        const result = await CalculatePseudonym(verifier_id, pid, api_id);
        const result_bytes = result.toRawBytes(true); // curve point as bytes
        // console.log(`pseudonym: ${bytesToHex(result_bytes)}`);
        assert.equal(bytesToHex(result_bytes), pseudonym);
      });
    }
  });
}
