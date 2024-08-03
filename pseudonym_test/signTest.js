/* global describe, it */
/* eslint-disable max-len */
import {API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE, hexToBytes} from '../lib/BBS.js';
import {readdir, readFile} from 'fs/promises';
import {assert} from 'chai';
import {PseudonymSign} from '../lib/PseudonymBBS.js';
import {bytesToHex} from '@noble/hashes/utils';

import {dirname} from 'path';
import {fileURLToPath} from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SHA_PATH = __dirname + '/fixture_data/bls12-381-sha-256/signature/';
const SHAKE_PATH = __dirname + '/fixture_data/bls12-381-shake-256/signature/';
const message_file = __dirname + '/fixture_data/messages.json';
const pid_vid_file = __dirname + '/fixture_data/pid_vid.json';

const messages = (JSON.parse(await readFile(message_file))).map(m_hex => hexToBytes(m_hex));
// console.log('messages:');
// console.log(messages.map(m => bytesToHex(m)));
const pid = hexToBytes(JSON.parse(await readFile(pid_vid_file)).pid);
// console.log(`pid: ${bytesToHex(pid)}`);
for(const api_id of [API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE]) {
  let path = SHA_PATH;
  if(api_id.includes('SHAKE-256')) {
    path = SHAKE_PATH;
  }
  const files = await readdir(path);
  // get all the test vectors in the dir
  const testVectors = [];
  for(const fn of files) {
    console.log(`working on  file:  ${fn}`);
    testVectors.push(JSON.parse(await readFile(path + fn)));
  }

  describe('Pseudonym Signature generation for ' + api_id, async function() {
    for(let i = 0; i < testVectors.length; i++) { // testVectors.length
      const sigFixture = testVectors[i];
      it(`case: ${sigFixture.caseName}`, async function() {
        const SK = BigInt('0x' + sigFixture.signerKeyPair.secretKey);
        const PK = hexToBytes(sigFixture.signerKeyPair.publicKey);
        const header = hexToBytes(sigFixture.header);
        const sig = await PseudonymSign(SK, PK, header, messages, pid, api_id);
        // console.log(`signature: ${bytesToHex(sig)}`);
        assert.equal(bytesToHex(sig), sigFixture.signature);
      });
    }
  });
}
