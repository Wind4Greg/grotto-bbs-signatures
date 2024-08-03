/* global describe, it */
/* eslint-disable max-len */
import {API_ID_BLIND_BBS_SHA, API_ID_BLIND_BBS_SHAKE, hexToBytes} from '../lib/BBS.js';
import {readdir, readFile} from 'fs/promises';
import {assert} from 'chai';
import {BlindVerify} from '../lib/BlindBBS.js';
// import {bytesToHex} from '@noble/hashes/utils';

import {dirname} from 'path';
import {fileURLToPath} from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

const SHA_PATH = __dirname + '/fixture_data/bls12-381-sha-256/signature/';
const SHAKE_PATH = __dirname + '/fixture_data/bls12-381-shake-256/signature/';

for(const api_id of [API_ID_BLIND_BBS_SHA]) { // , API_ID_BLIND_BBS_SHAKE
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

  describe('Signature Verification for ' + api_id, async function() {
    for(let i = 5; i < testVectors.length; i++) { // testVectors.length
      const commitFixture = testVectors[i];
      it(`case: ${commitFixture.caseName}`, async function() {
        const PK = hexToBytes(commitFixture.signerKeyPair.publicKey);
        const header = hexToBytes(commitFixture.header);
        const messages = commitFixture.messages.map(hexMsg => hexToBytes(hexMsg));
        let committed_messages = [];
        if(commitFixture.committedMessages) {
          committed_messages = commitFixture.committedMessages.map(hexMsg => hexToBytes(hexMsg));
        }
        const signature = hexToBytes(commitFixture.signature);
        let signerBlind = 0n;
        if(commitFixture.signerBlind) {
          signerBlind = BigInt('0x' + commitFixture.signerBlind);
        }
        let secret_prover_blind = 0n;
        if(commitFixture.proverBlind) {
          secret_prover_blind = BigInt('0x' + commitFixture.proverBlind);
        }
        const res = await BlindVerify(PK, signature, header, messages, committed_messages,
          secret_prover_blind, signerBlind, api_id)
        assert.isTrue(res);
      });
    }
  });
}
