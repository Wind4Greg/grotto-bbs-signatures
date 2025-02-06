/* global describe, it */
/* eslint-disable max-len */
import {API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE, hexToBytes} from '../lib/BBS.js';
import {readdir, readFile} from 'fs/promises';
import {assert} from 'chai';
import {BlindSignWithNym} from '../lib/PseudonymBBS.js'
import {bytesToHex} from '@noble/hashes/utils';

import {dirname} from 'path';
import {fileURLToPath} from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SHA_PATH = __dirname + '/fixture_data/bls12-381-sha-256/nymSignature/';
const SHAKE_PATH = __dirname + '/fixture_data/bls12-381-shake-256/nymSignature/';
const message_file = __dirname + '/fixture_data/messages.json';

const allMessages = (JSON.parse(await readFile(message_file)));
const messages = allMessages.messages.map(m_hex => hexToBytes(m_hex));
// console.log('messages:');
// console.log(messages.map(m => bytesToHex(m)));
for(const api_id of [API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE]) { // API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE
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

  describe('Pseudonym Signature generation for ' + api_id, async function() {
    for(let i = 0; i < testVectors.length; i++) { // testVectors.length
      const sigFixture = testVectors[i];
      it(`file: ${sigFixture.filename}, case: ${sigFixture.caseName}`, async function() {
        const SK = BigInt('0x' + sigFixture.signerKeyPair.secretKey);
        const PK = hexToBytes(sigFixture.signerKeyPair.publicKey);
        const header = hexToBytes(sigFixture.header);
        const commitmentWithProof = hexToBytes(sigFixture.commitmentWithProof);
        console.log(sigFixture.signer_nym_entropy);
        const nym_entropy = BigInt('0x' + sigFixture.signer_nym_entropy);
        // BlindSignWithNym(SK, PK, commitment_with_proof, signer_nym_entropy, header, messages, api_id)
        const res = await BlindSignWithNym(SK, PK, commitmentWithProof, nym_entropy, header, messages, api_id);
        const sig = res;
        console.log(`signature: ${bytesToHex(sig)}`);
        assert.equal(bytesToHex(sig), sigFixture.signature);
      });
    }
  });
}
