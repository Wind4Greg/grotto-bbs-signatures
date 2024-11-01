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

const messages = (JSON.parse(await readFile(message_file))).map(m_hex => hexToBytes(m_hex));
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
    testVectors.push(JSON.parse(await readFile(path + fn)));
  }

  describe('Hidden pid Pseudonym Signature generation for ' + api_id, async function() {
    for(let i = 0; i < testVectors.length; i++) { // testVectors.length
      const sigFixture = testVectors[i];
      it(`case: ${sigFixture.caseName}`, async function() {
        const SK = BigInt('0x' + sigFixture.signerKeyPair.secretKey);
        const PK = hexToBytes(sigFixture.signerKeyPair.publicKey);
        const header = hexToBytes(sigFixture.header);
        const commitmentWithProof = hexToBytes(sigFixture.commitmentWithProof);
        const nym_entropy = BigInt('0x' + sigFixture.signer_nym_entropy);
        // BlindSignWithNym(SK, PK, commitment_with_proof, header, messages, signer_nym_entropy, api_id) 
        const res = await BlindSignWithNym(SK, PK, commitmentWithProof, header, messages, nym_entropy, api_id);
        const [sig, back_entropy] = res;
        console.log(`signature: ${bytesToHex(sig)}, signer entropy: ${back_entropy.toString(16)}`);
        assert.equal(bytesToHex(sig), sigFixture.signature);
      });
    }
  });
}
