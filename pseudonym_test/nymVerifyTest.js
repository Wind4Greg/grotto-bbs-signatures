/* global describe, it */
/* eslint-disable max-len */
import {API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE, hexToBytes} from '../lib/BBS.js';
import {readdir, readFile} from 'fs/promises';
import {assert} from 'chai';
import {BlindVerify} from '../lib/BlindBBS.js';
import {BlindVerifyWithNym} from '../lib/PseudonymBBS.js';
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
for(const api_id of [API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE]) { // , API_ID_PSEUDONYM_BBS_SHAKE
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
        const prover_nym = BigInt('0x' + sigFixture.proverNym);
        const proverBlind = BigInt('0x' + sigFixture.proverBlind);
        const signer_nym_entropy = BigInt('0x' + sigFixture.signer_nym_entropy);
        const PK = hexToBytes(sigFixture.signerKeyPair.publicKey);
        const header = hexToBytes(sigFixture.header);
        const signature = hexToBytes(sigFixture.signature);
        // BlindVerifyWithNym(PK, signature, header, messages, committed_messages, prover_nym, signer_nym_entropy, secret_prover_blind, api_id)
        // const result = await BlindVerify(PK, signature, header, messages, [pid],
        //   proverBlind, 0n, api_id);
        const committed_messages = [];
        // BlindVerifyWithNym(PK, signature, header, messages, committed_messages, prover_nym, signer_nym_entropy, secret_prover_blind, api_id)
        const result = await BlindVerifyWithNym(PK, signature, header, messages, committed_messages,
          prover_nym, signer_nym_entropy, proverBlind, api_id);
        const [valid, nym_secret] = result;
        assert.isTrue(valid);
        console.log(`nym_secret: ${nym_secret.toString(16)}`);
      });
    }
  });
}
