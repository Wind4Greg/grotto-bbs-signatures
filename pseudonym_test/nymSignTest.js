/* global describe, it */
/* eslint-disable max-len */
import {API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE, hexToBytes} from '../lib/BBS.js';
import {BlindSignWithNym, traceInfo} from '../lib/PseudonymBBS.js';
import {readdir, readFile} from 'fs/promises';
import {assert} from 'chai';
import {bytesToHex} from '@noble/hashes/utils.js';
import {dirname} from 'path';
import {fileURLToPath} from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

for(const api_id of [API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE]) {
  const suite = api_id.includes('SHAKE-256') ? 'bls12-381-shake-256' : 'bls12-381-sha-256';
  const path = `${__dirname}/fixture_data/${suite}/nymSignature/`;
  const testVectors = [];
  for(const fn of await readdir(path)) {
    const vectorObj = JSON.parse(await readFile(path + fn));
    vectorObj.filename = fn;
    testVectors.push(vectorObj);
  }

  describe('Pseudonym Signature generation for ' + api_id, function() {
    for(const sigFixture of testVectors) {
      it(`file: ${sigFixture.filename}, case: ${sigFixture.caseName}`, async function() {
        const SK = BigInt('0x' + sigFixture.signerKeyPair.secretKey);
        const PK = hexToBytes(sigFixture.signerKeyPair.publicKey);
        const header = hexToBytes(sigFixture.header);
        const commitmentWithProof = hexToBytes(sigFixture.commitmentWithProof);
        const messages = sigFixture.messages.map(msg => [msg[0], hexToBytes(msg[1])]);
        const length_nym_vector = sigFixture.proverNyms.length;
        const signer_nym_entropy = BigInt('0x' + sigFixture.signer_nym_entropy);
        const sig = await BlindSignWithNym(SK, PK, commitmentWithProof, length_nym_vector,
          signer_nym_entropy, header, messages, api_id);
        assert.equal(bytesToHex(sig), sigFixture.signature);
        assert.deepEqual({B: traceInfo.BCalculate.B, domain: traceInfo.BCalculate.domain},
          sigFixture.trace);
      });
    }
  });
}
