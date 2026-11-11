/* global describe, it */
/* eslint-disable max-len */
import {API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE, hexToBytes} from '../lib/BBS.js';
import {readdir, readFile} from 'fs/promises';
import {assert} from 'chai';
import {dirname} from 'path';
import {fileURLToPath} from 'url';
import {VerifyFinalizeWithNym} from '../lib/PseudonymBBS.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * Checks that an async function throws (VerifyFinalizeWithNym signals INVALID
 * by throwing).
 *
 * @param {Function} fn - Async function to call.
 * @returns {Promise<boolean>} - True if fn threw.
 */
async function throws(fn) {
  try {
    await fn();
  } catch{
    return true;
  }
  return false;
}

for(const api_id of [API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE]) {
  const suite = api_id.includes('SHAKE-256') ? 'bls12-381-shake-256' : 'bls12-381-sha-256';
  const path = `${__dirname}/fixture_data/${suite}/nymSignature/`;
  const testVectors = [];
  for(const fn of await readdir(path)) {
    const vectorObj = JSON.parse(await readFile(path + fn));
    vectorObj.filename = fn;
    testVectors.push(vectorObj);
  }

  describe('Pseudonym Nym Calc/Verify for ' + api_id, function() {
    for(const sigFixture of testVectors) {
      const PK = hexToBytes(sigFixture.signerKeyPair.publicKey);
      const header = hexToBytes(sigFixture.header);
      const signature = hexToBytes(sigFixture.signature);
      const messages = sigFixture.messages.map(msg => [msg[0], hexToBytes(msg[1])]);
      const blindMessages = sigFixture.blindMessages.map(msg => [msg[0], hexToBytes(msg[1])]);
      const prover_nyms = sigFixture.proverNyms.map(nym => BigInt('0x' + nym));
      const signer_nym_entropy = BigInt('0x' + sigFixture.signer_nym_entropy);
      const proverBlind = BigInt('0x' + sigFixture.proverBlind);
      // Create verification function to easily implement negative tests.
      // For ?? see https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Nullish_coalescing
      const verify = (o = {}) => VerifyFinalizeWithNym(PK, o.signature ?? signature, header,
        o.messages ?? messages, blindMessages, o.prover_nyms ?? prover_nyms,
        o.entropy ?? signer_nym_entropy, proverBlind, api_id);

      it(`file: ${sigFixture.filename}, case: ${sigFixture.caseName}`, async function() {
        const nym_secrets = await verify();
        assert.deepEqual(nym_secrets, sigFixture.nym_secrets.map(nym => BigInt('0x' + nym)));
      });
      it(`file: ${sigFixture.filename}, wrong signer_nym_entropy is INVALID`, async function() {
        assert.isTrue(await throws(() => verify({entropy: signer_nym_entropy + 1n})));
      });
      it(`file: ${sigFixture.filename}, wrong length prover_nyms is INVALID`, async function() {
        assert.isTrue(await throws(() => verify({prover_nyms: [0n, ...prover_nyms]})));
      });
      it(`file: ${sigFixture.filename}, tampered signature is INVALID`, async function() {
        const tampered = signature.slice();
        tampered[tampered.length - 1] ^= 1;
        assert.isTrue(await throws(() => verify({signature: tampered})));
      });
    }
  });
}
