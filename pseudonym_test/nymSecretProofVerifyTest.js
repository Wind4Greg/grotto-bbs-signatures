/* global describe, it, TextEncoder */
/* eslint-disable max-len */
import {API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE, hexToBytes,
  seeded_random_scalars} from '../lib/BBS.js';
import {readdir, readFile} from 'fs/promises';
import {assert} from 'chai';
import {NymSecretProofVerify} from '../lib/PseudonymBBS.js';
import {bytesToHex} from '@noble/hashes/utils';

import {dirname} from 'path';
import {fileURLToPath} from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

const SHA_PATH = __dirname + '/fixture_data/bls12-381-sha-256/nymSecretProof/';
const SHAKE_PATH = __dirname + '/fixture_data/bls12-381-shake-256/nymSecretProof/';
const allMessagesFile = __dirname + '/fixture_data/messages.json';

const allMessages = JSON.parse(await readFile(allMessagesFile));
const messages = allMessages.map(hexMsg => hexToBytes(hexMsg));
for(const api_id of [API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE]) { //, API_ID_PSEUDONYM_BBS_SHAKE
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

  describe('Nym Secret Proof verification for ' + api_id, async function() {
    for(let i = 0; i < testVectors.length; i++) { // testVectors.length
      const proofFixture = testVectors[i];
      it(`case: ${proofFixture.caseName}`, async function() {
        const PK = hexToBytes(proofFixture.signerPublicKey);
        const proof = hexToBytes(proofFixture.proof);
        const header = hexToBytes(proofFixture.header);
        const ph = hexToBytes(proofFixture.presentationHeader);
        const disclosedIndexes = proofFixture.disclosedIndexes;
        const disclosedMessages = disclosedIndexes.map(i => messages[i]);
        const nym_secret = BigInt('0x' + proofFixture.nym_secret);
        const disComMsgs = []; // disclosed committed mesages
        const disComIndxs = proofFixture.disclosedComIndexes;
        const L = proofFixture.L;
        const result = await NymSecretProofVerify(PK, proof, header, ph, L,
          disclosedMessages, disComMsgs, nym_secret, disclosedIndexes, disComIndxs, api_id);
        assert.isTrue(result);
      });
    }
  });
}
