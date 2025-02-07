/* global describe, it, TextEncoder */
/* eslint-disable max-len */
import {API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE, hexToBytes,
  seeded_random_scalars} from '../lib/BBS.js';
import {readdir, readFile} from 'fs/promises';
import {assert} from 'chai';
import {ProofVerifyWithNym} from '../lib/PseudonymBBS.js';
import {bytesToHex} from '@noble/hashes/utils';

import {dirname} from 'path';
import {fileURLToPath} from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

const SHA_PATH = __dirname + '/fixture_data/bls12-381-sha-256/nymProof/';
const SHAKE_PATH = __dirname + '/fixture_data/bls12-381-shake-256/nymProof/';
const allMessagesFile = __dirname + '/fixture_data/messages.json';

// Get all the messages and convert to bytes, could do this from test vector file contents
const allMessages = JSON.parse(await readFile(allMessagesFile));
const messages = allMessages.messages.map(hexMsg => hexToBytes(hexMsg));
const comMessages = allMessages.committedMessages.map(hexMsg => hexToBytes(hexMsg));

for(const api_id of [API_ID_PSEUDONYM_BBS_SHA]) { //, API_ID_PSEUDONYM_BBS_SHAKE
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

  describe('Pseudonym Proof verification for ' + api_id, async function() {
    for(let i = 0; i < testVectors.length; i++) { // testVectors.length
      const proofFixture = testVectors[i];
      it(`file: ${proofFixture.filename}, case: ${proofFixture.caseName}`, async function() {
        const PK = hexToBytes(proofFixture.signerPublicKey);
        const proof = hexToBytes(proofFixture.proof);
        const header = hexToBytes(proofFixture.header);
        const ph = hexToBytes(proofFixture.presentationHeader);
        const pseudonym_bytes = hexToBytes(proofFixture.pseudonym);
        const context_id = hexToBytes(proofFixture.context_id);
        // Assemble messages and indexes
        const disclosedIndexes = Object.keys(proofFixture.revealedMessages).map(key => parseInt(key)).sort();
        const disComIndxs = Object.keys(proofFixture.revealedCommittedMessages).map(key => parseInt(key)).sort();
        const disclosedMessages = disclosedIndexes.map(i => messages[i]);
        const disComMsgs = disComIndxs.map(i => comMessages[i]);

        const L = proofFixture.L;
        const result = await ProofVerifyWithNym(PK, proof, header, ph, pseudonym_bytes, context_id,
          L, disclosedMessages, disComMsgs, disclosedIndexes, disComIndxs, api_id);
        /*
                const result = await ProofVerifyWithNym(PK, proof, header, ph, pseudonym, context_id,
  L, disclosed_messages, disclosed_committed_messages, disclosed_indexes,
  disclosed_committed_indexes, api_id)
        */
        assert.isTrue(result);
      });
    }
  });
}
