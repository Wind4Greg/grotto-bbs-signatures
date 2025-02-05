/* global describe, it, TextEncoder */
/* eslint-disable max-len */
import {API_ID_BLIND_BBS_SHA, API_ID_BLIND_BBS_SHAKE, hexToBytes,
  seeded_random_scalars} from '../lib/BBS.js';
import {readdir, readFile} from 'fs/promises';
import {assert} from 'chai';
import {BlindProofGen} from '../lib/BlindBBS.js';
import {bytesToHex} from '@noble/hashes/utils';

import {dirname} from 'path';
import {fileURLToPath} from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

const SHA_PATH = __dirname + '/fixture_data/bls12-381-sha-256/proof/';
const SHAKE_PATH = __dirname + '/fixture_data/bls12-381-shake-256/proof/';
const allMessagesFile = __dirname + '/fixture_data/messages.json';

const allMessages = JSON.parse(await readFile(allMessagesFile));
const messages = allMessages.messages.map(hexMsg => hexToBytes(hexMsg));
const committedMessages = allMessages.committedMessages.map(hexMsg => hexToBytes(hexMsg));
for(const api_id of [API_ID_BLIND_BBS_SHA, API_ID_BLIND_BBS_SHAKE]) { // API_ID_BLIND_BBS_SHA, API_ID_BLIND_BBS_SHAKE
  let path = SHA_PATH;
  if(api_id.includes('SHAKE-256')) {
    path = SHAKE_PATH;
  }
  const files = await readdir(path);
  // get all the test vectors in the dir
  const testVectors = [];

  for(const fn of files) {
    let vectorObj = JSON.parse(await readFile(path + fn));
    vectorObj.filename = fn;
    testVectors.push(vectorObj);
  }

  describe('Proof generation for ' + api_id, async function() {
    for(let i = 0; i < testVectors.length; i++) { // testVectors.length
      const proofFixture = testVectors[i];
      it(`file: ${proofFixture.filename}, case: ${proofFixture.caseName}`, async function() {
        const PK = hexToBytes(proofFixture.signerPublicKey);
        const signature = hexToBytes(proofFixture.signature);
        const header = hexToBytes(proofFixture.header);
        let proverBlind = 0n;
        if(proofFixture.proverBlind) {
          proverBlind = BigInt('0x' + proofFixture.proverBlind);
        }
        const ph = hexToBytes(proofFixture.presentationHeader);
        // Get indexes from objects
        const revealedCommittedMessages = proofFixture.revealedCommittedMessages;
        const revealedMessages = proofFixture.revealedMessages;
        const disclosedIndexes = Object.keys(revealedMessages).map(s => parseInt(s));
        let disclosedCommittedIndexes = [];
        let usedCommittedMessages = [];
        if(revealedCommittedMessages) {
          disclosedCommittedIndexes = Object.keys(revealedCommittedMessages).map(s => parseInt(s));
          usedCommittedMessages = committedMessages;
        }
        // Pseudo random (deterministic) scalar generation seed and function
        const rngParams = proofFixture.mockRngParameters;
        const te = new TextEncoder();
        const seed = te.encode(rngParams.SEED);
        const rng_dst = rngParams.proof.DST;
        const rand_scalar_func = seeded_random_scalars.bind(null, seed, rng_dst);
        // console.log(`disclosed idxs: ${disclosedIndexes}`);
        // console.log(`disclosed committed idxs: ${disclosedCommittedIndexes}`);
        const proof = await BlindProofGen(PK, signature, header, ph, messages,
          usedCommittedMessages, disclosedIndexes, disclosedCommittedIndexes,
          proverBlind, api_id,
          rand_scalar_func);
        // console.log(`proof: ${bytesToHex(proof)}`);
        // console.log(`indexes: ${disclosed_idxs}`);
        // console.log('disclosed_msgs:');
        // console.log(disclosed_msgs.map(bs => bytesToHex(bs)));
        assert.equal(bytesToHex(proof), proofFixture.proof);
      });
    }
  });
}
