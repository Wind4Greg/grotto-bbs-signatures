/*
  Verifies all Blind proof test vectors, but does not test proof generation.
*/
/*global describe, before, it*/
/* eslint-disable max-len */
import {API_ID_BLIND_BBS_SHA, API_ID_BLIND_BBS_SHAKE, hexToBytes, messages_to_scalars,
  prepareGenerators} from '../lib/BBS.js';
import {readdir, readFile} from 'fs/promises';
import {assert} from 'chai';
import { CD_BlindProofVerify } from '../lib/BlindBBS.js';
import {dirname} from 'path';
import {fileURLToPath} from 'url';

const maxL = 20; // Use when precomputing the generators
const __dirname = dirname(fileURLToPath(import.meta.url));
const SHA_PATH = __dirname + '/fixture_data/bls12-381-sha-256/proof/';
const SHAKE_PATH = __dirname + '/fixture_data/bls12-381-shake-256/proof/';

// Only working with tests that use "all messages" as defined below.
const allMessagesFile = __dirname + "/fixture_data/messages.json";
const allMessages = JSON.parse(await readFile(allMessagesFile));
const messages = allMessages.messages.map((hexMsg) => hexToBytes(hexMsg));
const blindMessages = allMessages.committedMessages.map((hexMsg) =>
  hexToBytes(hexMsg),
);

for(const api_id of [API_ID_BLIND_BBS_SHA]) { // , API_ID_BLIND_BBS_SHAKE
  let path = SHA_PATH;
  if(api_id.includes('SHAKE-256')) {
    path = SHAKE_PATH;
  }
  // Read all the proof test files into JavaScript objects
  const vectorPath = path;
  const testFiles = await readdir(vectorPath);
  // console.log(testFiles);
  const testVectors = [];
  for(const fn of testFiles) {
    const testVector = JSON.parse(await readFile(vectorPath + fn));
    if(fn != "proof009ComDis.json") {
      continue;
    }
    testVectors.push(testVector);
  }

  describe('Proof Verification ' + api_id, function() {
    for(const vector of testVectors) {
      // Create test name
      let testName = vector.caseName;
      if(vector.result.valid) {
        testName += ':valid';
      } else {
        testName += ':invalid:' + vector.result.reason;
      }

      it(testName + ' ' + api_id, async function() {
        // New  verification  function signature:
        // CD_BlindProofVerify(PK, proof, header, ph, issuer_known_messages_no, disclosed_messages, message_disclosures,  api_id)
        const PK = hexToBytes(vector.signerPublicKey);
        const proof = hexToBytes(vector.proof);
        const header = hexToBytes(vector.header);
        const ph = hexToBytes(vector.presentationHeader);
        const issuer_known_messages_no = vector.L;
        // From the test vector get the disclosed messages and message_disclosures
        const disclosed_messages = [];
        const message_disclosures = {};
        const issuerMessageDisclosures = vector.messageDisclosures;
        const blindMessageDisclosures = vector.blindMessageDisclosures;
        for(let i = 0; i < messages.length; i++) {
          if(issuerMessageDisclosures[i] == 'DISCLOSE') {
            disclosed_messages.push(messages[i]);
          }
        }
        for(let i = 0; i < blindMessages.length; i++) {
          if(blindMessageDisclosures[i] == 'DISCLOSE') {
            disclosed_messages.push(blindMessages[i]);
          }
        }
        for(let i = 0; i < issuer_known_messages_no; i++) {
          message_disclosures[i] = issuerMessageDisclosures[i];
        }
        for(let i = 0; i < Object.keys(blindMessageDisclosures).length; i++) {
          message_disclosures[issuer_known_messages_no + i] = blindMessageDisclosures[i];
        }
        console.log(`message_disclosures`);
        console.log(message_disclosures);
        const result = await CD_BlindProofVerify(PK, proof, header, ph,
          issuer_known_messages_no, disclosed_messages, message_disclosures, api_id);
        assert.equal(result, vector.result.valid);
      });
    }
  });
}
