/*
  Verifies all Blind proof test vectors, but does not test proof generation.
*/
/*global describe, before, it*/
/* eslint-disable max-len */
import {API_ID_BLIND_BBS_SHA, API_ID_BLIND_BBS_SHAKE, hexToBytes, messages_to_scalars,
  prepareGenerators} from '../lib/BBS.js';
import {readdir, readFile} from 'fs/promises';
import {assert} from 'chai';
import {BlindProofVerify, messages_to_scalars as blind_messages_to_scalars,
  octets_to_proof} from '../lib/BlindBBS.js';
import {dirname} from 'path';
import {fileURLToPath} from 'url';

const maxL = 20; // Use when precomputing the generators
const __dirname = dirname(fileURLToPath(import.meta.url));
const SHA_PATH = __dirname + '/fixture_data/bls12-381-sha-256/proof/';
const SHAKE_PATH = __dirname + '/fixture_data/bls12-381-shake-256/proof/';
const SIG_SHA_PATH = __dirname + "/fixture_data/bls12-381-sha-256/signature/";
const SIG_SHAKE_PATH = __dirname + "/fixture_data/bls12-381-shake-256/signature/";

for(const api_id of [API_ID_BLIND_BBS_SHA, API_ID_BLIND_BBS_SHAKE]) { // , API_ID_BLIND_BBS_SHAKE
  let path = SHA_PATH;
  let sig_path = SIG_SHA_PATH;
  if(api_id.includes('SHAKE-256')) {
    path = SHAKE_PATH;
    sig_path = SIG_SHAKE_PATH;
  }
  // Read all the proof test files into JavaScript objects
  const vectorPath = path;
  const testFiles = await readdir(vectorPath);
  // console.log(testFiles);
  const testVectors = [];
  for(const fn of testFiles) {
    // if(fn == 'proof009.json') {
    //   break;
    // }
    const testVector = JSON.parse(await readFile(vectorPath + fn));
    // Getting the signature file for this proof test vector
    const sigFixture = JSON.parse(await readFile(sig_path + testVector.signatureFile));
    // console.log(JSON.stringify(sigFixture, null, 2));
    testVector.sigInfo = sigFixture;
    testVectors.push(testVector);
  }

  describe('Proof Verification ' + api_id, function() {
    for(const proofFixture of testVectors) {
      // Create test name
      let testName = proofFixture.caseName;
      if(proofFixture.result.valid) {
        testName += ':valid';
      } else {
        testName += ':invalid:' + proofFixture.result.reason;
      }

      it(testName + ' ' + api_id, async function() {
        // From the test vector recreate the disclosed_messages and message_disclosures arrays
        let blindMessages = [];
        if(proofFixture.sigInfo.blindMessages !== null) {
          blindMessages = proofFixture.sigInfo.blindMessages.map(msg => [msg[0], hexToBytes(msg[1])]);
        }
        const messages = proofFixture.sigInfo.messages.map(msg => [msg[0], hexToBytes(msg[1])]);
        const messageDisclosures = proofFixture.messageDisclosures;
        const blindMessageDisclosures = proofFixture.blindMessageDisclosures;
        const allMessageDisclosures = messageDisclosures.concat(blindMessageDisclosures);
        const allMessages = messages.concat(blindMessages);
        const allDisclosedMessages = [];
        for(let i = 0; i < allMessages.length; i++) {
          if(allMessageDisclosures[i] == 'DISCLOSE') {
            allDisclosedMessages.push(allMessages[i]);
          }
        }

        // console.log(disclosedIndexes);
        // console.log(messagesOctets);
        const headerBytes = hexToBytes(proofFixture.header);
        const publicBytes = hexToBytes(proofFixture.signerPublicKey);
        const proof = hexToBytes(proofFixture.proof);
        const ph = hexToBytes(proofFixture.presentationHeader);
        const result = await BlindProofVerify(publicBytes, proof, headerBytes,
          ph, proofFixture.L, allDisclosedMessages, allMessageDisclosures, api_id);
        assert.equal(result, proofFixture.result.valid);
        if(!proofFixture.result.valid) {
          return;
        }

        // Check add_zkp_info (prover-only data for external ZKPs) against the
        // committed disclosure commitments carried in the proof.
        const {committed_message_scalars, commitment_rands} = proofFixture.add_zkp_info;
        const N = commitment_rands.length;
        const committedMessages = allMessages.filter((msg, i) => allMessageDisclosures[i] == 'COMMIT');
        assert.equal(N, committedMessages.length, 'commitment_rands length != number of COMMIT messages');
        assert.equal(committed_message_scalars.length, N, 'committed_message_scalars length != N');
        if(N === 0) {
          return;
        }
        // The committed message scalars must be those of the signed COMMIT messages
        const expectedScalars = await blind_messages_to_scalars(committedMessages, api_id);
        assert.deepEqual(committed_message_scalars.map(m => BigInt('0x' + m)), expectedScalars);
        // Each commitment C_i in the proof must open to Y_0 * s_i + Y_1 * m_i
        const [, commitments_proof] = octets_to_proof(proof, N);
        const [Y_0, Y_1] = (await prepareGenerators(2, 'COM_DIS_' + api_id)).generators;
        for(let i = 0; i < N; i++) {
          const s_i = BigInt('0x' + commitment_rands[i]);
          const m_i = BigInt('0x' + committed_message_scalars[i]);
          const C_i = Y_0.multiply(s_i).add(Y_1.multiply(m_i));
          assert.isTrue(C_i.equals(commitments_proof.commitments[i]), `commitment ${i} does not match add_zkp_info`);
        }
      });
    }
  });
}
