/* global describe, it, TextEncoder */
/* eslint-disable max-len */
/*
  Proof generation tests. Each proof test vector names the signature test
  vector it is based on via its signatureFile field.
*/
import {API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE, hexToBytes, numberToHex,
  seeded_random_scalars} from '../lib/BBS.js';
import {ProofGenWithNym, traceInfo} from '../lib/PseudonymBBS.js';
import {readdir, readFile} from 'fs/promises';
import {assert} from 'chai';
import {bytesToHex} from '@noble/hashes/utils.js';
import {dirname} from 'path';
import {fileURLToPath} from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

for(const api_id of [API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE]) {
  const suite = api_id.includes('SHAKE-256') ? 'bls12-381-shake-256' : 'bls12-381-sha-256';
  const path = `${__dirname}/fixture_data/${suite}/nymProof/`;
  const sigPath = `${__dirname}/fixture_data/${suite}/nymSignature/`;
  const testVectors = [];
  for(const fn of await readdir(path)) {
    const vectorObj = JSON.parse(await readFile(path + fn));
    vectorObj.filename = fn;
    vectorObj.sigInfo = JSON.parse(await readFile(sigPath + vectorObj.signatureFile));
    testVectors.push(vectorObj);
  }

  describe('Pseudonym Proof generation for ' + api_id, function() {
    for(const proofFixture of testVectors) {
      it(`file: ${proofFixture.filename}, case: ${proofFixture.caseName}`, async function() {
        const sigInfo = proofFixture.sigInfo;
        const PK = hexToBytes(proofFixture.signerPublicKey);
        const signature = hexToBytes(sigInfo.signature);
        const header = hexToBytes(proofFixture.header);
        const ph = hexToBytes(proofFixture.presentationHeader);
        const context_id = hexToBytes(proofFixture.context_id);
        const nym_secrets = sigInfo.nym_secrets.map(nym => BigInt('0x' + nym));
        const proverBlind = BigInt('0x' + sigInfo.proverBlind);
        const messages = sigInfo.messages.map(msg => [msg[0], hexToBytes(msg[1])]);
        const blindMessages = sigInfo.blindMessages.map(msg => [msg[0], hexToBytes(msg[1])]);
        // Pseudo random (deterministic) scalar generation seed and function
        const rngParams = proofFixture.mockRngParameters;
        const seed = new TextEncoder().encode(rngParams.SEED);
        const rand_scalar_func = seeded_random_scalars.bind(null, seed, rngParams.proof.DST);

        const [proof, pseudonym, add_zkp_info] = await ProofGenWithNym(PK, signature, header, ph,
          nym_secrets, context_id, messages, blindMessages, proofFixture.messageDisclosures,
          proofFixture.blindMessageDisclosures, proverBlind, api_id, rand_scalar_func);
        assert.equal(bytesToHex(proof), proofFixture.proof);
        assert.equal(bytesToHex(pseudonym.toBytes(true)), proofFixture.pseudonym);
        assert.deepEqual({
          committed_message_scalars: add_zkp_info.committed_message_scalars.map(m => numberToHex(m, 32)),
          commitment_rands: add_zkp_info.commitment_rands.map(s => numberToHex(s, 32)),
        }, proofFixture.add_zkp_info);
        assert.equal(traceInfo.CoreProofGen.count_random_scalars,
          rngParams.proof.count);
        assert.equal(traceInfo.CoreProofGen.challenge, proofFixture.trace.challenge);
      });
    }
  });
}
