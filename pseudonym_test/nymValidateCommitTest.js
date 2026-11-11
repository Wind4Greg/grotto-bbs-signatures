/* global describe, it */
/* eslint-disable max-len */
import {API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE, hexToBytes,
  prepareGenerators} from '../lib/BBS.js';
import {readdir, readFile} from 'fs/promises';
import {assert} from 'chai';
import {deserialize_and_validate_commit} from '../lib/BlindBBS.js';
import {dirname} from 'path';
import {fileURLToPath} from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

for(const api_id of [API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE]) {
  const suite = api_id.includes('SHAKE-256') ? 'bls12-381-shake-256' : 'bls12-381-sha-256';
  const path = `${__dirname}/fixture_data/${suite}/nymCommit/`;
  const testVectors = [];
  for(const fn of await readdir(path)) {
    const vectorObj = JSON.parse(await readFile(path + fn));
    vectorObj.filename = fn;
    testVectors.push(vectorObj);
  }

  describe('prover_nyms commit validation for ' + api_id, function() {
    for(const commitFixture of testVectors) {
      // The signer only knows M = blind messages + prover nyms from the commitment
      const M = commitFixture.blindMessages.length + commitFixture.proverNyms.length;
      it(`file: ${commitFixture.filename}, case: ${commitFixture.caseName}`, async function() {
        const blindGens = await prepareGenerators(M + 1, 'BLIND_' + api_id);
        const commitmentWithProof = hexToBytes(commitFixture.commitmentWithProof);
        const commit = await deserialize_and_validate_commit(commitmentWithProof, blindGens, api_id);
        assert.isFalse(commit.equals(commit.constructor.ZERO));
      });
      it(`file: ${commitFixture.filename}, tampered commitment proof is rejected`, async function() {
        const blindGens = await prepareGenerators(M + 1, 'BLIND_' + api_id);
        const tampered = hexToBytes(commitFixture.commitmentWithProof);
        tampered[tampered.length - 1] ^= 1; // flip a bit in the proof challenge
        let threw = false;
        try {
          await deserialize_and_validate_commit(tampered, blindGens, api_id);
        } catch{
          threw = true;
        }
        assert.isTrue(threw);
      });
    }
  });
}
