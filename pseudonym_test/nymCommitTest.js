/* global describe, it, TextEncoder */
/* eslint-disable max-len */
import {API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE, hexToBytes,
  seeded_random_scalars} from '../lib/BBS.js';
import {readdir, readFile} from 'fs/promises';
import {assert} from 'chai';
import {bytesToHex} from '@noble/hashes/utils.js';
import {CommitWithNym} from '../lib/PseudonymBBS.js';
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

  describe('Prover Nym commit generation for ' + api_id, function() {
    for(const commitFixture of testVectors) {
      it(`file: ${commitFixture.filename}, case: ${commitFixture.caseName}`, async function() {
        const blindMessages = commitFixture.blindMessages.map(msg => [msg[0], hexToBytes(msg[1])]);
        const prover_nyms = commitFixture.proverNyms.map(nym => BigInt('0x' + nym));
        const seed = new TextEncoder().encode(commitFixture.mockRngParameters.SEED);
        const rng_dst = commitFixture.mockRngParameters.commit.DST;
        const rand_scalar_func = seeded_random_scalars.bind(null, seed, rng_dst);
        const [commit_with_proof_octs, secret_prover_blind] =
          await CommitWithNym(blindMessages, prover_nyms, api_id, rand_scalar_func);
        assert.equal(bytesToHex(commit_with_proof_octs), commitFixture.commitmentWithProof);
        assert.equal(secret_prover_blind, BigInt('0x' + commitFixture.proverBlind));
      });
    }
  });
}
