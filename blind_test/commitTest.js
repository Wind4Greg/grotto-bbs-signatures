/* global describe, URL, it, before, TextEncoder*/
/* eslint-disable max-len */
import {API_ID_BLIND_BBS_SHA, API_ID_BLIND_BBS_SHAKE, hexToBytes,
  seeded_random_scalars} from '../lib/BBS.js';
import {readdir, readFile} from 'fs/promises';
import {assert} from 'chai';
import {bytesToHex} from '@noble/hashes/utils';
import {commit} from '../lib/BlindBBS.js';
import {dirname} from 'path';
import {fileURLToPath} from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

const SHA_PATH = __dirname + '/fixture_data/bls12-381-sha-256/commit/';
const SHAKE_PATH = __dirname + '/fixture_data/bls12-381-shake-256/commit/';

for(const api_id of [API_ID_BLIND_BBS_SHA, API_ID_BLIND_BBS_SHAKE]) {
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

  describe('Commit generation for ' + api_id, async function() {
    for(const commitFixture of testVectors) {
      it(`case: ${commitFixture.caseName}`, async function() {
        const msgs_in_octets = commitFixture.committedMessages.map(hexMsg =>
          hexToBytes(hexMsg));
        const seed = new TextEncoder().encode(commitFixture.mockRngParameters.SEED);
        const rng_dst = commitFixture.mockRngParameters.commit.DST;
        const rand_scalar_func = seeded_random_scalars.bind(null, seed, rng_dst);
        const [commit_with_proof_octs, secret_prover_blind] =
            await commit(msgs_in_octets, api_id, rand_scalar_func);
        // console.log(`commit with proof (hex): ${bytesToHex(commit_with_proof_octs)}`);
        // console.log(`secret prover blind (hex): ${secret_prover_blind.toString(16)}`);
        // console.log(`calcM: ${calcM(commit_with_proof_octs)}`);
        assert.equal(bytesToHex(commit_with_proof_octs),
          commitFixture.commitmentWithProof);
      });
    }
  });
}
