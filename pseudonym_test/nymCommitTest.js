/* global describe, URL, it, before, TextEncoder*/
/* eslint-disable max-len */
import {
  API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE, hexToBytes,
  seeded_random_scalars
} from '../lib/BBS.js';
import {readdir, readFile} from 'fs/promises';
import {commit} from '../lib/BlindBBS.js';
import {NymCommit} from '../lib/PseudonymBBS.js';

import {assert} from 'chai';
import {bytesToHex} from '@noble/hashes/utils';
import {dirname} from 'path';
import {fileURLToPath} from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

const SHA_PATH = __dirname + '/fixture_data/bls12-381-sha-256/nymCommit/';
const SHAKE_PATH = __dirname + '/fixture_data/bls12-381-shake-256/nymCommit/';

for(const api_id of [API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE]) { //API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE
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

  describe('Prover Nym commit generation for ' + api_id, async function () {
    for(const commitFixture of testVectors) {
      it(`case: ${commitFixture.caseName}`, async function () {
        const msgs_in_octets = commitFixture.committedMessages.map(hexMsg =>
          hexToBytes(hexMsg));
        const prover_nym = BigInt('0x' + commitFixture.proverNym);
        const seed = new TextEncoder().encode(commitFixture.mockRngParameters.SEED);
        const rng_dst = commitFixture.mockRngParameters.commit.DST;
        const rand_scalar_func = seeded_random_scalars.bind(null, seed, rng_dst);
        // NymCommit(messages, prover_nym, api_id, and_scalars = calculate_random_scalars)
        const [commit_with_proof_octs, secret_prover_blind] =
          await NymCommit(msgs_in_octets, prover_nym,api_id, rand_scalar_func);
        // console.log(`commit with proof (hex): ${bytesToHex(commit_with_proof_octs)}`);
        // console.log(`secret prover blind (hex): ${secret_prover_blind.toString(16)}`);
        assert.equal(bytesToHex(commit_with_proof_octs),
          commitFixture.commitmentWithProof);
      });
    }
  });
}
