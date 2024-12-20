/* global describe, URL, it, before, TextEncoder*/
/* eslint-disable max-len */
import {
  API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE, hexToBytes,
  prepareGenerators,
  seeded_random_scalars
} from '../lib/BBS.js';
import {readdir, readFile} from 'fs/promises';
import {deserialize_and_validate_commit} from '../lib/BlindBBS.js';
import {assert} from 'chai';
import {bytesToHex} from '@noble/hashes/utils';
import {dirname} from 'path';
import {fileURLToPath} from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

const SHA_PATH = __dirname + '/fixture_data/bls12-381-sha-256/nymCommit/';
const SHAKE_PATH = __dirname + '/fixture_data/bls12-381-shake-256/nymCommit/';

for(const api_id of [API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE]) {
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

  describe('prover_nym commit validation for ' + api_id, async function() {
    for(const commitFixture of testVectors) {
      it(`case: ${commitFixture.caseName}`, async function() {
        const gens = await prepareGenerators(2, 'BLIND_' + api_id);
        const commitmentWithProof = hexToBytes(commitFixture.commitmentWithProof);
        const commit = await deserialize_and_validate_commit(commitmentWithProof, gens, api_id);
        console.log(`commitment: ${bytesToHex(commit.toRawBytes(true))}`);
      });
    }
  });
}
