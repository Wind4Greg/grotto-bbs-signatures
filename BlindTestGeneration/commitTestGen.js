/* global describe, URL, TextEncoder, console*/
/* eslint-disable max-len */
import {API_ID_BLIND_BBS_SHA, API_ID_BLIND_BBS_SHAKE, hexToBytes,
  seeded_random_scalars} from '../lib/BBS.js';
import {Commit, traceInfo} from '../lib/BlindBBS.js';
import {readdir, readFile, writeFile} from 'fs/promises';
import {bytesToHex} from '@noble/hashes/utils.js';
import {dirname} from 'path';
import {fileURLToPath} from 'url';


const __dirname = dirname(fileURLToPath(import.meta.url));

const SHA_PATH = __dirname + '/inputs/bls12-381-sha-256/commit/';
const SHAKE_PATH = __dirname + '/inputs/bls12-381-shake-256/commit/';

for(const api_id of [API_ID_BLIND_BBS_SHA, API_ID_BLIND_BBS_SHAKE]) {
  let path = SHA_PATH;
  if(api_id.includes('SHAKE-256')) {
    path = SHAKE_PATH;
  }
  const files = await readdir(path);
  // get all the test vectors in the dir
  for(const fn of files) {
    const commitFixture = JSON.parse(await readFile(path + fn));
    const msgs_in_octets = commitFixture.blindMessages.map(msg => [msg[0], hexToBytes(msg[1])]);
    const seed = new TextEncoder().encode(commitFixture.mockRngParameters.SEED);
    const rng_dst = commitFixture.mockRngParameters.commit.DST;
    const rand_scalar_func = seeded_random_scalars.bind(null, seed, rng_dst);
    const [commit_with_proof_octs, secret_prover_blind] =
        await Commit(msgs_in_octets, api_id, rand_scalar_func);
    // console.log(`commit with proof (hex): ${bytesToHex(commit_with_proof_octs)}`);
    // console.log(`secret prover blind (hex): ${secret_prover_blind.toString(16)}`);
    commitFixture.commitmentWithProof = bytesToHex(commit_with_proof_octs);
    commitFixture.proverBlind = secret_prover_blind.toString(16);
    const currentTrace = Object.assign({}, traceInfo.CoreCommit);
    commitFixture.mockRngParameters.commit.count = currentTrace.count_random_scalars;
    commitFixture.trace = {random_scalars: {s_tilde: currentTrace.s_tilde, m_tildes: currentTrace.m_tildes}};

    // Write out the updated test vector to the corresponding output directory
    const outputPath = path.replace('/inputs/', '/outputs/');
    await writeFile(outputPath + fn, JSON.stringify(commitFixture, null, 2));
  }
}
