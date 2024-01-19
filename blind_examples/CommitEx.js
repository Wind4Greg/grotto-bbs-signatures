/* Example code to test blind commitment functionality */
/* global URL, console */
import {API_ID_BLIND_BBS_SHA, hexToBytes, seeded_random_scalars}
  from '../lib/BBS.js';
import {bytesToHex} from '@noble/hashes/utils';
import {commit} from '../lib/BlindBBS.js';
import {readFile} from 'fs/promises';
const path = '../blind_test/fixture_data/bls12-381-sha-256/commit/';

const commitFixture = JSON.parse(await readFile(
  new URL(path + 'commit002.json', import.meta.url))
);

console.log(commitFixture);
const msgs_in_octets = commitFixture.committedMessages.map(hexMsg =>
  hexToBytes(hexMsg));
// console.log(msgs_in_octets);
const api_id = API_ID_BLIND_BBS_SHA;
let seed = new TextEncoder().encode(commitFixture.mockRngParameters.SEED);
console.log(seed);
const challenge_dst = commitFixture.mockRngParameters.commit.DST;
/* The DST for mocked rng:
"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_COMMIT_MOCK_RANDOM_SCALARS_DST_"
my mocked creates DST from api_id + 'MOCK_RANDOM_SCALARS_DST_'
so try hack of api_id = BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_COMMIT_
*/
const mock_api_hack = 'BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_COMMIT_';
const rand_scalar_func = seeded_random_scalars.bind(null, seed, mock_api_hack);
const [commit_with_proof_octs, secret_prover_blind] = await commit(msgs_in_octets,
  api_id, rand_scalar_func);
console.log(`commit with proof (hex): ${bytesToHex(commit_with_proof_octs)}`);
console.log(`secret prover blind (hex): ${secret_prover_blind.toString(16)}`);
const verified = bytesToHex(commit_with_proof_octs) == commitFixture.commitmentWithProof;
console.log(`test vector verified: ${verified}`);
