/* global console, TextEncoder */
/* eslint-disable max-len */
// Generates the CommitWithNym test vectors.
import {API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE, hexToBytes, seeded_random_scalars} from '../lib/BBS.js';
import {mkdir, readdir, readFile, writeFile} from 'fs/promises';
import {bytesToHex} from '@noble/hashes/utils.js';
import {CommitWithNym} from '../lib/PseudonymBBS.js';
import {dirname} from 'path';
import {fileURLToPath} from 'url';
import {traceInfo} from '../lib/BlindBBS.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

for(const api_id of [API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE]) {
  const suite = api_id.includes('SHAKE-256') ? 'bls12-381-shake-256' : 'bls12-381-sha-256';
  const path = `${__dirname}/inputs/${suite}/nymCommit/`;
  const outputPath = path.replace('/inputs/', '/outputs/');
  await mkdir(outputPath, {recursive: true});
  const files = await readdir(path);
  for(const fn of files) {
    console.log(`Processing file: ${fn} for API ID: ${api_id}`);
    const commitFixture = JSON.parse(await readFile(path + fn));
    const blindMessages = commitFixture.blindMessages.map(msg => [msg[0], hexToBytes(msg[1])]);
    const prover_nyms = commitFixture.proverNyms.map(nym => BigInt('0x' + nym));
    const seed = new TextEncoder().encode(commitFixture.mockRngParameters.SEED);
    const rng_dst = commitFixture.mockRngParameters.commit.DST;
    const rand_scalar_func = seeded_random_scalars.bind(null, seed, rng_dst);
    const [commit_with_proof_octs, secret_prover_blind] =
      await CommitWithNym(blindMessages, prover_nyms, api_id, rand_scalar_func);
    commitFixture.commitmentWithProof = bytesToHex(commit_with_proof_octs);
    commitFixture.proverBlind = secret_prover_blind.toString(16);
    // CommitWithNym uses Blind.CoreCommit which fills in the Blind BBS trace
    const currentTrace = Object.assign({}, traceInfo.CoreCommit);
    commitFixture.mockRngParameters.commit.count = currentTrace.count_random_scalars;
    commitFixture.trace = {random_scalars: {s_tilde: currentTrace.s_tilde, m_tildes: currentTrace.m_tildes}};
    await writeFile(outputPath + fn, JSON.stringify(commitFixture, null, 2));
  }
}
