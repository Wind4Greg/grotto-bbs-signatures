/* global console, TextEncoder */
/* eslint-disable max-len */
import {API_ID_BLIND_BBS_SHA, API_ID_BLIND_BBS_SHAKE, hexToBytes, seeded_random_scalars} from '../lib/BBS.js';
import {BlindSign, Commit, traceInfo} from '../lib/BlindBBS.js';
import {readdir, readFile, writeFile} from 'fs/promises';
import {bytesToHex} from '@noble/hashes/utils.js';

import {dirname} from 'path';
import {fileURLToPath} from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

const SHA_PATH = __dirname + '/inputs/bls12-381-sha-256/signature/';
const SHAKE_PATH = __dirname + '/inputs/bls12-381-shake-256/signature/';

for(const api_id of [API_ID_BLIND_BBS_SHA, API_ID_BLIND_BBS_SHAKE]) { // API_ID_BLIND_BBS_SHA, API_ID_BLIND_BBS_SHAKE
  let path = SHA_PATH;
  if(api_id.includes('SHAKE-256')) {
    path = SHAKE_PATH;
  }
  const files = await readdir(path);
  // get all the test vectors in the dir

  for(const fn of files) {
    console.log(`Processing file: ${fn} for API ID: ${api_id}`);
    const sigFixture = JSON.parse(await readFile(path + fn));
    // Compute the commitment with proof and prover blind from the blind messages
    let commit_with_proof_octs = null;
    let secret_prover_blind = null;
    if(sigFixture.blindMessages !== null) {
      const blindMessages = sigFixture.blindMessages.map(msg => [msg[0], hexToBytes(msg[1])]);
      const seed = new TextEncoder().encode(sigFixture.mockRngParameters.SEED);
      const rng_dst = sigFixture.mockRngParameters.commit.DST;
      const rand_scalar_func = seeded_random_scalars.bind(null, seed, rng_dst);
      [commit_with_proof_octs, secret_prover_blind] =
          await Commit(blindMessages, api_id, rand_scalar_func);
    }
    const SK = BigInt('0x' + sigFixture.signerKeyPair.secretKey);
    const PK = hexToBytes(sigFixture.signerKeyPair.publicKey);

    const header = hexToBytes(sigFixture.header);
    const messages = sigFixture.messages.map(msg => [msg[0], hexToBytes(msg[1])]);
    // BlindSign(SK, PK, commitment_with_proof, header, messages,  api_id)
    const sig = await BlindSign(SK, PK, commit_with_proof_octs, header, messages, api_id);
    sigFixture.signature = bytesToHex(sig);
    if(commit_with_proof_octs !== null) {
      sigFixture.commitmentWithProof = bytesToHex(commit_with_proof_octs);
      sigFixture.proverBlind = secret_prover_blind.toString(16);
      const commitTrace = Object.assign({}, traceInfo.CoreCommit);
      sigFixture.mockRngParameters.commit.count = commitTrace.count_random_scalars;
    } else {
      sigFixture.commitmentWithProof = null;
      sigFixture.proverBlind = null;
    }

    const sigTrace = Object.assign({}, traceInfo.BCalculate);
    sigFixture.trace = {B: sigTrace.B, domain: sigTrace.domain};
    // console.log(JSON.stringify(sigFixture, null, 2));
    // Write out the updated test vector to the corresponding output directory
    const outputPath = path.replace('/inputs/', '/outputs/');
    await writeFile(outputPath + fn, JSON.stringify(sigFixture, null, 2));
  }
}
