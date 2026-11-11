/* global console, TextEncoder */
/* eslint-disable max-len */
// Generates the BlindSignWithNym test vectors. The prover's commitment is
// computed with CommitWithNym using the seeded RNG, and the resulting
// signature is checked, and nym_secrets computed, with VerifyFinalizeWithNym.
import {API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE, hexToBytes, numberToHex,
  seeded_random_scalars} from '../lib/BBS.js';
import {BlindSignWithNym, CommitWithNym, traceInfo, VerifyFinalizeWithNym} from '../lib/PseudonymBBS.js';
import {mkdir, readdir, readFile, writeFile} from 'fs/promises';
import {traceInfo as blindTraceInfo} from '../lib/BlindBBS.js';
import {bytesToHex} from '@noble/hashes/utils.js';
import {dirname} from 'path';
import {fileURLToPath} from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

for(const api_id of [API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE]) {
  const suite = api_id.includes('SHAKE-256') ? 'bls12-381-shake-256' : 'bls12-381-sha-256';
  const path = `${__dirname}/inputs/${suite}/nymSignature/`;
  const outputPath = path.replace('/inputs/', '/outputs/');
  await mkdir(outputPath, {recursive: true});
  const files = await readdir(path);
  for(const fn of files) {
    console.log(`Processing file: ${fn} for API ID: ${api_id}`);
    const sigFixture = JSON.parse(await readFile(path + fn));
    // Prover: commit to the blind messages and prover_nyms
    const blindMessages = sigFixture.blindMessages.map(msg => [msg[0], hexToBytes(msg[1])]);
    const prover_nyms = sigFixture.proverNyms.map(nym => BigInt('0x' + nym));
    const seed = new TextEncoder().encode(sigFixture.mockRngParameters.SEED);
    const rng_dst = sigFixture.mockRngParameters.commit.DST;
    const rand_scalar_func = seeded_random_scalars.bind(null, seed, rng_dst);
    const [commit_with_proof_octs, secret_prover_blind] =
      await CommitWithNym(blindMessages, prover_nyms, api_id, rand_scalar_func);
    sigFixture.mockRngParameters.commit.count = blindTraceInfo.CoreCommit.count_random_scalars;
    // Signer: blind sign with signer_nym_entropy
    const SK = BigInt('0x' + sigFixture.signerKeyPair.secretKey);
    const PK = hexToBytes(sigFixture.signerKeyPair.publicKey);
    const header = hexToBytes(sigFixture.header);
    const messages = sigFixture.messages.map(msg => [msg[0], hexToBytes(msg[1])]);
    const signer_nym_entropy = BigInt('0x' + sigFixture.signer_nym_entropy);
    const sig = await BlindSignWithNym(SK, PK, commit_with_proof_octs, prover_nyms.length,
      signer_nym_entropy, header, messages, api_id);
    const sigTrace = Object.assign({}, traceInfo.BCalculate);
    // Prover: verify the signature and compute nym_secrets (throws if INVALID)
    const nym_secrets = await VerifyFinalizeWithNym(PK, sig, header, messages, blindMessages,
      prover_nyms, signer_nym_entropy, secret_prover_blind, api_id);
    sigFixture.commitmentWithProof = bytesToHex(commit_with_proof_octs);
    sigFixture.proverBlind = secret_prover_blind.toString(16);
    sigFixture.nym_secrets = nym_secrets.map(nym => numberToHex(nym, 32));
    sigFixture.signature = bytesToHex(sig);
    sigFixture.trace = {B: sigTrace.B, domain: sigTrace.domain};
    await writeFile(outputPath + fn, JSON.stringify(sigFixture, null, 2));
  }
}
