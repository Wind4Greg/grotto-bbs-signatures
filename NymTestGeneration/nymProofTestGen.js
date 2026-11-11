/* global console, TextEncoder */
/* eslint-disable max-len */
// Generates the ProofGenWithNym test vectors. Each proof input names the
// signature output it is based on via signatureFile, so run nymSignTestGen.js
// first. Every generated proof is checked with ProofVerifyWithNym.
import {API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE, hexToBytes, numberToHex,
  seeded_random_scalars} from '../lib/BBS.js';
import {mkdir, readdir, readFile, writeFile} from 'fs/promises';
import {ProofGenWithNym, ProofVerifyWithNym, traceInfo} from '../lib/PseudonymBBS.js';
import {bytesToHex} from '@noble/hashes/utils.js';
import {dirname} from 'path';
import {fileURLToPath} from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

for(const api_id of [API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE]) {
  const suite = api_id.includes('SHAKE-256') ? 'bls12-381-shake-256' : 'bls12-381-sha-256';
  const path = `${__dirname}/inputs/${suite}/nymProof/`;
  const sigPath = `${__dirname}/outputs/${suite}/nymSignature/`;
  const outputPath = path.replace('/inputs/', '/outputs/');
  await mkdir(outputPath, {recursive: true});
  const files = await readdir(path);
  for(const fn of files) {
    console.log(`Processing file: ${fn} for API ID: ${api_id}`);
    const proofFixture = JSON.parse(await readFile(path + fn));
    const sigFixture = JSON.parse(await readFile(sigPath + proofFixture.signatureFile));
    const PK = hexToBytes(proofFixture.signerPublicKey);
    const signature = hexToBytes(sigFixture.signature);
    const header = hexToBytes(proofFixture.header);
    const ph = hexToBytes(proofFixture.presentationHeader);
    const context_id = hexToBytes(proofFixture.context_id);
    const nym_secrets = sigFixture.nym_secrets.map(nym => BigInt('0x' + nym));
    const proverBlind = BigInt('0x' + sigFixture.proverBlind);
    const messages = sigFixture.messages.map(msg => [msg[0], hexToBytes(msg[1])]);
    const blindMessages = sigFixture.blindMessages.map(msg => [msg[0], hexToBytes(msg[1])]);
    const messageDisclosures = proofFixture.messageDisclosures;
    const blindMessageDisclosures = proofFixture.blindMessageDisclosures;
    // Pseudo random (deterministic) scalar generation seed and function
    const rngParams = proofFixture.mockRngParameters;
    const seed = new TextEncoder().encode(rngParams.SEED);
    const rand_scalar_func = seeded_random_scalars.bind(null, seed, rngParams.proof.DST);

    const [proof, pseudonym, add_zkp_info] = await ProofGenWithNym(PK, signature, header, ph,
      nym_secrets, context_id, messages, blindMessages, messageDisclosures,
      blindMessageDisclosures, proverBlind, api_id, rand_scalar_func);
    const proofTrace = Object.assign({}, traceInfo.CoreProofGen);

    // Self check: verify the proof as a verifier would
    const disclosedMessages = [
      ...messages.filter((m, i) => messageDisclosures[i] === 'DISCLOSE'),
      ...blindMessages.filter((m, i) => blindMessageDisclosures[i] === 'DISCLOSE')
    ];
    const valid = await ProofVerifyWithNym(PK, proof, header, ph, pseudonym, context_id,
      nym_secrets.length, messages.length, disclosedMessages,
      [...messageDisclosures, ...blindMessageDisclosures], api_id);
    if(valid !== proofFixture.result.valid) {
      throw new Error(`${suite}/${fn}: ProofVerifyWithNym returned ${valid}, expected ${proofFixture.result.valid}`);
    }

    proofFixture.L = messages.length;
    proofFixture.proof = bytesToHex(proof);
    proofFixture.pseudonym = bytesToHex(pseudonym.toBytes(true));
    // Additional information for external ZKPs, never sent to the verifier
    proofFixture.add_zkp_info = {
      committed_message_scalars: add_zkp_info.committed_message_scalars.map(m => numberToHex(m, 32)),
      commitment_rands: add_zkp_info.commitment_rands.map(s => numberToHex(s, 32)),
    };
    proofFixture.mockRngParameters.proof.count = proofTrace.count_random_scalars;
    delete proofTrace.count_random_scalars;
    proofFixture.trace = proofTrace;
    await writeFile(outputPath + fn, JSON.stringify(proofFixture, null, 2));
  }
}
