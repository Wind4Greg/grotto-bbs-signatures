/* global console, TextEncoder */
/* eslint-disable max-len */

import {
  API_ID_BLIND_BBS_SHA,
  API_ID_BLIND_BBS_SHAKE,
  hexToBytes,
  seeded_random_scalars,
} from "../lib/BBS.js";
import {readdir, readFile} from "fs/promises";
import {BlindProofGen} from "../lib/BlindBBS.js";
import {bytesToHex} from "@noble/hashes/utils.js";

import {dirname} from "path";
import {fileURLToPath} from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));

const SHA_PATH = __dirname + "/inputs/bls12-381-sha-256/";
const SHAKE_PATH = __dirname + "/inputs/bls12-381-shake-256/";
const SIG_SHA_PATH = __dirname + "/outputs/bls12-381-sha-256/";
const SIG_SHAKE_PATH = __dirname + "/outputs/bls12-381-shake-256/";

for(const api_id of [API_ID_BLIND_BBS_SHA]) { // , API_ID_BLIND_BBS_SHAKE
  // API_ID_BLIND_BBS_SHA, API_ID_BLIND_BBS_SHAKE
  let path = SHA_PATH;
  let sig_path = SIG_SHA_PATH;
  if(api_id.includes("SHAKE-256")) {
    path = SHAKE_PATH;
    sig_path = SIG_SHAKE_PATH;
  }
  if(api_id.includes("SHAKE-256")) {
    path = SHAKE_PATH;
  }
  const files = await readdir(path + "proof/");

  for(const fn of files) {
    console.log(`Processing file: ${fn} for API ID: ${api_id}`);
    const proofFixture = JSON.parse(await readFile(path + 'proof/' + fn));
    // console.log(proofFixture.signatureFile);
    const sigFixture = JSON.parse(await readFile(sig_path + 'signature/' + proofFixture.signatureFile));
    // console.log(JSON.stringify(sigFixture, null, 2));
    const PK = hexToBytes(proofFixture.signerPublicKey);
    const signature = hexToBytes(sigFixture.signature);
    const header = hexToBytes(proofFixture.header);
    let proverBlind = 0n;
    if(sigFixture.proverBlind) {
      proverBlind = BigInt("0x" + sigFixture.proverBlind);
    }
    const ph = hexToBytes(proofFixture.presentationHeader);
    const blindMessages = sigFixture.blindMessages.map(msg => [msg[0], hexToBytes(msg[1])]);
    const messages = sigFixture.messages.map(msg => [msg[0], hexToBytes(msg[1])]);
    const messageDisclosures = proofFixture.messageDisclosures;
    const blindMessageDisclosures = proofFixture.blindMessageDisclosures;

    // Pseudo random (deterministic) scalar generation seed and function
    const rngParams = proofFixture.mockRngParameters;
    const te = new TextEncoder();
    const seed = te.encode(rngParams.SEED);
    const rng_dst = rngParams.proof.DST;
    const rand_scalar_func = seeded_random_scalars.bind(
      null,
      seed,
      rng_dst,
    );

    const proof = await BlindProofGen(
      PK,
      signature,
      header,
      ph,
      messages,
      blindMessages,
      messageDisclosures,
      blindMessageDisclosures,
      proverBlind,
      api_id,
      rand_scalar_func,
    );
    console.log(`proof: ${bytesToHex(proof)}`);
  }

}
