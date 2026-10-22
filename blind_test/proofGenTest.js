/* global describe, it, TextEncoder */
/* eslint-disable max-len */
/*
  All these proof generation tests work with the same set of signer and prover (committed)
  messages. The signature corresponds to the signature test vector file: signature004.json.
*/
import {
  API_ID_BLIND_BBS_SHA,
  API_ID_BLIND_BBS_SHAKE,
  hexToBytes,
  seeded_random_scalars,
} from "../lib/BBS.js";
import {readdir, readFile} from "fs/promises";
import {assert} from "chai";
import {BlindProofGen} from "../lib/BlindBBS.js";
import {bytesToHex} from "@noble/hashes/utils.js";

import {dirname} from "path";
import {fileURLToPath} from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));

const SHA_PATH = __dirname + "/fixture_data/bls12-381-sha-256/proof/";
const SHAKE_PATH = __dirname + "/fixture_data/bls12-381-shake-256/proof/";
const SIG_SHA_PATH = __dirname + "/fixture_data/bls12-381-sha-256/signature/";
const SIG_SHAKE_PATH = __dirname + "/fixture_data/bls12-381-shake-256/signature/";

for(const api_id of [API_ID_BLIND_BBS_SHA, API_ID_BLIND_BBS_SHAKE]) {
  let path = SHA_PATH;
  let sig_path = SIG_SHA_PATH;
  if(api_id.includes("SHAKE-256")) {
    path = SHAKE_PATH;
    sig_path = SIG_SHAKE_PATH;
  }
  const files = await readdir(path);
  // get all the test vectors in the dir
  const testVectors = [];

  for(const fn of files) {
    const vectorObj = JSON.parse(await readFile(path + fn));
    vectorObj.filename = fn;
    // Getting the signature file for this proof test vector
    const sigFixture = JSON.parse(await readFile(sig_path + vectorObj.signatureFile));
    vectorObj.sigInfo = sigFixture;
    testVectors.push(vectorObj);
  }

  describe('Proof generation for ' + api_id, async function() {
    for(let i = 0; i < testVectors.length; i++) {
      // testVectors.length
      const proofFixture = testVectors[i];
      it(`file: ${proofFixture.filename}, case: ${proofFixture.caseName}`, async function () {
        const PK = hexToBytes(proofFixture.signerPublicKey);
        const signature = hexToBytes(proofFixture.sigInfo.signature);
        const header = hexToBytes(proofFixture.header);
        let proverBlind = 0n;
        if(proofFixture.sigInfo.proverBlind) {
          proverBlind = BigInt("0x" + proofFixture.sigInfo.proverBlind);
        }
        const ph = hexToBytes(proofFixture.presentationHeader);

        let blindMessages = [];
        if(proofFixture.sigInfo.blindMessages !== null) {
          blindMessages = proofFixture.sigInfo.blindMessages.map(msg => [msg[0], hexToBytes(msg[1])]);
        }
        const messages = proofFixture.sigInfo.messages.map(msg => [msg[0], hexToBytes(msg[1])]);
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
        // console.log(`disclosed idxs: ${disclosedIndexes}`);
        // console.log(`disclosed committed idxs: ${disclosedCommittedIndexes}`);
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
        // console.log(`proof: ${bytesToHex(proof)}`);
        // console.log(`indexes: ${disclosed_idxs}`);
        // console.log('disclosed_msgs:');
        // console.log(disclosed_msgs.map(bs => bytesToHex(bs)));
        assert.equal(bytesToHex(proof), proofFixture.proof);
      });
    }
  });
}
