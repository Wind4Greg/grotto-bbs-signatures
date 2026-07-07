/* global describe, it, TextEncoder */
/* eslint-disable max-len */
import {
  API_ID_PSEUDONYM_BBS_SHA,
  API_ID_PSEUDONYM_BBS_SHAKE,
  calculate_random_scalars,
  hexToBytes,
  seeded_random_scalars,
} from "../lib/BBS.js";
import { mkdir, readdir, readFile, writeFile } from "fs/promises";
import { assert } from "chai";
import { ProofGenWithNym } from "../lib/PseudonymBBS.js";
import { bytesToHex } from "@noble/hashes/utils.js";

import { dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));

const SHA_PATH = __dirname + "/fixture_data/bls12-381-sha-256/nymProof/";
const SHAKE_PATH = __dirname + "/fixture_data/bls12-381-shake-256/nymProof/";
// Used to hold supplemental data produced in test
const SUPP_PATH = __dirname + '/fixture_data/bls12-381-sha-256/supplement/';
await mkdir(SUPP_PATH, { recursive: true });

for(const api_id of [API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE]) {
  // API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE
  let path = SHA_PATH;
  if (api_id.includes("SHAKE-256")) {
    path = SHAKE_PATH;
  }
  const files = await readdir(path);
  // get all the test vectors in the dir
  const testVectors = [];
  for(const fn of files) {
    if(fn !== 'nymProof110.json') { // use fn == "nymCommit004.json" for specific file
      const vectorObj = JSON.parse(await readFile(path + fn));
      vectorObj.filename = fn;
      testVectors.push(vectorObj);
    }
  }

  describe("Pseudonym Proof generation for " + api_id, async function () {
    for (let i = 0; i < testVectors.length; i++) {
      // testVectors.length
      const proofFixture = testVectors[i];
      it(`file: ${proofFixture.filename}, case: ${proofFixture.caseName}`, async function () {
        const PK = hexToBytes(proofFixture.signerPublicKey);
        const signature = hexToBytes(proofFixture.signature);
        const header = hexToBytes(proofFixture.header);
        const ph = hexToBytes(proofFixture.presentationHeader);
        // const pseudonym_bytes = hexToBytes(proofFixture.pseudonym);
        const context_id = hexToBytes(proofFixture.context_id);
        const nym_secrets = proofFixture.nym_secrets.map((nym_secret) =>
          BigInt("0x" + nym_secret)
        );
        // Get selected indexes
        const disclosedIndexes = Object.keys(proofFixture.revealedMessages)
          .map((key) => parseInt(key))
          .sort();
        // const disclosedIndexes = proofFixture.disclosedIndexes;
        // const disclosed_commitment_indexes = proofFixture.disclosedComIndexes;
        const disclosed_commitment_indexes = Object.keys(
          proofFixture.revealedCommittedMessages
        )
          .map((key) => parseInt(key))
          .sort();
        const proverBlind = BigInt("0x" + proofFixture.proverBlind);
        // Pseudo random (deterministic) scalar generation seed and function
        let rand_scalar_func;
        if(proofFixture.mockRngParameters) {
          const rngParams = proofFixture.mockRngParameters;
          const te = new TextEncoder();
          const seed = te.encode(rngParams.SEED);
          const rng_dst = rngParams.proof.DST;
          rand_scalar_func = seeded_random_scalars.bind(null, seed, rng_dst);
        } else {
          rand_scalar_func = calculate_random_scalars;
        }
        const messages = proofFixture.messages.map(hexMsg => hexToBytes(hexMsg));
        const committed_messages = proofFixture.committedMessages.map(hexMsg => hexToBytes(hexMsg));
        // const proof = await HiddenPidProofGen(PK, signature, pseudonym_bytes, verifier_id,
        //   pid, header, ph, messages, disclosedIndexes, proverBlind,
        //   0n, api_id, rand_scalar_func);
        const [proof, pseudonym] = await ProofGenWithNym(PK, signature, header, ph,
          nym_secrets, context_id, messages, committed_messages, disclosedIndexes,
          disclosed_commitment_indexes, proverBlind, api_id, rand_scalar_func
        );
        if(proofFixture.mockRngParameters) {
          console.log(`proof: ${bytesToHex(proof)}`);
          assert.equal(bytesToHex(proof), proofFixture.proof);
          assert.equal(
            bytesToHex(pseudonym.toBytes(true)),
            proofFixture.pseudonym
          );
        } else {
          console.log('Writing supplement file for proof and pseudonym');
          const myObject = {proof: bytesToHex(proof),
            pseudonym: bytesToHex(pseudonym.toBytes(true))
          };
          await writeFile(SUPP_PATH + proofFixture.filename, JSON.stringify(myObject, null, 2));
        }
      });
    }
  });
}
