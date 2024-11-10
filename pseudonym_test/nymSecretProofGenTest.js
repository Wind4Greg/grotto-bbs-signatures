/* global describe, it, TextEncoder */
/* eslint-disable max-len */
import {API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE, hexToBytes,
  seeded_random_scalars} from '../lib/BBS.js';
import {readdir, readFile} from 'fs/promises';
import {assert} from 'chai';
import {NymSecretProofGen, ProofGenWithNym} from '../lib/PseudonymBBS.js';
import {bytesToHex} from '@noble/hashes/utils';

import {dirname} from 'path';
import {fileURLToPath} from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

const SHA_PATH = __dirname + '/fixture_data/bls12-381-sha-256/nymSecretProof/';
const SHAKE_PATH = __dirname + '/fixture_data/bls12-381-shake-256/nymSecretProof/';
const allMessagesFile = __dirname + '/fixture_data/messages.json';

const allMessages = JSON.parse(await readFile(allMessagesFile));
const messages = allMessages.map(hexMsg => hexToBytes(hexMsg));
for(const api_id of [API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE]) { // API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE
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

  describe('Nym Secret Proof generation for ' + api_id, async function() {
    for(let i = 0; i < testVectors.length; i++) { // testVectors.length
      const proofFixture = testVectors[i];
      it(`case: ${proofFixture.caseName}`, async function() {
        const PK = hexToBytes(proofFixture.signerPublicKey);
        const signature = hexToBytes(proofFixture.signature);
        const header = hexToBytes(proofFixture.header);
        const ph = hexToBytes(proofFixture.presentationHeader);
        // const pseudonym_bytes = hexToBytes(proofFixture.pseudonym);
        const nym_secret = BigInt('0x' + proofFixture.nym_secret);
        const disclosedIndexes = proofFixture.disclosedIndexes;
        const disclosed_commitment_indexes = proofFixture.disclosedComIndexes;
        const proverBlind = BigInt('0x' + proofFixture.proverBlind);
        // Pseudo random (deterministic) scalar generation seed and function
        const rngParams = proofFixture.mockRngParameters;
        const te = new TextEncoder();
        const seed = te.encode(rngParams.SEED);
        const rng_dst = rngParams.proof.DST;
        const rand_scalar_func = seeded_random_scalars.bind(null, seed, rng_dst);
        // const proof = await HiddenPidProofGen(PK, signature, pseudonym_bytes, verifier_id,
        //   pid, header, ph, messages, disclosedIndexes, proverBlind,
        //   0n, api_id, rand_scalar_func);
        const committed_messages = [];
        /*
        NymSecretProofGen(PK, signature, header, ph, messages,
  committed_messages, disclosed_indexes, disclosed_commitment_indexes,
  secret_prover_blind, nym_secret, api_id,
  rand_scalars = calculate_random_scalars)
        */
        const proof = await NymSecretProofGen(PK, signature, header, ph,
          messages, committed_messages, disclosedIndexes, disclosed_commitment_indexes,
          proverBlind, nym_secret, api_id, rand_scalar_func);
        console.log(`proof: ${bytesToHex(proof)}`);
        assert.equal(bytesToHex(proof), proofFixture.proof);
      });
    }
  });
}
