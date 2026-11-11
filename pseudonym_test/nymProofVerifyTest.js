/* global describe, it, TextEncoder */
/* eslint-disable max-len */
/*
  Verifies all pseudonym proof test vectors, checks add_zkp_info against the
  committed disclosure commitments, and checks that modified inputs are
  rejected.
*/
import {API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE, hexToBytes,
  prepareGenerators} from '../lib/BBS.js';
import {messages_to_scalars, octets_to_proof} from '../lib/BlindBBS.js';
import {readdir, readFile} from 'fs/promises';
import {assert} from 'chai';
import {bls12_381 as bls} from '@noble/curves/bls12-381.js';
import {dirname} from 'path';
import {fileURLToPath} from 'url';
import {ProofVerifyWithNym} from '../lib/PseudonymBBS.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

for(const api_id of [API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE]) {
  const suite = api_id.includes('SHAKE-256') ? 'bls12-381-shake-256' : 'bls12-381-sha-256';
  const path = `${__dirname}/fixture_data/${suite}/nymProof/`;
  const sigPath = `${__dirname}/fixture_data/${suite}/nymSignature/`;
  const testVectors = [];
  for(const fn of await readdir(path)) {
    const vectorObj = JSON.parse(await readFile(path + fn));
    vectorObj.filename = fn;
    vectorObj.sigInfo = JSON.parse(await readFile(sigPath + vectorObj.signatureFile));
    testVectors.push(vectorObj);
  }

  describe('Pseudonym Proof verification for ' + api_id, function() {
    for(const proofFixture of testVectors) {
      // What the verifier receives: disclosures and disclosed messages for
      // all signer messages followed by all prover (blind) messages.
      const sigInfo = proofFixture.sigInfo;
      const messages = sigInfo.messages.map(msg => [msg[0], hexToBytes(msg[1])]);
      const blindMessages = sigInfo.blindMessages.map(msg => [msg[0], hexToBytes(msg[1])]);
      const allMessages = messages.concat(blindMessages);
      const allDisclosures = proofFixture.messageDisclosures.concat(proofFixture.blindMessageDisclosures);
      const disclosedMessages = allMessages.filter((msg, i) => allDisclosures[i] === 'DISCLOSE');
      const PK = hexToBytes(proofFixture.signerPublicKey);
      const proof = hexToBytes(proofFixture.proof);
      const header = hexToBytes(proofFixture.header);
      const ph = hexToBytes(proofFixture.presentationHeader);
      const pseudonym = hexToBytes(proofFixture.pseudonym);
      const context_id = hexToBytes(proofFixture.context_id);
      const length_nym_vector = sigInfo.nym_secrets.length;
      // Create verification function to easily implement negative tests.
      // For ?? see https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Nullish_coalescing
      const verify = (o = {}) => ProofVerifyWithNym(PK, o.proof ?? proof, header, ph,
        o.pseudonym ?? pseudonym, o.context_id ?? context_id,
        o.length_nym_vector ?? length_nym_vector, proofFixture.L,
        o.disclosedMessages ?? disclosedMessages, o.disclosures ?? allDisclosures, api_id);
      const name = `file: ${proofFixture.filename}`;

      it(`${name}, case: ${proofFixture.caseName}`, async function() {
        assert.equal(await verify(), proofFixture.result.valid);
      });

      it(`${name}, add_zkp_info matches the committed disclosure commitments`, async function() {
        const {committed_message_scalars, commitment_rands} = proofFixture.add_zkp_info;
        const N = commitment_rands.length;
        const committedMessages = allMessages.filter((msg, i) => allDisclosures[i] === 'COMMIT');
        assert.equal(N, committedMessages.length, 'commitment_rands length != number of COMMIT messages');
        assert.equal(committed_message_scalars.length, N, 'committed_message_scalars length != N');
        // The committed message scalars must be those of the signed COMMIT messages
        const expectedScalars = await messages_to_scalars(committedMessages, api_id);
        assert.deepEqual(committed_message_scalars.map(m => BigInt('0x' + m)), expectedScalars);
        // Each commitment C_i in the proof must open to Y_0 * s_i + Y_1 * m_i
        const [, commitments_proof] = octets_to_proof(proof, N);
        const [Y_0, Y_1] = (await prepareGenerators(2, 'COM_DIS_' + api_id)).generators;
        for(let i = 0; i < N; i++) {
          const C_i = Y_0.multiply(BigInt('0x' + commitment_rands[i]))
            .add(Y_1.multiply(BigInt('0x' + committed_message_scalars[i])));
          assert.isTrue(C_i.equals(commitments_proof.commitments[i]), `commitment ${i} does not match add_zkp_info`);
        }
      });

      // Negative cases, all must return false (INVALID)
      it(`${name}, wrong context_id is INVALID`, async function() {
        assert.isFalse(await verify({context_id: new TextEncoder().encode('wrong context')}));
      });
      it(`${name}, tampered pseudonym is INVALID`, async function() {
        const other = bls.G1.Point.fromBytes(pseudonym).double().toBytes(true);
        assert.isFalse(await verify({pseudonym: other}));
      });
      it(`${name}, identity pseudonym is INVALID`, async function() {
        assert.isFalse(await verify({pseudonym: bls.G1.Point.ZERO.toBytes(true)}));
      });
      it(`${name}, wrong length_nym_vector is INVALID`, async function() {
        assert.isFalse(await verify({length_nym_vector: length_nym_vector + 1}));
        if(length_nym_vector > 1) {
          assert.isFalse(await verify({length_nym_vector: length_nym_vector - 1}));
        }
      });
      it(`${name}, bad message_disclosures length is INVALID`, async function() {
        assert.isFalse(await verify({disclosures: allDisclosures.slice(1)}));
        assert.isFalse(await verify({disclosures: [...allDisclosures, 'HIDE']}));
      });
      it(`${name}, tampered proof is INVALID`, async function() {
        const tampered = proof.slice();
        tampered[tampered.length - 1] ^= 1;
        assert.isFalse(await verify({proof: tampered}));
      });
      if(disclosedMessages.length > 0) {
        it(`${name}, modified disclosed message is INVALID`, async function() {
          const modified = disclosedMessages.slice();
          modified[0] = [modified[0][0], new Uint8Array([...modified[0][1], 0])];
          assert.isFalse(await verify({disclosedMessages: modified}));
        });
      }
      if(allDisclosures.includes('COMMIT')) {
        it(`${name}, COMMIT relabelled as HIDE is INVALID`, async function() {
          const relabelled = allDisclosures.slice();
          relabelled[relabelled.indexOf('COMMIT')] = 'HIDE';
          assert.isFalse(await verify({disclosures: relabelled}));
        });
      }
    }
  });
}
