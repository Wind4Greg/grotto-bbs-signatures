/*global TextEncoder, console*/
/* eslint-disable max-len */
/* Functions used in BBS Per Verifier Id (pseudonym) operations
   API subject to change!
*/

import {B_calculate, traceInfo as BlindTraceInfo, calcM, CoreCommit, deserialize_and_validate_commit,
  FinalizeBlindSign, get_combined_idxs, messages_to_scalars, octets_to_proof, prepare_parameters,
  proof_to_octets} from './BlindBBS.js';
import {ProofFinalize, ProofInit, ProofVerifyInit, bytesToHex, calculate_random_scalars, concat, hash_to_scalar, i2osp,
  numberToHex, octets_to_sig, os2ip, prepareGenerators, serialize, verify} from './BBS.js';
import {bls12_381 as bls} from '@noble/curves/bls12-381.js';
import {shake256} from '@noble/hashes/sha3.js';

const GEN_TRACE_INFO = false; // set to true to send trace info to console.
const GEN_TRACE_OBJECT = true; // Set to true to generate trace info object for test vector generation.
export const traceInfo = {};
const TIME_PERF = false; // set to true for timing of long computations, trace should be off
let startTime; // for performance timing
let finishTime; // for performance timing

const SCALAR_LENGTH = 32;
// const EXPAND_LEN = 48;
const POINT_LENGTH = 48;
// const rPrimeOrder = bls.fields.Fr.ORDER; // prime order of the subgroups G1, G2

/**
 * This operation is used by the Prover to create commitment to a set of
 * messages (blind_messages) along with their prover_nyms that they intend to
 * include in the blind signature.
 *  Note that this operation returns both the serialized combination of the
 *  commitment and its proof of correctness (commitment_with_proof), as well as
 *  the random scalar used to blind the commitment (secret_prover_blind).
 *
 * @param {Array} blind_messages - A vector of messages to be committed. Each
 * message is either an array of the form [flag, value] where flag is 'HASH' or
 * 'RAW' and value is a Uint8Array, or a plain Uint8Array (treated as 'HASH').
 * If not supplied it defaults to the empty array.
 * @param {Array} prover_nyms - A vector of random prover_nym scalars (bigint).
 * @param {string} api_id - The API id for the signature suite.
 * @param {Function} rand_scalars - A function for generating cryptographically
 *  secure random or pseudo random scalars.
 * @returns {Array}  - Comprising an octet string (Uint8Array) for the commitment with proof
 * and the secret_prover_blind scalar in that order.
 */

export async function CommitWithNym(blind_messages = [], prover_nyms, api_id = '',
  rand_scalars = calculate_random_scalars) {
  // 1. committed_message_scalars = Blind.messages_to_scalars(blind_messages, api_id)
  let msgScalars = await messages_to_scalars(blind_messages, api_id);
  // 2. committed_message_scalars.append(prover_nyms)
  msgScalars = msgScalars.concat(prover_nyms);
  const M = msgScalars.length;
  // 3. blind_generators = BBS.create_generators(length(committed_message_scalars) + 1, 'BLIND_' || api_id)
  if(TIME_PERF) {
    startTime = new Date();
  }
  const gens = await prepareGenerators(M + 1, 'BLIND_' + api_id);
  if(TIME_PERF) {
    finishTime = new Date();
    console.log(`CommitWithNym:prepareGenerators time: ${finishTime - startTime}`);
  }
  const blind_generators = gens.generators.slice(0, M + 1);
  // 4. return Blind.CoreCommit(committed_message_scalars, blind_generators, api_id)
  if(TIME_PERF) {
    startTime = new Date();
  }
  const [commit_with_proof_octs, secret_prover_blind] = await CoreCommit(blind_generators, msgScalars, api_id, rand_scalars);
  if(TIME_PERF) {
    finishTime = new Date();
    console.log(`CommitWithNym:CoreCommit time: ${finishTime - startTime}`);
  }
  return [commit_with_proof_octs, secret_prover_blind];
}

/**
 * Blind signs a commitment (that includes the prover_nyms) after verification
 * and optionally signs an additional list of messages. The signer's
 * signer_nym_entropy is added to the last of the prover_nyms.
 *
 * @param {bigint} SK - A scalar secret key.
 * @param {Uint8Array} PK -  Public key as a compressed G2 point raw bytes.
 * @param {Uint8Array} commitment_with_proof - An octet array of the commitment
 * with proof.
 * @param {number} length_nym_vector - The length of the nym_vector as specified
 * by the prover.
 * @param {bigint} signer_nym_entropy - A cryptographic random scalar.
 * @param {Uint8Array} header - Header as a byte array.
 * @param {Array} messages - Array of duplets of the form
 * [string, Uint8Array] where the string can take the  values "RAW" or "HASH" and
 * the Uint8Array is the message value.
 * @param {string} api_id - API_ID string.
 * @returns {Uint8Array} - The blind signature.
 */
export async function BlindSignWithNym(SK, PK, commitment_with_proof, length_nym_vector,
  signer_nym_entropy, header = new Uint8Array(), messages = [], api_id = '') {
  // Deserialization:
  const L = messages.length;
  const M = calcM(commitment_with_proof);
  // Procedure:
  const gens = await prepareGenerators(L + 1, api_id);
  if(TIME_PERF) {
    startTime = new Date();
  }
  const blindGens = await prepareGenerators(M + 1, 'BLIND_' + api_id);
  if(TIME_PERF) {
    finishTime = new Date();
    console.log(`BlindSignWithNym:prepareGenerators-Blind time: ${finishTime - startTime}`);
  }
  if(TIME_PERF) {
    startTime = new Date();
  }
  const commitment = await deserialize_and_validate_commit(commitment_with_proof, blindGens, api_id);
  if(TIME_PERF) {
    finishTime = new Date();
    console.log(`BlindSignWithNym:deserialize_and_validate_commit: ${finishTime - startTime}`);
  }
  if(TIME_PERF) {
    startTime = new Date();
  }
  const message_scalars = await messages_to_scalars(messages, api_id);
  const combined_header = concat(header, i2osp(length_nym_vector, 8));
  let B = await B_calculate(PK, gens, blindGens, commitment, message_scalars,
    combined_header, api_id);
  // Add in signer nym_entropy to the last prover_nym element
  // 10. B = B + blind_generators[-1] * signer_nym_entropy
  B = B.add(blindGens.generators.at(-1).multiply(signer_nym_entropy));
  if(B.equals(bls.G1.Point.ZERO)) {
    throw new Error('B equals Identity_G1, Invalid!');
  }
  if(GEN_TRACE_OBJECT) {
    // Record B after the signer_nym_entropy has been added, keep the domain
    // from Blind.B_calculate.
    traceInfo.BCalculate = {
      B: bytesToHex(B.toBytes(true)),
      domain: BlindTraceInfo.BCalculate.domain
    };
  }
  // 11. blind_sig = Blind.FinalizeBlindSign(SK, B, api_id)
  // 12. if blind_sig is INVALID, return INVALID
  const blind_sig = await FinalizeBlindSign(SK, B, api_id);
  if(TIME_PERF) {
    finishTime = new Date();
    console.log(`BlindSignWithNym:rest of blind sign: ${finishTime - startTime}`);
  }
  // 13. return blind_sig
  return blind_sig;
}

/**
 * Verifies a blind signature with pseudonym and computes the final
 * nym_secrets (the prover_nyms with the signer_nym_entropy added to the last
 * element).
 *
 * @param {Uint8Array} PK -  Public key as a compressed G2 point raw bytes.
 * @param {Uint8Array} signature - The signature as an octet string.
 * @param {Uint8Array} header - Header as a byte array.
 * @param {Array} messages - Array of duplets of the form
 * [string, Uint8Array] where the string can take the  values "RAW" or "HASH" and
 * the Uint8Array is the message value.
 * @param {Array} blind_messages - Array of duplets of the form
 * [string, Uint8Array] where the string can take the  values "RAW" or "HASH" and
 * the Uint8Array is the message value.
 * @param {Array} prover_nyms - Array of provers secrets as bigints.
 * @param {bigint} signer_nym_entropy - The signers random part of the nym.
 * @param {bigint} secret_prover_blind - The prover's commitment blind.
 * @param {string} api_id - API ID string.
 * @returns {Array} - The nym_secrets, an array of scalars (bigint).
 * @throws {Error} - If the signature is INVALID.
 */
export async function VerifyFinalizeWithNym(PK, signature, header = new Uint8Array(),
  messages = [], blind_messages = [], prover_nyms, signer_nym_entropy = 0n,
  secret_prover_blind = 0n, api_id = '') {
  // Deserialization:
  // 1. L = length(messages)
  // 2. M = length(blind_messages)
  // 3. N = length(prover_nyms)
  const L = messages.length;
  const M = blind_messages.length;
  const N = prover_nyms.length;
  if(N < 1) {
    throw new TypeError('prover_nyms must contain at least one element');
  }
  // Procedure:
  // 1. generators = BBS.create_generators(L + 1, api_id)
  // 2. blind_generators = BBS.create_generators(M + N + 1, "BLIND_" || api_id)
  // 3. signer_scalars = Blind.messages_to_scalars(messages, api_id)
  // 4. blind_message_scalars = Blind.messages_to_scalars(blind_messages, api_id)
  // 5. proof_scalars = signer_scalars.append(secret_prover_blind)
  //                                  .append(blind_message_scalars)
  if(TIME_PERF) {
    startTime = new Date();
  }
  const [proof_scalars, combinedGens] = await prepare_parameters(messages, blind_messages,
    L + 1, M + N + 1, secret_prover_blind, api_id);
  if(TIME_PERF) {
    finishTime = new Date();
    console.log(`VerifyFinalizeWithNym:prepare_parameters (including gens): ${finishTime - startTime}`);
  }
  // 6. nym_secrets = prover_nyms.copy()
  // 7. nym_secrets[-1] = prover_nyms[-1] + signer_nym_entropy (in the scalar field)
  const nym_secrets = prover_nyms.slice();
  nym_secrets[N - 1] = bls.fields.Fr.add(bls.fields.Fr.create(prover_nyms[N - 1]),
    bls.fields.Fr.create(signer_nym_entropy));
  // 8. proof_scalars.append(nym_secrets)
  const combinedScalars = proof_scalars.concat(nym_secrets);
  // 9. combined_header = header || I2OSP(N, 8)
  const combined_header = concat(header, i2osp(N, 8));
  // 10. res = BBS.CoreVerify(PK, signature, generators.append(blind_generators),
  //                          combined_header, proof_scalars, api_id)
  if(TIME_PERF) {
    startTime = new Date();
  }
  const valid = await verify(PK, signature, combined_header, combinedScalars, combinedGens, api_id);
  if(TIME_PERF) {
    finishTime = new Date();
    console.log(`VerifyFinalizeWithNym:verify (from BBS): ${finishTime - startTime}`);
  }
  // 11. if res is INVALID, return INVALID
  if(!valid) {
    throw new Error('VerifyFinalizeWithNym: signature is INVALID');
  }
  // 12. return nym_secrets
  return nym_secrets;
}

/**
 * Pseudonym proof generation. Generates a BBS proof together with a proof of
 * correctness of the pseudonym computed from the nym_secrets and context_id.
 *
 * @param {Uint8Array} PK -  Public key as a compressed G2 point raw bytes.
 * @param {Uint8Array} signature - The signature as an octet string.
 * @param {Uint8Array} header - Header as a byte array.
 * @param {Uint8Array} ph - Presentation header as a byte array.
 * @param {Array} nym_secrets - Array of Nym secret scalars (bigint).
 * @param {Uint8Array} context_id - Context (or verifier) id as a byte array.
 * @param {Array} messages - Array of duplets of the form
 * [string, Uint8Array] where the string can take the values "RAW" or "HASH" and
 * the Uint8Array is the message value. These are the issuer (signer) messages.
 * @param {Array} blind_messages - Array of duplets of the form
 * [string, Uint8Array] where the string can take the values "RAW" or "HASH" and
 * the Uint8Array is the message value. These are the prover's committed messages.
 * @param {Array} message_disclosures - Vector of strings in "HIDE", "DISCLOSE", "COMMIT"
 * must be the same length as the messages array.
 * @param {Array} blind_message_disclosures - Vector of strings in "HIDE", "DISCLOSE", "COMMIT"
 * must be the same length as the blind_messages array.
 * @param {bigint} secret_prover_blind - The secret prover blind used when committing
 * prover messages and prover_nyms.
 * @param {string} api_id - The API id for the signature suite.
 * @param {Function} rand_scalars - A function for generating cryptographically
 *  secure random or pseudo random scalars.
 * @returns {Array} - [proof, pseudonym, add_zkp_info] where proof is an octet
 * string (Uint8Array), pseudonym is a G1 point, and add_zkp_info is an object
 * of the form {committed_message_scalars, commitment_rands} for the messages
 * used in committed disclosure.
 */
export async function ProofGenWithNym(PK, signature, header = new Uint8Array(),
  ph = new Uint8Array(), nym_secrets, context_id, messages = [], blind_messages = [],
  message_disclosures = [], blind_message_disclosures = [], secret_prover_blind = 0n,
  api_id = '', rand_scalars = calculate_random_scalars) {
  // Deserialization:
  const L = messages.length;
  if(message_disclosures.length !== L) {
    throw new TypeError('ProofGenWithNym: length of message_disclosures must equal length of messages');
  }
  const M = blind_messages.length;
  if(blind_message_disclosures.length !== M) {
    throw new TypeError('ProofGenWithNym: length of blind_message_disclosures must equal length of blind_messages');
  }
  const allowed = ['DISCLOSE', 'HIDE', 'COMMIT'];
  if(!message_disclosures.every(d => allowed.includes(d)) ||
    !blind_message_disclosures.every(d => allowed.includes(d))) {
    throw new TypeError('ProofGenWithNym: disclosure values must be DISCLOSE, HIDE, or COMMIT');
  }
  // 7. - 10. issuer/blind disclosed and commitment indexes in ascending order
  const disclosuresToIndexes = (disclosures, value) => disclosures.reduce(
    (idxs, d, i) => (d === value ? [...idxs, i] : idxs), []);
  const issuer_disclosed_indexes = disclosuresToIndexes(message_disclosures, 'DISCLOSE');
  const issuer_commitment_indexes = disclosuresToIndexes(message_disclosures, 'COMMIT');
  const blind_disclosed_indexes = disclosuresToIndexes(blind_message_disclosures, 'DISCLOSE');
  const blind_commitment_indexes = disclosuresToIndexes(blind_message_disclosures, 'COMMIT');
  // 11. N = length(nym_secrets)
  const N = nym_secrets.length;
  if(N < 1) {
    throw new TypeError('ProofGenWithNym: nym_secrets must contain at least one element');
  }
  // Procedure:
  // 1. generators = BBS.create_generators(L + 1, api_id)
  // 2. blind_generators = BBS.create_generators(M + N + 1, "BLIND_" || api_id)
  // 3. issuer_scalars = messages_to_scalars(issuer_messages, api_id)
  // 4. blind_scalars = messages_to_scalars(blind_messages, api_id)
  if(TIME_PERF) {
    startTime = new Date();
  }
  const [allScalars, combinedGens] = await prepare_parameters(messages, blind_messages,
    L + 1, M + N + 1, secret_prover_blind, api_id);
  if(TIME_PERF) {
    finishTime = new Date();
    console.log(`ProofGenWithNym:prepare_parameters (including gens): ${finishTime - startTime}`);
  }
  // 6. proof_scalars = issuer_scalars.append(secret_prover_blind)
  //                                  .append(blind_scalars).append(nym_secrets)
  const proof_scalars = allScalars.concat(nym_secrets);
  // 7. - 12. combine indexes, blind indexes are offset by L + 1.
  // Note that no nym_secrets are disclosed or committed.
  const proof_disclosed_indexes = get_combined_idxs(L, issuer_disclosed_indexes,
    blind_disclosed_indexes);
  const proof_commitment_indexes = get_combined_idxs(L, issuer_commitment_indexes,
    blind_commitment_indexes);
  // 13. [proof, pseudonym, add_zkp_info] = CoreProofGenWithNym(PK, signature,
  //       generators.append(blind_generators), header, ph, context_id,
  //       proof_scalars, proof_disclosed_indexes, proof_commitment_indexes,
  //       length(nym_secrets), api_id)
  const [proof, pseudonym, add_zkp_info] = await CoreProofGenWithNym(PK, signature,
    combinedGens, header, ph, context_id, proof_scalars, proof_disclosed_indexes,
    proof_commitment_indexes, N, api_id, rand_scalars);
  // 14. return [proof, pseudonym, add_zkp_info]
  return [proof, pseudonym, add_zkp_info];
}

/**
 * CoreProofGenWithNym: Generates a BBS proof, with optional committed
 * disclosure, together with a proof of correctness of the pseudonym, using
 * common randomness.
 *
 * @param {Uint8Array} PK - Public key as a compressed G2 point raw bytes.
 * @param {Uint8Array} signature - A previously computed signature.
 * @param {object} gens - Containing an array of group G1 generators
 * (generators.append(blind_generators)) and the point P1.
 * @param {Uint8Array} header - Header used when signature was created.
 * @param {Uint8Array} ph - Presentation header, used during proof creation.
 * @param {Uint8Array} context_id - Context (or verifier) id as a byte array.
 * @param {Array} proof_scalars - Array of message scalars (bigint), MUST end
 * with the nym_secrets.
 * @param {Array} disclosed_indexes - Strictly ascending indexes of the
 * disclosed messages.
 * @param {Array} commitment_indexes - Strictly ascending indexes of the
 * messages used in committed disclosure.
 * @param {number} length_nym_secrets - The length of the nym_secrets vector.
 * @param {string} api_id - The API id for the signature suite.
 * @param {Function} rand_scalars - A function for generating cryptographically
 *  secure random or pseudo random scalars.
 * @returns {Array} - [proof, pseudonym, add_zkp_info].
 */
async function CoreProofGenWithNym(PK, signature, gens, header, ph, context_id,
  proof_scalars, disclosed_indexes, commitment_indexes, length_nym_secrets, api_id,
  rand_scalars = calculate_random_scalars) {
  // Parameters:
  // (Y_0, Y_1) = BBS.create_generators(2, "COM_DIS_" || api_id)
  const comGens = await prepareGenerators(2, 'COM_DIS_' + api_id);
  const [Y_0, Y_1] = comGens.generators;
  // Deserialization:
  // 1.  signature_result = octets_to_signature(signature)
  // 2.  if signature_result is INVALID, return INVALID
  // 3.  (A, e) = signature_result
  const {A, e} = octets_to_sig(signature); // Get curve point and scalar
  // 4.  L = length(proof_scalars) // nym_secrets at the end
  const L = proof_scalars.length;
  const Nn = length_nym_secrets;
  if(!Number.isInteger(Nn) || Nn < 1 || Nn > L) {
    throw new TypeError('CoreProofGenWithNym: invalid length_nym_secrets');
  }
  // 5. if commitment_indexes is not a strictly ascending list of integers
  //    in 0..L - 1, return INVALID
  // 6. if disclosed_indexes is not a strictly ascending list of integers
  //    in 0..L - 1, return INVALID
  const strictlyAscendingInRange = idxs => idxs.every((idx, i) =>
    Number.isInteger(idx) && idx >= 0 && idx < L && (i === 0 || idx > idxs[i - 1]));
  if(!strictlyAscendingInRange(commitment_indexes)) {
    throw new TypeError('CoreProofGenWithNym: commitment_indexes not strictly ascending in range');
  }
  if(!strictlyAscendingInRange(disclosed_indexes)) {
    throw new TypeError('CoreProofGenWithNym: disclosed_indexes not strictly ascending in range');
  }
  // 7. if disclosed_indexes and commitment_indexes are not disjoint,
  //    return INVALID
  if(commitment_indexes.some(idx => disclosed_indexes.includes(idx))) {
    throw new TypeError('CoreProofGenWithNym: disclosed_indexes and commitment_indexes not disjoint');
  }
  // 8. if any i in disclosed_indexes or in commitment_indexes has
  //    i >= L - length_nym_secrets, return INVALID
  if([...disclosed_indexes, ...commitment_indexes].some(idx => idx >= L - Nn)) {
    throw new TypeError('CoreProofGenWithNym: nym_secrets cannot be disclosed or committed');
  }
  // 9.  N = length(commitment_indexes)
  const Nc = commitment_indexes.length;
  // 10. R = length(disclosed_indexes)
  const R = disclosed_indexes.length;
  // 11. U = L - R
  const U = L - R;
  // 12. (i1, ..., iR) = disclosed_indexes
  // 13. disclosed_messages = (proof_scalars[i1], ..., proof_scalars[iR])
  const disclosed_scalars = disclosed_indexes.map(idx => proof_scalars[idx]);
  // 14. undisclosed_indexes = (0, 1, ..., L - 1) \ disclosed_indexes
  // 15. (j1, ..., jU) = undisclosed_indexes
  // 16. undisclosed_messages = (proof_scalars[j1], ..., proof_scalars[jU])
  const undisclosed_indexes = [];
  for(let i = 0; i < L; i++) {
    if(!disclosed_indexes.includes(i)) {
      undisclosed_indexes.push(i);
    }
  }
  // Procedure:
  // 1.  all_random_scalars = BBS.calculate_random_scalars(5 + U + 2*N)
  // 2.  (r1, r2, e~, r1~, r3~, m~_j1, ..., m~_jU, s_1, ..., s_N,
  //                             s~_1, ..., s~_N) = all_random_scalars
  // 3.  init_random_scalars = (r1, r2, e~, r1~, r3~, m~_j1, ..., m~_jU)
  const allRandScalars = await rand_scalars(5 + U + 2 * Nc);
  const init_rands = allRandScalars.slice(0, 5 + U);
  const s_rands = allRandScalars.slice(5 + U, 5 + U + Nc);
  const s_tilde_rands = allRandScalars.slice(5 + U + Nc, 5 + U + 2 * Nc);
  // 4.  combined_header = header || I2OSP(length_nym_secrets, 8)
  const combined_header = concat(header, i2osp(Nn, 8));
  // 5.  init_res = BBS.ProofInit(PK, signature_result, generators,
  //         init_random_scalars, combined_header, proof_scalars,
  //         undisclosed_indexes, api_id)
  // 6.  if init_res is INVALID, return INVALID
  if(TIME_PERF) {
    startTime = new Date();
  }
  const init_res = await ProofInit(PK, [A, e], gens, init_rands, combined_header,
    proof_scalars, undisclosed_indexes, api_id);
  if(TIME_PERF) {
    finishTime = new Date();
    console.log(`ProofGenWithNym:CoreProofGenWithNym:ProofInit (BBS): ${finishTime - startTime}`);
  }
  // 7.  nym_scalars  = proof_scalars[L - length_nym_secrets, L]
  const nym_scalars = proof_scalars.slice(L - Nn, L);
  // 8.  nym_rands = init_random_scalars[5 + U - length_nym_secrets, 5 + U]
  const nym_rands = init_rands.slice(5 + U - Nn, 5 + U);
  // 9.  pseudonym_init_res = PseudonymProofInit(context_id, nym_scalars, nym_rands)
  // 10. if pseudonym_init_res is INVALID, return INVALID
  if(TIME_PERF) {
    startTime = new Date();
  }
  const pseudonym_init_res = await PseudonymProofInit(context_id, nym_scalars,
    nym_rands, api_id);
  if(TIME_PERF) {
    finishTime = new Date();
    console.log(`ProofGenWithNym:CoreProofGenWithNym:PseudonymProofInit: ${finishTime - startTime}`);
  }
  // 11. pseudonym = pseudonym_init_res[0]
  const pseudonym = pseudonym_init_res[0];
  // Calculate the commitments and initiate the correctness proof
  const comDis = []; // C_i
  const comDisProofs = []; // C~_i
  // 12. for i in (1, 2, ..., N):
  for(let i = 0; i < Nc; i++) {
    // 13. idx = commitment_indexes[i]
    const idx = commitment_indexes[i];
    // 14. C_i = Y_0 * s_i + Y_1 * proof_scalars[idx]
    comDis.push(Y_0.multiply(s_rands[i]).add(Y_1.multiply(proof_scalars[idx])));
    // 15. let k be the integer such that j_k == idx
    const k = undisclosed_indexes.indexOf(idx);
    // 16. C~_i = Y_0 * s~_i + Y_1 * m~_k
    const mTilde_k = init_rands[5 + k];
    comDisProofs.push(Y_0.multiply(s_tilde_rands[i]).add(Y_1.multiply(mTilde_k)));
  }
  // 17. commitment_init_res = {commitments: (C_1, ..., C_N),
  //                            commitments_proofs: (C~_1, ...,C~_N),
  //                            commitment_indexes: commitment_indexes}
  const commitment_init_res = {commitments: comDis, commitments_proofs: comDisProofs,
    commitment_indexes};
  // 18. challenge = ProofWithPseudonymChallengeCalculate(init_res,
  //         commitment_init_res, pseudonym_init_res, disclosed_messages,
  //         disclosed_indexes, ph, api_id)
  // 19. if challenge is INVALID, return INVALID
  const challenge = await ProofWithPseudonymChallengeCalculate(init_res, commitment_init_res,
    pseudonym_init_res, disclosed_scalars, disclosed_indexes, ph, api_id);
  // 20. bbs_proof = BBS.ProofFinalize(init_res, challenge, e,
  //                     init_random_scalars, undisclosed_messages)
  if(TIME_PERF) {
    startTime = new Date();
  }
  const bbs_proof = await ProofFinalize(init_res, challenge, e, init_rands, proof_scalars,
    undisclosed_indexes, PK);
  if(TIME_PERF) {
    finishTime = new Date();
    console.log(`ProofGenWithNym:CoreProofGenWithNym:ProofFinalize (BBS): ${finishTime - startTime}`);
  }
  // Finalize the commitment correctness proof
  // 21. for i in (1, 2, ..., N): s^_i =  s~_i + challenge * s_i
  const sHats = [];
  for(let i = 0; i < Nc; i++) {
    sHats.push(bls.fields.Fr.add(s_tilde_rands[i], bls.fields.Fr.mul(s_rands[i], challenge)));
  }
  // 22. commitments_proof = ((C_1, ..., C_N), (s^_1, ..., s^_N))
  const commitments_proof = {commitments: comDis, commitments_proof_scalars: sHats};
  // 23. proof = Blind.proof_to_octets(bbs_proof, commitments_proof)
  const proof = proof_to_octets(bbs_proof, Nc, commitments_proof);
  // 24. add_zkp_info = {committed_message_scalars:
  //                        (proof_scalars[commitment_indexes[1]], ...,
  //                         proof_scalars[commitment_indexes[N]]),
  //                     commitment_rands: (s_1, ..., s_N)}
  const add_zkp_info = {
    committed_message_scalars: commitment_indexes.map(idx => proof_scalars[idx]),
    commitment_rands: s_rands
  };
  if(GEN_TRACE_OBJECT) {
    const [Abar, Bbar, D, T1, T2, domain] = init_res;
    const [r1, r2, eTilde, r1Tilde, r3Tilde, ...mTildeU] = init_rands;
    const Ut = pseudonym_init_res[2];
    traceInfo.CoreProofGen = {
      count_random_scalars: allRandScalars.length,
      randomScalars: {
        r1: numberToHex(r1, SCALAR_LENGTH),
        r2: numberToHex(r2, SCALAR_LENGTH),
        e_Tilde: numberToHex(eTilde, SCALAR_LENGTH),
        r1_Tilde: numberToHex(r1Tilde, SCALAR_LENGTH),
        r3_Tilde: numberToHex(r3Tilde, SCALAR_LENGTH),
        m_tilde_scalars: mTildeU.map(mT => numberToHex(mT, SCALAR_LENGTH)),
        s_i: s_rands.map(sv => numberToHex(sv, SCALAR_LENGTH)),
        s_tilde_i: s_tilde_rands.map(sT => numberToHex(sT, SCALAR_LENGTH)),
      },
      A: bytesToHex(A.toBytes(true)),
      Abar: bytesToHex(Abar.toBytes(true)),
      Bbar: bytesToHex(Bbar.toBytes(true)),
      D: bytesToHex(D.toBytes(true)),
      T1: bytesToHex(T1.toBytes(true)),
      T2: bytesToHex(T2.toBytes(true)),
      C_i: comDis.map(c => bytesToHex(c.toBytes(true))),
      C_tilde_i: comDisProofs.map(cT => bytesToHex(cT.toBytes(true))),
      pseudonym: bytesToHex(pseudonym.toBytes(true)),
      Ut: bytesToHex(Ut.toBytes(true)),
      domain: numberToHex(domain, SCALAR_LENGTH),
      challenge: numberToHex(challenge, SCALAR_LENGTH),
    };
  }
  // 25. return [proof, pseudonym, add_zkp_info]
  return [proof, pseudonym, add_zkp_info];
}

async function PseudonymProofInit(context_id, nym_secrets, random_scalars, api_id) {
  // Procedure:
  const OP = await hash_to_curve_g1(context_id, api_id);
  const dst1 = new TextEncoder().encode(api_id + 'VECT_NYM_SECRETS');
  const z = await hash_to_scalar(context_id, dst1, api_id);
  // console.log(z);
  let poly_eval_pseudo = nym_secrets[0];
  let poly_eval_proof = random_scalars[0];
  let z_n = z;
  // console.log(nym_secrets);
  for(let i = 1; i < nym_secrets.length; i++) {
    poly_eval_pseudo = bls.fields.Fr.add(
      poly_eval_pseudo,
      bls.fields.Fr.mul(nym_secrets[i], z_n)
    ); // nym_secrets[i]*z_n; in field
    poly_eval_proof = bls.fields.Fr.add(
      poly_eval_proof,
      bls.fields.Fr.mul(random_scalars[i], z_n)
    ); // nym_secrets[i]*z_n; in field
    z_n = bls.fields.Fr.mul(z_n, z); // z_n *= z; in field
  }
  const pseudonym = OP.multiply(poly_eval_pseudo);
  const Ut = OP.multiply(poly_eval_proof);

  // 4. if Pseudonym == Identity_G1 or Ut == Identity_G1, return INVALID
  if(pseudonym.equals(bls.G1.Point.ZERO)) {
    throw new Error('pseudonym equals Identity_G1, Invalid!');
  }
  if(GEN_TRACE_INFO) {
    // PK, signature, pseudonym, verifier_id,
    // pid_scalar, gens, header, ph, msg_scalars, disclosed_indexes, api_id, rand_scalars
    const info = {
      info: 'from PseudonymProofInit',
      OP: bytesToHex(OP.toBytes(true)),
      poly_eval_pseudo: numberToHex(poly_eval_pseudo, SCALAR_LENGTH),
      poly_eval_proof: numberToHex(poly_eval_proof, SCALAR_LENGTH),
      pseudonym: bytesToHex(pseudonym.toBytes(true)),
      Ut: bytesToHex(Ut.toBytes(true)),
      context_id: bytesToHex(context_id)
    };
    console.log(JSON.stringify(info, null, 2));
  }
  // 5. return (Pseudonym, OPs, Ut)
  return [pseudonym, context_id, Ut];
}

/**
 * Calculates the challenge for a proof with pseudonym, including any
 * committed disclosure commitments.
 *
 * @param {Array} init_res - The (Abar, Bbar, D, T1, T2, domain) tuple from
 * ProofInit or ProofVerifyInit.
 * @param {object} commitment_init_res - The {commitments, commitments_proofs,
 * commitment_indexes} object for committed disclosure.
 * @param {Array} pseudonym_init_res - The (pseudonym, context_id, Ut) tuple.
 * @param {Array} disclosed_messages - Scalars of the disclosed messages.
 * @param {Array} disclosed_indexes - Indexes of the disclosed messages.
 * @param {Uint8Array} ph - Presentation header.
 * @param {string} api_id - The API id for the signature suite.
 * @returns {bigint} - The challenge scalar.
 */
async function ProofWithPseudonymChallengeCalculate(init_res, commitment_init_res,
  pseudonym_init_res, disclosed_messages, disclosed_indexes, ph, api_id) {
  // Deserialization:
  const [Abar, Bbar, D, T1, T2, domain] = init_res;
  const R = disclosed_indexes.length;
  if(disclosed_messages.length !== R) {
    throw new TypeError('ProofWithPseudonymChallengeCalculate: disclosed messages and indexes length mismatch');
  }
  // 9.  (C_1, ..., C_N) = commitment_init_res.commitments
  // 10. (C~_1, ...,C~_N) = commitment_init_res.commitments_proofs
  // 11. (ci_1, ..., ci_N) = commitment_init_res.commitment_indexes
  const {commitments, commitments_proofs, commitment_indexes} = commitment_init_res;
  const N = commitments.length;
  if(commitments_proofs.length !== N || commitment_indexes.length !== N) {
    throw new TypeError('ProofWithPseudonymChallengeCalculate: commitment_init_res length mismatch');
  }
  // 12. (pseudonym, context_id, Ut) = pseudonym_init_res
  const [pseudonym, , Ut] = pseudonym_init_res;
  // ABORT if:
  // 1. R > 2^64 - 1
  // 2. length(ph) > 2^64 - 1 (not possible in JavaScript)
  const dst = new TextEncoder().encode(api_id + 'H2S_');
  // Procedure:
  // 1. c_arr = (R, i1, msg_i1, i2, msg_i2, ..., iR, msg_iR, Abar, Bbar,
  //                 D, T1, T2, pseudonym, Ut, domain)
  const c_array = [{type: 'NonNegInt', value: R}];
  for(let i = 0; i < R; i++) { // i_j, msg_j
    c_array.push({type: 'NonNegInt', value: disclosed_indexes[i]});
    c_array.push({type: 'Scalar', value: disclosed_messages[i]});
  }
  c_array.push({type: 'GPoint', value: Abar});
  c_array.push({type: 'GPoint', value: Bbar});
  c_array.push({type: 'GPoint', value: D});
  c_array.push({type: 'GPoint', value: T1});
  c_array.push({type: 'GPoint', value: T2});
  c_array.push({type: 'GPoint', value: pseudonym});
  c_array.push({type: 'GPoint', value: Ut});
  c_array.push({type: 'Scalar', value: domain});
  // 2. c_octs = serialize(c_arr)
  let c_octs = serialize(c_array);
  // 3. commitment_arr = (N, ci_1, C_1, C~_1, ..., ci_N, C_N, C~_N)
  const commitment_arr = [{type: 'NonNegInt', value: N}];
  for(let i = 0; i < N; i++) {
    commitment_arr.push({type: 'NonNegInt', value: commitment_indexes[i]});
    commitment_arr.push({type: 'GPoint', value: commitments[i]});
    commitment_arr.push({type: 'GPoint', value: commitments_proofs[i]});
  }
  // 4. c_octs = c_octs || BBS.serialize(commitment_arr)
  c_octs = concat(c_octs, serialize(commitment_arr));
  // 5. c_octs = c_octs || I2OSP(length(ph), 8) || ph
  c_octs = concat(c_octs, concat(i2osp(ph.length, 8), ph));
  // 6. return BBS.hash_to_scalar(c_octs, hash_to_scalar_dst)
  const c = await hash_to_scalar(c_octs, dst, api_id);
  if(GEN_TRACE_INFO) {
    const info = {
      info: 'from ProofWithPseudonymChallengeCalculate',
      Abar: bytesToHex(Abar.toBytes(true)),
      Bbar: bytesToHex(Bbar.toBytes(true)),
      D: bytesToHex(D.toBytes(true)),
      T1: bytesToHex(T1.toBytes(true)),
      T2: bytesToHex(T2.toBytes(true)),
      domain: numberToHex(domain, SCALAR_LENGTH),
      pseudonym: bytesToHex(pseudonym.toBytes(true)),
      Ut: bytesToHex(Ut.toBytes(true)),
      N,
      challenge: numberToHex(c, SCALAR_LENGTH)
    };
    console.log(JSON.stringify(info, null, 2));
  }
  return c;
}

/**
 * Pseudonym proof verification. Verifies a BBS proof with pseudonym, including
 * any committed disclosure.
 *
 * @param {Uint8Array} PK - Public key as a compressed G2 point raw bytes.
 * @param {Uint8Array} proof - A previously computed proof.
 * @param {Uint8Array} header - Header used when signature was created.
 * @param {Uint8Array} ph - Presentation header, used during proof creation.
 * @param {Uint8Array|object} pseudonym - The pseudonym, either a G1 point or
 * its compressed octet encoding.
 * @param {Uint8Array} context_id - Context (or verifier) id as a byte array.
 * @param {number} length_nym_vector - The length of the nym secrets vector.
 * @param {number} issuer_known_messages_no - Total number of signer messages.
 * @param {Array} disclosed_messages - Array of duplets of the form
 * [string, Uint8Array] where the string can take the  values "RAW" or "HASH" and
 * the Uint8Array is the message value, where disclosed signer messages are
 * followed by disclosed prover messages.
 * @param {Array} message_disclosures - Vector of strings in "HIDE", "DISCLOSE",
 * "COMMIT" covering all signer messages followed by all prover messages.
 * @param {string} api_id - The API id for the signature suite.
 * @returns {boolean} - True if the proof is VALID, false otherwise.
 */
export async function ProofVerifyWithNym(PK, proof, header = new Uint8Array(),
  ph = new Uint8Array(), pseudonym, context_id, length_nym_vector,
  issuer_known_messages_no = 0, disclosed_messages = [], message_disclosures = [],
  api_id = '') {
  try {
    // Deserialization:
    // 1. bbs_proof_len = OS2IP(proof[0..7])
    if(proof.length < 8) {
      return false;
    }
    const bbs_proof_len = Number(os2ip(proof.slice(0, 8)));
    // 2. undisclosed_msgs_no = (bbs_proof_len - 3 * octet_point_length
    //                           - 4 * octet_scalar_length) / octet_scalar_length
    const bbsProofLenFloor = 3 * POINT_LENGTH + 4 * SCALAR_LENGTH;
    if(bbs_proof_len < bbsProofLenFloor ||
      (bbs_proof_len - bbsProofLenFloor) % SCALAR_LENGTH !== 0) {
      return false;
    }
    const undisclosed_msgs_no = (bbs_proof_len - bbsProofLenFloor) / SCALAR_LENGTH;
    // 3. proof_msgs_no = undisclosed_msgs_no + length(disclosed_messages)
    const proof_msgs_no = undisclosed_msgs_no + disclosed_messages.length;
    // 4. if proof_msgs_no == 0, return INVALID
    if(proof_msgs_no === 0) {
      return false;
    }
    // 5. total_msgs_no = proof_msgs_no - 1 - length_nym_vector
    if(!Number.isInteger(length_nym_vector) || length_nym_vector < 1) {
      return false;
    }
    const total_msgs_no = proof_msgs_no - 1 - length_nym_vector;
    if(total_msgs_no < 0) {
      return false;
    }
    // 6. if issuer_known_messages_no > total_msgs_no, return INVALID
    if(issuer_known_messages_no > total_msgs_no) {
      return false;
    }
    // 7. if length(message_disclosures) != total_msgs_no, return INVALID
    // 8. keys of message_disclosures are 0..total_msgs_no - 1 (array form)
    if(message_disclosures.length !== total_msgs_no) {
      return false;
    }
    // 9. if any value in message_disclosures is not one of DISCLOSE, HIDE,
    //    or COMMIT, return INVALID
    const allowed = ['DISCLOSE', 'HIDE', 'COMMIT'];
    if(!message_disclosures.every(d => allowed.includes(d))) {
      return false;
    }
    // 10. disclosed_indexes, 11. commitment_indexes, in ascending order
    const disclosed_indexes = [];
    const commitment_indexes = [];
    for(let i = 0; i < total_msgs_no; i++) {
      if(message_disclosures[i] === 'DISCLOSE') {
        disclosed_indexes.push(i);
      }
      if(message_disclosures[i] === 'COMMIT') {
        commitment_indexes.push(i);
      }
    }
    // 12. if length(disclosed_indexes) != length(disclosed_messages),
    //     return INVALID
    if(disclosed_indexes.length !== disclosed_messages.length) {
      return false;
    }
    // 13. proof_index(i) = i if i < issuer_known_messages_no, i + 1 otherwise
    const proof_index = i => (i < issuer_known_messages_no ? i : i + 1);
    // 14. proof_disclosed_indexes = (proof_index(i) for i in disclosed_indexes)
    // 15. proof_commitment_indexes = (proof_index(i) for i in commitment_indexes)
    const proof_disclosed_indexes = disclosed_indexes.map(proof_index);
    const proof_commitment_indexes = commitment_indexes.map(proof_index);
    // Pseudonym must be a valid G1 point that is not the identity.
    const pseudonym_pt = (pseudonym instanceof Uint8Array) ?
      bls.G1.Point.fromBytes(pseudonym) : pseudonym;
    pseudonym_pt.assertValidity();
    if(pseudonym_pt.equals(bls.G1.Point.ZERO)) {
      return false;
    }
    // Procedure:
    // 1. generators = BBS.create_generators(issuer_known_messages_no + 1, api_id)
    // 2. blind_generators = BBS.create_generators(total_msgs_no -
    //      issuer_known_messages_no + length_nym_vector + 1, "BLIND_" || api_id)
    if(TIME_PERF) {
      startTime = new Date();
    }
    const gens = await prepareGenerators(issuer_known_messages_no + 1, api_id);
    const blindGens = await prepareGenerators(total_msgs_no - issuer_known_messages_no +
      length_nym_vector + 1, 'BLIND_' + api_id);
    if(TIME_PERF) {
      finishTime = new Date();
      console.log(`ProofVerifyWithNym:prepareGenerators: ${finishTime - startTime}`);
    }
    const combinedGens = {
      P1: gens.P1,
      generators: [...gens.generators, ...blindGens.generators]
    };
    // 3. message_scalars = messages_to_scalars(disclosed_messages, api_id)
    const message_scalars = await messages_to_scalars(disclosed_messages, api_id);
    // 4. result = CoreProofVerifyWithNym(PK, proof, pseudonym, context_id,
    //      length_nym_vector, generators.append(blind_generators), header, ph,
    //      message_scalars, proof_disclosed_indexes, proof_commitment_indexes, api_id)
    // 5. return result
    return await CoreProofVerifyWithNym(PK, proof, pseudonym_pt, context_id,
      length_nym_vector, combinedGens, header, ph, message_scalars,
      proof_disclosed_indexes, proof_commitment_indexes, api_id);
  } catch(err) {
    if(GEN_TRACE_INFO) {
      console.log(`ProofVerifyWithNym: INVALID, ${err.message}`);
    }
    return false;
  }
}

/**
 * CoreProofVerifyWithNym: Verifies a BBS proof with pseudonym, including any
 * committed disclosure commitments.
 *
 * @param {Uint8Array} PK - Public key as a compressed G2 point raw bytes.
 * @param {Uint8Array} proof - A previously computed proof.
 * @param {object} pseudonym - The pseudonym, a G1 point.
 * @param {Uint8Array} context_id - Context (or verifier) id as a byte array.
 * @param {number} length_nym_vector - The length of the nym secrets vector.
 * @param {object} gens - Containing an array of group G1 generators
 * (generators.append(blind_generators)) and the point P1.
 * @param {Uint8Array} header - Header used when signature was created.
 * @param {Uint8Array} ph - Presentation header, used during proof creation.
 * @param {Array} disclosed_messages - Scalars of the disclosed messages.
 * @param {Array} disclosed_indexes - Strictly ascending indexes of the
 * disclosed messages.
 * @param {Array} commitment_indexes - Strictly ascending indexes of the
 * messages used in committed disclosure.
 * @param {string} api_id - The API id for the signature suite.
 * @returns {boolean} - True if the proof is VALID, false otherwise.
 */
async function CoreProofVerifyWithNym(PK, proof, pseudonym, context_id, length_nym_vector,
  gens, header, ph, disclosed_messages, disclosed_indexes, commitment_indexes, api_id) {
  // Parameters:
  // (Y_0, Y_1) = BBS.create_generators(2, "COM_DIS_" || api_id)
  const comGens = await prepareGenerators(2, 'COM_DIS_' + api_id);
  const [Y_0, Y_1] = comGens.generators;
  // Deserialization:
  // 1.  W = BBS.octets_to_pubkey(PK)
  // 2.  if W is INVALID, return INVALID
  const W = bls.G2.Point.fromBytes(PK);
  // 3.  proof_res = Blind.octets_to_proof(proof, length(commitment_indexes))
  // 4.  if proof_res is INVALID, return INVALID
  // 5.  (bbs_proof_res, commitments_proof_res) = proof_res
  const [bbs_proof_res, commitments_proof_res] = octets_to_proof(proof,
    commitment_indexes.length);
  // 6.  (Abar, Bbar, D, e^, r1^, r3^, hats, cp) = bbs_proof_res
  const {Abar, Bbar, mHatU: hats, c: cp} = bbs_proof_res;
  // 7.  (commitments, commitments_proof) = commitments_proof_res
  const {commitments, s_vect: commitments_proof} = commitments_proof_res;
  // 8.  N = length(commitments)
  // 9.  if length(commitments_proof) != N, return INVALID
  // 10. if length(commitment_indexes) != N, return INVALID
  const Nc = commitments.length;
  if(commitments_proof.length !== Nc || commitment_indexes.length !== Nc) {
    return false;
  }
  // 11. U = length(hats)
  // 12. R = length(disclosed_indexes)
  // 13. if length(disclosed_messages) != R, return INVALID
  // 14. L = R + U
  const U = hats.length;
  const R = disclosed_indexes.length;
  if(disclosed_messages.length !== R) {
    return false;
  }
  const L = R + U;
  // 15. if commitment_indexes is not a strictly ascending list of integers
  //     in 0..L - 1, return INVALID
  // 16. if disclosed_indexes is not a strictly ascending list of integers
  //     in 0..L - 1, return INVALID
  const strictlyAscendingInRange = idxs => idxs.every((idx, i) =>
    Number.isInteger(idx) && idx >= 0 && idx < L && (i === 0 || idx > idxs[i - 1]));
  if(!strictlyAscendingInRange(commitment_indexes) ||
    !strictlyAscendingInRange(disclosed_indexes)) {
    return false;
  }
  // 17. if disclosed_indexes and commitment_indexes are not disjoint,
  //     return INVALID
  if(commitment_indexes.some(idx => disclosed_indexes.includes(idx))) {
    return false;
  }
  // 18. if length_nym_vector < 1 or length_nym_vector > U, return INVALID
  const Nn = length_nym_vector;
  if(Nn < 1 || Nn > U) {
    return false;
  }
  // 19. if any i in disclosed_indexes or in commitment_indexes has
  //     i >= L - length_nym_vector, return INVALID
  if([...disclosed_indexes, ...commitment_indexes].some(idx => idx >= L - Nn)) {
    return false;
  }
  // 20. undisclosed_indexes = (0, 1, ..., L - 1) \ disclosed_indexes
  // 21. (j1, ..., jU) = undisclosed_indexes
  // 22. (m^_j1, ..., m^_jU) = hats
  // 23. (C_1, ... C_N) = commitments
  // 24. (s^_1, ..., s^_N) = commitments_proof
  const undisclosed_indexes = [];
  for(let i = 0; i < L; i++) {
    if(!disclosed_indexes.includes(i)) {
      undisclosed_indexes.push(i);
    }
  }
  // Procedure:
  // 1. combined_header = header || I2OSP(length_nym_vector, 8)
  const combined_header = concat(header, i2osp(Nn, 8));
  // 2. init_res = BBS.ProofVerifyInit(PK, bbs_proof_res, generators,
  //                  combined_header, disclosed_messages, disclosed_indexes, api_id)
  // 3. if init_res is INVALID, return INVALID
  if(TIME_PERF) {
    startTime = new Date();
  }
  const init_res = await ProofVerifyInit(PK, bbs_proof_res, gens, combined_header,
    disclosed_messages, disclosed_indexes, api_id);
  if(TIME_PERF) {
    finishTime = new Date();
    console.log(`ProofVerifyWithNym:CoreProofVerifyWithNym:ProofVerifyInit(BBS) : ${finishTime - startTime}`);
  }
  // 4. for i in (1, 2, ..., N):
  const CHats = [];
  for(let i = 0; i < Nc; i++) {
    // 5. idx = commitment_indexes[i]
    const idx = commitment_indexes[i];
    // 6. let k be the integer such that j_k == idx
    const k = undisclosed_indexes.indexOf(idx);
    // 7. C^_i = Y_0 * s^_i + Y_1 * m^_k - C_i * cp
    CHats.push(Y_0.multiply(commitments_proof[i]).add(Y_1.multiply(hats[k]))
      .subtract(commitments[i].multiply(cp)));
  }
  // 8. commitment_init_res = {commitments: (C_1, ..., C_N),
  //                           commitments_proofs: (C^_1, ...,C^_N),
  //                           commitment_indexes: commitment_indexes}
  const commitment_init_res = {commitments, commitments_proofs: CHats, commitment_indexes};
  // 9.  pseudonym_init_res = PseudonymProofVerifyInit(pseudonym, context_id,
  //                              hats[-length_nym_vector], cp)
  // 10. if pseudonym_init_res is INVALID, return INVALID
  if(TIME_PERF) {
    startTime = new Date();
  }
  const pseudonym_init_res = await PseudonymProofVerifyInit(pseudonym, context_id,
    hats.slice(-Nn), cp, api_id);
  if(TIME_PERF) {
    finishTime = new Date();
    console.log(`ProofVerifyWithNym:CoreProofVerifyWithNym:PseudonymProofVerifyInit : ${finishTime - startTime}`);
  }
  // 11. challenge = ProofWithPseudonymChallengeCalculate(init_res,
  //        commitment_init_res, pseudonym_init_res, disclosed_messages,
  //        disclosed_indexes, ph, api_id)
  const challenge = await ProofWithPseudonymChallengeCalculate(init_res, commitment_init_res,
    pseudonym_init_res, disclosed_messages, disclosed_indexes, ph, api_id);
  // 12. if cp != challenge, return INVALID
  if(cp !== challenge) {
    return false;
  }
  // 13. if e(Abar, W) * e(Bbar, -BP2) != Identity_GT, return INVALID
  const negP2 = bls.G2.Point.BASE.negate();
  const ptGT1 = bls.pairing(Abar, W);
  const ptGT2 = bls.pairing(Bbar, negP2);
  let result = bls.fields.Fp12.mul(ptGT1, ptGT2);
  result = bls.fields.Fp12.finalExponentiate(result); // See noble BLS12-381
  // 14. return VALID
  return bls.fields.Fp12.eql(result, bls.fields.Fp12.ONE);
}

async function PseudonymProofVerifyInit(pseudonym, context_id, nym_secret_commitments, proof_challenge, api_id) {
  let Uv;
  // Using Horner's rule. https://en.wikipedia.org/wiki/Horner%27s_method
  const OP = await hash_to_curve_g1(context_id, api_id); // What should we choose?
  const dst = new TextEncoder().encode(api_id + 'VECT_NYM_SECRETS');
  const z = await hash_to_scalar(context_id, dst, api_id);
  // let poly_eval_proof = nym_secret_commitments[0];
  // let z_n = z;
  // for(let i = 1; i < nym_secret_commitments.length; i++) {
  //   poly_eval_proof = bls.fields.Fr.add(poly_eval_proof,
  //     bls.fields.Fr.mul(nym_secret_commitments[i], z_n));
  //   z_n = bls.fields.Fr.mul(z_n, z); // z_n *= z; n field
  // }
  // Below uses Horner's rule to evaluate the polynomial.
  let poly_eval_proof = nym_secret_commitments.at(-1);
  for(let i = nym_secret_commitments.length - 2; i >= 0; i--) {
    poly_eval_proof = bls.fields.Fr.add(nym_secret_commitments[i],
      bls.fields.Fr.mul(poly_eval_proof, z));
  }
  Uv = OP.multiply(poly_eval_proof);
  Uv = Uv.subtract(pseudonym.multiply(proof_challenge));

  // 3. if Uv == Identity_G1, return INVALID
  if(Uv.equals(bls.G1.Point.ZERO)) {
    throw new Error('Uv equals Identity_G1, Invalid!');
  }
  // 4. return (Pseudonym, OP, Uv)
  return [pseudonym, context_id, Uv];
}

export async function hash_to_curve_g1(thing, api_id) {
  if(api_id.includes('SHA-256')) {
    return bls.G1.hashToCurve(thing, {DST: api_id});
  } else {
    return bls.G1.hashToCurve(thing, {
      DST: api_id,
      expand: 'xof',
      hash: shake256,
    });
  }
}
