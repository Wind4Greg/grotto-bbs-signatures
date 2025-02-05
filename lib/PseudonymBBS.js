/*global TextEncoder, console*/
/* eslint-disable max-len */
/* Functions used in BBS Per Verifier Id (pseudonym) operations
   API subject to change!
*/

import {calcM, CoreCommit, deserialize_and_validate_commit, FinalizeBlindSign, get_combined_idxs, prepare_parameters} from './BlindBBS.js';
import {ProofFinalize, ProofInit, ProofVerifyInit, bytesToHex, calculate_random_scalars, hash_to_scalar, messages_to_scalars, numberToHex,
  octets_to_proof, octets_to_sig, prepareGenerators, serialize, verify} from './BBS.js';
import {bls12_381 as bls} from '@noble/curves/bls12-381';
import {shake256} from '@noble/hashes/sha3';

const GEN_TRACE_INFO = true; // set to true to send trace info to console.

const SCALAR_LENGTH = 32;
// const EXPAND_LEN = 48;
const POINT_LENGTH = 48;
// const rPrimeOrder = bls.fields.Fr.ORDER; // prime order of the subgroups G1, G2

/**
 * This operation is used by the Prover to create commitment to a set of
 * messages (committed_messages) along with their prover_nym that they intend to
 * include in the blind signature.
 *  Note that this operation returns both the serialized combination of the
 *  commitment and its proof of correctness (commitment_with_proof), as well as
 *  the random scalar used to blind the commitment (secret_prover_blind).
 *
 * @param {Array} messages - A vector of octet strings, messages, to be
 * committed. If not supplied it defaults to the empty array.
 * @param {string} api_id - The API id for the signature suite.
 * @param {Function} rand_scalars - A function for generating cryptographically
 *  secure random or pseudo random scalars.
 * @returns {Array}  - Comprising an octet string (Uint8Array) for the commitment with proof
 * and a the secret_prover_blind scalar in that order.
 */

export async function CommitWithNym(messages, prover_nym, api_id,
  rand_scalars = calculate_random_scalars) {
  // 1. committed_message_scalars = BBS.messages_to_scalars(committed_messages, api_id)
  const msgScalars = await messages_to_scalars(messages, api_id);
  msgScalars.push(prover_nym);
  const M = msgScalars.length;
  // 2. blind_generators = BBS.create_generators(length(committed_message_scalars) + 1, "BLIND_" || api_id)
  const gens = await prepareGenerators(M + 1, 'BLIND_' + api_id);
  const blind_generators = gens.generators.slice(0, M + 1);
  // 3. return CoreCommit(committed_message_scalars, blind_generators, api_id)
  return CoreCommit(blind_generators, msgScalars, api_id, rand_scalars);
}

/**
 * @param {bigint} SK - A scalar secret key.
 * @param {Uint8Array} PK -  Public key as a compressed G2 point raw bytes.
 * @param {Uint8Array} commitment_with_proof - An octet array of the commitment
 * with proof.
 * @param {Uint8Array} header - Header as a byte array.
 * @param {Array} messages - An array of Uint8Arrays that represent the
 * messages.
 * @param {bigint} signer_nym_entropy - A cryptographic random scalar.
 * @param {string} api_id - API_ID string.
 * @returns {Array} - An array containing two elements: the blind signature (UInt8Array)
 * and signer_nym_entropy (bigint).
 */
export async function BlindSignWithNym(SK, PK, commitment_with_proof, signer_nym_entropy, header, messages, api_id) {
  // Deserialization:
  // 1. L = length(messages)
  const L = messages.length;
  // 2. M = length(commitment_with_proof)
  // 3. if M != 0, M = M - octet_point_length - octet_scalar_length
  // 4. M = M / octet_scalar_length
  // 5. if M < 0, return INVALID
  const M = calcM(commitment_with_proof);
  // Procedure:
  // 1.  generators = BBS.create_generators(L + 1, api_id)
  // 2.  blind_generators = BBS.create_generators(M + 1, "BLIND_" || api_id)
  const gens = await prepareGenerators(L + 1, api_id);
  const blindGens = await prepareGenerators(M + 1, 'BLIND_' + api_id);
  // 3.  commit = deserialize_and_validate_commit(commitment_with_proof, blind_generators, api_id)
  const commit = await deserialize_and_validate_commit(commitment_with_proof, blindGens, api_id);
  // 4.  if commit is INVALID, return INVALID
  // 5.  message_scalars = BBS.messages_to_scalars(messages, api_id)
  const message_scalars = await messages_to_scalars(messages, api_id);
  // 6.  res = B_calculate(message_scalars, generators, blind_generators[-1])
  const res = await B_calculate_with_nym(gens, commit, blindGens.generators.at(-1),
    message_scalars, signer_nym_entropy);
  // 7.  if res is INVALID, return INVALID
  const B = res;
  // 9.  blind_sig = FinalizeBlindSign(SK, PK, B, generators, blind_generators, header, api_id)
  const blind_sig = await FinalizeBlindSign(SK, PK, B, gens.generators, blindGens.generators,
    header, api_id);
  // 10. if blind_sig is INVALID, return INVALID
  // 11. return (blind_sig, signer_nym_entropy)
  return blind_sig;
}

async function B_calculate_with_nym(gens, commitment, nym_generator, message_scalars, signer_nym_entropy) {
  // Deserialization:
  // 1. L = length(messages)
  const L = message_scalars.length;
  // 2. if length(generators) != L + 1, return INVALID
  if(gens.generators.length != L + 1) {
    throw new TypeError('wrong number of generators');
  }
  // 3. (Q_1, H_1, ..., H_L) = generators
  const [Q_1, ...H] = gens.generators;
  //   Procedure:
  // 1. B = P1 + H_1 * msg_1 + ... + H_L * msg_L + commitment
  let B = gens.P1;
  for(let i = 0; i < message_scalars.length; i++) {
    B = B.add(H[i].multiply(message_scalars[i]));
  }
  B = B.add(commitment);
  // 2. signer_nym_entropy = get_random(1) ==> **TODO** for now take as a parameter
  // 3. B = B + nym_generator * signer_nym_entropy
  B = B.add(nym_generator.multiply(signer_nym_entropy));
  // 4. If B is Identity_G1, return INVALID
  if(B.equals(bls.G1.ProjectivePoint.ZERO)) {
    new Error('B equals Identity_G1, Invalid!');
  }
  return B;
}

/**
 * @param {Uint8Array} PK -  Public key as a compressed G2 point raw bytes.
 * @param {Uint8Array} signature - The signature as an octet string.
 * @param {Uint8Array} header - Header as a byte array.
 * @param {Array} messages - An array of Uint8Arrays that represent the
 * messages.
 * @param {Array} committed_messages - An array of Uint8Arrays that represent
 * the committed messages.
 * @param {bigint} prover_nym - The provers secret part of the nym.
 * @param {bigint} signer_nym_entropy - The signers random part of the nym.
 * @param {bigint} secret_prover_blind - The prover's commitment blind.
 * @param {string} api_id - API ID string.
 */
export async function VerifyFinalizeWithNym(PK, signature, header, messages, committed_messages,
  prover_nym, signer_nym_entropy, secret_prover_blind, api_id) {

  const nym_secret = bls.fields.Fr.add(prover_nym, signer_nym_entropy);
  const L = messages.length;
  const M = committed_messages.length;
  const [allScalars, combinedGens] = await prepare_parameters(messages, committed_messages,
    L + 1, M + 2, secret_prover_blind, api_id);
  allScalars.push(nym_secret);
  const valid = await verify(PK, signature, header, allScalars, combinedGens, api_id);
  return [valid, nym_secret];
}

/**
 * @param {Uint8Array} PK -  Public key as a compressed G2 point raw bytes.
 * @param {Uint8Array} signature - The signature as an octet string.
 * @param {Uint8Array} header - Header as a byte array.
 * @param {Uint8Array} ph - Presentation header as a byte array.
 * @param {bigint} nym_secret - Nym secret scalar.
 * @param {Uint8Array} context_id - Context (or verifier) id as a byte array.
 * @param {Array} messages - A vector of octet strings (Uint8Array). If not
 * supplied, it defaults to the empty array. These should be all the messages
 * the signer used in the signature.
 * @param {Array} committed_messages - A vector of octet strings (Uint8Array).
 * If not supplied, it defaults to the empty array. These should be all the
 * messages the prover put in the commitment.
 * @param {Array} disclosed_indexes - Vector of unsigned integers in ascending
 * order. Indexes of disclosed messages that originated with the signer. If not
 * supplied, it defaults to an empty array.
 * @param {Array} disclosed_commitment_indexes - Vector of unsigned integers
 * in ascending order. Indexes of disclosed committed messages. If not supplied,
 * it defaults to an empty array.
 * @param {bigint} secret_prover_blind - The secret prover blind used when committing
 * prover messages and prover_nym.
 * @param {string} api_id - The API id for the signature suite.
 * @param {Function} rand_scalars - A function for generating cryptographically
 *  secure random or pseudo random scalars.
 */
export async function ProofGenWithNym(PK, signature, header, ph, nym_secret, context_id, messages,
  committed_messages, disclosed_indexes, disclosed_commitment_indexes, secret_prover_blind, api_id,
  rand_scalars = calculate_random_scalars) {
  // Deserialization:
  // 1. L = length(messages)
  const L = messages.length;
  // 2. M = length(committed_messages)
  const M = committed_messages.length;
  // 3. if length(disclosed_indexes) > L, return INVALID
  if(disclosed_indexes.length > L) {
    throw TypeError('ProofGenWithNym: too many disclosed indexes');
  }
  // 4. for i in disclosed_indexes, if i < 0 or i >= L, return INVALID
  for(const index of disclosed_indexes) {
    if(index < 0 || index >= L) {
      throw TypeError('ProofGenWithNym: disclosed index out of bounds');
    }
  }
  // 5. if length(disclosed_commitment_indexes) > M, return INVALID
  if(disclosed_commitment_indexes.length > M + 1) { // allow reveal of nym secret
    throw TypeError('ProofGenWithNym: too many disclosed commitment indexes');
  }
  // 6. for j in disclosed_commitment_indexes, if i < 0 or i >= M, return INVALID
  for(const index of disclosed_commitment_indexes) {
    if(index < 0 || index >= L) {
      throw TypeError('ProofGenWithNym: disclosed commitment index out of bounds');
    }
  }
  let combined_indexes = [];
  // 9.  indexes.append(disclosed_indexes)
  combined_indexes = combined_indexes.concat(disclosed_indexes);
  // 10. for j in disclosed_commitment_indexes: indexes.append(j + L + 1)
  for(const j of disclosed_commitment_indexes) {
    combined_indexes.push(j + L + 1);
  }
  const [allScalars, combinedGens] = await prepare_parameters(messages, committed_messages,
    L + 1, M + 2, secret_prover_blind, api_id);
  allScalars.push(bls.fields.Fr.create(nym_secret));
  // 11. proof = CoreProofGenWithNym(PK, signature, generators.append(blind_generators), header,
  //               ph, context_id, message_scalars.append(committed_message_scalars), indexes, api_id)
  const [proof, pseudonym] = await CoreProofGenWithNym(PK, signature, combinedGens, header, ph, context_id,
    allScalars, combined_indexes, api_id, rand_scalars);
  // 12. return proof
  return [proof, pseudonym];
}

async function CoreProofGenWithNym(PK, signature, gens, header, ph, context_id, msg_scalars,
  disclosed_indexes, api_id, rand_scalars) {
  // Deserialization:
  // 1.  signature_result = octets_to_signature(signature)
  // 2.  if signature_result is INVALID, return INVALID
  // 3.  (A, e) = signature_result
  const {A, e} = octets_to_sig(signature); // Get curve point and scalar
  // 4.  L = length(message_scalars)
  const L = msg_scalars.length;
  // 5.  R = length(disclosed_indexes)
  const R = disclosed_indexes.length;
  // 6.  (i1, ..., iR) = disclosed_indexes
  // 7.  if R > L - 1, return INVALID, Note: we never reveal the nym_secret.
  if(R > L - 1) {
    throw new TypeError(`CoreProofGenWithNym: too many disclosed indexes R = ${R} > L - 1 = ${L - 1}`);
  }
  // 8.  U = L - R
  const U = L - R;
  // // Note: nym_secret is last message and is not revealed.
  // 9.  undisclosed_indexes = (0, 1, ..., L - 1) \ disclosed_indexes
  // 10. (i1, ..., iR) = disclosed_indexes
  // 11. (j1, ..., jU) = undisclosed_indexes
  const allIndexes = [];
  for(let i = 0; i < L; i++) {
    allIndexes[i] = i;
  }
  const tempSet = new Set(allIndexes);
  for(const dis of disclosed_indexes) {
    tempSet.delete(dis);
  }
  const undisclosed_indexes = Array.from(tempSet);
  // 12. disclosed_messages = (message_scalars[i1], ..., message_scalars[iR])
  // 13. undisclosed_messages = (message_scalars[j1], ..., message_scalars[jU])
  // ABORT if:
  // 1. for i in disclosed_indexes, i < 0 or i > L - 1, // Note: nym_secret is the Lth message and not revealed.
  for(const i of disclosed_indexes) {
    if(i < 0 || i > L - 1) {
      throw new TypeError('CoreProofGenWithNym: disclosed index out of bounds');
    }
  }
  const disclosed_scalars = msg_scalars.filter((msg, i) => disclosed_indexes.includes(i));
  // Procedure:
  // 1. random_scalars = calculate_random_scalars(5+U)
  const randScalars = await rand_scalars(5 + U);
  if(GEN_TRACE_INFO) {
    // PK, signature, pseudonym, verifier_id,
    // pid_scalar, gens, header, ph, msg_scalars, disclosed_indexes, api_id, rand_scalars
    const info = {
      info: 'from CoreProofGenWithNym',
      PK: bytesToHex(PK),
      signature: bytesToHex(signature),
      A: bytesToHex(A.toRawBytes(true)),
      e: numberToHex(e, SCALAR_LENGTH),
      H: gens.generators.map(h => bytesToHex(h.toRawBytes(true))), // Includes Q1 at beginning
      ph: bytesToHex(ph),
      msg_scalars: msg_scalars.map(ms => numberToHex(ms, SCALAR_LENGTH)),
      disclosed_indexes
    };
    console.log(JSON.stringify(info, null, 2));
  }
  // 2. init_res = BBS.ProofInit(PK, signature_res, header, random_scalars, generators, message_scalars,
  //                         undisclosed_indexes, api_id)
  // 3. if init_res is INVALID, return INVALID
  const init_res = await ProofInit(PK, [A, e], gens, randScalars, header,
    msg_scalars, undisclosed_indexes, api_id);
  // 4. pseudonym_init_res = NymProofInit(context_id, message_scalars[-1], random_scalars[-1])
  const pseudonym_init_res = await NymProofInit(context_id, msg_scalars.at(-1),
    randScalars.at(-1), api_id);
  // 5. if pseudonym_init_res is INVALID, return INVALID
  // 6. Pseudonym = pseudonym_init_res[0]
  const pseudonym = pseudonym_init_res[0];
  // 7. challenge = ProofWithNymChallengeCalculate(init_res, pseudonym_init_res, disclosed_indexes,
  //                  disclosed_messages, ph, api_id)
  const challenge = await ProofWithNymChallengeCalculate(init_res, pseudonym_init_res, disclosed_indexes,
    disclosed_scalars, ph, api_id);
  // 8. proof = BBS.ProofFinalize(init_res, challenge, e_value, random_scalars, undisclosed_messages)
  const proof = await ProofFinalize(init_res, challenge, e, randScalars, msg_scalars,
    undisclosed_indexes, PK);
  if(GEN_TRACE_INFO) {
    console.log('Checking ProofVerifyInit in CoreProofGenWithNym:');
    const proof_result = octets_to_proof(proof);
    const stuff = await ProofVerifyInit(PK, proof_result, gens, header,
      disclosed_scalars, disclosed_indexes, api_id);
  }
  // 9. return (proof, Pseudonym)
  return [proof, pseudonym];
}

async function NymProofInit(context_id, nym_secret, random_scalar, api_id) {
  // Procedure:
  // 1. OP = hash_to_curve_g1(context_id, api_id)
  const OP = await hash_to_curve_g1(context_id, api_id);
  // 2. Pseudonym = OP * nym_secret
  const pseudonym = OP.multiply(nym_secret);
  // 3. Ut = OP * random_scalar
  console.log(`Nym proof init rand scalar: ${random_scalar.toString(16)}`);
  const Ut = OP.multiply(random_scalar);
  // 4. if Pseudonym == Identity_G1 or Ut == Identity_G1, return INVALID
  if(pseudonym.equals(bls.G1.ProjectivePoint.ZERO)) {
    throw new Error('pseudonym equals Identity_G1, Invalid!');
  }
  // 5. return (Pseudonym, OP, Ut)
  return [pseudonym, OP, Ut];
}

async function ProofWithNymChallengeCalculate(init_res, pseudonym_init_res, i_array,
  msg_array, ph, api_id) {
  // Deserialization:
  // 1. R = length(i_array)
  const R = i_array.length;
  // 2. (i1, ..., iR) = i_array
  // 3. (msg_i1, ..., msg_iR) = msg_array
  // 4. (Abar, Bbar, D, T1, T2, domain) = init_res
  const [Abar, Bbar, D, T1, T2, domain] = init_res;
  // 5. (Pseudonym, OP, Ut) = pseudonym_init_res
  const [pseudonym, OP, Ut] = pseudonym_init_res;
  // ABORT if:
  // 1. R > 2^64 - 1 or R != length(msg_array)
  // 2. length(ph) > 2^64 - 1

  const dst = new TextEncoder().encode(api_id + 'H2S_');
  // Procedure:
  // 1. c_arr = (R, i1, msg_i1, i2, msg_i2, ..., iR, msg_iR, Abar, Bbar,
  //                 D, T1, T2, Pseudonym, OP, Ut, domain)
  const c_array = [
    {type: 'NonNegInt', value: R},
  ];
  for(let i = 0; i < i_array.length; i++) { // i_j, msg_j
    c_array.push({type: 'NonNegInt', value: i_array[i]});
    c_array.push({type: 'Scalar', value: msg_array[i]});
  }
  c_array.push({type: 'GPoint', value: Abar});
  c_array.push({type: 'GPoint', value: Bbar});
  c_array.push({type: 'GPoint', value: D});
  c_array.push({type: 'GPoint', value: T1});
  c_array.push({type: 'GPoint', value: T2});
  c_array.push({type: 'GPoint', value: pseudonym});
  c_array.push({type: 'GPoint', value: OP});
  c_array.push({type: 'GPoint', value: Ut});
  c_array.push({type: 'Scalar', value: domain});
  c_array.push({type: 'PlainOctets', value: ph});
  // 2. c_octs = serialize(c_arr) || I2OSP(length(ph), 8) || ph
  const c_octs = serialize(c_array);
  const c = await hash_to_scalar(c_octs, dst, api_id);
  // 3. return hash_to_scalar(c_octs, challenge_dst)
  if(GEN_TRACE_INFO) {
    const info = {
      info: 'from ProofWithNymChallengeCalculate',
      Abar: bytesToHex(Abar.toRawBytes(true)),
      Bbar: bytesToHex(Bbar.toRawBytes(true)),
      D: bytesToHex(D.toRawBytes(true)),
      T1: bytesToHex(T1.toRawBytes(true)),
      T2: bytesToHex(T2.toRawBytes(true)),
      domain: numberToHex(domain, SCALAR_LENGTH),
      pseudonym: bytesToHex(pseudonym.toRawBytes(true)),
      OP: bytesToHex(OP.toRawBytes(true)),
      Ut: bytesToHex(Ut.toRawBytes(true)),
      challenge: numberToHex(c, SCALAR_LENGTH)
    };
    console.log(JSON.stringify(info, null, 2));
  }
  return c;
}

export async function ProofVerifyWithNym(PK, proof, header, ph, pseudonym_bytes, context_id,
  L, disclosed_messages, disclosed_committed_messages, disclosed_indexes,
  disclosed_committed_indexes, api_id) {
  // Deserialization:
  const pseudonym = bls.G1.ProjectivePoint.fromHex(pseudonym_bytes);
  // 1. proof_len_floor = 2 * octet_point_length + 3 * octet_scalar_length
  const proofLenFloor = 3 * POINT_LENGTH + 4 * SCALAR_LENGTH; // WAS 4 * SCALAR_LENGTH
  // 2. if length(proof) < proof_len_floor, return INVALID
  if(proof.length < proofLenFloor) {
    if(GEN_TRACE_INFO) {
      console.log('from ProofVerifyWithNym: proof is too short.');
    }
    return false;
  }
  // 3. U = floor((length(proof) - proof_len_floor) / octet_scalar_length)
  const U = Math.floor((proof.length - proofLenFloor) / SCALAR_LENGTH);
  // 4. total_no_messages = length(disclosed_indexes) + length(disclosed_committed_indexes) + U
  const totalNumMessages = disclosed_indexes.length + U - 1; // WAS + U - 1
  // 5. M = total_no_messages - L
  const M = totalNumMessages - L;
  // Procedure:
  // 6.  indexes = ()
  let indexes = [];
  // 7.  indexes.append(disclosed_indexes)
  indexes = indexes.concat(disclosed_indexes);
  // 8.  for j in disclosed_commitment_indexes: indexes.append(j + L + 1)
  for(const j of disclosed_committed_indexes) {
    indexes.push(j + L + 1);
  }
  const [msg_scalars, combinedGens] = await prepare_parameters(disclosed_messages,
    disclosed_committed_messages, L + 1, M + 1, null, api_id);
  // 9.  result = CoreProofVerifyWithNym(PK, proof, Pseudonym, context_id,
  //       generators.append(blind_generators), header, ph, message_scalars, indexes, api_id)
  const result = await CoreProofVerifyWithNym(PK, proof, pseudonym, context_id, combinedGens,
    header, ph, msg_scalars, disclosed_indexes, api_id);
  // 10. return result
  return result;
}

async function CoreProofVerifyWithNym(PK, proof, pseudonym, context_id, gens,
  header, ph, disclosed_messages, disclosed_indexes, api_id) {
  // Deserialization:
  // 1. proof_result = octets_to_proof(proof)
  // 2. if proof_result is INVALID, return INVALID
  let proof_result;
  try {
    proof_result = octets_to_proof(proof);
  } catch{
    // console.log('Problem with octets_to_proof');
    return false;
  }
  // 3. (Abar, Bbar, r2^, r3^, commitments, cp) = proof_result
  // Issue octets_to_proof returns: {Abar, Bbar, D, eHat, r1Hat, r3Hat, mHatU, c};
  const {Abar, Bbar, D, eHat, r1Hat, r3Hat, mHatU, c} = proof_result;
  // 4. W = octets_to_pubkey(PK)
  // 5. if W is INVALID, return INVALID
  const W = bls.G2.ProjectivePoint.fromHex(PK);
  // 6. R = length(disclosed_indexes)
  const R = disclosed_indexes.length;
  // 7. (i1, ..., iR) = disclosed_indexes
  // ABORT if:
  // 1. for i in disclosed_indexes, i < 1 or i > R + length(commitments) - 1
  // Procedure:
  // 1. init_res = BBS.ProofVerifyInit(PK, proof_result, header, generators, messages, disclosed_indexes, api_id)
  const init_res = await ProofVerifyInit(PK, proof_result, gens, header,
    disclosed_messages, disclosed_indexes, api_id);
  // 2. pseudonym_init_res = NymProofVerifyInit(Pseudonym, context_id, commitments[-1], cp)
  // 3. if pseudonym_init_res is INVALID, return INVALID
  const nym_secret_commitment = mHatU.at(-1); // comes at the end of all the proof commitments
  // NymProofVerifyInit(pseudonym, context_id, nym_secret_commitment, proof_challenge, api_id)
  const pseudonym_init_res = await NymProofVerifyInit(pseudonym, context_id, nym_secret_commitment,
    c, api_id);
  // 4. challenge = ProofWithNymChallengeCalculate(init_res, pseudonym_init_res, disclosed_indexes,
  //                  messages, ph, api_id)
  const challenge = await ProofWithNymChallengeCalculate(init_res, pseudonym_init_res, disclosed_indexes,
    disclosed_messages, ph, api_id);
  // 5. if cp != challenge, return INVALID
  if(c !== challenge) {
    console.log('challenge failed');
    return false;
  }
  // 6. if e(Abar, W) * e(Bbar, -BP2) != Identity_GT, return INVALID
  // Compute item in G2
  const negP2 = bls.G2.ProjectivePoint.BASE.negate();
  // Compute items in GT, i.e., Fp12
  const ptGT1 = bls.pairing(Abar, W);
  const ptGT2 = bls.pairing(Bbar, negP2);
  let result = bls.fields.Fp12.mul(ptGT1, ptGT2);
  result = bls.fields.Fp12.finalExponentiate(result); // See noble BLS12-381
  const valid = await bls.fields.Fp12.eql(result, bls.fields.Fp12.ONE);
  console.log(`equality test: ${valid}`);
  return valid;
}

async function NymProofVerifyInit(pseudonym, context_id, nym_secret_commitment, proof_challenge, api_id) {
  // Procedure:
  // 1. OP = hash_to_curve_g1(context_id)
  const OP = await hash_to_curve_g1(context_id, api_id);
  // 2. Uv = OP * nym_secret_commitment - Pseudonym * proof_challenge
  let Uv = OP.multiply(nym_secret_commitment);
  Uv = Uv.subtract(pseudonym.multiply(proof_challenge));
  // 3. if Uv == Identity_G1, return INVALID
  if(Uv.equals(bls.G1.ProjectivePoint.ZERO)) {
    throw new Error('Uv equals Identity_G1, Invalid!');
  }
  // 4. return (Pseudonym, OP, Uv)
  return [pseudonym, OP, Uv];
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
