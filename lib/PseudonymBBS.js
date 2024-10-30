/* Functions used in BBS Per Verifier Id (pseudonym) operations
   API subject to change!
*/
/*global TextEncoder, console*/
/* eslint-disable max-len */

import {BlindSign, calcM, CoreCommit, deserialize_and_validate_commit, FinalizeBlindSign} from './BlindBBS.js';
import {
  bytesToHex, calculate_random_scalars, concat, hash_to_scalar, messages_to_scalars,
  octets_to_sig, octets_to_proof, os2ip, prepareGenerators, ProofInit, ProofFinalize,
  ProofVerifyInit, serialize, numberToHex, verify
}
  from './BBS.js';
import {bls12_381 as bls} from '@noble/curves/bls12-381';
import {shake256} from '@noble/hashes/sha3';

const GEN_TRACE_INFO = false; // set to true to send trace info to console.

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

export async function NymCommit(messages, prover_nym, api_id,
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
export async function BlindSignWithNym(SK, PK, commitment_with_proof, header, messages, signer_nym_entropy, api_id) {
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
  // 8.  (B, signer_nym_entropy) = res
  const [B, nym_entropy] = res;
  // 9.  blind_sig = FinalizeBlindSign(SK, PK, B, generators, blind_generators, header, api_id)
  const blind_sig = await FinalizeBlindSign(SK, PK, B, gens.generators, blindGens.generators,
    header, api_id);
  // 10. if blind_sig is INVALID, return INVALID
  // 11. return (blind_sig, signer_nym_entropy)
  return [blind_sig, nym_entropy];
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
  // 5. return (B, signer_nym_entropy)
  return [B, signer_nym_entropy];
}

/**
 * @param {Uint8Array} PK -  Public key as a compressed G2 point raw bytes.
 * @param {Uint8Array} signature - the signature as an octet string
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
export async function Finalize(PK, signature, header, messages, committed_messages,
  prover_nym, signer_nym_entropy, secret_prover_blind, api_id) {
  // Procedure: From Pseudonym
  // 1. nym_secret = prover_nym + signer_nym_entropy
  const nym_secret = bls.fields.Fr.add(prover_nym, signer_nym_entropy);
  // Procedure from Blind
  // 1. message_scalars = BBS.messages_to_scalars(messages, api_id)
  const message_scalars = await messages_to_scalars(messages, api_id);
  // 2. committed_message_scalars = ()
  let committed_message_scalars = [];
  // 4. committed_message_scalars.append(secret_prover_blind) bls.fields.Fr.create(e)
  committed_message_scalars.push(bls.fields.Fr.create(secret_prover_blind)); // very first committed message scalar
  // 5. committed_message_scalars.append(BBS.messages_to_scalars(committed_messages, api_id))
  console.log(`Committed messages: ${committed_messages}`);
  const tempScalars = await messages_to_scalars(committed_messages, api_id);
  committed_message_scalars = committed_message_scalars.concat(tempScalars);
  // Pseudonym: 2. committed_messages.append(nym_secret) -- very last committed message scalar
  committed_message_scalars = committed_message_scalars.concat([nym_secret]);
  // 6. generators = BBS.create_generators(length(message_scalars) + 1, api_id)
  const L = messages.length;
  const gens = await prepareGenerators(L + 1, api_id);
  // 7. blind_generators = BBS.create_generators(length(committed_message_scalars), "BLIND_" || api_id)
  const M = committed_message_scalars.length;
  const blindGens = await prepareGenerators(M + 1, 'BLIND_' + api_id);
  // 8. res = BBS.CoreVerify(PK, signature, generators.append(blind_generators), header, 
  //            message_scalars.append(committed_message_scalars), api_id)
  const allScalars = [...message_scalars, ...committed_message_scalars];
  const combinedGens = {
    P1: gens.P1,
    generators: [...gens.generators, ...blindGens.generators]
  };
  const valid = await verify(PK, signature, header, allScalars, combinedGens, api_id);
  return [valid, nym_secret];
}

/**
 * 
 * @param {Uint8Array} PK -  Public key as a compressed G2 point raw bytes.
 * @param {Uint8Array} signature - the signature as an octet string
 * @param {Uint8Array} header - Header as a byte array.
 * @param {Uint8Array} ph - Presentation header as a byte array.
 * @param {bigint} nym_secret - Nym secret scalar
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
  if(disclosed_commitment_indexes.length > M) {
    throw TypeError('ProofGenWithNym: too many disclosed commitment indexes');
  }
  // 6. for j in disclosed_commitment_indexes, if i < 0 or i >= M, return INVALID
  for(const index of disclosed_commitment_indexes) {
    if(index < 0 || index >= L) {
      throw TypeError('ProofGenWithNym: disclosed commitment index out of bounds');
    }
  }
  // Procedure:
  // 1.  message_scalars = BBS.messages_to_scalars(messages, api_id)
  const message_scalars = await messages_to_scalars(messages, api_id);
  // 2.  committed_message_scalars = ()
  let committed_message_scalars = [];
  // 3.  committed_message_scalars.append(secret_prover_blind)
  committed_message_scalars.push(bls.fields.Fr.create(secret_prover_blind)); // doesn't count as a committed mesage
  // 4.  committed_message_scalars.append(BBS.messages_to_scalars(committed_messages, api_id))
  const tempScalars = await messages_to_scalars(committed_messages, api_id);
  committed_message_scalars = committed_message_scalars.concat(tempScalars);
  // 5.  committed_message_scalars.append(nym_secret)
  committed_message_scalars.push(nym_secret); // counts as a committed message
  // 6.  generators = BBS.create_generators(length(message_scalars) + 1, api_id)
  const gens = await prepareGenerators(L + 1, api_id);
  // 7.  blind_generators = BBS.create_generators(length(committed_message_scalars), "BLIND_" || api_id)
  const blindGens = await prepareGenerators(committed_message_scalars.length, 'BLIND_' + api_id);
  console.log(`Number of committed message scalars: ${committed_message_scalars.length}`);
  // 8.  indexes = ()
  let combined_indexes = [];
  // 9.  indexes.append(disclosed_indexes)
  combined_indexes = combined_indexes.concat(disclosed_indexes);
  // 10. for j in disclosed_commitment_indexes: indexes.append(j + L + 1)
  for(const j of disclosed_commitment_indexes) {
    combined_indexes.push(j + L + 1);
  }
  // console.log("ProofGenWithNym Combined Indexes:");
  // console.log(combined_indexes);
  // Set combine scalars and generators
  const allScalars = [...message_scalars, ...committed_message_scalars];
  const combinedGens = {
    P1: gens.P1,
    generators: [...gens.generators, ...blindGens.generators]
  };
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
  console.log("CoreProofGenWithNym disclosed_indexes:");
  console.log(disclosed_indexes);
  if(R > L - 1) {
    throw new TypeError(`CoreProofGenWithNym: too many disclosed indexes R = ${R} > L-1 = ${L-1}`);
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
  // 4. pseudonym_init_res = PseudonymProofInit(context_id, message_scalars[-1], random_scalars[-1])
  const pseudonym_init_res = await PseudonymProofInit(context_id, msg_scalars.at(-1), 
    randScalars.at(-1), api_id);
  // 5. if pseudonym_init_res is INVALID, return INVALID
  // 6. Pseudonym = pseudonym_init_res[0]
  const pseudonym = pseudonym_init_res[0];
  // 7. challenge = ProofWithPseudonymChallengeCalculate(init_res, pseudonym_init_res, disclosed_indexes,
  //                  disclosed_messages, ph, api_id)
  const challenge = await ProofWithPseudonymChallengeCalculate(init_res, pseudonym_init_res, disclosed_indexes,
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

async function PseudonymProofInit(context_id, nym_secret, random_scalar, api_id) {
  // Procedure:
  // 1. OP = hash_to_curve_g1(context_id, api_id)
  const OP = await hash_to_curve_g1(context_id, api_id);
  // 2. Pseudonym = OP * nym_secret
  const pseudonym = OP.multiply(nym_secret);
  // 3. Ut = OP * random_scalar
  const Ut = OP.multiply(random_scalar);
  // 4. if Pseudonym == Identity_G1 or Ut == Identity_G1, return INVALID
  if(pseudonym.equals(bls.G1.ProjectivePoint.ZERO)) {
    throw new Error('pseudonym equals Identity_G1, Invalid!');
  }
  // 5. return (Pseudonym, OP, Ut)
  return [pseudonym, OP, Ut];
}

async function ProofWithPseudonymChallengeCalculate(init_res, pseudonym_init_res, i_array,
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
  c_array.push({type: 'GPoint', value: pseudonym });
  c_array.push({type: 'GPoint', value: OP});
  c_array.push({type: 'GPoint', value: Ut});
  c_array.push({type: 'Scalar', value: domain});
  c_array.push({type: 'PlainOctets', value: ph });
  // 2. c_octs = serialize(c_arr) || I2OSP(length(ph), 8) || ph
  const c_octs = serialize(c_array);
  const c = await hash_to_scalar(c_octs, dst, api_id);
  // 3. return hash_to_scalar(c_octs, challenge_dst)
  if(GEN_TRACE_INFO) {
    const info = {
      info: 'from ProofWithPseudonymChallengeCalculate',
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

export async function ProofVerifyWithPseudonym(PK, proof, header, ph, Pseudonym, context_id,
  L, disclosed_messages, disclosed_committed_messages, disclosed_indexes, disclosed_committed_indexes) {

}

async function CoreProofVerifyWithPseudonym(PK, proof, Pseudonym, context_id, generators,
  header, ph, disclosed_messages, disclosed_indexes, api_id) {

}

async function PseudonymProofVerifyInit(Pseudonym, context_id, nym_secret_commitment, proof_challenge) {

}

//////////////////////////////////////////////
// OLD PSEUDONYM API AND CODE
//////////////////////////////////////////////

/**
 * Signs a list of messages and prover identifier (pid) for the issuer
 * known pid pseudonym case.
 *
 * @param {bigint} SK - A scalar secret key.
 * @param {Uint8Array} PK -  Public key as a compressed G2 point raw bytes.
 * @param {Uint8Array} header - Header as a byte array.
 * @param {Array} messages - An array of Uint8Arrays that represent the
 * messages.
 * @param {Uint8Array} pid - The prover identifier.
 * @param {string} api_id - The API id for the signature suite.
 * @returns {Uint8Array} - The signature.
 */
export async function PseudonymSign(SK, PK, header, messages, pid, api_id) {
  const dup_messages = messages.slice(); // make a copy so not to mess with messages
  dup_messages.push(pid);
  const commitment_with_proof = null;
  const signer_blind = 0n;
  const signature = await BlindSign(SK, PK, commitment_with_proof, header, dup_messages,
    signer_blind, api_id);
  return signature;
}

/**
 * Verifies a signature over messages and issuer  known pid.
 * 
 * @param {Uint8Array} PK - Public key as a compressed G2 point raw bytes.
 * @param {Uint8Array} signature - A previously computed signature.
 * @param {Uint8Array} header - Header used when signature was created.
 * @param {Array} messages - Array of byte arrays (Uint8Array) of signer
 * messages.
 * @param {Uint8Array} pid - The prover identifier.
 * @param {string} api_id - The API id for the signature suite.
 * @returns {boolean} - True or False depending on whether the signature
 *  is valid.
 */
export async function PseudonymVerify(PK, signature, header, messages, pid, api_id) {
  const dup_messages = messages.slice(); // make a copy so not to mess with messages
  dup_messages.push(pid);
  const gens = await prepareGenerators(dup_messages.length + 1, api_id);
  const msg_scalars = await messages_to_scalars(dup_messages, api_id);
  const committed_messages = [];
  const secret_prover_blind = 0n;
  const signer_blind = 0n;
  const result = await BlindVerify(PK, signature, header, dup_messages, committed_messages,
    secret_prover_blind, signer_blind, api_id);
  return result;
}

export async function CalculatePseudonym(verifier_id, pid, api_id) {
  // 1. OP = hash_to_curve_g1(verifier_id, api_id)
  // 2. if OP is INVALID, return INVALID
  const OP = await hash_to_curve_g1(verifier_id, api_id);
  // 3. if OP == Identity_G1 or OP == BP1 or OP == P1, return INVALID
  // 3. pid_scalar = messages_to_scalars((pid), api_id)
  const [pid_scalar] = await messages_to_scalars([pid], api_id);
  // 4. return OP * pid_scalar
  return OP.multiply(pid_scalar);
}

export async function hash_to_curve_g1(thing, api_id) {
  if (api_id.includes('SHA-256')) {
    return bls.G1.hashToCurve(thing, { DST: api_id });
  } else {
    return bls.G1.hashToCurve(thing, {
      DST: api_id,
      expand: 'xof',
      hash: shake256,
    });
  }
}

/**
 * Pseudonym BBS proof generation.
 *
 * @param {Uint8Array} PK - Public key as a compressed G2 point raw bytes.
 * @param {Uint8Array} signature - A previously computed signature.
 * @param {Uint8Array} pseudonym_bytes - Pseudonym computed with pid and verifier_id.
 * @param {Uint8Array} verifier_id - Verifier Identifier
 * @param {Uint8Array} pid - Prover Identifier
 * @param {Uint8Array} header - Header used when signature was created.
 * @param {Uint8Array} ph - Presentation header, used during proof creation.
 * @param {Array} messages - A vector of octet strings (Uint8Array). If not
 * supplied, it defaults to the empty array. These should be all the messages
 * the signer used in the signature.
 * @param {Array} disclosed_indexes - Vector of unsigned integers in ascending
 * order. Indexes of disclosed messages that originated with the signer. If not
 * supplied, it defaults to an empty array.
 * @param {string} api_id - The API id for the signature suite.
 * @param {Function} rand_scalars - A function for generating cryptographically
 *  secure random or pseudo random scalars.
 * @returns {Array} [proof, disclosed_msgs, disclosed_idxs] a tuple comprising
 * an octet string, an array of octet strings and an array of non-zero integers;
 * or will throw an exception.
 */
export async function ProofGenWithPseudonym(PK, signature, pseudonym_bytes, verifier_id,
  pid, header, ph, messages, disclosed_indexes, api_id, rand_scalars = calculate_random_scalars) {
  const pseudonym = bls.G1.ProjectivePoint.fromHex(pseudonym_bytes);

  const msg_scalars = await messages_to_scalars(messages, api_id);
  const [pid_scalar] = await messages_to_scalars([pid], api_id);

  // Generator creation
  const gens = await prepareGenerators(messages.length + 2, api_id)  // We didn't add pid yet
  const blindGens = await prepareGenerators(1, 'BLIND_' + api_id);
  const combinedGens = {
    P1: gens.P1,
    generators: [...gens.generators, ...blindGens.generators]
  };

  msg_scalars.push(pid_scalar);
  // Trying this out since we are using the blind sign we need an additional zero message
  // msg_scalars.push(0n); // Trying this...

  const proof = await CoreProofGenWithPseudonym(PK, signature, pseudonym, verifier_id,
    combinedGens, header, ph, msg_scalars, disclosed_indexes, api_id, rand_scalars);
  if (GEN_TRACE_INFO) {
    // PK, signature, pseudonym, verifier_id,
    // pid_scalar, gens, header, ph, msg_scalars, disclosed_indexes, api_id, rand_scalars
    const info = {
      info: 'from ProofGenWithPseudonym',
      gens: gens.generators.map(h => bytesToHex(h.toRawBytes(true))),  // Includes Q1 at beginning
      blindGens: blindGens.generators.map(h => bytesToHex(h.toRawBytes(true)))
    };
    console.log(JSON.stringify(info, null, 2));
  }
  return proof;
}

// taking out pid_scalar as parameter and putting it as last msg_scalars
async function CoreProofGenWithPseudonymOld(PK, signature, pseudonym, verifier_id,
  gens, header, ph, msg_scalars, disclosed_indexes, api_id, rand_scalars) {
  // Deserialization:
  // 1.  signature_result = octets_to_signature(signature)
  // 2.  if signature_result is INVALID, return INVALID
  // 3.  (A, e) = signature_result
  const { A, e } = octets_to_sig(signature); // Get curve point and scalar
  // 4.  messages = messages.push(pid_scalar)
  // const dup_msg_scalars = msg_scalars.slice(); // Make copy
  // dup_msg_scalars.push(pid_scalar);
  // 5.  L = length(messages)
  const L = msg_scalars.length; // Includes pid_scalar
  // 6.  R = length(disclosed_indexes)
  const R = disclosed_indexes.length;
  // 7.  (i1, ..., iR) = disclosed_indexes
  // 8.  if R > L - 1, return INVALID; PID is never revealed
  if (R > L - 1) {
    throw new TypeError('CoreProofGenWithPseudonym: too many disclosed indexes');
  }
  // 9.  U = L - R
  const U = L - R;
  // 10. undisclosed_indexes = range(0, L-1) \ disclosed_indexes
  const allIndexes = [];
  for (let i = 0; i < L; i++) {
    allIndexes[i] = i;
  }
  const tempSet = new Set(allIndexes);
  for (const dis of disclosed_indexes) {
    tempSet.delete(dis);
  }
  const undisclosed_indexes = Array.from(tempSet); // Contains all undisclosed indexes
  // console.log('undisclosed indexes:');
  // console.log(undisclosed_indexes);
  // console.log('disclosed indexes');
  // console.log(disclosed_indexes);
  // 11. disclosed_messages = (messages[i1], ..., messages[iR])
  // ABORT if: for i in disclosed_indexes, i < 1 or i > L - 1
  console.log(`dislosed indexes: ${disclosed_indexes}`);
  for (const i of disclosed_indexes) {
    if (i < 0 || i > L - 2) {
      throw new TypeError('CoreProofGenWithPseudonym: disclosed index out of bounds');
    }
  }
  const disclosed_scalars = msg_scalars.filter((msg, i) => disclosed_indexes.includes(i));
  // 1.  random_scalars = calculate_random_scalars(5+U+1)
  const randScalars = await rand_scalars(5 + U); // last one is for pid~
  // 2.  init_res = ProofInit(PK, signature_res, header, random_scalars, generators,messages,undisclosed_indexes,api_id)
  // 3.  if init_res is INVALID, return INVALID
  // ProofInit(PK, signature, gens, randScalars, header,
  // messages, undisclosed_indexes, api_id)
  if (GEN_TRACE_INFO) {
    // PK, signature, pseudonym, verifier_id,
    // pid_scalar, gens, header, ph, msg_scalars, disclosed_indexes, api_id, rand_scalars
    const info = {
      info: 'from CoreProofGenWithPseudonym',
      PK: bytesToHex(PK),
      signature: bytesToHex(signature),
      A: bytesToHex(A.toRawBytes(true)),
      e: numberToHex(e, SCALAR_LENGTH),
      H: gens.generators.map(h => bytesToHex(h.toRawBytes(true))),  // Includes Q1 at beginning
      ph: bytesToHex(ph),
      msg_scalars: msg_scalars.map(ms => numberToHex(ms, SCALAR_LENGTH)),
      disclosed_indexes
    };
    console.log(JSON.stringify(info, null, 2));
  }
  const init_res = await ProofInit(PK, [A, e], gens, randScalars, header,
    msg_scalars, undisclosed_indexes, api_id);
  // 4.  OP = hash_to_curve_g1(verifier_id, api_id)
  const OP = await hash_to_curve_g1(verifier_id, api_id);
  // 5.  pid~ = random_scalars[5 + U + 1] // last element of random_scalars
  const pidTilde = randScalars[randScalars.length - 1];
  // 6.  Ut = OP * pid~
  const Ut = OP.multiply(pidTilde);
  // 7.  pseudonym_init_res = (Pseudonym, OP, Ut)
  const pseudonym_init_res = [pseudonym, OP, Ut];
  // 8.  challenge = ProofWithPseudonymChallengeCalculate(init_res, pseudonym_init_res,
  //   disclosed_indexes,disclosed_messages, ph, api_id)
  const challenge = await ProofWithPseudonymChallengeCalculate(init_res, pseudonym_init_res,
    disclosed_indexes, disclosed_scalars, ph, api_id);
  // 9.  proof = ProofFinalize(challenge, e, random_scalars, messages, undisclosed_indexes)
  const proof = await ProofFinalize(init_res, challenge, e, randScalars, msg_scalars,
    undisclosed_indexes, PK);
  if (GEN_TRACE_INFO) {
    console.log('Checking ProofVerifyInit in ProofGen:');
    const proof_result = octets_to_proof(proof);
    const stuff = await ProofVerifyInit(PK, proof_result, gens, header,
      disclosed_scalars, disclosed_indexes, api_id);
  }
  return proof;
}

async function ProofWithPseudonymChallengeCalculateOLD(init_res, pseudonym_init_res,
  i_array, msg_array, ph, api_id) {
  // Old: 1. c_arr = (Abar, Bbar, D, T1, T2, Pseudonym, OP, Ut, R, i1, ..., iR, msg_i1, ..., msg_iR, domain)
  // Update for BBS-v06:
  // 1. c_arr = (R, i1, msg_i1, i2, msg_i2, ..., iR, msg_iR, Abar, Bbar, D, T1, T2, Pseudonym, OP, Ut, domain)
  // 2. c_octs = serialize(c_arr) || I2OSP(length(ph), 8) || ph
  // 3. return hash_to_scalar(c_octs, challenge_dst)
  const [Abar, Bbar, D, T1, T2, domain] = init_res;
  const [pseudonym, OP, Ut] = pseudonym_init_res;
  const dst = new TextEncoder().encode(api_id + 'H2S_');
  const c_array = [
    { type: 'NonNegInt', value: i_array.length }, // R
  ];
  for (let i = 0; i < i_array.length; i++) { // i_j, msg_j
    c_array.push({ type: 'NonNegInt', value: i_array[i] });
    c_array.push({ type: 'Scalar', value: msg_array[i] });
  }
  c_array.push({ type: 'GPoint', value: Abar });
  c_array.push({ type: 'GPoint', value: Bbar });
  c_array.push({ type: 'GPoint', value: D });
  c_array.push({ type: 'GPoint', value: T1 });
  c_array.push({ type: 'GPoint', value: T2 });
  c_array.push({ type: 'GPoint', value: pseudonym });
  c_array.push({ type: 'GPoint', value: OP });
  c_array.push({ type: 'GPoint', value: Ut });
  c_array.push({ type: 'Scalar', value: domain });
  c_array.push({ type: 'PlainOctets', value: ph });
  // c_for_hash = encode_for_hash(c_array)
  // if c_for_hash is INVALID, return INVALID
  const c_for_hash = serialize(c_array);
  const c = await hash_to_scalar(c_for_hash, dst, api_id);
  if (GEN_TRACE_INFO) {
    const info = {
      info: 'from ProofWithPseudonymChallengeCalculate',
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

/**
 * Verifies a previously generated proof with pseudonym against original signers
 * public key, pseudonym, and additional information.
 *
 * @async
 * @param {Uint8Array} PK - Public key as a compressed G2 point raw bytes.
 * @param {Uint8Array} proof - The proof as a byte array.
 * @param {integer} L - the total number of signer messages (may include
 * the pid).
 * @param {Uint8Array} pseudonym_bytes - The Pseudonym as a byte array.
 * @param {Uint8Array} verifier_id - The verifier id as a byte array.
 * @param {Uint8Array} header - Header used when original signature was created.
 * @param {Uint8Array} ph - Presentation header that was used during proof
 * creation.
 * @param {Array} disclosed_messages - Array of scalars (bigint) derived from
 *  actual  disclosed messages. Computed by {@link messages_to_scalars}.
 * @param {Array} disclosed_indexes - Array of sorted (non-repeating) zero
 * based indices corresponding to the disclosed messages.
 * @param {Array} gens - Contains an array of group G1 generators created by the
 *  {@link prepareGenerators} function and the point P1.
 * @param {string} api_id - The API id for the signature suite.
 * @returns {boolean} - True or False depending on whether the proof is valid.
 */
export async function ProofVerifyWithPseudonymOLD(PK, proof, L, pseudonym_bytes,
  verifier_id, header, ph, disclosed_messages, disclosed_indexes, api_id) {
  // 1. proof_len_floor = 2 * octet_point_length + 3 * octet_scalar_length
  // 2. if length(proof) < proof_len_floor, return INVALID
  // 3. U = floor((length(proof) - proof_len_floor) / octet_scalar_length)
  // 4. R = length(disclosed_indexes)
  // 5. L = U + R
  // proof: (Abar, Bbar, D, e^, r1^, r3^, (m^_j1, ..., m^_jU), challenge)
  //     Deserialization:
  // 1. proof_len_floor = 3 * octet_point_length + 4 * octet_scalar_length
  const proofLenFloor = 3 * POINT_LENGTH + 4 * SCALAR_LENGTH;
  // 2. if length(proof) < proof_len_floor, return INVALID
  if (proof.length < proofLenFloor) {
    if (GEN_TRACE_INFO) {
      console.log('from ProofVerifyWithPseudonym: proof is too short.');
    }
    return false;
  }
  // 3. U = floor((length(proof) - proof_len_floor) / octet_scalar_length)
  const U = Math.floor((proof.length - proofLenFloor) / SCALAR_LENGTH);
  // 4. total_no_messages = length(disclosed_indexes) + length(disclosed_committed_indexes) + U
  const totalNumMessages = disclosed_indexes.length + U - 1; //
  // 5. M = total_no_messages - L
  let M = totalNumMessages - L;
  if (M < 0) {
    M = 0;
  }
  let proof_result;
  try {
    proof_result = octets_to_proof(proof);
  } catch {
    // console.log('Problem with octets_to_proof');
    return false;
  }
  const { mHatU } = proof_result;
  const R = disclosed_indexes.length;
  // const U = mHatU.length;
  // const L = R + U;
  // console.log(`L = ${L}, R = ${R}, U = ${U}`);
  // Check disclosed indexes length same as disclosed messages length
  if (disclosed_messages.length !== R) {
    console.log('disclosed messages not the same as length of disclosed indexes');
    return false;
  }
  const pseudonym = bls.G1.ProjectivePoint.fromHex(pseudonym_bytes);
  //   1. message_scalars = messages_to_scalars(disclosed_messages, api_id)
  const msg_scalars = await messages_to_scalars(disclosed_messages, api_id);
  // 2. generators = create_generators(L + 1, PK, api_id)
  const gens = await prepareGenerators(L + 1, api_id);
  const blindGens = await prepareGenerators(M + 1, 'BLIND_' + api_id);
  const combinedGens = {
    P1: gens.P1,
    generators: [...gens.generators, ...blindGens.generators]
  };
  if (GEN_TRACE_INFO) {
    const info = {
      info: 'from ProofVerifyWithPseudonym',
      L, U, M,
    };
    console.log(JSON.stringify(info, null, 2));
  }
  // 3. result = CoreProofVerifyWithPseudonym(...)
  // 4. return result
  const result = await CoreProofVerifyWithPseudonym(PK, proof_result, pseudonym, verifier_id,
    combinedGens, header, ph, msg_scalars, disclosed_indexes, api_id);
  return result;
}

async function CoreProofVerifyWithPseudonymOLD(PK, proof_result, pseudonym, verifier_id,
  gens, header, ph, disclosed_messages, disclosed_indexes, api_id) {
  // 3. (Abar, Bbar, r2^, r3^, commitments, cp) = proof_result
  const { Abar, Bbar, D, eHat, r1Hat, r3Hat, mHatU, c } = proof_result;
  if (GEN_TRACE_INFO) {
    const info = {
      info: 'from CoreProofVerifyWithPseudonym',
      PK: bytesToHex(PK),
      Abar: bytesToHex(Abar.toRawBytes(true)),
      Bbar: bytesToHex(Bbar.toRawBytes(true)),
      eHat: numberToHex(eHat, SCALAR_LENGTH),
      r1Hat: numberToHex(r1Hat, SCALAR_LENGTH),
      r3Hat: numberToHex(r3Hat, SCALAR_LENGTH),
      mHatU: mHatU.map(mHat => numberToHex(mHat, SCALAR_LENGTH)),
      challenge: numberToHex(c, SCALAR_LENGTH)
    };
    console.log(JSON.stringify(info, null, 2));
  }
  // 4. W = octets_to_pubkey(PK)
  const W = bls.G2.ProjectivePoint.fromHex(PK);
  // 5. if W is INVALID, return INVALID
  // 6. R = length(disclosed_indexes)
  const R = disclosed_indexes.length;
  const U = mHatU.length;
  // 7. (i1, ..., iR) = disclosed_indexes
  // ABORT if: for i in disclosed_indexes, i < 1 or i > R + length(commitments) - 1
  // console.log('disclosed indexes:');
  // console.log(disclosed_indexes);
  for (const i of disclosed_indexes) {
    if (i < 0 || i > U + R - 1) {
      // console.log('Something weird with disclosed indexes');
      return false;
    }
  }
  const init_res = await ProofVerifyInit(PK, proof_result, gens, header,
    disclosed_messages, disclosed_indexes, api_id);
  // ProofVerifyInit(PK, proof_result, gens, header, disclosed_messages, disclosed_indexes, api_id)
  // 2.  OP = hash_to_curve_g1(verifier_id)
  const OP = await hash_to_curve_g1(verifier_id, api_id);
  // 3.  U = length(commitments)
  // 4.  pid^ = commitments[U] // last element of the commitments
  const pidHat = mHatU[mHatU.length - 1];
  // 5.  Uv = OP * pid^ - Pseudonym * cp
  let Uv = OP.multiply(pidHat);
  Uv = Uv.subtract(pseudonym.multiply(c));
  // 6.  pseudonym_init_res = (Pseudonym, OP, Uv)
  const pseudonym_init_res = [pseudonym, OP, Uv];
  const challenge = await ProofWithPseudonymChallengeCalculate(init_res,
    pseudonym_init_res, disclosed_indexes, disclosed_messages, ph, api_id);
  // console.log(`challenge: ${numberToHex(challenge, SCALAR_LENGTH)}`);
  if (c !== challenge) {
    console.log('challenge failed');
    return false;
  }
  // 9.  if e(Abar, W) * e(Bbar, -BP2) != Identity_GT, return INVALID
  // 10. return VALID
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

/**
 * Hidden pid Pseudonym BBS proof generation.
 *
 * @param {Uint8Array} PK - Public key as a compressed G2 point raw bytes.
 * @param {Uint8Array} signature - A previously computed signature.
 * @param {Uint8Array} pseudonym_bytes - Pseudonym computed with pid and verifier_id.
 * @param {Uint8Array} verifier_id - Verifier Identifier.
 * @param {Array} pid - The prover identifier.
 * @param {Uint8Array} header - Header used when signature was created.
 * @param {Uint8Array} ph - Presentation header, used during proof creation.
 * @param {Array} messages - A vector of octet strings (Uint8Array). If not
 * supplied, it defaults to the empty array. These should be all the messages
 * the signer used in the signature.
 * @param {Array} disclosed_indexes - Vector of unsigned integers in ascending
 * order. Indexes of disclosed messages that originated with the signer. If not
 * supplied, it defaults to an empty array.
 * @param {bigint} secret_prover_blind - A scalar value. If not used it should
 * set to 0n.
 * @param {bigint} signer_blind - A scalar value. If not used it should be set
 * to 0n.
 * @param {string} api_id - The API id for the signature suite.
 * @param {Function} rand_scalars - A function for generating cryptographically
 *  secure random or pseudo random scalars.
 * @returns {Array} proof -an octet string or will throw an exception.
 */
export async function HiddenPidProofGen(PK, signature, pseudonym_bytes, verifier_id,
  pid, header, ph, messages, disclosed_indexes, secret_prover_blind,
  signer_blind, api_id, rand_scalars = calculate_random_scalars) {

  const pseudonym = bls.G1.ProjectivePoint.fromHex(pseudonym_bytes);
  // single pid value takes place of committed messages
  // disclosed_commitment_indexes = [] since we never reveal pid
  const L = messages.length;
  if (disclosed_indexes.length > L) {
    throw TypeError('HiddenPidProofGen: to many disclosed indexes');
  }
  for (const index of disclosed_indexes) {
    if (index < 0 || index >= L) {
      throw TypeError('HiddenPidProofGen: disclosed index out of bounds');
    }
  }
  const M = 1; // the pid is our only committed message
  // From Blind BBS ProofGen
  // 1.  generators = BBS.create_generators(L + 1, api_id)
  const gens = await prepareGenerators(L + 1, api_id);
  // 2.  blind_generators = BBS.create_generators(M + 1, "BLIND_" || api_id)
  let blindGens = await prepareGenerators(M + 1, 'BLIND_' + api_id);
  let committed_message_scalars = [bls.fields.Fr.add(secret_prover_blind, signer_blind)];
  const signer_message_scalars = await messages_to_scalars(messages, api_id);
  const prover_message_scalars = await messages_to_scalars([pid], api_id);
  committed_message_scalars = committed_message_scalars.concat(prover_message_scalars);
  const message_scalars = signer_message_scalars.concat(committed_message_scalars);
  // Note order: signer message scalars, (secret_prover_blind + signer_blind), pid_scalar,
  const combinedGens = {
    P1: gens.P1,
    generators: [...gens.generators, ...blindGens.generators]
  };
  const proof = await CoreProofGenWithPseudonym(PK, signature, pseudonym, verifier_id,
    combinedGens, header, ph, message_scalars, disclosed_indexes, api_id, rand_scalars);
  return proof;
}
