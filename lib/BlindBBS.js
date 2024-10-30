/* Functions used in Blind BBS signature operations.
   API is subject to change!
*/
/*global TextEncoder, console*/
/* eslint-disable max-len */
import {bytesToHex, calculate_random_scalars, calculate_domain, concat, 
  hash_to_scalar, messages_to_scalars, numberToHex, os2ip, prepareGenerators,
  proofGen, proofVerify, serialize, signature_to_octets, verify}
  from './BBS.js';
import {bls12_381 as bls} from '@noble/curves/bls12-381';

const GEN_TRACE_INFO = true; // Set to true to send trace info to console.

const SCALAR_LENGTH = 32;
// const EXPAND_LEN = 48;
const POINT_LENGTH = 48;
const rPrimeOrder = bls.fields.Fr.ORDER; // prime order of the subgroups G1, G2

/**
 * This operation is used by the Prover to create commitment to a set of
 * messages (committed_messages), that they intend to include in the blind
 * signature.
 *  Note that this operation returns both the serialized combination of the
 *  commitment and its proof of correctness (commitment_with_proof), as well as
 *  the random scalar used to blind the commitment (secret_prover_blind).
 *
 * @param {Array} messages - A vector of octet strings, messages, to be
 * committed. If not supplied it defaults to the empty array.
 * @param {string} api_id - The API id for the signature suite.
 * @param {Function} rand_scalars - A function for generating cryptographically
 *  secure random or pseudo random scalars.
 * @returns {Array}  - comprising an octet string (Uint8Array) for the commitment with proof
 * and a the secret_prover_blind scalar in that order.
 */

export async function commit(messages, api_id,
  rand_scalars = calculate_random_scalars) {
  // 1. committed_message_scalars = BBS.messages_to_scalars(committed_messages, api_id)
  const msgScalars = await messages_to_scalars(messages, api_id);
  const M = messages.length;
  // 2. blind_generators = BBS.create_generators(length(committed_message_scalars) + 1, "BLIND_" || api_id)
  const gens = await prepareGenerators(M + 1, 'BLIND_' + api_id);
  const blind_generators = gens.generators.slice(0, M + 1);
  // 3. return CoreCommit(committed_message_scalars, blind_generators, api_id)
  return CoreCommit(blind_generators, msgScalars, api_id, rand_scalars);
}

/**
 * 
 * @param {Array} blind_generators - An array of blind generators including Q2.
 * @param {Array} committed_msg_scalars - An array of message scalars for the committed messages.
 * @param {string} api_id - The API id for the signature suite.
 * @param {Function} rand_scalars - A function for generating cryptographically
 * secure random or pseudo random scalars.
 * @returns {Array}  - comprising an octet string (Uint8Array) for the commitment with proof
 * and a the secret_prover_blind scalar in that order.
 */
export async function CoreCommit(blind_generators, committed_msg_scalars, api_id, rand_scalars) {
  // Deserialization:
  // 1. M = length(committed_messages)
  const M = committed_msg_scalars.length;
  // 2. if length(blind_generators) != M + 1, return INVALID
  if (blind_generators.length !== M + 1) {
    throw new TypeError('Wrong size blind_generator array');
  }
  // 3. (Q_2, J_1, ..., J_M) = blind_generators[1..M+1]
  const [Q_2, ...J] = blind_generators;
  // Procedure:
  // 1. (secret_prover_blind, s~, m~_1, ..., m~_M) = BBS.get_random_scalars(M + 2)
  const [secret_prover_blind, s_tilde, ...m_tildes] = await rand_scalars(M + 2);
  // 2. C = Q_2 * secret_prover_blind + J_1 * msg_1 + ... + J_M * msg_M
  let C = Q_2.multiply(secret_prover_blind);
  for(let i = 0; i < committed_msg_scalars.length; i++) {
    C = C.add(J[i].multiply(committed_msg_scalars[i]));
  }
  // 3. Cbar = Q_2 * s~ + J_1 * m~_1 + ... + J_M * m~_M
  let Cbar = Q_2.multiply(s_tilde);
  for(let i = 0; i < committed_msg_scalars.length; i++) {
    Cbar = Cbar.add(J[i].multiply(m_tildes[i]));
  }
  // 4. challenge = calculate_blind_challenge(C, Cbar, blind_generators, api_id)
  const challenge = await calculate_blind_challenge(C, Cbar, blind_generators,
    api_id);
  // 5. s^ = s~ + secret_prover_blind * challenge
  const s_hat = bls.fields.Fr.add(s_tilde,
    bls.fields.Fr.mul(secret_prover_blind, challenge));
  // 6. for m in (1, 2, ..., M): m^_i = m~_1 + msg_i * challenge
  const mHat = [];
  for(let i = 0; i < M; i++) {
    const mHati = bls.fields.Fr.add(m_tildes[i],
      bls.fields.Fr.mul(committed_msg_scalars[i], challenge));
    mHat.push(mHati);
  }
  // 7. proof = (s^, (m^_1, ..., m^_M), challenge)
  const proof = [s_hat, ...mHat, challenge];
  // 8. commit_with_proof = commitment_with_proof_to_octets(C, proof)
  const commit_with_proof_octs = commitment_with_proof_to_octets(C, proof);
  // 9. return (commit_with_proof, secret_prover_blind)
  if(GEN_TRACE_INFO) {
    const info = {
      info: 'from Blind BBS CoreCommit',
      M,
      secret_prover_blind: numberToHex(secret_prover_blind, SCALAR_LENGTH),
      s_tilde: numberToHex(s_tilde, SCALAR_LENGTH),
      m_tildes: m_tildes.map(m => numberToHex(m, SCALAR_LENGTH)),
      C: bytesToHex(C.toRawBytes(true)),
      Cbar: bytesToHex(Cbar.toRawBytes(true))
    };
    console.log(JSON.stringify(info, null, 2));
  }
  return [commit_with_proof_octs, secret_prover_blind];
}

async function calculate_blind_challenge(C, Cbar, generators, api_id) {
  // Deserialization:
  // 1. if length(generators) == 0, return INVALID
  if(generators.length == 0) {
    throw new TypeError('Wrong size blind_generator array');
  }
  // 2. M = length(generators) - 1
  const M = generators.length - 1;
  // Procedure:
  // 1. c_arr = (M)
  // 2. c_arr.append(generators)
  // 3. c_octs = serialize(c_arr.append(C, Cbar))
  // 4. return BBS.hash_to_scalar(c_octs, blind_challenge_dst)
  const dst = new TextEncoder().encode(api_id + 'H2S_');
  const c_array = [
    {type: 'NonNegInt', value: M},
  ];
  for(const g of generators) {
    c_array.push({type: 'GPoint', value: g});
  }
  c_array.push({type: 'GPoint', value: C});
  c_array.push({type: 'GPoint', value: Cbar});
  const c_for_hash = serialize(c_array);
  const c = await hash_to_scalar(c_for_hash, dst, api_id);
  return c;
}

function commitment_with_proof_to_octets(commitment, proof) {
  let c_array = [
    {type: 'GPoint', value: commitment}
  ];
  const commitment_octs = serialize(c_array);
  c_array = [];
  for(const scalar of proof) {
    c_array.push({type: 'Scalar', value: scalar})
  }
  const proof_octs = serialize(c_array);
  return concat(commitment_octs, proof_octs);
}

async function CoreCommitVerify(commitment, commitment_proof, blind_generators, api_id) {
  // Deserialization:
  // 1. (s^, commitments, cp) = commitment_proof
  const [s_hat, commitments, cp] = commitment_proof;
  // 2. M = length(commitments)
  const M = commitments.length;
  // 3. (m^_1, ..., m^_M) = commitments
  const m_hats = commitments;
  // 4. if length(blind_generators) != M + 1, return INVALID
  if(blind_generators.length !== M + 1) {
    throw new TypeError('Wrong size blind_generator array');
  }
  // 5. (Q_2, J_1, ..., J_M) = blind_generators
  const [Q_2, ...Js] = blind_generators;
  // Procedure:
  // 1. Cbar = Q_2 * s^ + J_1 * m^_1 + ... + J_M * m^_M + commitment * (-cp)

  let Cbar = Q_2.multiply(s_hat);
  for(let i = 0; i < Js.length; i++) {
    Cbar = Cbar.add(Js[i].multiply(m_hats[i]));
  }
  Cbar = Cbar.add(commitment.multiply(bls.fields.Fr.neg(cp)));
  // 2. cv = calculate_blind_challenge(commitment, Cbar, blind_generators, api_id)
  const cv = await calculate_blind_challenge(commitment, Cbar, blind_generators, api_id);
  // 3. if cv != cp, return INVALID
  // 4. return VALID
  if(GEN_TRACE_INFO) {
    const info = {
      info: 'from Blind BBS verify commitment',
      M,
      s_hat: numberToHex(s_hat, SCALAR_LENGTH),
      m_hats: m_hats.map(m_hat => numberToHex(m_hat, SCALAR_LENGTH)),
      cp: numberToHex(cp, SCALAR_LENGTH),
      cv: numberToHex(cv, SCALAR_LENGTH),
      comparisonCheck: `cv == cp ${cv == cp}`,
      sizeCheck: `cp > order: ${rPrimeOrder < cp}`,
      C: bytesToHex(commitment.toRawBytes(true)),
      Cbar: bytesToHex(Cbar.toRawBytes(true))
    };
    console.log(JSON.stringify(info, null, 2));
  }
  return (cv == cp);
}

/**
 * Deserializes and validates a commitment with proof octet array.
 *
 * @param {Uint8Array} commitment_with_proof - Commitment with proof encoded in
 * a octet array.
 * @param {object} blindGens - A (blind) BBS generator object.
 * @param {string} api_id - The API id for the signature suite.
 * @returns {Array} [commit, blind_gen_no], a tuple comprising a commitment, and the
 * number of commitment generators used. Or throws an Exception.
 */
export async function deserialize_and_validate_commit(commitment_with_proof,
  blindGens, api_id) {
  // 1. if commitment_with_proof is the empty string (""), return Identity_G1
  if(!commitment_with_proof) {
    return bls.G1.ProjectivePoint.ZERO;
  }
  if(commitment_with_proof.length == 0) {
    return bls.G1.ProjectivePoint.ZERO;
  }

  // 2. com_res = octets_to_commitment_with_proof(commitment_with_proof)
  // 3.  if com_res is INVALID, return INVALID
  const com_res = octets_to_commitment_with_proof(commitment_with_proof);
  // 4.  (commit, commit_proof) = com_res
  const [commit, ...commit_proof] = com_res;
  // 5. if length(commit_proof[1]) + 1 != length(blind_generators), return INVALID
  const M = commit_proof[1].length;
  if(blindGens.generators.length < M + 1) {
    throw new TypeError('not enough generators');
  }
  // 6. validation_res = CoreCommitVerify(commit, commit_proof, blind_generators, api_id)
  // 7. if validation_res is INVALID, return INVALID
  // 8. commitment
  const blind_generators = blindGens.generators.slice(0, M + 1);
  const res = await CoreCommitVerify(commit, commit_proof, blind_generators, api_id);
  if(!res) {
    throw new TypeError('Commitment did not validate!');
  }
  return commit;
}

function octets_to_commitment_with_proof(commitment_octs) {
  // 1.  commit_len_floor = octet_point_length + 2 * octet_scalar_length
  const commit_len_floor = POINT_LENGTH + 2 * SCALAR_LENGTH;
  // 2.  if length(commitment) < commit_len_floor, return INVALID ==> should be commitment_octs not commitment
  if(commitment_octs.length < commit_len_floor) {
    throw new TypeError('commitment octets too short');
  }
  // 3.  C_octets = commitment_octs[0..(octet_point_length - 1)]
  const C_octets = commitment_octs.slice(0, POINT_LENGTH);
  // console.log(`C_octets length = ${C_octets.length}`);
  // 4.  C = octets_to_point_g1(C_octets)
  const C = bls.G1.ProjectivePoint.fromHex(C_octets);
  // TODO: Perform these checks...`
  // 5.  if C is INVALID, return INVALID
  // 6.  if C == Identity_G1, return INVALID
  // 7.  j = 0
  let j = 0;
  const scalars = [];
  // 8.  index = octet_point_length
  let index = POINT_LENGTH;
  // 9.  while index < length(commitment_octs):
  while(index < commitment_octs.length) {
  // 10.     end_index = index + octet_scalar_length - 1
    const end_index = index + SCALAR_LENGTH;
    // 11.     s_j = OS2IP(proof_octets[index..end_index]) ==> should be commitment_octets not proof_octets
    const s_j = os2ip(commitment_octs.slice(index, end_index));
    scalars.push(s_j);
    // 12.     if s_j = 0 or if s_j >= r, return INVALID
    if((s_j == 0) || (s_j >= bls.fields.Fr.ORDER)) {
      throw new TypeError('Invalid commitment proof scalars');
    }
    // 13.     index += octet_scalar_length
    index += SCALAR_LENGTH;
    // 14.     j += 1
    j++;
  }
  // 15. if index != length(commitment_octs), return INVALID
  if(index !== commitment_octs.length) {
    throw new TypeError('Invalid commitment proof length');
  }
  // 16. if j < 2, return INVALID
  if(j < 2) {
    throw new TypeError('Too few scalars in commitment_octs');
  }
  // Note form of commitment proof: [s_hat, ...mHat, challenge]
  // 17. msg_commitment = ()
  // 18. if j >= 3, set msg_commitment = (s_2, ..., s_(j-1))
  // 19. return (C, (s_0, msg_commitments, s_j))
  if(j === 2) { // [C, s_hat, ...mHat, challenge]
    return [C, scalars[0], [], scalars[1]];
  } else { // [C, s_hat, mHat array, challenge]
    return [C, scalars[0], scalars.slice(1, -1), scalars[scalars.length - 1]];
  }
}

/**
 * Blind signs a commitment after verification and optionally signs an
 * additional list of messages.
 *
 * @param {bigint} SK - A scalar secret key.
 * @param {Uint8Array} PK -  Public key as a compressed G2 point raw bytes.
 * @param {Uint8Array} commitment_with_proof - An octet array of the commitment
 * with proof.
 * @param {Uint8Array} header - Header as a byte array.
 * @param {Array} messages - An array of Uint8Arrays that represent the
 * messages.

 * @param {string} api_id - The API id for the signature suite.
 * @returns {Uint8Array} - The signature.
 */
export async function BlindSign(SK, PK, commitment_with_proof, header, messages,
  api_id) {
  /* Refactored without signer blind:

  Deserialization: essentially the same
  */
  // Deserialization:
  // 1. L = length(messages)
  const L = messages.length;
  // calculate the number of blind generators used by the commitment,
  // if any.
  // 2. M = length(commitment_with_proof)
  // 3. if M != 0, M = M - octet_point_length - octet_scalar_length
  // 4. M = M / octet_scalar_length
  // 5. if M < 0, return INVALID
  const M = calcM(commitment_with_proof);
  // Procedure:
  // 1. generators = BBS.create_generators(L + 1, api_id)
  // 2. blind_generators = BBS.create_generators(M + 1, "BLIND_" || api_id)
  const gens = await prepareGenerators(L + 1, api_id);
  console.log(`BlindSign M = ${M}`);
  const blindGens = await prepareGenerators(M + 1, 'BLIND_' + api_id);
  // 3.  commit = deserialize_and_validate_commit(commitment_with_proof, blind_generators, api_id)
  // 4.  if commit is INVALID, return INVALID
  const commit = await deserialize_and_validate_commit(commitment_with_proof, blindGens, api_id);
  // 5.  (msg_1, ..., msg_L) = BBS.messages_to_scalars(messages, api_id)
  const message_scalars = await messages_to_scalars(messages, api_id);
  // 6.  res = B_calculate(generators, commit, messages)
  // 7.  if res is INVALID, return INVALID
  // 8.  (B) = res
  const B = await B_calculate(gens, commit, message_scalars);
  // 9.  blind_sig = FinalizeBlindSign(SK, PK, B, generators, blind_generators, header, api_id)
  const blind_sig = await FinalizeBlindSign(SK, PK, B, gens.generators, blindGens.generators, 
    header, api_id);
  // 10. if blind_sig is INVALID, return INVALID
  // 11. return blind_sig
  return blind_sig;
}

function B_calculate(gens, commitment, message_scalars) {
  // Deserialization:
  // 1. L = length(messages)
  const L = message_scalars.length;
  // 2. if length(generators) != L + 1, return INVALID
  if(gens.generators.length != L + 1) {
    throw new TypeError('wrong number of generators');
  }
  // 3. (Q_1, H_1, ..., H_L) = generators
  const [Q_1, ...H] = gens.generators;
  // 4. (msg_1, ..., msg_L) = messages
  // Procedure:
  // 1. B = P1 + H_1 * msg_1 + ... + H_L * msg_L + commitment
  // We'll bring in Q_1 * domain in FinalizeBlindSign
  // **TODO**: RESOLVE INCONSISTENCY IN B COMPUTATION COMPARED TO PREVIOUS SPEC
  // **OLD** 5. B = P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L + commit
  // **OLD** let B = gens.P1;
  // **OLD** B = B.add(Q_1.multiply(domain));
  let B = gens.P1;
  for(let i = 0; i < message_scalars.length; i++) {
    B = B.add(H[i].multiply(message_scalars[i]));
  }
  B = B.add(commitment);
  // 2. if B is Identity_G1, return INVALID
  if(B.equals(bls.G1.ProjectivePoint.ZERO)) {
    new Error('B equals Identity_G1, Invalid!');
  }
  // 3. return B
  return B;
}

export async function FinalizeBlindSign(SK, PK, B, generators, blind_generators, header, api_id) {
  // Deserialization:
  // 1. L = length(generators) - 1
  const L = generators.length - 1;
  // 2. M = length(blind_generators) - 1 **MY FIX**
  const M = blind_generators.length - 1;
  // 3. if L <= 0 or M <=0, return INVALID **TO STRICT?**
  // **TODO** implement above check once we resolve issue.
  // 4. (Q_1, H_1, ..., H_L) = generators
  const [Q_1, ...H] = generators;
  // 5. (Q_2, J_1, ..., J_M) = blind_generators **MY FIX**
  const [Q_2, ...J] = blind_generators;

  // Procedure:
  // 1. domain = calculate_domain(PK, Q_1, (H_1, ..., H_L, Q_2, J_1, ..., J_M), header, api_id)
  const domain = await calculate_domain(PK, Q_1, [...H, Q_2, ...J], header, api_id);
  // **UPDATE B**
  B = B.add(Q_1.multiply(domain));
  // 2. e_octs = serialize((SK, B)) **MY UPDATE**
  const valArray = [
    {type: 'Scalar', value: SK},
    {type: 'GPoint', value: B}
  ];
  const e_serial_octs = serialize(valArray);
  // 3. e = BBS.hash_to_scalar(e_octs, signature_dst)
  const sig_dst = new TextEncoder().encode(api_id + 'H2S_');
  const e = await hash_to_scalar(e_serial_octs, sig_dst, api_id);
  // 4. A = B * (1 / (SK + e))
  // For this we need to work in Fr which noble-BLS12-381 provides
  const denom = bls.fields.Fr.add(bls.fields.Fr.create(SK), bls.fields.Fr.create(e));
  const num = bls.fields.Fr.inv(denom);
  const A = B.multiply(num);
  const sig = signature_to_octets(A, e);
  if(GEN_TRACE_INFO) {
    const info = {
      info: 'from FinalizeBlindSign',
      L: L,
      M: M,
      domain: numberToHex(domain, SCALAR_LENGTH),
      B: bytesToHex(B.toRawBytes(true)),
      A: bytesToHex(A.toRawBytes(true)),
      e: numberToHex(e, SCALAR_LENGTH),
      sig: bytesToHex(sig)
    };
    console.log(JSON.stringify(info, null, 2));
  }
  // 5. return signature_to_octets((A, e))
  return sig;
}

/**
 * Helper function to get the number of committed messages in a commitment with
 * proof
 *
 * @param {Uint8Array} commitment_with_proof - The raw bytes for this value.
 * @returns {number} - The number of blind generators used by the commitment, if any.
 */
export function calcM(commitment_with_proof) {
  //  Note: commitment is a G1 point and proof = [s_hat, ...mHat, challenge];
  //  So M = (length(commitment_with_proof) - point_length - 2*scalar_length)/scalar_length
  if(!commitment_with_proof) {
    return 0;
  }
  if(commitment_with_proof.length == 0) {
    return 0;
  }
  let M = commitment_with_proof.length - POINT_LENGTH - 2 * SCALAR_LENGTH;
  if(M < 0) {
    throw new Error('M < 0, Invalid commitment with proof');
  }
  return M / SCALAR_LENGTH;
}

/**
 *
 * @param {Uint8Array} PK - Public key as a compressed G2 point raw bytes.
 * @param {Uint8Array} signature - A previously computed signature.
 * @param {Uint8Array} header - Header used when signature was created.
 * @param {Array} messages - Array of byte arrays (Uint8Array) of signer
 * messages.
 * @param {Array} committed_messages - Array of byte arrays (Uint8Array) of
 * prover committed messages.
 * @param {BigInt} secret_prover_blind - For committed messages or 0n if not
 * used.
 * @param {string} api_id - The API id for the signature suite.
 * @returns {boolean} - True or False depending on whether the signature
 *  is valid.
 */
export async function BlindVerify(PK, signature, header, messages, committed_messages,
  secret_prover_blind, api_id) {
  // Procedure:
  // 1. message_scalars = BBS.messages_to_scalars(messages, api_id)
  const message_scalars = await messages_to_scalars(messages, api_id);
  // 2. committed_message_scalars = ()
  let committed_message_scalars = [];
  // 4. committed_message_scalars.append(secret_prover_blind) bls.fields.Fr.create(e)
  committed_message_scalars.push(bls.fields.Fr.create(secret_prover_blind));
  // 5. committed_message_scalars.append(BBS.messages_to_scalars(committed_messages, api_id))
  const tempScalars = await messages_to_scalars(committed_messages, api_id);
  committed_message_scalars = committed_message_scalars.concat(tempScalars);
  // 6. generators = BBS.create_generators(length(message_scalars) + 1, api_id)
  const L = messages.length;
  const gens = await prepareGenerators(L + 1, api_id);
  // 7. blind_generators = BBS.create_generators(length(committed_message_scalars), "BLIND_" || api_id)
  const M = committed_messages.length;
  const blindGens = await prepareGenerators(M + 1, 'BLIND_' + api_id);
  // 8. res = BBS.CoreVerify(PK, signature, generators.append(blind_generators), header, 
  //            message_scalars.append(committed_message_scalars), api_id)
  const allScalars = [...message_scalars, ...committed_message_scalars];
  const combinedGens = {
    P1: gens.P1,
    generators: [...gens.generators, ...blindGens.generators]
  };
  const res = await verify(PK, signature, header, allScalars, combinedGens, api_id);
  if(GEN_TRACE_INFO) {
    const info = {
      info: 'from BlindBBS BlindVerify',
      L, M,
      secret_prover_blind: numberToHex(secret_prover_blind, SCALAR_LENGTH)
    };
    console.log(JSON.stringify(info, null, 2));
  }
  // 9. return res
  return res;
}

/**
 * Blind BBS proof generation.
 *
 * @param {Uint8Array} PK - Public key as a compressed G2 point raw bytes.
 * @param {Uint8Array} signature - A previously computed signature.
 * @param {Uint8Array} header - Header used when signature was created.
 * @param {Uint8Array} ph - Presentation header, used during proof creation.
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
 * @param {bigint} secret_prover_blind - A scalar value. If not used it should
 * set to 0n.
 * @param {string} api_id - The API id for the signature suite.
 * @param {Function} rand_scalars - A function for generating cryptographically
 *  secure random or pseudo random scalars.
 * @returns {Array} {Array} proof - an octet string or will throw an exception.
 */
export async function BlindProofGen(PK, signature, header, ph, messages,
  committed_messages, disclosed_indexes, disclosed_commitment_indexes,
  secret_prover_blind, api_id,
  rand_scalars = calculate_random_scalars) {

  // 1. L = length(messages)
  const L = messages.length;
  // 2. M = length(committed_messages)
  const M = committed_messages.length;
  // 3. if length(disclosed_indexes) > L, return INVALID
  if(disclosed_indexes.length > L) {
    throw TypeError('BlindProofGen: to many disclosed indexes');
  }
  // 4. for i in disclosed_indexes, if i < 0 or i >= L, return INVALID
  for(const index of disclosed_indexes) {
    if(index < 0 || index >= L) {
      throw TypeError('BlindProofGen: disclosed index out of bounds');
    }
  }
  // 5. if length(disclosed_commitment_indexes) > M, return INVALID
  if(disclosed_commitment_indexes.length > M) {
    throw TypeError('BlindProofGen: to many disclosed commitment indexes');
  }
  // 6. for j in disclosed_commitment_indexes, if i < 0 or i >= L, return INVALID
  for(const index of disclosed_commitment_indexes) {
    if(index < 0 || index >= M) {
      throw TypeError('BlindProofGen: disclosed commitment index out of bounds');
    }
  }
  const gens = await prepareGenerators(L + 1, api_id);
  let blindGens = await prepareGenerators(M + 1, 'BLIND_' + api_id);
  const combinedGens = {
    P1: gens.P1,
    generators: [...gens.generators, ...blindGens.generators]
  };
  
  let committed_message_scalars = [];
  committed_message_scalars.push(bls.fields.Fr.create(secret_prover_blind));
  const prover_message_scalars = await messages_to_scalars(committed_messages, api_id);
  committed_message_scalars = committed_message_scalars.concat(prover_message_scalars);
  
  const signer_message_scalars = await messages_to_scalars(messages, api_id);
  const message_scalars = signer_message_scalars.concat(committed_message_scalars);

  const combined_disclosed_idxs = get_combined_idxs(L, disclosed_indexes,
    disclosed_commitment_indexes);

  const proof = await proofGen(PK, signature, header, ph, message_scalars,
    combined_disclosed_idxs, combinedGens, api_id, rand_scalars);
  return proof;
}

export function get_combined_idxs(L, disclosed_indexes, disclosed_commitment_indexes) {
  const combined_idxs = [];
  for(const i of disclosed_indexes) {
    combined_idxs.push(i);
  }
  for(const j of disclosed_commitment_indexes) {
    combined_idxs.push(L + j + 1);
  }
  return combined_idxs;
}

/**
 *
 * @param {Uint8Array} PK - Public key as a compressed G2 point raw bytes.
 * @param {Uint8Array} proof = A previously computed proof.
 * @param {Uint8Array} header - Header used when signature was created.
 * @param {Uint8Array} ph - Presentation header, used during proof creation.
 * @param {Integer} L - Total number of signer messages
 * @param {Array} disclosed_messages = Array of byte arrays (Uint8Array) of
 * disclosed signer messages.
 * @param {Array} disclosed_committed_messages - Array of byte arrays
 * (Uint8Array) of disclosed prover committed messages.
 * @param {Array} disclosed_indexes - indexes of disclosed signer messages.
 * @param {Array} disclosed_committed_indexes - indexes of disclosed prover
 * messages.
 * @param {string} api_id - The API identifier.
 */
export async function BlindProofVerify(PK, proof, header, ph, L,
  disclosed_messages, disclosed_committed_messages, disclosed_indexes,
  disclosed_committed_indexes, api_id) {
  // proof: (Abar, Bbar, D, e^, r1^, r3^, (m^_j1, ..., m^_jU), challenge)
  //     Deserialization:
  // 1. proof_len_floor = 3 * octet_point_length + 4 * octet_scalar_length
  const proofLenFloor = 3 * POINT_LENGTH + 4 * SCALAR_LENGTH;
  // 2. if length(proof) < proof_len_floor, return INVALID
  if(proof.length < proofLenFloor) {
    if(GEN_TRACE_INFO) {
      console.log('from BlindProofVerify: proof is too short.');
    }
    return false;
  }
  // 3. U = floor((length(proof) - proof_len_floor) / octet_scalar_length)
  const U = Math.floor((proof.length - proofLenFloor) / SCALAR_LENGTH);
  // 4. total_no_messages = length(disclosed_indexes) + length(disclosed_committed_indexes) + U
  const totalNumMessages = disclosed_indexes.length +
    disclosed_committed_indexes.length + U - 1;
  // 5. M = total_no_messages - L
  const M = totalNumMessages - L;
  // 1. generators = BBS.create_generators(L + 1, api_id)
  // 2. blind_generators = BBS.create_generators(M + 1, "BLIND_" || api_id)
  const gens = await prepareGenerators(L + 1, api_id);
  let blindGens;
  if(M === -1) { // No commitments are used!
    blindGens = {generators: []};
  } else {
    blindGens = await prepareGenerators(M + 1, 'BLIND_' + api_id);
  }
  const combinedGens = {
    P1: gens.P1,
    generators: [...gens.generators, ...blindGens.generators]
  };
  // 3. message_scalars = messages_to_scalars(disclosed_messages, api_id)
  const message_scalars = await messages_to_scalars(disclosed_messages, api_id);
  // 4. committed_message_scalars =  messages_to_scalars(disclosed_committed_messages, api_id)
  const committed_message_scalars = await messages_to_scalars(disclosed_committed_messages, api_id);
  const combined_scalars = message_scalars.concat(committed_message_scalars);
  const combined_idxs = get_combined_idxs(L, disclosed_indexes, disclosed_committed_indexes);
  const result = await proofVerify(PK, proof, header, ph, combined_scalars, combined_idxs, combinedGens, api_id);
  // 8. result = CoreProofVerify(PK, proof, generators, header, ph,
  //                              disclosed_msgs, disclosed_idxs, api_id)
  // 9. return result

  if(GEN_TRACE_INFO) {
    const info = {
      info: 'from BlindBBS BlindProofVerify',
      proofLength: proof.length,
      U, totalNumMessages, L, M
    };
    console.log(JSON.stringify(info, null, 2));
  }
  return result;
}

