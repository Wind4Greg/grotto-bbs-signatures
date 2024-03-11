/* Functions used in Blind BBS signature operations */
/*global TextEncoder, console*/
/* eslint-disable max-len */
import {bytesToHex, calculate_random_scalars, concat, hash_to_scalar, messages_to_scalars,
  os2ip, prepareGenerators, serialize, signature_to_octets, verify}
  from './BBS.js';
import {bls12_381 as bls} from '@noble/curves/bls12-381';
import {expand_message_xmd} from '@noble/curves/abstract/hash-to-curve';
import {randomBytes} from './randomBytes.js';
import {sha256} from '@noble/hashes/sha256';
import {shake256} from '@noble/hashes/sha3';

const SCALAR_LENGTH = 32;
const EXPAND_LEN = 48;
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
 * @returns {Array}  - A vector, blind_result, comprising from an octet string
 * and a random scalar in that order.
 */
export async function commit(messages, api_id,
  rand_scalars = calculate_random_scalars) {
  // 1.  M = length(committed_messages)
  const M = messages.length;
  // 2.  generators = BBS.create_generators(M + 2, api_id)
  const gens = await prepareGenerators(M + 2, api_id);
  // 3.  (Q_2, J_1, ..., J_M) = generators[1..M+1]
  const [Q_2, ...J] = gens.generators.slice(1, M + 2);
  // 4.  (msg_1, ..., msg_M) = messages_to_scalars(committed_messages, api_id)
  const msgScalars = await messages_to_scalars(messages, api_id);
  // 5.  (secret_prover_blind, s~, m~_1, ..., m~_M) = get_random_scalars(M + 2)
  // console.log(`M = ${M}`);
  const [secret_prover_blind, s_tilde, ...m_tildes] = await rand_scalars(M + 2);
  // 6.  C = Q_2 * secret_prover_blind + J_1 * msg_1 + ... + J_M * msg_M
  let C = Q_2.multiply(secret_prover_blind);
  for(let i = 0; i < msgScalars.length; i++) {
    C = C.add(J[i].multiply(msgScalars[i]));
  }
  // 7.  Cbar = Q_2 * s~ + J_1 * m~_1 + ... + J_M * m~_M
  let Cbar = Q_2.multiply(s_tilde);
  for(let i = 0; i < msgScalars.length; i++) {
    Cbar = Cbar.add(J[i].multiply(m_tildes[i]));
  }
  // 8.  challenge = calculate_blind_challenge(C, Cbar, generators, api_id)
  const challenge = await calculate_blind_challenge(C, Cbar,
    gens.generators.slice(1, M + 2), api_id);
  // 9.  s^ = s~ + secret_prover_blind * challenge
  // const eHat = bls.fields.Fr.add(eTilde, bls.fields.Fr.mul(e, c));
  const s_hat = bls.fields.Fr.add(s_tilde,
    bls.fields.Fr.mul(secret_prover_blind, challenge));
  // 10. for m in (1, 2, ..., M): m^_i = m~_1 + msg_i * challenge
  const mHat = [];
  for(let i = 0; i < M; i++) {
    const mHati = bls.fields.Fr.add(m_tildes[i],
      bls.fields.Fr.mul(msgScalars[i], challenge));
    mHat.push(mHati);
  }
  // 11. proof = (s^, (m^_1, ..., m^_M), challenge)
  const proof = [s_hat, ...mHat, challenge];
  // 12. commit_with_proof_octs = commitment_with_proof_to_octets(C, proof)
  const commit_with_proof_octs = commitment_with_proof_to_octets(C, proof);
  // 13. return (commit_with_proof_octs, secret_prover_blind)
  return [commit_with_proof_octs, secret_prover_blind];
}

async function calculate_blind_challenge(C, Cbar, generators, api_id) {
  const dst = new TextEncoder().encode(api_id + 'H2S_');
  const M = generators.length - 1;
  const c_array = [
    {type: 'GPoint', value: C},
    {type: 'GPoint', value: Cbar},
    {type: 'NonNegInt', value: M},
  ];
  for(const g of generators) {
    c_array.push({type: 'GPoint', value: g});
  }
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

async function verify_commitment(commitment, commitment_proof, blind_generators, api_id) {
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
  Cbar = Cbar.add(commitment.multiply(-cp));
  // 2. cv = calculate_blind_challenge(commitment, Cbar, blind_generators, api_id)
  const cv = await calculate_blind_challenge(commitment, Cbar, blind_generators, api_id);
  // 3. if cv != cp, return INVALID
  // 4. return VALID
  return (cv !== cp);
}

/**
 * Deserializes and validates a commitment with proof octet array.
 *
 * @param {Uint8Array} commitment_with_proof - Commitment with proof encoded in
 * a octet array.
 * @param {object} gens - A (blind) BBS generator object.
 * @param {string} api_id - The API id for the signature suite.
 * @returns {Array} [commit, blind_gen_no], a tuple comprising a commitment, and the
 * number of commitment generators used. Or throws an Exception.
 */
export async function deserialize_and_validate_commit(commitment_with_proof, gens, api_id) {
  // 1.  if commitment_with_proof is the empty string (""), return (Identity_G1, 0)
  if(commitment_with_proof.length == 0) {
    return [bls.G1.ProjectivePoint.ZERO.toAffine(), 0];
  }
  // 2.  com_res = octets_to_commitment_with_proof(commitment_with_proof)
  // 3.  if com_res is INVALID, return INVALID
  const com_res = octets_to_commitment_with_proof(commitment_with_proof);
  // 4.  (commit, commit_proof) = com_res
  const [commit, ...commit_proof] = com_res;
  // console.log('Commit and commit proof:');
  // console.log(commit, commit_proof);
  // 5.  M = length(commit_proof[1]) + 1
  const M = commit_proof[1].length + 1;
  // 6.  if length(generators) < M + 1, return INVALID
  if(gens.generators.length < M + 1) {
    throw new TypeError('not enough generators');
  }
  // 7.  blind_generators = generators[1..M + 1]
  const blind_generators = gens.generators.slice(2, -1);
  // 8.  validation_res = verify_commitment(commit, commit_proof, blind_generators, api_id)
  const res = verify_commitment(commit, blind_generators, commit_proof, blind_generators, api_id);
  // 9.  if validation_res is INVALID, return INVALID
  if(!res) {
    throw new TypeError('Commitment did not validate!');
  }
  // 10. (commitment, M)
  return [commit, M];
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
  if(j === 2) {
    return [C, scalars[0], [], scalars[1]];
  } else {
    return [C, scalars.slice(0), scalars.slice(1, -1), scalars.slice(-1)];
  }
}

/*
blind_signature = BlindSign(SK, PK, commitment_with_proof, header, messages, signer_blind)

Inputs:

- SK (REQUIRED), a secret key in the form outputted by the KeyGen
                 operation.
- PK (REQUIRED), an octet string of the form outputted by SkToPk
                 provided the above SK as input.
- commitment_with_proof (OPTIONAL), an octet string, representing a
                                    serialized commitment and
                                    commitment_proof, as the first
                                    element outputted by the Commit
                                    operation. If not supplied, it
                                    defaults to the empty string ("").
- header (OPTIONAL), an octet string containing context and application
                     specific information. If not supplied, it defaults
                     to an empty string ("").
- messages (OPTIONAL), a vector of octet strings. If not supplied, it
                       defaults to the empty array ("()").
- signer_blind (OPTIONAL), a random scalar value. If not supplied it
                           defaults to zero ("0").

Parameters:

- api_id, the octet string ciphersuite_id || "BLIND_H2G_HM2S_", where
          ciphersuite_id is defined by the ciphersuite and
          "BLIND_H2G_HM2S_"is an ASCII string composed of 15 bytes.
- (octet_point_length, octet_scalar_length), defined by the ciphersuite.

*/
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
 * @param {bigint} signer_blind - An optional signer blind, set to 0n if not
 * used.
 * @param {string} api_id - The API id for the signature suite.
 * @returns {Uint8Array} - The signature.
 */
export async function BlindSign(SK, PK, commitment_with_proof, header, messages,
  signer_blind, api_id) {
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
  // 1. generators = BBS.create_generators(M + L + 1, api_id)
  const gens = await prepareGenerators(M + L + 1, api_id);
  // console.log('Generators:');
  // console.log(gens);
  // 2. message_scalars = BBS.messages_to_scalars(messages, api_id)
  const message_scalars = await messages_to_scalars(messages, api_id);
  // 3. blind_sig = CoreBlindSign(SK, PK, commitment_with_proof, generators, header, messages, signer_blind,
  //     api_id)
  const blind_sig = await CoreBlindSign(SK, PK, commitment_with_proof,
    gens, header, message_scalars, signer_blind, api_id);
  // 4. if blind_sig is INVALID, return INVALID
  // 5. return blind_sig
  return blind_sig;
}

async function CoreBlindSign(SK, PK, commitment_with_proof, gens, header,
  message_scalars, signer_blind, api_id) {

  // Deserialization:
  // 1. L = length(messages)
  // 2. (msg_1, ..., msg_L) = messages
  const L = message_scalars.length;
  // 3. commit_res = deserialize_and_validate_commit(commitment_with_proof, generators, api_id)
  // 4. if commit_res is INVALID, return INVALID
  // // if commitment_with_proof == "", then commit_res = (Identity_G1, 0).
  let commit_res = [bls.G1.ProjectivePoint.ZERO, 0];
  // 4. (commit, M) = commit_res
  if(commitment_with_proof) {
    commit_res = await deserialize_and_validate_commit(commitment_with_proof, gens, api_id);
  }
  let [commit, M] = commit_res;
  // 5. Q_1 = generators[0]
  const Q_1 = gens.generators[0];
  // 6. Q_2 = Identity_G1
  let Q_2 = bls.G1.ProjectivePoint.ZERO;
  // 7. if commitment_with_proof != "", Q_2 = generators[1]
  if(commitment_with_proof) {
    Q_2 = gens.generators[1];
  }
  // 8. (H_1, ..., H_L) = generators[M + 1..M + L + 1]
  const H = gens.generators.slice(M + 1, M + 1 + L);
  const temp_generators = gens.generators.slice(1, M + 1 + L);
  // Procedure:
  // 1. domain = calculate_domain(PK, generators, header, api_id)
  const domain = await calculate_domain(PK, temp_generators.length, Q_1, temp_generators, header, api_id);
  // 2. e_octs = serialize((SK, domain, msg_1, ..., msg_L, signer_blind))
  // NOTE: Test vectors only verify if we don't add 0 signer blind to e_octs.
  const valArray = [
    {type: 'Scalar', value: SK},
    {type: 'Scalar', value: domain},
  ];
  for(let i = 0; i < L; i++) {
    valArray.push({type: 'Scalar', value: message_scalars[i]});
  }
  if(signer_blind !== 0n) {
    valArray.push({type: 'Scalar', value: signer_blind});
  }
  const e_serial_octs = serialize(valArray);
  // 3. e = BBS.hash_to_scalar(e_octs || commitment_with_proof, signature_dst)
  const sig_dst = new TextEncoder().encode(api_id + 'H2S_');
  let e;
  if(commitment_with_proof) {
    e = await hash_to_scalar(concat(e_serial_octs, commitment_with_proof), sig_dst, api_id);
  } else {
    e = await hash_to_scalar(e_serial_octs, sig_dst, api_id);
  }
  // // if a commitment is not supplied, Q_2 = Identity_G1, meaning that
  // // signer_blind will be ignored.
  // 4. commit = commit + Q_2 * signer_blind
  if(signer_blind !== 0n) {
    commit = commit.add(Q_2.multiply(signer_blind));
  }
  // 5. B = P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L + commit
  let B = gens.P1;
  B = B.add(Q_1.multiply(domain));
  for(let i = 0; i < message_scalars.length; i++) {
    B = B.add(H[i].multiply(message_scalars[i]));
  }
  B = B.add(commit);
  // console.log(`B: ${bytesToHex(B.toRawBytes(true))}`);
  // 6. A = B * (1 / (SK + e))
  // For this we need to work in Fr which noble-BLS12-381 provides
  const denom = bls.fields.Fr.add(bls.fields.Fr.create(SK), bls.fields.Fr.create(e));
  const num = bls.fields.Fr.inv(denom);
  const A = B.multiply(num);
  // 7. return signature_to_octets((A, e))
  return signature_to_octets(A, e);
  // 8. return signature
}

/**
 * Helper function to get the number of blind generators used in a commitment
 * with proof.
 *
 * @param {Uint8Array} commitment_with_proof - The raw bytes for this value.
 * @returns {number} - The number of blind generators used by the commitment, if any.
 */
export function calcM(commitment_with_proof) {
  if(!commitment_with_proof) {
    return 0;
  }
  // 2. M = length(commitment_with_proof)
  let M = commitment_with_proof.length;
  // 3. if M != 0, M = M - octet_point_length - octet_scalar_length
  // 4. M = M / octet_scalar_length
  if(M !== 0) {
    M = M - POINT_LENGTH - SCALAR_LENGTH;
    M = M / SCALAR_LENGTH;
  }
  // 5. if M < 0, return INVALID
  if(M < 0) {
    throw new Error('M < 0, Invalid commitment with proof');
  }
  return M;
}

async function calculate_domain(PK, L, Q_1, H_Points, header, api_id) {
  const dom_array = [
    {type: 'PublicKey', value: PK},
    {type: 'NonNegInt', value: L},
    {type: 'GPoint', value: Q_1}
  ];
  for(let i = 0; i < L; i++) {
    dom_array.push({type: 'GPoint', value: H_Points[i]});
  }
  dom_array.push({type: 'CipherID', value: api_id});
  dom_array.push({type: 'PlainOctets', value: header});
  const dom_for_hash = serialize(dom_array);
  const dst = new TextEncoder().encode(api_id + 'H2S_');
  const domain = await hash_to_scalar(dom_for_hash, dst, api_id);
  return domain;
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
 * @param {BigInt} signer_blind - From signer or 0n if not used.
 * @param {string} api_id - The API id for the signature suite.
 * @returns {boolean} - True or False depending on whether the signature
 *  is valid.
 */
export async function BlindVerify(PK, signature, header, messages, committed_messages,
  secret_prover_blind, signer_blind, api_id) {
  // const L = messages.length;
  // const M = committed_messages.length;
  // console.log(`PK: ${bytesToHex(PK)}`);
  // console.log(`signature: ${bytesToHex(signature)}`);
  // console.log(`header: ${bytesToHex(header)}`);
  // console.log(`messages: ${messages}`);
  // console.log(`committed messages: ${committed_messages}`);
  // console.log(`prover blind: ${secret_prover_blind.toString(16)}`);
  // console.log(`signer blind: ${signer_blind.toString(16)}`);
  // 1. message_scalars = ()
  let message_scalars = [];
  // 2. if secret_prover_blind != 0, message_scalars.append(secret_prover_blind + signer_blind)
  // **NOTE** the above addition MUST be in the field!!!
  if(secret_prover_blind !== 0n) {
    message_scalars.push(bls.fields.Fr.add(secret_prover_blind, signer_blind));
  }
  // 3. message_scalars.append(BBS.messages_to_scalars(committed_messages, api_id))
  const prover_message_scalars = await messages_to_scalars(committed_messages, api_id);
  message_scalars = message_scalars.concat(prover_message_scalars);
  // 4. message_scalars.append(BBS.messages_to_scalars(messages, api_id))
  const signer_message_scalars = await messages_to_scalars(messages, api_id);
  message_scalars = message_scalars.concat(signer_message_scalars);
  // console.log(`length message scalars: ${message_scalars.length}`);
  // console.log(message_scalars);
  // 5. generators = BBS.create_generators(length(message_scalars) + 1, api_id)
  const gens = await prepareGenerators(message_scalars.length + 1, api_id);
  // 6. res = BBS.CoreVerify(PK, signature, generators, header, messages, api_id)
  const res = await verify(PK, signature, header, message_scalars, gens, api_id);
  return res;
}
