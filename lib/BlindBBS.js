/* Functions used in Blind BBS signature operations */
/*global TextEncoder, console*/
/* eslint-disable max-len */
import {calculate_random_scalars, concat, hash_to_scalar, messages_to_scalars,
  os2ip, prepareGenerators, serialize}
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
    gens.generators.slice(1, M+2), api_id);
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

/*
calculate_blind_challenge(C, Cbar, generators, api_id)

- C (REQUIRED), a point of G1.
- Cbar (REQUIRED), a point of G1.
- generators (REQUIRED), an array of points from G1, of length at
                         least 1.
- api_id (OPTIONAL), octet string. If not supplied it defaults to the
                     empty octet string ("").

Definition:

- blind_challenge_dst, an octet string representing the domain
                       separation tag: api_id || "H2S_" where
                       ciphersuite_id is defined by the ciphersuite and
                       "H2S_" is an ASCII string composed of 4 bytes.

Deserialization:

1. if length(generators) == 0, return INVALID
2. M = length(generators) - 1

Procedure:

1. c_arr = (C, Cbar, M)
2. c_arr.append(generators)
3. c_octs = serialize(c_arr)
4. return BBS.hash_to_scalar(c_octs, blind_challenge_dst)
*/
async function calculate_blind_challenge(C, Cbar, generators, api_id) {
  const dst = new TextEncoder().encode(api_id + 'H2S_');
  let M = generators.length - 1;
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

/*
commitment_octets = commitment_with_proof_to_octets(commitment, proof)

Inputs:

- commitment (REQUIRED), a point of G1.
- proof (REQUIRED), a vector comprising of a scalar, a possibly empty
                    vector of scalars and another scalar in that order.

Outputs:

- commitment_octets, an octet string or INVALID.

Procedure:

1. commitment_octs = serialize(commitment)
2. if commitment_octs is INVALID, return INVALID
3. proof_octs = serialize(proof)
4. if proof_octs is INVALID, return INVALID
5. return commitment_octs || proof_octs
*/

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

/*
verify_commitment(commitment, commitment_proof, blind_generators, api_id)

Inputs:

- commitment (REQUIRED), a commitment (see (#terminology)).
- commitment_proof (REQUIRED), a commitment_proof (see (#terminology)).
- blind_generators (REQUIRED), vector of pseudo-random points in G1.
- api_id (OPTIONAL), octet string. If not supplied it defaults to the
                     empty octet string ("").

Outputs:

- result: either VALID or INVALID
*/

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

/*
(commit, blind_gen_no) = deserialize_and_validate_commit(
                                                  commitment_with_proof,
                                                  generators,
                                                  api_id)

Inputs:
- commitment_with_proof (OPTIONAL), octet string. If it is not supplied
                                    it defaults to the empty octet
                                    string ("").
- generators (OPTIONAL), vector of points of G1. If it is not supplied
                         it defaults to the empty set ("()").
- api_id (OPTIONAL), octet string. If not supplied it defaults to the
                     empty octet string ("").

Outputs:

- (commit, blind_gen_no), a tuple comprising from commitment, a
                          commitment_proof (see (#terminology)), in that
                          order; or INVALID.
*/

export async function deserialize_and_validate_commit(commitment_with_proof, gens, api_id) {
  // Procedure:
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
  const M = commit_proof[1].length;
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

/* octets_to_commitment_with_proof(commitment_octs)

Inputs:
- commitment_octs (REQUIRED), an octet string in the form outputted from
                              the commitment_to_octets operation.

Parameters:
- (octet_point_length, octet_scalar_length), defined by the ciphersuite.

Outputs:
- commitment, a commitment in the form (C, proof), where C a point of G1
              and proof a vector comprising of a scalar, a possibly
              empty vector of scalars and another scalar in that order.
*/
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
