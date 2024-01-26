/* Functions used in Blind BBS signature operations */

/*global TextEncoder, console*/
import {calculate_random_scalars, concat, hash_to_scalar, messages_to_scalars,
  prepareGenerators, serialize}
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
  // 2.  generators = BBS.create_generators(M + 1, api_id)
  const generators = await prepareGenerators(M + 1, api_id);
  // 3.  (Q_2, J_1, ..., J_M) = generators[1..M+1]
  const [Q_2, ...J] = generators.H;
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
  const challenge = await calculate_blind_challenge(C, Cbar, generators.H,
    api_id);
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
  for (let scalar of proof) {
    c_array.push({type: 'Scalar', value: scalar})
  }
  const proof_octs = serialize(c_array);
  return concat(commitment_octs, proof_octs);
}