/* Functions used in Blind BBS signature operations */

/*global TextEncoder, console*/
import {bls12_381 as bls} from '@noble/curves/bls12-381';
import {expand_message_xmd} from '@noble/curves/abstract/hash-to-curve';
import {randomBytes} from './randomBytes.js';
import {sha256} from '@noble/hashes/sha256';
import {shake256} from '@noble/hashes/sha3';

const API_ID = 'BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_BLIND_H2G_HM2S_';
const API_ID_SHAKE = 'BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_BLIND_H2G_HM2S_';
/*
- api_id, the octet string ciphersuite_id || "BLIND_H2G_HM2S_", where
          ciphersuite_id is defined by the ciphersuite and
          "BLIND_H2G_HM2S_"is an ASCII string comprised of 15 bytes.
*/
const SCALAR_LENGTH = 32;
const EXPAND_LEN = 48;
const POINT_LENGTH = 48;
const rPrimeOrder = bls.fields.Fr.ORDER; // prime order of the subgroups G1, G2

/**
 * This operation is used by the Prover to create commitment to a set of
 * messages (committed_messages), that they intent to include to the signature.
 * Note that this operation returns both the serialized commitment as well as
 * the random scalar used to blind it (prover_blind).
 *
 * @param {Array} messages - A vector of octet strings, messages, to be
 * committed. If not supplied it defaults to the empty array.
 * @param {string} api_id - **TODO** as octet string or string?
 * @returns {Array}  - A vector, blind_result, comprising from an octet string
 * and a random scalar in that order.
 */
export async function commit(messages, api_id) {
  // 1.  M = length(messages)
  // 2.  generators = BBS.create_generators(M + 2, api_id)
  // 3.  (Q_2, J_1, ..., J_M) = generators[1..M+1]
  // 4.  (msg_1, ..., msg_M) = messages_to_scalars(committed_messages, api_id)
  // 5.  (prover_blind, s~, m~_1, ..., m~_M) = BBS.get_random_scalars(M + 2)
  // 6.  C = Q_2 * prover_blind + J_1 * msg_1 + ... + J_M * msg_M
  // 7.  Cbar = Q_2 * s~ + J_1 * m~_1 + ... + J_M * m~_M
  // 8.  challenge = calculate_blind_challenge(C, Cbar, generators, api_id)
  // 9.  s^ = s~ + prover_blind * challenge
  // 10. for m in (1, 2, ..., M): m^_i = m~_1 + msg_i * challenge
  // 11. proof = (s^, (m^_1, ..., m^_M), challenge)
  // 12. commitment_with_proof_octs = commitment_to_octets(C, proof)
  // 13. return (commitment_with_proof_octs, prover_blind)
}