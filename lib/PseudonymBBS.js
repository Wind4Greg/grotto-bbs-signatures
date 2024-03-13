/* Functions used in Blind BBS signature operations */
/*global TextEncoder, console*/
/* eslint-disable max-len */
import {bytesToHex, calculate_random_scalars, concat, hash_to_scalar, messages_to_scalars,
  os2ip, prepareGenerators, proofGen, serialize, sign, signature_to_octets, verify}
  from './BBS.js';
import {bls12_381 as bls} from '@noble/curves/bls12-381';
// import {expand_message_xmd} from '@noble/curves/abstract/hash-to-curve';
// import {randomBytes} from './randomBytes.js';
// import {sha256} from '@noble/hashes/sha256';
import {shake256} from '@noble/hashes/sha3';

const SCALAR_LENGTH = 32;
// const EXPAND_LEN = 48;
const POINT_LENGTH = 48;
// const rPrimeOrder = bls.fields.Fr.ORDER; // prime order of the subgroups G1, G2

/**
 * Pseudonym signs a list of messages and prover identifier.
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
  const gen = await prepareGenerators(dup_messages.length + 1, api_id);
  // console.log(dup_messages.map(m => bytesToHex(m)));
  // console.log(`Generators length: ${gen.generators.length}`);
  const msg_scalars = await messages_to_scalars(dup_messages);
  const signature = await sign(SK, PK, header, msg_scalars, gen, api_id);
  return signature;
}

/**
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
  const msg_scalars = await messages_to_scalars(dup_messages);
  const result = await verify(PK, signature, header, msg_scalars, gens, api_id);
  return result;
}

/*

Inputs:

- verifier_id (REQUIRED), an octet string, representing the unique proof
                          Verifier identifier.
- pid (REQUIRED), an octet string, representing the unique Prover
                  identifier.
- api_id (OPTIONAL), an octet string. If not supplied it defaults to the
                     empty octet string ("").


Outputs:

- pseudonym, A point of G1, different from the Identity_G1, BP1 and P1
             (see the Parameters of this operation); or INVALID.

Parameters:

- hash_to_curve_g1, the hash_to_curve operation defined by the Hash to
                    Curve suite determined by the ciphersuite, through
                    the hash_to_curve_suite parameter.
- P1, fixed point of G1, defined by the ciphersuite.

*/
export async function CalculatePseudonym(verifier_id, pid, api_id) {
  // 1. OP = hash_to_curve_g1(verifier_id, api_id)
  // 2. if OP is INVALID, return INVALID
  let OP;
  if(api_id.includes('SHA-256')) {
    OP = await bls.G1.hashToCurve(verifier_id, {DST: api_id});
  } else {
    OP = await bls.G1.hashToCurve(verifier_id, {
      DST: api_id,
      expand: 'xof',
      hash: shake256,
    });
  }
  // 3. if OP == Identity_G1 or OP == BP1 or OP == P1, return INVALID
  // 3. pid_scalar = messages_to_scalars((pid), api_id)
  const [pid_scalar] = await messages_to_scalars([pid], api_id);
  // 4. return OP * pid_scalar
  return OP.multiply(pid_scalar);
}

/**
 * Pseudonym BBS proof generation.
 *
 * @param {Uint8Array} PK - Public key as a compressed G2 point raw bytes.
 * @param {Uint8Array} signature - A previously computed signature.
 * @param {Uint8Array} header - Header used when signature was created.
 * @param {Uint8Array} ph - Presentation header, used during proof creation.
 * @param {Array} messages - A vector of octet strings (Uint8Array). If not
 * supplied, it defaults to the empty array. These should be all the messages
 * the signer used in the signature.
 * @param {Uint8Array} pid - The prover identifier.
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
export async function PseudonymProofGen(PK, signature, header, ph, messages,
  pid, disclosed_indexes, api_id, rand_scalars = calculate_random_scalars) {

}


