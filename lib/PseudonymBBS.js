/* Functions used in Blind BBS signature operations */
/*global TextEncoder, console*/
/* eslint-disable max-len */
import {bytesToHex, calculate_random_scalars, concat, hash_to_scalar, messages_to_scalars,
  octets_to_sig, os2ip, prepareGenerators, ProofInit, ProofFinalize, serialize,
  sign, verify}
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
  const OP = await hash_to_curve_g1(verifier_id, api_id);
  // 3. if OP == Identity_G1 or OP == BP1 or OP == P1, return INVALID
  // 3. pid_scalar = messages_to_scalars((pid), api_id)
  const [pid_scalar] = await messages_to_scalars([pid], api_id);
  // 4. return OP * pid_scalar
  return OP.multiply(pid_scalar);
}

async function hash_to_curve_g1(thing, api_id) {
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

/**
 * Pseudonym BBS proof generation.
 *
 * @param {Uint8Array} PK - Public key as a compressed G2 point raw bytes.
 * @param {Uint8Array} signature - A previously computed signature.
 * @param {Uint8Array} pseudonym - Pseudonym computed with pid and verifier_id.
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
export async function ProofGenWithPseudonym(PK, signature, pseudonym, verifier_id,
  pid, header, ph, messages, disclosed_indexes, api_id, rand_scalars = calculate_random_scalars) {
  // 1. message_scalars = messages_to_scalars(messages, api_id)
  const msg_scalars = await messages_to_scalars(messages);
  // 2. pid_scalar = messages_to_scalars((pid), api_id)
  const [pid_scalar] = await messages_to_scalars([pid], api_id);
  // 3. generators = create_generators(length(messages) + 2, PK, api_id)
  const gens = await prepareGenerators(messages.length + 2, api_id)
  // 4. proof = CoreProofGenWithPseudonym(PK, signature, Pseudonym, verifier_id, pid_scalar,
  //   generators, header, ph, message_scalars, disclosed_indexes, api_id, rand_scalars)
  // 5. if proof is INVALID, return INVALID
  // 6. return proof
  const proof = await CoreProofGenWithPseudonym(PK, signature, pseudonym, verifier_id,
    pid_scalar, gens, header, ph, msg_scalars, disclosed_indexes, api_id, rand_scalars);
  return proof;
}

async function CoreProofGenWithPseudonym(PK, signature, pseudonym, verifier_id,
  pid_scalar, gens, header, ph, msg_scalars, disclosed_indexes, api_id, rand_scalars) {
  // Deserialization:
  // 1.  signature_result = octets_to_signature(signature)
  // 2.  if signature_result is INVALID, return INVALID
  // 3.  (A, e) = signature_result
  const {A, e} = octets_to_sig(signature); // Get curve point and scalar
  // 4.  messages = messages.push(pid_scalar)
  const dup_msg_scalars = msg_scalars.slice(); // Make copy
  dup_msg_scalars.push(pid_scalar);
  // 5.  L = length(messages)
  const L = dup_msg_scalars.length;
  // 6.  R = length(disclosed_indexes)
  const R = disclosed_indexes.length;
  // 7.  (i1, ..., iR) = disclosed_indexes
  // 8.  if R > L - 1, return INVALID; PID is never revealed
  if(R > L - 1) {
    throw new TypeError('CoreProofGenWithPseudonym: too many disclosed indexes');
  }
  // 9.  U = L - R
  const U = L - R;
  // 10. undisclosed_indexes = range(0, L-1) \ disclosed_indexes
  const allIndexes = [];
  for(let i = 0; i < L; i++) {
    allIndexes[i] = i;
  }
  const tempSet = new Set(allIndexes);
  for(const dis of disclosed_indexes) {
    tempSet.delete(dis);
  }
  const undisclosed_indexes = Array.from(tempSet); // Contains all undisclosed indexes
  // 11. disclosed_messages = (messages[i1], ..., messages[iR])
  // ABORT if: for i in disclosed_indexes, i < 1 or i > L - 1
  for(const i of disclosed_indexes) {
    if(i < 0 || i > L - 2) {
      throw new TypeError('CoreProofGenWithPseudonym: disclosed index out of bounds');
    }
  }
  const disclosed_scalars = msg_scalars.filter((msg, i) => disclosed_indexes.includes(i));
  // 1.  random_scalars = calculate_random_scalars(5+U+1)
  const randScalars = await rand_scalars(5 + U + 1); // last one is for pid~
  // 2.  init_res = ProofInit(PK, signature_res, header, random_scalars, generators,messages,undisclosed_indexes,api_id)
  // 3.  if init_res is INVALID, return INVALID
  const init_res = ProofInit(PK, [A, e], gens, randScalars, header,
    dup_msg_scalars, undisclosed_indexes, api_id);
  // 4.  OP = hash_to_curve_g1(verifier_id, api_id)
  const OP = await hash_to_curve_g1(verifier_id, api_id);
  // 5.  pid~ = random_scalars[5 + U + 1] // last element of random_scalars
  const pidTilde = randScalars[5 + U];
  // 6.  Ut = OP * pid~
  const Ut = OP.multiply(pidTilde);
  // 7.  pseudonym_init_res = (Pseudonym, OP, Ut)
  const pseudonym_init_res = [pseudonym, OP, Ut];
  // 8.  challenge = ProofWithPseudonymChallengeCalculate(init_res, pseudonym_init_res,
  //   disclosed_indexes,disclosed_messages, ph, api_id)
  const challenge = ProofWithPseudonymChallengeCalculate(init_res, pseudonym_init_res,
    disclosed_indexes, disclosed_scalars, ph, api_id);
  // 9.  proof = ProofFinalize(challenge, e, random_scalars, messages, undisclosed_indexes)
  return ProofFinalize(init_res, challenge, e, randScalars, dup_msg_scalars,
    undisclosed_indexes);
}

async function ProofWithPseudonymChallengeCalculate(init_res, pseudonym_init_res,
  i_array, msg_array, ph, api_id) {
  // 1. c_arr = (Abar, Bbar, D, T1, T2, Pseudonym, OP, Ut, R, i1, ..., iR, msg_i1, ..., msg_iR, domain)
  // 2. c_octs = serialize(c_arr) || I2OSP(length(ph), 8) || ph
  // 3. return hash_to_scalar(c_octs, challenge_dst)
  const [Abar, Bbar, D, T1, T2, domain] = init_res;
  const [pseudonym, OP, Ut,] = pseudonym_init_res;
  const dst = new TextEncoder().encode(api_id + 'H2S_');
  const c_array = [
    {type: 'GPoint', value: Abar},
    {type: 'GPoint', value: Bbar},
    {type: 'GPoint', value: D},
    {type: 'GPoint', value: T1},
    {type: 'GPoint', value: T2},
    {type: 'GPoint', value: pseudonym},
    {type: 'GPoint', value: OP},
    {type: 'GPoint', value: Ut},
    {type: 'NonNegInt', value: i_array.length}, //R
  ];
  for(const iR of i_array) {
    c_array.push({type: 'NonNegInt', value: iR});
  }
  for(const msg of msg_array) {
    c_array.push({type: 'Scalar', value: msg});
  }
  c_array.push({type: 'Scalar', value: domain});
  c_array.push({type: 'PlainOctets', value: ph});
  // c_for_hash = encode_for_hash(c_array)
  // if c_for_hash is INVALID, return INVALID
  const c_for_hash = serialize(c_array);
  const c = await hash_to_scalar(c_for_hash, dst, api_id);
  return c;
}
