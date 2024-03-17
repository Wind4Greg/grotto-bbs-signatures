/* Functions used in Blind BBS signature operations */
/*global TextEncoder, console*/
/* eslint-disable max-len */
import {bytesToHex, calculate_random_scalars, concat, hash_to_scalar, messages_to_scalars,
  octets_to_sig, octets_to_proof, os2ip, prepareGenerators, ProofInit, ProofFinalize,
  ProofVerifyInit, serialize, sign, verify, numberToHex}
  from './BBS.js';
import {get_disclosed_data} from './BlindBBS.js';
import {bls12_381 as bls} from '@noble/curves/bls12-381';
// import {expand_message_xmd} from '@noble/curves/abstract/hash-to-curve';
// import {randomBytes} from './randomBytes.js';
// import {sha256} from '@noble/hashes/sha256';
import {shake256} from '@noble/hashes/sha3';

const GEN_TRACE_INFO = false;

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
  const msg_scalars = await messages_to_scalars(dup_messages, api_id);
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
  const msg_scalars = await messages_to_scalars(dup_messages, api_id);
  const result = await verify(PK, signature, header, msg_scalars, gens, api_id);
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
  // console.log(`pseudonym bytes: ${bytesToHex(pseudonym_bytes)}`);
  // console.log(`As point bytes: ${bytesToHex(pseudonym.toRawBytes(true))}`);
  // 1. message_scalars = messages_to_scalars(messages, api_id)
  const msg_scalars = await messages_to_scalars(messages, api_id);
  // 2. pid_scalar = messages_to_scalars((pid), api_id)
  const [pid_scalar] = await messages_to_scalars([pid], api_id);
  // console.log(`pid scalar: ${numberToHex(pid_scalar, SCALAR_LENGTH)}`);
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
  const L = dup_msg_scalars.length; // Includes pid_scalar
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
  // console.log('undisclosed indexes:');
  // console.log(undisclosed_indexes);
  // console.log('disclosed indexes');
  // console.log(disclosed_indexes);
  // 11. disclosed_messages = (messages[i1], ..., messages[iR])
  // ABORT if: for i in disclosed_indexes, i < 1 or i > L - 1
  for(const i of disclosed_indexes) {
    if(i < 0 || i > L - 2) {
      throw new TypeError('CoreProofGenWithPseudonym: disclosed index out of bounds');
    }
  }
  const disclosed_scalars = dup_msg_scalars.filter((msg, i) => disclosed_indexes.includes(i));
  // 1.  random_scalars = calculate_random_scalars(5+U+1)
  const randScalars = await rand_scalars(5 + U); // last one is for pid~
  // 2.  init_res = ProofInit(PK, signature_res, header, random_scalars, generators,messages,undisclosed_indexes,api_id)
  // 3.  if init_res is INVALID, return INVALID
  // ProofInit(PK, signature, gens, randScalars, header,
  // messages, undisclosed_indexes, api_id)
  const init_res = await ProofInit(PK, [A, e], gens, randScalars, header,
    dup_msg_scalars, undisclosed_indexes, api_id);
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
  const proof = await ProofFinalize(init_res, challenge, e, randScalars, dup_msg_scalars,
    undisclosed_indexes, PK);
  if(GEN_TRACE_INFO) {
    console.log('Checking ProofVerifyInit in ProofGen:');
    const proof_result = octets_to_proof(proof);
    const stuff = await ProofVerifyInit(PK, proof_result, gens, header,
      disclosed_scalars, disclosed_indexes, api_id);
  }
  return proof;
}

async function ProofWithPseudonymChallengeCalculate(init_res, pseudonym_init_res,
  i_array, msg_array, ph, api_id) {
  // 1. c_arr = (Abar, Bbar, D, T1, T2, Pseudonym, OP, Ut, R, i1, ..., iR, msg_i1, ..., msg_iR, domain)
  // 2. c_octs = serialize(c_arr) || I2OSP(length(ph), 8) || ph
  // 3. return hash_to_scalar(c_octs, challenge_dst)
  const [Abar, Bbar, D, T1, T2, domain] = init_res;
  const [pseudonym, OP, Ut] = pseudonym_init_res;
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
  if(GEN_TRACE_INFO) {
    const info = {
      info: 'from ProofWithPseudonymChallengeCalculate',
      pseudonym: bytesToHex(pseudonym.toRawBytes(true)),
      OP: bytesToHex(OP.toRawBytes(true)),
      Ut: bytesToHex(Ut.toRawBytes(true)),
      challenge: numberToHex(c, SCALAR_LENGTH)
    };
    console.log(JSON.stringify(info, null, 2));
  }
  return c;
}

/*
- PK (REQUIRED), an octet string of the form outputted by the SkToPk
                 operation.
- proof (REQUIRED), an octet string of the form outputted by the
                    ProofGen operation.
- Pseudonym (REQUIRED), A point of G1, different from the Identity of
                        G1, as outputted by the CalculatePseudonym
                        operation.
- verifier_id (REQUIRED), an octet string, representing the unique proof
                          Verifier identifier.
- header (OPTIONAL), an optional octet string containing context and
                     application specific information. If not supplied,
                     it defaults to an empty string.
- ph (OPTIONAL), an octet string containing the presentation header. If
                 not supplied, it defaults to an empty string.
- disclosed_messages (OPTIONAL), a vector of octet strings. If not
                                 supplied, it defaults to the empty
                                 array "()".
- disclosed_indexes (OPTIONAL), vector of unsigned integers in ascending
                                order. Indexes of disclosed messages. If
                                not supplied, it defaults to the empty
                                array "()".

*/
/**
 * Verifies a previously generated proof with pseudonym against original signers
 * public key, pseudonym, and additional information.
 *
 * @async
 * @param {Uint8Array} PK - Public key as a compressed G2 point raw bytes.
 * @param {Uint8Array} proof - The proof as a byte array.
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
export async function ProofVerifyWithPseudonym(PK, proof, pseudonym_bytes,
  verifier_id, header, ph, disclosed_messages, disclosed_indexes, api_id) {
  // 1. proof_len_floor = 2 * octet_point_length + 3 * octet_scalar_length
  // 2. if length(proof) < proof_len_floor, return INVALID
  // 3. U = floor((length(proof) - proof_len_floor) / octet_scalar_length)
  // 4. R = length(disclosed_indexes)
  // 5. L = U + R
  let proof_result;
  try {
    proof_result = octets_to_proof(proof);
  } catch{
    // console.log('Problem with octets_to_proof');
    return false;
  }
  const {mHatU} = proof_result;
  const R = disclosed_indexes.length;
  const U = mHatU.length;
  const L = R + U;
  // console.log(`L = ${L}, R = ${R}, U = ${U}`);
  // Check disclosed indexes length same as disclosed messages length
  if(disclosed_messages.length !== R) {
    // console.log('disclosed messages not the same as length of disclosed indexes');
    return false;
  }
  const pseudonym = bls.G1.ProjectivePoint.fromHex(pseudonym_bytes);
  //   1. message_scalars = messages_to_scalars(disclosed_messages, api_id)
  const msg_scalars = await messages_to_scalars(disclosed_messages, api_id);
  // 2. generators = create_generators(L + 1, PK, api_id)
  const gens = await prepareGenerators(L + 1, api_id);
  // 3. result = CoreProofVerifyWithPseudonym(...)
  // 4. return result
  const result = await CoreProofVerifyWithPseudonym(PK, proof_result, pseudonym, verifier_id,
    gens, header, ph, msg_scalars, disclosed_indexes, api_id);
  return result;
}

async function CoreProofVerifyWithPseudonym(PK, proof_result, pseudonym, verifier_id,
  gens, header, ph, disclosed_messages, disclosed_indexes, api_id) {
  // 3. (Abar, Bbar, r2^, r3^, commitments, cp) = proof_result
  const {Abar, Bbar, D, eHat, r1Hat, r3Hat, mHatU, c} = proof_result;
  if(GEN_TRACE_INFO) {
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
  for(const i of disclosed_indexes) {
    if(i < 0 || i > U + R - 1) {
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
  const pidHat = mHatU[mHatU.length - 1]; // Different in the hidden pid case.
  // 5.  Uv = OP * pid^ - Pseudonym * cp
  let Uv = OP.multiply(pidHat);
  Uv = Uv.subtract(pseudonym.multiply(c));
  // 6.  pseudonym_init_res = (Pseudonym, OP, Uv)
  const pseudonym_init_res = [pseudonym, OP, Uv];
  // 7.  challenge = ProofWithPseudonymChallengeCalculate(init_res,
  //                      pseudonym_init_res,
  //                      disclosed_indexes,
  //                      messages,
  //                      ph,
  //                      api_id)
  // 8.  if cp != challenge, return INVALID
  const challenge = await ProofWithPseudonymChallengeCalculate(init_res,
    pseudonym_init_res, disclosed_indexes, disclosed_messages, ph, api_id);
  // console.log(`challenge: ${numberToHex(challenge, SCALAR_LENGTH)}`);
  if(c !== challenge) {
    // console.log('challenge failed');
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
  // console.log(`equality test: ${valid}`);
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
 * @returns {Array} [proof, disclosed_msgs, disclosed_idxs] a tuple comprising
 * an octet string, an array of octet strings and an array of non-zero integers;
 * or will throw an exception.
 */
export async function HiddenPidProofGen(PK, signature, pseudonym_bytes, verifier_id,
  pid, header, ph, messages, disclosed_indexes, secret_prover_blind,
  signer_blind, api_id, rand_scalars = calculate_random_scalars) {

  const pseudonym = bls.G1.ProjectivePoint.fromHex(pseudonym_bytes);
  // single pid value takes place of committed messages
  // disclosed_commitment_indexes = [] since we never reveal pid
  let L = messages.length;
  if(disclosed_indexes.length > L) {
    throw TypeError('HiddenPidProofGen: to many disclosed indexes');
  }
  for(const index of disclosed_indexes) {
    if(index < 0 || index >= L) {
      throw TypeError('HiddenPidProofGen: disclosed index out of bounds');
    }
  }
  // Puts the sum of the prover blind and signer_blind as the first message scalar
  let message_scalars = [];
  if(secret_prover_blind !== 0n) {
    message_scalars.push(bls.fields.Fr.add(secret_prover_blind, signer_blind));
  }
  // Put hidden message scalars onto list, only the pid in our case
  const prover_message_scalars = await messages_to_scalars([pid], api_id);
  message_scalars = message_scalars.concat(prover_message_scalars);
  // Put message scalars from signer onto the list
  const signer_message_scalars = await messages_to_scalars(messages, api_id);
  message_scalars = message_scalars.concat(signer_message_scalars);
  // Create the generators
  const gens = await prepareGenerators(message_scalars.length + 1, api_id);
  // Get the complete list of disclosed messages, and adjusted list of disclosed indexes
  //  get_disclosed_data(messages, committed_messages, disclosed_indexes, disclosed_commitment_indexes, secret_prover_blind)
  const [disclosed_msgs, adjDisclosedIdxs] = get_disclosed_data(messages,
    [pid], disclosed_indexes, [], secret_prover_blind);
  // From this point on use message_scalars, adjDisclosedIdxs in proof generation
  // Give the verifier disclosed_messages and adjDisclosedIdxs.

  L = message_scalars.length; // longer now includes pid scalar
  const R = adjDisclosedIdxs.length;
  const U = L - R;
  const allIndexes = [];
  for(let i = 0; i < L; i++) {
    allIndexes[i] = i;
  }
  const tempSet = new Set(allIndexes);
  for(const dis of adjDisclosedIdxs) {
    tempSet.delete(dis);
  }
  const undisclosedIndexes = Array.from(tempSet);
  const {A, e} = octets_to_sig(signature); // Get curve point and scalars
  // check that we have enough generators for the messages
  if(messages.length > gens.generators.length + 1) {
    throw new TypeError('Sign: not enough generators! string');
  }
  const randScalars = await rand_scalars(5 + U);
  const init_res = await ProofInit(PK, [A, e], gens,
    randScalars, header, message_scalars, undisclosedIndexes, api_id);
  // Now special pseudonym stuff
  const OP = await hash_to_curve_g1(verifier_id, api_id);
  // We want the mTilde[1] so 5 rand scalars then the mTilde
  const pidTilde = randScalars[6]; // since pid is second message, i.e., after prover blind
  const Ut = OP.multiply(pidTilde);
  const pseudonym_init_res = [pseudonym, OP, Ut];
  const disclosed_scalars = adjDisclosedIdxs.map(i => message_scalars[i]);
  const challenge = await ProofWithPseudonymChallengeCalculate(init_res, pseudonym_init_res,
    adjDisclosedIdxs, disclosed_scalars, ph, api_id);
  const proof = await ProofFinalize(init_res, challenge, e, randScalars, message_scalars,
    undisclosedIndexes, PK);
  return [proof, disclosed_msgs, adjDisclosedIdxs];
}

/**
 * Verifies a previously generated proof with pseudonym against original signers
 * public key, pseudonym, and additional information.
 *
 * @async
 * @param {Uint8Array} PK - Public key as a compressed G2 point raw bytes.
 * @param {Uint8Array} proof - The proof as a byte array.
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
export async function HiddenPidProofVerifyWithPseudonym(PK, proof, pseudonym_bytes,
  verifier_id, header, ph, disclosed_messages, disclosed_indexes, api_id) {

  let proof_result;
  try {
    proof_result = octets_to_proof(proof);
  } catch{
    // console.log('Problem with octets_to_proof');
    return false;
  }
  const {mHatU} = proof_result;
  const R = disclosed_indexes.length;
  const U = mHatU.length;
  const L = R + U;
  // console.log(`L = ${L}, R = ${R}, U = ${U}`);
  // Check disclosed indexes length same as disclosed messages length
  if(disclosed_messages.length !== R) {
    // console.log('disclosed messages not the same as length of disclosed indexes');
    return false;
  }
  const pseudonym = bls.G1.ProjectivePoint.fromHex(pseudonym_bytes);
  const msg_scalars = await messages_to_scalars(disclosed_messages, api_id);
  const gens = await prepareGenerators(L + 1, api_id);
  const result = await HiddenPidCoreProofVerifyWithPseudonym(PK, proof_result, pseudonym, verifier_id,
    gens, header, ph, msg_scalars, disclosed_indexes, api_id);
  return result;
}

async function HiddenPidCoreProofVerifyWithPseudonym(PK, proof_result, pseudonym, verifier_id,
  gens, header, ph, disclosed_messages, disclosed_indexes, api_id) {

  const {Abar, Bbar, D, eHat, r1Hat, r3Hat, mHatU, c} = proof_result;
  if(GEN_TRACE_INFO) {
    const info = {
      info: 'from HiddenPidCoreProofVerifyWithPseudonym',
      PK: bytesToHex(PK),
      Abar: bytesToHex(Abar.toRawBytes(true)),
      Bbar: bytesToHex(Bbar.toRawBytes(true)),
      eHat: numberToHex(eHat, SCALAR_LENGTH),
      r1Hat: numberToHex(r1Hat, SCALAR_LENGTH),
      r3Hat: numberToHex(r3Hat, SCALAR_LENGTH),
      mHatU: mHatU.map(mHat => numberToHex(mHat, SCALAR_LENGTH)),
      challenge: numberToHex(c, SCALAR_LENGTH),
      disclosed_indexes
    };
    console.log(JSON.stringify(info, null, 2));
  }
  const W = bls.G2.ProjectivePoint.fromHex(PK); //W = octets_to_pubkey(PK)
  const R = disclosed_indexes.length;
  const U = mHatU.length;
  for(const i of disclosed_indexes) {
    if(i < 0 || i > U + R - 1) {
      // console.log('Something weird with disclosed indexes');
      return false;
    }
  }

  const init_res = await ProofVerifyInit(PK, proof_result, gens, header,
    disclosed_messages, disclosed_indexes, api_id);
  // ProofVerifyInit(PK, proof_result, gens, header, disclosed_messages, disclosed_indexes, api_id)
  const OP = await hash_to_curve_g1(verifier_id, api_id);
  const pidHat = mHatU[1]; // must use same element as in proof gen
  // 5.  Uv = OP * pid^ - Pseudonym * cp
  let Uv = OP.multiply(pidHat);
  console.log(`verify pidHat: ${numberToHex(pidHat, SCALAR_LENGTH)}`);
  Uv = Uv.subtract(pseudonym.multiply(c));
  // 6.  pseudonym_init_res = (Pseudonym, OP, Uv)
  const pseudonym_init_res = [pseudonym, OP, Uv];
  const challenge = await ProofWithPseudonymChallengeCalculate(init_res,
    pseudonym_init_res, disclosed_indexes, disclosed_messages, ph, api_id);
  // console.log(`challenge: ${numberToHex(challenge, SCALAR_LENGTH)}`);
  let challenge_test = true;
  if(c !== challenge) {
    console.log('challenge failed');
    challenge_test = false;
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
  return valid && challenge_test;
}
