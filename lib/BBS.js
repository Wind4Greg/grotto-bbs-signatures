/* Functions used in multiple BBS signature operations */

/*global TextEncoder, console*/
import {bls12_381 as bls} from '@noble/curves/bls12-381';
import {expand_message_xmd} from '@noble/curves/abstract/hash-to-curve';
import {randomBytes} from './randomBytes.js';
import {sha256} from '@noble/hashes/sha256';
import {shake256} from '@noble/hashes/sha3';

// Constants for hash to curve, cipher suite, and API
const H2C_SUITE_SHAKE = 'BLS12381G1_XOF:SHAKE-256_SSWU_RO_';
const H2C_SUITE_SHA = 'BLS12381G1_XMD:SHA-256_SSWU_RO_';
const CIPHERSUITE_ID_SHAKE = 'BBS_' + H2C_SUITE_SHAKE;
const CIPHERSUITE_ID_SHA = 'BBS_' + H2C_SUITE_SHA;
export const API_ID_BBS_SHAKE = CIPHERSUITE_ID_SHAKE + 'H2G_HM2S_';
export const API_ID_BBS_SHA = CIPHERSUITE_ID_SHA + 'H2G_HM2S_';
export const API_ID_BLIND_BBS_SHAKE = CIPHERSUITE_ID_SHAKE + 'BLIND_H2G_HM2S_';
export const API_ID_BLIND_BBS_SHA = CIPHERSUITE_ID_SHA + 'BLIND_H2G_HM2S_';
export const SUPPORTED_API_IDS = [API_ID_BBS_SHAKE, API_ID_BBS_SHA,
  API_ID_BLIND_BBS_SHAKE, API_ID_BLIND_BBS_SHA];

const SCALAR_LENGTH = 32;
const EXPAND_LEN = 48;
const POINT_LENGTH = 48;
const rPrimeOrder = bls.fields.Fr.ORDER; // prime order of the subgroups G1, G2

/**
 * Produces an appropriate secret key starting from initial key material. This
 * procedure enhances the entropy of the key material but is deterministic so
 * initial key material must be kept secret.
 *
 * @param {Uint8Array} key_material - Secret key material. Must be >= 32 bytes
 * long.
 * @param {Uint8Array} key_info - Optional key information.
 * @param {string} key_dst - Key domain separation tag, defaults
 * to 'KEYGEN_DST_'.
 * @param {string} api_id - The hash type for the signature suite.
 * @returns {Uint8Array} Derived secret key as an array of bytes.
 */
export async function keyGen(key_material, key_info, key_dst = '',
  api_id = API_ID_BBS_SHAKE) {

  if(key_dst === '') {
    key_dst = api_id + 'KEYGEN_DST_';
  }
  if(key_material.length < 32 || key_material.length > 65535) {
    throw new TypeError('keyGen: bad length key_material');
  }
  const derive_input = concat(key_material, concat(i2osp(key_info.length, 2),
    key_info));
  const dst = new TextEncoder().encode(key_dst);
  const sk = await hash_to_scalar(derive_input, dst, api_id);
  return numberToBytesBE(sk, SCALAR_LENGTH);
}

/**
 *
 * @param {Uint8Array} privateBytes - Private key bytes must have length 32.
 * @returns {Uint8Array} Containing encoded public key in G2.
 */
export function publicFromPrivate(privateBytes) {
  const pointPk = bls.G2.ProjectivePoint.fromPrivateKey(privateBytes);
  return pointPk.toRawBytes(true);
}

/**
 * Creates a BBS signature over a list of "messages".
 *
 * @async
 * @param {bigint | Uint8Array } SK - A scalar or byte array for the
 * secret key.
 * @param {Uint8Array} PK -  Public key as a compressed G2 point raw bytes.
 * @param {Uint8Array} header - Header as a byte array.
 * @param {Array} messages - Array of scalars (bigint) derived from actual
 *  messages. Computed by {@link messages_to_scalars}.
 * @param {Array} generators - Array of group G1 generators created by the
 *  {@link prepareGenerators} function.
 * @param {string} api_id - The API ID for the signature suite.
 */
export async function sign(SK, PK, header, messages, generators, api_id) {
  if(typeof SK !== 'bigint') { // if byte array convert to BigInt
    SK = os2ip(SK);
  }
  // check that we have enough generators for the messages
  if(messages.length > generators.H.length) {
    throw new TypeError('Sign: not enough generators! string');
  }
  const L = messages.length;
  const dst = new TextEncoder().encode(api_id + 'H2S_');
  const domain = await calculate_domain(PK, L, generators.Q1, generators.H,
    header, api_id);
  // e = hash_to_scalar(serialize((SK, domain, msg_1, ..., msg_L)))
  const valArray = [
    {type: 'Scalar', value: SK},
    {type: 'Scalar', value: domain},
  ];
  for(let i = 0; i < L; i++) {
    valArray.push({type: 'Scalar', value: messages[i]});
  }
  const e_serial_octs = serialize(valArray);
  const e = await hash_to_scalar(e_serial_octs, dst, api_id);
  // B = P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L
  let B = generators.P1;
  B = B.add(generators.Q1.multiply(domain));
  for(let i = 0; i < messages.length; i++) {
    B = B.add(generators.H[i].multiply(messages[i]));
  }
  // A = B * (1 / (SK + e))
  // For this we need to work in Fr which noble-BLS12-381 provides
  const denom = bls.fields.Fr.add(bls.fields.Fr.create(SK),
    bls.fields.Fr.create(e));
  const num = bls.fields.Fr.inv(denom);
  const A = B.multiply(num);
  return signature_to_octets(A, e);
}

/**
 * Verify a BBS signature against a public key.
 *
 * @async
 * @param {Uint8Array} PK - Public key as a compressed G2 point raw bytes.
 * @param {Uint8Array} signature - A previously computed signature.
 * @param {Uint8Array} header - Header used when signature was created.
 * @param {Array} messages - Array of scalars (bigint) derived from actual
 *  messages. Computed by {@link messages_to_scalars}.
 * @param {Array} generators - Array of group G1 generators created by the
 *  {@link prepareGenerators} function.
 * @param {string} api_id - The API ID for the signature suite.
 * @returns {boolean} - True or False depending on whether the signature
 *  is valid.
 */
export async function verify(PK, signature, header, messages, generators,
  api_id) {
  const {A, e} = octets_to_sig(signature); // Get curve point and scalars
  // W = octets_to_pubkey(PK)
  const W = bls.G2.ProjectivePoint.fromHex(PK);
  // dom_array = (PK, L, Q_1, Q_2, H_1, ..., H_L, ciphersuite_id, header)
  const L = messages.length;
  const domain = await calculate_domain(PK, L, generators.Q1, generators.H,
    header, api_id);
  // B = P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L
  let B = generators.P1;
  B = B.add(generators.Q1.multiply(domain));
  for(let i = 0; i < messages.length; i++) {
    B = B.add(generators.H[i].multiply(messages[i]));
  }
  //  if e(A, W + P2 * e) * e(B, -P2) != Identity_GT,
  // return INVALID otherwise return VALID
  // Compute items in G2
  const temp1G2 = W.add(bls.G2.ProjectivePoint.BASE.multiply(e));
  const temp2G2 = bls.G2.ProjectivePoint.BASE.negate();
  // Compute items in GT, i.e., Fp12
  const ptGT1 = bls.pairing(A, temp1G2);
  const ptGT2 = bls.pairing(B, temp2G2);
  let result = bls.fields.Fp12.mul(ptGT1, ptGT2);
  result = bls.fields.Fp12.finalExponentiate(result); // See noble BLS12-381
  return bls.fields.Fp12.eql(result, bls.fields.Fp12.ONE);
}

/**
 * Generates an unlinkable, selective disclosure proof based on a
 * signature and message set, and related information.
 *
 * @async
 * @param {Uint8Array} PK - Public key as a compressed G2 point raw bytes.
 * @param {Uint8Array} signature - A previously computed signature.
 * @param {Uint8Array} header - Header used when signature was created.
 * @param {Uint8Array} ph - Presentation header, used during proof creation.
 * @param {Array} messages - Array of scalars (bigint) derived from actual
 *  messages. Computed by {@link messages_to_scalars}.
 * @param {Array} disclosed_indexes - Array of sorted (non-repeating) zero
 * based indices of the messages to be disclosed.
 * @param {Array} generators - Array of group G1 generators created by the
 *  {@link prepareGenerators} function.
 * @param {string} api_id - The API id for the signature suite.
 * @param {Function} rand_scalars - A function for generating cryptographically
 *  secure random or pseudo random scalars.
 * @returns {Uint8Array} - The proof as an byte array.
 */
export async function proofGen(PK, signature, header, ph, messages,
  disclosed_indexes, generators, api_id,
  rand_scalars = calculate_random_scalars
) {
  // TODO: check indexes for correctness, i.e., bounds and such...
  const L = messages.length;
  const R = disclosed_indexes.length;
  const U = L - R;
  const allIndexes = [];
  for(let i = 0; i < L; i++) {
    allIndexes[i] = i;
  }
  const tempSet = new Set(allIndexes);
  for(const dis of disclosed_indexes) {
    tempSet.delete(dis);
  }
  const undisclosed = Array.from(tempSet); // Contains all undisclosed indexes
  const {A, e} = octets_to_sig(signature); // Get curve point and scalars
  // check that we have enough generators for the messages
  if(messages.length > generators.H.length) {
    throw new TypeError('Sign: not enough generators! string');
  }
  const randScalars = await rand_scalars(5 + U);
  // Proof Initialization/ProofInit
  // (r1, r2, e~, r1~, r3~, m~_j1, ..., m~_jU) = random_scalars
  const [r1, r2, eTilde, r1Tilde, r3Tilde, ...mTildeU] = randScalars;
  const domain = await calculate_domain(PK, L, generators.Q1, generators.H,
    header, api_id);
  // console.log(`domain: ${domain}`);
  // B = P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L
  let B = generators.P1;
  B = B.add(generators.Q1.multiply(domain));
  for(let i = 0; i < messages.length; i++) {
    B = B.add(generators.H[i].multiply(messages[i]));
  }
  // 3. D = B * r2
  const D = B.multiply(r2);
  // 4. Abar = A * (r1 * r2)
  const Abar = A.multiply(bls.fields.Fr.mul(r1, r2));
  // 5. Bbar = D * r1 - Abar * e
  const Bbar = D.multiply(r1).subtract(Abar.multiply(e));
  // 6. T1 = Abar * e~ + D * r1~
  const T1 = Abar.multiply(eTilde).add(D.multiply(r1Tilde));
  // 7. T2 = D * r3~ + H_j1 * m~_j1 + ... + H_jU * m~_jU
  let T2 = D.multiply(r3Tilde);
  for(let j = 0; j < U; j++) {
    T2 = T2.add(generators.H[undisclosed[j]].multiply(mTildeU[j]));
  }
  // End of ProofInit
  const disclosed_messages = messages.filter((msg, i) =>
    disclosed_indexes.includes(i)
  );
  const c = await calculate_challenge(Abar, Bbar, D, T1, T2, disclosed_indexes,
    disclosed_messages, domain, ph, api_id);
  // ProofFinalize:
  // 1. r3 = r2^-1 (mod r)
  const r3 = bls.fields.Fr.inv(r2);
  // 2. e^ = e~ + e_value * challenge
  const eHat = bls.fields.Fr.add(eTilde, bls.fields.Fr.mul(e, c));
  // 3. r1^ = r1~ - r1 * challenge
  const r1Hat = bls.fields.Fr.sub(r1Tilde, bls.fields.Fr.mul(r1, c));
  // 4. r3^ = r3~ - r3 * challenge
  const r3Hat = bls.fields.Fr.sub(r3Tilde, bls.fields.Fr.mul(r3, c));
  // 5. for j in (1, ..., U): m^_j = m~_j + undisclosed_j * challenge (mod r)
  const mHatU = [];
  for(let j = 0; j < U; j++) {
    const mHatj = bls.fields.Fr.add(mTildeU[j],
      bls.fields.Fr.mul(messages[undisclosed[j]], c));
    mHatU.push(mHatj);
  }
  // 6. proof = (Abar, Bbar, D, e^, r1^, r3^, (m^_j1, ..., m^_jU), challenge)
  // 7. return proof_to_octets(proof)
  return proof_to_octets(Abar, Bbar, D, eHat, r1Hat, r3Hat, mHatU, c);
}

/**
 * Verifies a previously generated proof against original signers public key,
 * and additional information.
 *
 * @async
 * @param {Uint8Array} PK - Public key as a compressed G2 point raw bytes.
 * @param {Uint8Array} proof - The proof as a byte array.
 * @param {Uint8Array} header - Header used when original signature was created.
 * @param {Uint8Array} ph - Presentation header that was used during proof
 * creation.
 * @param {Array} disclosed_messages - Array of scalars (bigint) derived from
 *  actual  disclosed messages. Computed by {@link messages_to_scalars}.
 * @param {Array} disclosed_indexes - Array of sorted (non-repeating) zero
 * based indices corresponding to the disclosed messages.
 * @param {Array} generators - Array of group G1 generators created by the
 *  {@link prepareGenerators} function.
 * @param {string} api_id - The API id for the signature suite.
 * @returns {boolean} - True or False depending on whether the proof is valid.
 */
export async function proofVerify(PK, proof, header, ph, disclosed_messages,
  disclosed_indexes, generators, api_id
) {
  // (Abar, Bbar, D, e^, r1^, r3^, commitments, c) = proof
  // (m^_j1, ...., m^_jU) = commitments
  let proof_result;
  try {
    proof_result = octets_to_proof(proof);
  } catch{
    console.log('Problem with octets_to_proof');
    return false;
  }
  const {Abar, Bbar, D, eHat, r1Hat, r3Hat, mHatU, c} = proof_result;
  const R = disclosed_indexes.length;
  const U = mHatU.length;
  const L = R + U;
  // console.log(`L = ${L}, R = ${R}, U = ${U}`);
  // Check disclosed indexes length same as disclosed messages length
  if(disclosed_messages.length !== R) {
    // disclosed messages not the same as length of disclosed indexes
    return false;
  }
  const allIndexes = [];
  for(let i = 0; i < L; i++) {
    allIndexes[i] = i;
  }
  const tempSet = new Set(allIndexes);
  for(const dis of disclosed_indexes) {
    tempSet.delete(dis);
  }
  const undisclosed = Array.from(tempSet); // Contains all undisclosed indexes

  // W = octets_to_pubkey(PK)
  const W = bls.G2.ProjectivePoint.fromHex(PK);
  // 1. domain = calculate_domain(PK, Q_1, (H_1, ..., H_L), header, api_id)
  const domain = await calculate_domain(PK, L, generators.Q1, generators.H,
    header, api_id
  );
  // 2. T1 = Bbar * c + Abar * e^ + D * r1^
  const T1 = Bbar.multiply(c).add(Abar.multiply(eHat)).add(D.multiply(r1Hat));
  // 3. Bv = P1 + Q_1 * domain + H_i1 * msg_i1 + ... + H_iR * msg_iR
  let Bv = generators.P1;
  Bv = Bv.add(generators.Q1.multiply(domain));
  for(let i = 0; i < R; i++) {
    Bv = Bv.add(
      generators.H[disclosed_indexes[i]].multiply(disclosed_messages[i])
    );
  }
  // 4. T2 = Bv * c + D * r3^ + H_j1 * m^_j1 + ... +  H_jU * m^_jU
  let T2 = Bv.multiply(c);
  T2 = T2.add(D.multiply(r3Hat));
  for(let j = 0; j < U; j++) {
    T2 = T2.add(generators.H[undisclosed[j]].multiply(mHatU[j]));
  }
  // 5. return (Abar, Bbar, D, T1, T2, domain)

  // 3. challenge = ProofChallengeCalculate(init_res, disclosed_indexes,
  //     messages, ph, api_id)
  // 4. if cp != challenge, return INVALID
  const cv = await calculate_challenge(Abar, Bbar, D, T1, T2, disclosed_indexes,
    disclosed_messages, domain, ph, api_id);
  if(c !== cv) {
    // console.log('c is not equal to cv');
    return false;
  }
  // 5. if e(Abar, W) * e(Bbar, -BP2) != Identity_GT, return INVALID
  // 6. return VALID
  //if e(Abar, W) * e(Bbar, -P2) != Identity_GT, return INVALID
  // Compute item in G2
  const negP2 = bls.G2.ProjectivePoint.BASE.negate();
  // Compute items in GT, i.e., Fp12
  const ptGT1 = bls.pairing(Abar, W);
  const ptGT2 = bls.pairing(Bbar, negP2);
  let result = bls.fields.Fp12.mul(ptGT1, ptGT2);
  result = bls.fields.Fp12.finalExponentiate(result); // See noble BLS12-381
  return bls.fields.Fp12.eql(result, bls.fields.Fp12.ONE);
}

/**
 * Helper function to give the number of undisclosed messages in a proof. This
 * can be added to the number of disclosed messages to calculate the number of
 * generators needed in proof verification.
 *
 * @param {Uint8Array} proofOctets - Byte array containing the raw bytes of a
 * proof.
 * @returns {number} - The number of undisclosed messages, U.
 */
export function numUndisclosed(proofOctets) {
  let proof_result;
  try {
    proof_result = octets_to_proof(proofOctets);
  } catch{
    console.log('Problem with octets_to_proof');
    return false;
  }
  const {mHatU} = proof_result;
  return mHatU.length;
}
// General BBS related constants and functions

function octets_to_proof(octets) {
  // Recover (Abar, Bbar, D, e^, r1^, r3^, commitments, c)  from octets
  const min_length = 3 * POINT_LENGTH + 4 * SCALAR_LENGTH; //+ U * SCALAR_LENGTH
  if(octets.length < min_length) {
    throw new TypeError('octets_to_proof: bad proof length, too short');
  }
  if((octets.length - min_length) % SCALAR_LENGTH !== 0) {
    throw new TypeError('octets_to_proof: bad proof length');
  }
  const U = (octets.length - min_length) / SCALAR_LENGTH;
  let index = 0;
  const Abar_oct = octets.slice(0, POINT_LENGTH);
  const Abar = bls.G1.ProjectivePoint.fromHex(Abar_oct);
  index += POINT_LENGTH;
  const Bbar_oct = octets.slice(index, index + POINT_LENGTH);
  const Bbar = bls.G1.ProjectivePoint.fromHex(Bbar_oct);
  index += POINT_LENGTH;
  const D_oct = octets.slice(index, index + POINT_LENGTH);
  const D = bls.G1.ProjectivePoint.fromHex(D_oct);
  index += POINT_LENGTH;
  const eHat = os2ip(octets.slice(index, index + SCALAR_LENGTH));
  if(eHat < 0n || eHat >= rPrimeOrder) {
    throw new TypeError('octets_to_sig: bad eHat value');
  }
  index += SCALAR_LENGTH;
  const r1Hat = os2ip(octets.slice(index, index + SCALAR_LENGTH));
  if(r1Hat < 0n || r1Hat >= rPrimeOrder) {
    throw new TypeError('octets_to_sig: bad r1Hat value');
  }
  index += SCALAR_LENGTH;
  const r3Hat = os2ip(octets.slice(index, index + SCALAR_LENGTH));
  if(r3Hat < 0n || r3Hat >= rPrimeOrder) {
    throw new TypeError('octets_to_sig: bad r3Hat value');
  }
  index += SCALAR_LENGTH;
  const mHatU = [];
  for(let j = 0; j < U; j++) {
    const mHatj = os2ip(octets.slice(index, index + SCALAR_LENGTH));
    if(mHatj < 0n || mHatj >= rPrimeOrder) {
      throw new TypeError('octets_to_sig: bad mHatj value');
    }
    mHatU.push(mHatj);
    index += SCALAR_LENGTH;
  }
  const c = os2ip(octets.slice(index, index + SCALAR_LENGTH));
  if(c < 0n || c >= rPrimeOrder) {
    throw new TypeError('octets_to_sig: bad c value');
  }
  return {Abar, Bbar, D, eHat, r1Hat, r3Hat, mHatU, c};
}

// proof_to_octets(Abar, Bbar, D, eHat, r1Hat, r3Hat, mHatU, c);
function proof_to_octets(Abar, Bbar, D, eHat, r1Hat, r3Hat, mHatU, c) {
  let octets = Abar.toRawBytes(true);
  octets = concat(octets, Bbar.toRawBytes(true));
  octets = concat(octets, D.toRawBytes(true));
  octets = concat(octets, numberToBytesBE(eHat, SCALAR_LENGTH));
  octets = concat(octets, numberToBytesBE(r1Hat, SCALAR_LENGTH));
  octets = concat(octets, numberToBytesBE(r3Hat, SCALAR_LENGTH));
  for(const mHatj of mHatU) {
    octets = concat(octets, numberToBytesBE(mHatj, SCALAR_LENGTH));
  }
  octets = concat(octets, numberToBytesBE(c, SCALAR_LENGTH));
  return octets;
}

function signature_to_octets(A, e) {
  let octets = A.toRawBytes(true);
  octets = concat(octets, numberToBytesBE(e, SCALAR_LENGTH));
  return octets;
}

// We include L explicitly since the number of H_Points can be greater than L
// since we can reuse the generator information.
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

// (Abar, Bbar, D, T1, T2, R, i1, ..., iR, msg_i1, ..., msg_iR, domain)
async function calculate_challenge(Abar, Bbar, D, T1, T2, i_array, msg_array,
  domain, ph, api_id
) {
  const dst = new TextEncoder().encode(api_id + 'H2S_');
  const c_array = [
    {type: 'GPoint', value: Abar},
    {type: 'GPoint', value: Bbar},
    {type: 'GPoint', value: D},
    {type: 'GPoint', value: T1},
    {type: 'GPoint', value: T2},
    {type: 'NonNegInt', value: i_array.length},
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

/*
    The input element arraywill contain elements of the form
    {type: 'an elemType', value: thingy}
    elemTypes = ['PublicKey', 'NonNegInt', 'GPoint', 'Scalar',
    'PlainOctets', 'CipherID', 'ASCII'];
*/
function serialize(elem_array) {
  let octets = new Uint8Array();
  for(const element of elem_array) {
    switch(element.type) {
      case 'PublicKey':
        octets = concat(octets, element.value);
        break;
      case 'NonNegInt':
        octets = concat(octets, i2osp(element.value, 8));
        break;
      case 'GPoint':
        octets = concat(octets, element.value.toRawBytes(true));
        break;
      case 'Scalar':
        octets = concat(octets, numberToBytesBE(element.value, SCALAR_LENGTH));
        break;
      case 'PlainOctets':
        // TODO: check length
        octets = concat(
          octets,
          concat(i2osp(element.value.length, 8), element.value)
        );
        break;
      case 'CipherID':
        const te = new TextEncoder();
        octets = concat(octets, te.encode(element.value));
        break;
      case 'ASCII':
        let temp = new TextEncoder().encode(element.value);
        temp = concat(i2osp(temp.length, 8), temp);
        octets = concat(octets, temp);
        break;
      default:
        throw new Error(`bad type to encode for hash: type=${element.type}`);
    }
  }
  return octets;
}

export async function hash_to_scalar(msg_octets, dst, api_id) {
  // 1. uniform_bytes = expand_message(msg_octets, dst, expand_len)
  // 2. return OS2IP(uniform_bytes) mod r
  let uniform_bytes;
  if(api_id.includes(H2C_SUITE_SHA)) {
    uniform_bytes = await expand_message_xmd(msg_octets, dst, EXPAND_LEN,
      sha256);
  } else {
    uniform_bytes = expandMessageXOF(msg_octets, dst, EXPAND_LEN);
  }
  return os2ip(uniform_bytes) % rPrimeOrder;
}

/**
 * This function converts (hashes) byte array messages into scalars representing
 * the messages for use in signature/proof operations.
 *
 * @async
 * @param {Array} messages - Messages as an Array of Uint8Arrays, i.e., these
 * byte arrays not strings.
 * @param {string} api_id - The API ID for the signature suite.
 * @returns {Array} - An array of scalars (bigint) representing the messages.
 */
export async function messages_to_scalars(messages, api_id = API_ID_BBS_SHAKE) {
  // let ciphersuite_id = CIPHERSUITE_ID;
  // if(hashType === 'SHAKE-256') {
  //   ciphersuite_id = CIPHERSUITE_ID_SHAKE;
  // }
  const dst = new TextEncoder().encode(
    api_id + 'MAP_MSG_TO_SCALAR_AS_HASH_'
  );
  const scalars = [];
  for(let i = 0; i < messages.length; i++) {
    const msg = messages[i];
    const stuff = await hash_to_scalar(msg, dst, api_id);
    scalars.push(stuff);
  }
  return scalars;
}

/**
 * Prepares the "group G1 generators" used by the BBS signature suite.
 * These values can be reused in many calls to the sign, verify, proofGen, and
 * proofVerify functions. You must have enough generators for the number of
 * messages. You do not need to know what the "group G1" or a "generator" is!
 * These take a while to compute so we prepare them separately and reuse them.
 *
 * @async
 * @param {number} L - An integer that indicates the number of generators to be
 * created. This number must be large than the total number of messages in a
 * signature or proof.
 * @param {string} api_id - The API ID for the signature suite.
 * @returns {Array} - A array of group generators used by the signature/proof
 *  suite.
 */
export async function prepareGenerators(L, api_id) {
  // Compute P1, Q1, H1, ..., HL
  const generators = {H: []};
  const te = new TextEncoder(); // Used to convert to uint8Array, utf8 encoding
  const seed_dst = te.encode(api_id + 'SIG_GENERATOR_SEED_');
  const gen_dst_string = api_id + 'SIG_GENERATOR_DST_';
  const gen_seed = te.encode(api_id + 'MESSAGE_GENERATOR_SEED');
  let v;
  if(api_id.includes('SHA-256')) {
    v = await expand_message_xmd(gen_seed, seed_dst, EXPAND_LEN, sha256);
  } else {
    v = expandMessageXOF(gen_seed, seed_dst, EXPAND_LEN);
  }
  const count = L + 1;
  for(let i = 1; i <= count; i++) {
    if(api_id.includes('SHA-256')) {
      v = await expand_message_xmd(concat(v, i2osp(i, 8)), seed_dst, EXPAND_LEN,
        sha256);
    } else {
      v = expandMessageXOF(concat(v, i2osp(i, 8)), seed_dst, EXPAND_LEN);
    }
    let candidate;
    if(api_id.includes('SHA-256')) {
      candidate = await bls.G1.hashToCurve(v, {DST: gen_dst_string});
    } else {
      candidate = await bls.G1.hashToCurve(v, {
        DST: gen_dst_string,
        expand: 'xof',
        hash: shake256,
      });
    }
    if(i === 1) {
      generators.Q1 = candidate;
    } else {
      generators.H.push(candidate);
    }
  }
  // Generate P1. Per spec use the following values based on ciphersuite_id:
  // - seed_dst: ciphersuite_id || "H2G_HM2S_SIG_GENERATOR_SEED_"
  // - generator_dst: ciphersuite_id || "H2G_HM2S_SIG_GENERATOR_DST_"
  // - generator_seed: ciphersuite_id || "H2G_HM2S_BP_MESSAGE_GENERATOR_SEED"
  let ciphersuite_id;
  if(api_id.includes(CIPHERSUITE_ID_SHAKE)) {
    ciphersuite_id = CIPHERSUITE_ID_SHAKE;
  } else {
    ciphersuite_id = CIPHERSUITE_ID_SHA;
  }
  const gen_seed_P1 = te.encode(ciphersuite_id +
    'H2G_HM2S_BP_MESSAGE_GENERATOR_SEED');
  const seed_dst_P1 = te.encode(ciphersuite_id +
    'H2G_HM2S_SIG_GENERATOR_SEED_');
  const gen_dst_P1_string = ciphersuite_id + 'H2G_HM2S_SIG_GENERATOR_DST_';
  let candidate;
  if(api_id.includes('SHA-256')) {
    v = await expand_message_xmd(gen_seed_P1, seed_dst_P1, EXPAND_LEN, sha256);
    v = await expand_message_xmd(concat(v, i2osp(1, 8)), seed_dst_P1,
      EXPAND_LEN, sha256);
    candidate = await bls.G1.hashToCurve(v, {DST: gen_dst_P1_string});
  } else {
    v = expandMessageXOF(gen_seed_P1, seed_dst_P1, EXPAND_LEN);
    v = expandMessageXOF(concat(v, i2osp(1, 8)), seed_dst_P1, EXPAND_LEN);
    candidate = await bls.G1.hashToCurve(v, {
      DST: gen_dst_P1_string,
      expand: 'xof',
      hash: shake256,
    });
  }
  generators.P1 = candidate;
  return generators;
}

export function calculate_random_scalars(count) {
  // 1. for i in (1, ..., count):
  // 2.     r_i = OS2IP(get_random(expand_len)) mod r
  // 3. return (r_1, r_2, ..., r_count)
  const scalars = [];
  for(let i = 0; i < count; i++) {
    const r_i = os2ip(randomBytes(EXPAND_LEN)) % rPrimeOrder;
    scalars.push(r_i);
  }
  return scalars;
}

export async function seeded_random_scalars(seed, api_id, count) {
  // let ciphersuite_id = CIPHERSUITE_ID;
  // if(hashType === 'SHAKE-256') {
  //   ciphersuite_id = CIPHERSUITE_ID_SHAKE;
  // }
  const te = new TextEncoder();
  const MOCK_DST = te.encode(api_id + 'MOCK_RANDOM_SCALARS_DST_');
  // 1. out_len = expand_len * count
  const out_len = EXPAND_LEN * count;
  // 2. v = expand_message(SEED, dst, out_len)
  let v;
  if(api_id.includes('SHA-256')) {
    v = await expand_message_xmd(seed, MOCK_DST, out_len, sha256);
  } else {
    v = expandMessageXOF(seed, MOCK_DST, out_len);
  }
  // 3. if v is INVALID, return INVALID
  const scalars = [];
  // 4. for i in (1, ..., count):
  // 5.     start_idx = (i-1) * expand_len
  // 6.     end_idx = i * expand_len - 1
  // 7.     r_i = OS2IP(v[start_idx..end_idx]) mod r
  for(let i = 0; i < count; i++) {
    const tv = v.slice(i * EXPAND_LEN, (i + 1) * EXPAND_LEN);
    // console.log(`length tv: ${tv.length}`);
    const scalar_i = os2ip(tv) % rPrimeOrder;
    scalars[i] = scalar_i;
  }
  // 8. return (r_1, ...., r_count)
  return scalars;
}

function expandMessageXOF(msg, DST, len_in_bytes) {
  const DST_prime = concat(DST, i2osp(DST.length, 1));
  // console.log(bytesToHex(DST_prime))
  const msg_prime = concat(concat(msg, i2osp(len_in_bytes, 2)), DST_prime);
  // console.log(bytesToHex(msg_prime));
  // console.log(`Output length: ${len_in_bytes}`);
  return shake256(msg_prime, {dkLen: len_in_bytes});
}

function octets_to_sig(sig_octets) {
  if(sig_octets.length !== 80) {
    throw new TypeError('octets_to_sig: bad signature length');
  }
  const A_oct = sig_octets.slice(0, 48);
  const A = bls.G1.ProjectivePoint.fromHex(A_oct);
  const e = os2ip(sig_octets.slice(48, 80));
  if(e < 0n || e >= rPrimeOrder) {
    throw new TypeError('octets_to_sig: bad e value');
  }
  return {A, e};
}

// Some necessary utilities some borrowed others hacked

// Integer to Octet Stream borrowed from inside bls12-381 modified to
// handle larger length values
function i2osp(value, length) {
  // This check fails if length is 4 or greater since the integer raps
  // around in the browser
  // See https://www.w3schools.com/js/js_bitwise.asp caveat on 32 bit integers
  // if (value < 0 || value >= 1 << (8 * length)) {
  //     throw new Error(`bad I2OSP call: value=${value} length=${length}`);
  // }
  // This works for larger length values
  if(value < 0 || value >= 2 ** (8 * length)) {
    throw new Error(`bad I2OSP call: value=${value} length=${length}`);
  }
  const res = Array.from({length}).fill(0);
  for(let i = length - 1; i >= 0; i--) {
    res[i] = value & 0xff;
    value >>>= 8; // zero fill right shift. Doesn't work with BigInt
  }
  return new Uint8Array(res);
}

// Octet Stream to Integer (bytesToNumberBE)
export function os2ip(bytes) {
  let result = 0n;
  for(let i = 0; i < bytes.length; i++) {
    result <<= 8n;
    result += BigInt(bytes[i]);
  }
  return result;
}

// Strange that this doesn't exist...
function concat(buffer1, buffer2) {
  const tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
  for(let i = 0; i < buffer1.byteLength; i++) {
    tmp[i] = buffer1[i];
  }
  for(let i = 0; i < buffer2.byteLength; i++) {
    tmp[i + buffer1.byteLength] = buffer2[i];
  }
  return tmp;
}

// from noble but not exported
export function hexToBytes(hex) {
  if(typeof hex !== 'string') {
    throw new TypeError('hexToBytes: expected string, got ' + typeof hex);
  }
  if(hex.length % 2) {
    throw new Error('hexToBytes: received invalid unpadded hex');
  }
  const array = new Uint8Array(hex.length / 2);
  for(let i = 0; i < array.length; i++) {
    const j = i * 2;
    const hexByte = hex.slice(j, j + 2);
    if(hexByte.length !== 2) {
      throw new Error('Invalid byte sequence');
    }
    const byte = Number.parseInt(hexByte, 16);
    if(Number.isNaN(byte) || byte < 0) {
      throw new Error('Invalid byte sequence');
    }
    array[i] = byte;
  }
  return array;
}

const hexes = Array.from({length: 256}, (v, i) =>
  i.toString(16).padStart(2, '0')
);
export function bytesToHex(uint8a) {
  let hex = '';
  for(let i = 0; i < uint8a.length; i++) {
    hex += hexes[uint8a[i]];
  }
  return hex;
}
export function numberToHex(num, byteLength) {
  if(!byteLength) {
    throw new Error('byteLength target must be specified');
  }
  const hex = num.toString(16);
  const p1 = hex.length & 1 ? `0${hex}` : hex;
  return p1.padStart(byteLength * 2, '0');
}

export function numberToBytesBE(num, byteLength) {
  const res = hexToBytes(numberToHex(num, byteLength));
  if(res.length !== byteLength) {
    throw new Error('numberToBytesBE: wrong byteLength');
  }
  return res;
}
