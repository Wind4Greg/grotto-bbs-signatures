/* Single file BBS signature implementation */

/* Functions used in multiple BBS signature operations */
import { bls12_381 as bls } from '@noble/curves/bls12-381';
import { randomBytes } from './randomBytes.js';

const CIPHERSUITE_ID = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";
const PRF_LEN = 32;
const SCALAR_LENGTH = 32;
const EXPAND_LEN = 48;
const SEED_LEN = 48;
const POINT_LENGTH = 48;

/**
 * 
 * @param {Uint8Array of length 32} privateBytes 
 * @returns Uint8Array containing encoded public key in G2
 */
export function publicFromPrivate(privateBytes) {
    let pointPk = bls.G2.ProjectivePoint.fromPrivateKey(privateBytes);
    return pointPk.toRawBytes(true);
}

/**
 * 
 * @param {scalar bigInt} SK 
 * @param {Uint8Array compressed G2 point raw bytes} PK 
 * @param {Uint8Array default 0 length} header 
 * @param {array of scalars (bigInt)} messages 
 */
export async function sign(SK, PK, header, messages, generators) {
    // check that we have enough generators for the messages
    if (messages.length > generators.H.length) {
        throw new TypeError('Sign: not enough generators! string');
    }
    // elemTypes:"PublicKey", "NonNegInt", "GPoint", "Scalar", "PlainOctets", "CipherID", "ASCII"
    // dom_array = (PK, L, Q_1, Q_2, H_1, ..., H_L, ciphersuite_id, header)
    let L = messages.length;
    let dom_array = [
        { type: "PublicKey", value: PK }, { type: "NonNegInt", value: L },
        { type: "GPoint", value: generators.Q1 },
        { type: "GPoint", value: generators.Q2 },
    ];
    for (let i = 0; i < L; i++) {
        dom_array.push({ type: "GPoint", value: generators.H[i] })
    }
    dom_array.push({ type: "CipherID", value: CIPHERSUITE_ID });
    dom_array.push({ type: "PlainOctets", value: header });
    let dom_for_hash = encode_to_hash(dom_array);
    let dst = new TextEncoder().encode(CIPHERSUITE_ID + "H2S_");
    let [domain] = await hash_to_scalar(dom_for_hash, 1, dst);
    // e_s_for_hash = encode_for_hash((SK, domain, msg_1, ..., msg_L))
    let valArray = [{ type: "Scalar", value: SK }, { type: "Scalar", value: domain }];
    for (let i = 0; i < L; i++) {
        valArray.push({ type: "Scalar", value: messages[i] });
    }
    let e_s_for_hash = encode_to_hash(valArray);
    let [e, s] = await hash_to_scalar(e_s_for_hash, 2, dst);
    // B = P1 + Q_1 * s + Q_2 * domain + H_1 * msg_1 + ... + H_L * msg_L
    let B = generators.P1;
    B = B.add(generators.Q1.multiply(s));
    B = B.add(generators.Q2.multiply(domain));
    for (let i = 0; i < messages.length; i++) {
        B = B.add(generators.H[i].multiply(messages[i]));
    }
    // A = B * (1 / (SK + e))   # For this we need to work in Fr which noble-BLS12-381 provides
    let denom = bls.Fr.add(bls.Fr.create(SK), bls.Fr.create(e));
    let num = bls.Fr.inv(denom);
    let A = B.multiply(num);
    return signature_to_octets(A, e, s);
}

export async function verify(PK, signature, header, messages, generators) {
    let { A, e, s } = octets_to_sig(signature); // Get curve point and scalars
    // W = octets_to_pubkey(PK)
    let W = bls.G2.ProjectivePoint.fromHex(PK);
    // dom_array = (PK, L, Q_1, Q_2, H_1, ..., H_L, ciphersuite_id, header)
    let L = messages.length;
    let dom_array = [
        { type: "PublicKey", value: PK }, { type: "NonNegInt", value: L },
        { type: "GPoint", value: generators.Q1 },
        { type: "GPoint", value: generators.Q2 },
    ];
    for (let i = 0; i < L; i++) {
        dom_array.push({ type: "GPoint", value: generators.H[i] })
    }
    dom_array.push({ type: "CipherID", value: CIPHERSUITE_ID });
    dom_array.push({ type: "PlainOctets", value: header });
    let dom_for_hash = encode_to_hash(dom_array);
    let dst = new TextEncoder().encode(CIPHERSUITE_ID + "H2S_");
    let [domain] = await hash_to_scalar(dom_for_hash, 1, dst);
    // B = P1 + Q_1 * s + Q_2 * domain + H_1 * msg_1 + ... + H_L * msg_L
    let B = generators.P1;
    B = B.add(generators.Q1.multiply(s));
    B = B.add(generators.Q2.multiply(domain));
    for (let i = 0; i < messages.length; i++) {
        B = B.add(generators.H[i].multiply(messages[i]));
    }
    //  if e(A, W + P2 * e) * e(B, -P2) != Identity_GT, return INVALID otherwise return VALID
    // Compute items in G2
    let temp1G2 = W.add(bls.G2.ProjectivePoint.BASE.multiply(e));
    let temp2G2 = bls.G2.ProjectivePoint.BASE.negate();
    // Compute items in GT, i.e., Fp12
    let ptGT1 = bls.pairing(A, temp1G2);
    let ptGT2 = bls.pairing(B, temp2G2);
    let result = bls.Fp12.mul(ptGT1, ptGT2)
    result = bls.Fp12.finalExponentiate(result); // See noble BLS12-381
    return bls.Fp12.eql(result, bls.Fp12.ONE);
}

export async function proofGen(PK, signature, header, ph, messages, disclosed_indexes, generators) {
    // TODO: check indexes for correctness, i.e., bounds and such...
    let L = messages.length;
    let R = disclosed_indexes.length;
    let U = L - R;
    let allIndexes = [];
    for (let i = 0; i < L; i++) {
        allIndexes[i] = i;
    }
    let tempSet = new Set(allIndexes);
    for (let dis of disclosed_indexes) {
        tempSet.delete(dis);
    }
    let undisclosed = Array.from(tempSet); // Contains all the undisclosed indexes
    let { A, e, s } = octets_to_sig(signature); // Get curve point and scalars
    // check that we have enough generators for the messages
    if (messages.length > generators.H.length) {
        throw new TypeError('Sign: not enough generators! string');
    }
    // elemTypes:"PublicKey", "NonNegInt", "GPoint", "Scalar", "PlainOctets", "CipherID", "ASCII"
    // dom_array = (PK, L, Q_1, Q_2, H_1, ..., H_L, ciphersuite_id, header)
    let dom_array = [
        { type: "PublicKey", value: PK }, { type: "NonNegInt", value: L },
        { type: "GPoint", value: generators.Q1 },
        { type: "GPoint", value: generators.Q2 },
    ];
    for (let i = 0; i < L; i++) {
        dom_array.push({ type: "GPoint", value: generators.H[i] })
    }
    dom_array.push({ type: "CipherID", value: CIPHERSUITE_ID });
    dom_array.push({ type: "PlainOctets", value: header });
    // dom_for_hash = encode_for_hash(dom_array)
    let dom_for_hash = encode_to_hash(dom_array);
    let dst = new TextEncoder().encode(CIPHERSUITE_ID + "H2S_");
    let [domain] = await hash_to_scalar(dom_for_hash, 1, dst);
    // console.log(`domain: ${domain}`);
    // B = P1 + Q_1 * s + Q_2 * domain + H_1 * msg_1 + ... + H_L * msg_L
    let B = generators.P1;
    B = B.add(generators.Q1.multiply(s));
    B = B.add(generators.Q2.multiply(domain));
    for (let i = 0; i < messages.length; i++) {
        B = B.add(generators.H[i].multiply(messages[i]));
    }
    // 8.  (r1, r2, e~, r2~, r3~, s~) = hash_to_scalar(PRF(prf_len), 6)
    // 9.  (m~_j1, ..., m~_jU) = hash_to_scalar(PRF(prf_len), U)
    let [r1, r2, eTilde, r2Tilde, r3Tilde, sTilde] = await hash_to_scalar(randomBytes(PRF_LEN), 6, dst);
    let mTildeU = await hash_to_scalar(randomBytes(PRF_LEN), U, dst);
    // 11. r3 = r1 ^ -1 mod r
    let r3 = bls.Fr.inv(bls.Fr.create(r1));
    // 12. A' = A * r1
    let Aprime = A.multiply(r1);
    // 13. Abar = A' * (-e) + B * r1
    let negE = bls.Fr.neg(e);
    let Abar = Aprime.multiply(negE).add(B.multiply(r1));
    // 14. D = B * r1 + Q_1 * r2
    let D = B.multiply(r1).add(generators.Q1.multiply(r2));
    // 15. s' = r2 * r3 + s mod r
    let sPrime = bls.Fr.add(bls.Fr.mul(r2, r3), s);
    // 16. C1 = A' * e~ + Q_1 * r2~
    let C1 = Aprime.multiply(eTilde).add(generators.Q1.multiply(r2Tilde));
    // 17. C2 = D * (-r3~) + Q_1 * s~ + H_j1 * m~_j1 + ... + H_jU * m~_jU
    let neg_r3Tilde = bls.Fr.neg(r3Tilde);
    let C2 = D.multiply(neg_r3Tilde);
    C2 = C2.add(generators.Q1.multiply(sTilde));
    for (let j = 0; j < U; j++) {
        C2 = C2.add(generators.H[undisclosed[j]].multiply(mTildeU[j]));
    }
    // 18. c_array = (A', Abar, D, C1, C2, R, i1, ..., iR, msg_i1, ..., msg_iR, domain, ph)
    // // elemTypes:"PublicKey", "NonNegInt", "GPoint", "Scalar", "PlainOctets", "CipherID", "ASCII"
    let c_array = [{ type: "GPoint", value: Aprime }, { type: "GPoint", value: Abar },
    { type: "GPoint", value: D }, { type: "GPoint", value: C1 },
    { type: "GPoint", value: C2 }, { type: "NonNegInt", value: R }
    ];
    for (let iR of disclosed_indexes) {
        c_array.push({ type: "NonNegInt", value: iR });
    }
    for (let iR of disclosed_indexes) {
        c_array.push({ type: "Scalar", value: messages[iR] });
    }
    c_array.push({ type: "Scalar", value: domain });
    c_array.push({ type: "PlainOctets", value: ph });
    // 19. c_for_hash = encode_for_hash(c_array)
    // 20. if c_for_hash is INVALID, return INVALID
    let c_for_hash = encode_to_hash(c_array);
    // 21. c = hash_to_scalar(c_for_hash, 1)
    let [c] = await hash_to_scalar(c_for_hash, 1, dst);
    // 22. e^ = c * e + e~ mod r
    // console.log(`type c: ${typeof(c)}, e: ${typeof(e)}, eTilde: ${typeof(eTilde)}`);
    let eHat = bls.Fr.add(bls.Fr.mul(c, e), eTilde);
    // 23. r2^ = c * r2 + r2~ mod r
    let r2Hat = bls.Fr.add(bls.Fr.mul(c, r2), r2Tilde);
    // 24. r3^ = c * r3 + r3~ mod r
    let r3Hat = bls.Fr.add(bls.Fr.mul(c, r3), r3Tilde);
    // 25. s^ = c * s' + s~ mod r
    let sHat = bls.Fr.add(bls.Fr.mul(c, sPrime), sTilde);
    // 26. for j in (j1, ..., jU): m^_j = c * msg_j + m~_j mod r
    let mHatU = [];
    for (let j = 0; j < U; j++) {
        let mHatj = bls.Fr.add(bls.Fr.mul(c, messages[undisclosed[j]]), mTildeU[j]);
        mHatU.push(mHatj);
    }
    // 27. proof = (A', Abar, D, c, e^, r2^, r3^, s^, (m^_j1, ..., m^_jU))
    // 28. return proof_to_octets(proof)
    return proof_to_octets(Aprime, Abar, D, c, eHat, r2Hat, r3Hat, sHat, mHatU);
}

export async function proofVerify(PK, proof, L, header, ph, disclosed_messages, disclosed_indexes, generators) {
    let R = disclosed_indexes.length;
    let U = L - R;
    let allIndexes = [];
    for (let i = 0; i < L; i++) {
        allIndexes[i] = i;
    }
    let tempSet = new Set(allIndexes);
    for (let dis of disclosed_indexes) {
        tempSet.delete(dis);
    }
    let undisclosed = Array.from(tempSet); // Contains all the undisclosed indexes
    // (A', Abar, D, c, e^, r2^, r3^, s^, (m^_j1,...,m^_jU)) = proof_result
    let proof_result;
    try {
        proof_result = octets_to_proof(proof, U);
    } catch {
        return false;
    }
    let { Aprime, Abar, D, c, eHat, r2Hat, r3Hat, sHat, mHatU } = proof_result;
    // W = octets_to_pubkey(PK)
    let W = bls.G2.ProjectivePoint.fromHex(PK);
    // dom_array = (PK, L, Q_1, Q_2, H_1, ..., H_L, ciphersuite_id, header)
    let dom_array = [
        { type: "PublicKey", value: PK }, { type: "NonNegInt", value: L },
        { type: "GPoint", value: generators.Q1 },
        { type: "GPoint", value: generators.Q2 },
    ];
    for (let i = 0; i < L; i++) {
        dom_array.push({ type: "GPoint", value: generators.H[i] })
    }
    dom_array.push({ type: "CipherID", value: CIPHERSUITE_ID });
    dom_array.push({ type: "PlainOctets", value: header });
    let dom_for_hash = encode_to_hash(dom_array);
    let dst = new TextEncoder().encode(CIPHERSUITE_ID + "H2S_");
    let [domain] = await hash_to_scalar(dom_for_hash, 1, dst);
    // C1 = (Abar - D) * c + A' * e^ + Q_1 * r2^
    let C1 = Abar.subtract(D).multiply(c).add(Aprime.multiply(eHat)).add(generators.Q1.multiply(r2Hat));
    // T = P1 + Q_2 * domain + H_i1 * msg_i1 + ... + H_iR * msg_iR
    let T = generators.P1.add(generators.Q2.multiply(domain));
    for (let i = 0; i < R; i++) {
        T = T.add(generators.H[disclosed_indexes[i]].multiply(disclosed_messages[i]));
    }
    // C2 = T * c - D * r3^ + Q_1 * s^ + H_j1 * m^_j1 + ... + H_jU * m^_jU
    let C2 = T.multiply(c).subtract(D.multiply(r3Hat)).add(generators.Q1.multiply(sHat));
    for (let j = 0; j < U; j++) {
        C2 = C2.add(generators.H[undisclosed[j]].multiply(mHatU[j]));
    }
    // 13. cv_array = (A', Abar, D, C1, C2, R, i1, ..., iR, msg_i1, ..., msg_iR, domain, ph)
    // 14. cv_for_hash = encode_for_hash(cv_array)
    // 15. if cv_for_hash is INVALID, return INVALID
    // 16. cv = hash_to_scalar(cv_for_hash, 1)
    // 17. if c != cv, return INVALID
    let cv_array = [{ type: "GPoint", value: Aprime }, { type: "GPoint", value: Abar },
    { type: "GPoint", value: D }, { type: "GPoint", value: C1 }, { type: "GPoint", value: C2 },
    { type: "NonNegInt", value: R },
    ];
    for (let index of disclosed_indexes) {
        cv_array.push({ type: "NonNegInt", value: index });
    }
    for (let msg of disclosed_messages) {
        cv_array.push({ type: "Scalar", value: msg });
    }
    cv_array.push({ type: "Scalar", value: domain });
    cv_array.push({ type: "PlainOctets", value: ph });
    let cv_for_hash = encode_to_hash(cv_array);
    let [cv] = await hash_to_scalar(cv_for_hash, 1, dst);
    if (c !== cv) {
        // console.log("c is not equal to cv");
        return false;
    }
    // 18. if A' == Identity_G1, return INVALID
    if (Aprime.equals(bls.G1.ProjectivePoint.ZERO)) {
        console.log("Aprime is the identity in G1");
        return false;
    }
    // 19. if e(A', W) * e(Abar, -P2) != Identity_GT, return INVALID else return VALID
    // Compute item in G2
    let negP2 = bls.G2.ProjectivePoint.BASE.negate();
    // Compute items in GT, i.e., Fp12
    let ptGT1 = bls.pairing(Aprime, W);
    let ptGT2 = bls.pairing(Abar, negP2);
    let result = bls.Fp12.mul(ptGT1, ptGT2)
    result = bls.Fp12.finalExponentiate(result); // See noble BLS12-381
    return bls.Fp12.eql(result, bls.Fp12.ONE);
}

// General BBS related constants and functions

function octets_to_proof(octets, U) {
    // recover (A', Abar, D, c, e^, r2^, r3^, s^, (m^_j1,...,m^_jU)) from octets
    let expected_length = 3 * POINT_LENGTH + 5 * SCALAR_LENGTH + U * SCALAR_LENGTH;
    if (octets.length !== expected_length) {
        throw new TypeError('octets_to_proof: bad proof length');
    }
    let index = 0;
    let Aprime_oct = octets.slice(0, POINT_LENGTH);
    let Aprime = bls.G1.ProjectivePoint.fromHex(Aprime_oct);
    index += POINT_LENGTH;
    let Abar_oct = octets.slice(index, index + POINT_LENGTH);
    let Abar = bls.G1.ProjectivePoint.fromHex(Abar_oct);
    index += POINT_LENGTH;
    let D_oct = octets.slice(index, index + POINT_LENGTH);
    let D = bls.G1.ProjectivePoint.fromHex(D_oct);
    index += POINT_LENGTH;
    let c = os2ip(octets.slice(index, index + SCALAR_LENGTH));
    if (c < 0n || c >= bls.CURVE.r) {
        throw new TypeError('octets_to_sig: bad c value');
    }
    index += SCALAR_LENGTH;
    let eHat = os2ip(octets.slice(index, index + SCALAR_LENGTH));
    if (eHat < 0n || eHat >= bls.CURVE.r) {
        throw new TypeError('octets_to_sig: bad eHat value');
    }
    index += SCALAR_LENGTH;
    let r2Hat = os2ip(octets.slice(index, index + SCALAR_LENGTH));
    if (r2Hat < 0n || r2Hat >= bls.CURVE.r) {
        throw new TypeError('octets_to_sig: bad r2Hat value');
    }
    index += SCALAR_LENGTH;
    let r3Hat = os2ip(octets.slice(index, index + SCALAR_LENGTH));
    if (r3Hat < 0n || r3Hat >= bls.CURVE.r) {
        throw new TypeError('octets_to_sig: bad r3Hat value');
    }
    index += SCALAR_LENGTH;
    let sHat = os2ip(octets.slice(index, index + SCALAR_LENGTH));
    if (sHat < 0n || sHat >= bls.CURVE.r) {
        throw new TypeError('octets_to_sig: bad sHat value');
    }
    index += SCALAR_LENGTH;
    let mHatU = [];
    for (let j = 0; j < U; j++) {
        let mHatj = os2ip(octets.slice(index, index + SCALAR_LENGTH));
        if (mHatj < 0n || mHatj >= bls.CURVE.r) {
            throw new TypeError('octets_to_sig: bad mHatj value');
        }
        mHatU.push(mHatj);
        index += SCALAR_LENGTH;
    }
    return { Aprime, Abar, D, c, eHat, r2Hat, r3Hat, sHat, mHatU };
}

function proof_to_octets(Aprime, Abar, D, c, eHat, r2Hat, r3Hat, sHat, mHatU) {
    let octets = Aprime.toRawBytes(true);
    octets = concat(octets, Abar.toRawBytes(true));
    octets = concat(octets, D.toRawBytes(true));
    octets = concat(octets, numberToBytesBE(c, SCALAR_LENGTH));
    octets = concat(octets, numberToBytesBE(eHat, SCALAR_LENGTH));
    octets = concat(octets, numberToBytesBE(r2Hat, SCALAR_LENGTH));
    octets = concat(octets, numberToBytesBE(r3Hat, SCALAR_LENGTH));
    octets = concat(octets, numberToBytesBE(sHat, SCALAR_LENGTH));
    for (let mHatj of mHatU) {
        octets = concat(octets, numberToBytesBE(mHatj, SCALAR_LENGTH));
    }
    return octets;
}

function signature_to_octets(A, e, s) {
    let octets = A.toRawBytes(true);
    octets = concat(octets, numberToBytesBE(e, SCALAR_LENGTH));
    octets = concat(octets, numberToBytesBE(s, SCALAR_LENGTH));
    return octets;
}

/* 
    For my implementation the input element array will contain elements of the form
    {type: "an elemType", value: thingy}
    elemTypes = ["PublicKey", "NonNegInt", "GPoint", "Scalar", "PlainOctets", "CipherID", "ASCII"];

*/
function encode_to_hash(elem_array) {
    let octets = new Uint8Array();
    for (let element of elem_array) {
        switch (element.type) {
            case "PublicKey":
                octets = concat(octets, element.value);
                break;
            case "NonNegInt":
                octets = concat(octets, i2osp(element.value, 8));
                break;
            case "GPoint":
                octets = concat(octets, element.value.toRawBytes(true));
                break;
            case "Scalar":
                octets = concat(octets, numberToBytesBE(element.value, SCALAR_LENGTH));
                break;
            case "PlainOctets":
                // TODO: check length
                octets = concat(octets, concat(i2osp(element.value.length, 8), element.value));
                break;
            case "CipherID":
                let te = new TextEncoder();
                octets = concat(octets, te.encode(element.value));
                break;
            case "ASCII":
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

export async function hash_to_scalar(msg_octets, count, dst) {
    const len_in_bytes = count * EXPAND_LEN;
    let t = 0;
    let have_scalars = false;
    let scalars = [];
    while (!have_scalars) {
        let msg_prime = concat(msg_octets, concat(i2osp(t, 1), i2osp(count, 4)));
        let uniform_bytes = await bls.utils.expandMessageXMD(msg_prime, dst, len_in_bytes);
        have_scalars = true;
        for (let i = 0; i < count; i++) {
            let tv = uniform_bytes.slice(i * EXPAND_LEN, (i + 1) * EXPAND_LEN);
            // console.log(`length tv: ${tv.length}`);
            let scalar_i = os2ip(tv) % bls.CURVE.r;
            scalars[i] = scalar_i;
            if (scalar_i === 0n) {
                have_scalars = false;
            }
        }
        t++;
    }
    return scalars;
}

export async function messages_to_scalars(messages) {
    const dst = new TextEncoder().encode(CIPHERSUITE_ID + "MAP_MSG_TO_SCALAR_AS_HASH_");
    let scalars = [];
    for (let i = 0; i < messages.length; i++) {
        let msg = messages[i];
        // Need to "encode to hash" before feeding the message to hash to scalar
        // For a message in octets they use: el_octs = I2OSP(length(el), 8) || el
        let encode_for_hash = concat(i2osp(msg.length, 8), msg)
        let stuff = await hash_to_scalar(encode_for_hash, 1, dst);
        scalars.push(stuff[0]);
    }
    return scalars;
}

export async function prepareGenerators(L) {
    // Compute P1, Q1, Q2, H1, ..., HL
    let generators = { H: [] };
    let te = new TextEncoder(); // Used to convert string to uint8Array, utf8 encoding
    const seed_dst = te.encode(CIPHERSUITE_ID + "SIG_GENERATOR_SEED_");
    const gen_dst_string = CIPHERSUITE_ID + "SIG_GENERATOR_DST_";
    const gen_seed = te.encode("BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_MESSAGE_GENERATOR_SEED");
    let v = await bls.utils.expandMessageXMD(gen_seed, seed_dst, SEED_LEN);
    let count = L + 2;
    let n = 1;
    for (let i = 0; i < count; i++) {
        v = await bls.utils.expandMessageXMD(concat(v, i2osp(n, 4)), seed_dst, SEED_LEN);
        n = n + 1;
        let candidate = await bls.hashToCurve.G1.hashToCurve(v, { DST: gen_dst_string });
        if (i === 0) {
            generators.Q1 = candidate;
        } else if (i === 1) {
            generators.Q2 = candidate;
        } else {
            generators.H.push(candidate);
        }
    }
    // Generate P1
    const gen_seed_P1 = te.encode("BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_BP_MESSAGE_GENERATOR_SEED");
    v = await bls.utils.expandMessageXMD(gen_seed_P1, seed_dst, SEED_LEN);
    v = await bls.utils.expandMessageXMD(concat(v, i2osp(1, 4)), seed_dst, SEED_LEN);
    let candidate = await bls.hashToCurve.G1.hashToCurve(v, { DST: gen_dst_string });
    generators.P1 = candidate;
    return generators;
}

function octets_to_sig(sig_octets) {
    if (sig_octets.length !== 112) {
        throw new TypeError('octets_to_sig: bad signature length');
    }
    let A_oct = sig_octets.slice(0, 48);
    let A = bls.G1.ProjectivePoint.fromHex(A_oct);
    let e = os2ip(sig_octets.slice(48, 80));
    if (e < 0n || e >= bls.CURVE.r) {
        throw new TypeError('octets_to_sig: bad e value');
    }
    let s = os2ip(sig_octets.slice(80, 112));
    if (s < 0n || s >= bls.CURVE.r) {
        throw new TypeError('octets_to_sig: bad s value');
    }
    return { A, e, s };
}

// Some necessary utilities some borrowed others hacked

// Integer to Octet Stream borrowed from inside bls12-381 modified to handle larger
// length values
function i2osp(value, length) {
    // This check fails if length is 4 or greater since the integer raps around in the browser
    // See https://www.w3schools.com/js/js_bitwise.asp caveat on 32 bit integers
    // if (value < 0 || value >= 1 << (8 * length)) {
    //     throw new Error(`bad I2OSP call: value=${value} length=${length}`);
    // }
    // This works for larger length values
    if (value < 0 || value >= 2 ** (8 * length)) {
        throw new Error(`bad I2OSP call: value=${value} length=${length}`);
    }
    const res = Array.from({ length }).fill(0);
    for (let i = length - 1; i >= 0; i--) {
        res[i] = value & 0xff;
        value >>>= 8; // zero fill right shift. Doesn't work with BigInt
    }
    return new Uint8Array(res);
}

// Octet Stream to Integer (bytesToNumberBE)
export function os2ip(bytes) {
    let result = 0n;
    for (let i = 0; i < bytes.length; i++) {
        result <<= 8n;
        result += BigInt(bytes[i]);
    }
    return result;
}

// Strange that this doesn't exist...
function concat(buffer1, buffer2) {
    let tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
    for (let i = 0; i < buffer1.byteLength; i++) tmp[i] = buffer1[i];
    for (let i = 0; i < buffer2.byteLength; i++) tmp[i + buffer1.byteLength] = buffer2[i];
    return tmp;
};

// from noble but not exported
export function hexToBytes(hex) {
    if (typeof hex !== 'string') {
        throw new TypeError('hexToBytes: expected string, got ' + typeof hex);
    }
    if (hex.length % 2) throw new Error('hexToBytes: received invalid unpadded hex');
    const array = new Uint8Array(hex.length / 2);
    for (let i = 0; i < array.length; i++) {
        const j = i * 2;
        const hexByte = hex.slice(j, j + 2);
        if (hexByte.length !== 2) throw new Error('Invalid byte sequence');
        const byte = Number.parseInt(hexByte, 16);
        if (Number.isNaN(byte) || byte < 0) throw new Error('Invalid byte sequence');
        array[i] = byte;
    }
    return array;
}

const hexes = Array.from({ length: 256 }, (v, i) => i.toString(16).padStart(2, '0'));
export function bytesToHex(uint8a) {
    let hex = '';
    for (let i = 0; i < uint8a.length; i++) {
        hex += hexes[uint8a[i]];
    }
    return hex;
}
function numberToHex(num, byteLength) {
    if (!byteLength) throw new Error('byteLength target must be specified');
    const hex = num.toString(16);
    const p1 = hex.length & 1 ? `0${hex}` : hex;
    return p1.padStart(byteLength * 2, '0');
}

function numberToBytesBE(num, byteLength) {
    const res = hexToBytes(numberToHex(num, byteLength));
    if (res.length !== byteLength) throw new Error('numberToBytesBE: wrong byteLength');
    return res;
}
