# JavaScript BBS Signatures

This repository contains an all JavaScript implementation of the emerging BBS+ digital 
signature standard being developed in conjunction with the 
[Decentralized Identity Foundation (DIF)](https://identity.foundation/) and the [Crypto Forum Research Group (CFRG) of the IRTF](https://datatracker.ietf.org/rg/cfrg/about/).

You can find the latest draft specification at [The BBS Signature Scheme (DIF)](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html) this work then feeds into the IRTF draft which is available at [draft-irtf-cfrg-bbs-signatures](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/).

Note that there are other draft implementations available notably in Rust, Typescript, etc... This is a *JavaScript only* implementation with a single dependency on the [noble-curves](https://github.com/paulmillr/noble-curves) project which has a single dependency on the [noble-hash](https://github.com/paulmillr/noble-hashes) project. This implementation can be used with Node.js or in the browser. We provide Node.js based example code and you can see our [BBS Signature Demo](https://www.grotto-networking.com/BBSDemo/) where we use this library in the browser to demonstrate interactively the properties of BBS signatures.

## BBS Signature Basics

BBS signatures are different from other common digital signatures schemes such as [EdDSA](https://en.wikipedia.org/wiki/EdDSA) or [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm) in that it supports:

1. The signing of multiple messages at a time, rather than a single message.
2. A single short signature covering all the messages.
3. The ability to derive a secondary signature, called a *proof* in BBS terminology, that may choose not to disclose some of the messages in the original signature. This is called *selective disclosure*.
4. The digital *proofs* generated in the previous section are *unlinkable* to each other in the cryptographic sense, and cannot be used for tracking. Note that this does not apply to any information disclosed.

Both the original *signature* and any *proofs* generated are verified with the original issuers *public key*.  The contents of individual messages covered by a signature may not be changed, nor can new messages be added to a *proof* only messages can be withheld from a *proof* and still have the *proof* verify.

One prime example of the use of BBS signatures is in a three party *issuer*, *holder*, *verifier* model. For example suppose the issuer is the department of motor vehicles (DMV) and wants to issue the digital equivalent of a drivers license which contains an assortment of information. A fictitious set of information is shown below in JSON format for a **tree** living in northern California:

``` json
[   "FirstName: Sequoia",
    "LastName: Sempervirens",
    "Address: Jedediah Smith Redwoods State Park, California",
    "Date of Birth: 1200/03/21",
    "Height: 296 feet",
    "Eyes: None",
    "Hair: Brown bark, green needles",
    "Picture: Encoded photo",
    "License Class: None, Trees can't drive" ]
```

The DMV would use its secret key to produce a signature on this list of *messages*. It would then return to the *holder*, the aforementioned tree in out case, a bundle of information containing the signature, i.e., something like:

```json
{
  "publicKey": "b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7",
  "header": "11223344556677889900aabbccddeeff",
  "messages": [
    "FirstName: Sequoia",
    "LastName: Sempervirens",
    "Address: Jedediah Smith Redwoods State Park, California",
    "Date of Birth: 1200/03/21",
    "Height: 296 feet",
    "Eyes: None",
    "Hair: Brown bark, green needles",
    "Picture: Encoded photo",
    "License Class: None, Trees can't drive"
  ],
  "signature": "94bb93062e05bc702d0ab222b861fd0311533d6dcbcad4050e45dd2392de951a912915af08bd87b2284807432245f9960e1f59680a59cd9fae490dee659d63fd3922a728e2ba3ee33db6bcc806ec2cea3d7264489a42ca09deeac7ca88b1811c2158b51d81560832daf6a0000037a87a"
}
```

Note that this "document" contains a lot of potentially sensitive information. Hence should be sent securely from the *issuer* to the *holder* .

Now suppose that the tree needs to prove its age, e.g., in order to gain entrance to a club or bar, but doesn't want to divulge any extra information besides the minimum necessary, i.e., it just wants to show the following to the bouncer at the door in a verifiable manner:

``` json
[    "Date of Birth: 1200/03/21",
    "Picture: Encoded photo" ]
```

It then uses the BBS proof generation algorithm to generate proof information such as:

```json
{
  "pk": "b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7",
  "header": "11223344556677889900aabbccddeeff",
  "ph": "",
  "disclosedIndexes": [
    3,
    7
  ],
  "disclosedMsgs": [
    "Date of Birth: 1200/03/21",
    "Picture: Encoded photo"
  ],
  "proof": "8432472ce9cb174043856753306c290d87ecc8564038d34f18f5ac0127166aefd2e0c67b680285aff3401efc0c834a9ca133d85e8695d9085847c5d537cda5c37740df5d9eb5abf3d8e5f1242336d01eaf11dd80a06efd43e887ade2c3f5352ca8c53d8b7217d90c46af1f45a70ebeff512e6dc689bea361c91c2d1bc38b063ae78958d6e3a09d88a3cd3d78bc94c6c96f8788dad9c17e8afac3e0bb1a8c2e83f6c3d718c723ea36a06c9ac0b81561b66bacbf68b56ff09007df6b5258f36eb2ff1886e081702b829cd43da22510e1b35f07bc316f391f88807843d9a81ccfd42731196f5d3ac377c0679e7a0e58d30a5529e7d04bc350769bbe44d26416a77b7d799594e570370c649ddfbabbfc3e830e223ba53d86b19a9a3291038e425419af90f5ecd9c25d309cf6ce17b8339177363eb113a065b853cd4a6b47ff8b04ac7799fb931f4a42d754685c81852c34734aba447ec2a414df702e66dc67570b4603d2cd1f0af406925e4525738fbd4b8a4799d9fd6cd0a2c7761f49c76cb048f004cf09939621a7368da2ae5ac671b16a00f108fd57002bd835c9760758ef11f6b074ab40e7e47eb3fc31ecb1af00cf033c8dd2cfba0ea4d36388d9f15f8e58813988abe14b89075b37a3caa98cb4328e4daf98253ce16b1f4152358ef86f34695997086a1927f67fe69d7df94391a3661a9cd0340cf5618d9334f97cf6db5f25c203b55c866a014bc7981668fd208f55"
}
```

The bouncer at the door, the *verifier*, verifies this against the DMV's public key, i.e., the two messages disclosed were part of the orginal signed information and have not been modified.

Now suppose this tree is very thirsty and visits another bar, given California's issue with drought the next bar states it will only serve trees from a state or national parks. So the tree includes its address information as well as its photo and date of birth as follows:

``` json
[   "Address: Jedediah Smith Redwoods State Park, California",
    "Date of Birth: 1200/03/21",
    "Picture: Encoded photo" ]
```

It produces another BBS proof such as:

```json
{
  "pk": "b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7",
  "header": "11223344556677889900aabbccddeeff",
  "ph": "",
  "disclosedIndexes": [
    2,
    3,
    7
  ],
  "disclosedMsgs": [
    "Address: Jedediah Smith Redwoods State Park, California",
    "Date of Birth: 1200/03/21",
    "Picture: Encoded photo"
  ],
  "proof": "80c4b1301cd5964e1e69fd1a95d074fb30b085a733ae56d4bc427da89dfaf9dc63bf32e6d5d027d9ba6d3f59091aeb8e92e3baead45b9be6d501013478d4fbdd6cdbf637f201bd2c8c840cc55b2b33562e6429c88b96866e0ca86ce242408e8aaf3abb41d8c89bf436058504f43f8e7f31bec5a28a571666421201971341e731cafba531188d67f40553166c616a7c4839f7a605b3a774c158e1a45841d1eb07bd8534390010027f14bae9dc59bd75a63b6b532940d1ea98bdfb2354bf25b464f8b685fd4723aca13fbb58a5b3c8a1f143cba92acda6a731ba876b12b55b4c1fffa79699d3cc3f271f27b4a34ef4b356582147fdd19477c9bd9cfc7ba270de1bbe3c68038df39bebc289e265008631720b17aa4ca2bc89769f791b78bec9bcf7b19886f14130a232f7368649ea2fa2c843ecb9014ba4d622e80cef0fcbbc557aad02e3e5fac75569e6d0428662034ba93c2a50c4c17336656d4b44c3d9170e22460f699b514af2583e9011877443d30d50515db20845242b2d55a0a8960ae4b19cb6604bca7c47cd3fbef486a0ed76953eb450096123121826fa12a5b45a7a57554d92ab1d6b0c9e1df880504093f7a87159173ade25480fdce339611c96ad0dcf8b83543bbded15b21af56f8aff918957743e4ca81a5113be17b0a834807b374df76a1196b3152cca3646acc7055667"
}
```

Which the bartender at the second bar can verify with the DMV's public key. By *unlinkable* we mean the cryptographic *proof* field in these two *proofs* are uncorrelated and can't be used to track the tree from bar to bar. The tree, however, has disclosed its "date of birth" and "photo" to both bars which could be used for tracking purpose.

You may have noticed that the proofs in these two examples have different sizes. Currently BBS *signatures* have a size of 112 bytes, while BBS *proofs* have a size of $304 + U*32$ bytes where *U* is the number of undisclosed messages. We say currently since [new work](https://eprint.iacr.org/2023/275) may reduce these numbers a bit while preserving security properties.

## Library Usage

### Key Generation

For signing a *secret* (also known as a private) key is needed. For signature and proof verification the verifiers need the corresponding *public* key. A recomended procedure for deriving an appropriate secret key from some initial random bytes is given in the BBS specification and available via the `keyGen()` function. See the [KeyGenExample.js](examples/KeyGenExample.js) file for details.

```javascript
import {bytesToHex, keyGen, publicFromPrivate} from '@grottonetworking/bbs-signatures';
import crypto from 'crypto';

const bytesLength = 40; // >= 32 bytes
// Generate random initial key material -- Node.js
const keyMaterial = new Uint8Array(crypto.randomBytes(bytesLength).buffer);
const keyInfo = new TextEncoder().encode('BBS-Example Key info');
const sk_bytes = await keyGen(keyMaterial, keyInfo);
console.log(`Private key, length ${sk_bytes.length}, (hex):`);
console.log(bytesToHex(sk_bytes));
const pub_bytes = publicFromPrivate(sk_bytes);
console.log(`Public key, length ${pub_bytes.length}, (hex):`);
console.log(bytesToHex(pub_bytes));
```

### Message Encoding

Since BBS works works with multiple *messages* the encoding (really cryptographic processing) of the messages is done as separate step. This is accomplished with the `messages_to_scalars()` function. For example:

```javascript
import {messages_to_scalars, numberToHex} from '@grottonetworking/bbs-signatures';

const messages = [
  'FirstName: Sequoia',
  'LastName: Sempervirens',
  'Address: Jedediah Smith Redwoods State Park, California',
  'Date of Birth: 1200/03/21',
  'Height: 296 feet',
  'Eyes: None',
  'Hair: Brown bark, green needles',
  'Picture: Encoded photo',
  'License Class: None, Trees can\'t drive'
];

const te = new TextEncoder(); // To convert strings to byte arrays
const messagesOctets = messages.map(msg => te.encode(msg));
const msg_scalars = await messages_to_scalars(messagesOctets);
for(let i = 0; i < messages.length; i++) {
  console.log(`msg ${i} ${messages[i]}`);
  console.log(`scalar (hex): ${numberToHex(msg_scalars[i], 32)}`);
}
```

### Generator Preparation

All major BBS operations (signing, signature verification, proof generation, and proof verification) require the use of cryptographic group "generators". There need to be as many "generators" as messages that are or were originally signed. These take a bit of time to compute but can be reused in all the aforementioned operations and do not take up too much space. Hence we break out the preparation of these "generators" into a separate step via the `prepareGenerators()` function. 

Below we show an example that creates the generators and these can be confirmed against the "message generator" test vectors given in the specification. You would never have a need to look at these in a real application.

```javascript
import {prepareGenerators} from '@grottonetworking/bbs-signatures';

const L = 10;
const gens = await prepareGenerators(L); // Default SHA-256 hash
console.log(`Q1:${gens.Q1.toHex(true)}`); // Elliptic point to compressed hex
console.log(`Q2:${gens.Q2.toHex(true)}`);
for(let i = 0; i < gens.H.length; i++) {
  console.log(`H${i}:${gens.H[i].toHex(true)}`);
}
```

### Signing and Verifying

Generate a signature for a list of messages we need the following: (1) private/public key pair, (2) list of encoded messages, (3) prepared generators. Optionally a "header" (as a byte array) maybe supplied that contains context or application information. To verify a signature we need all of the above but not the private key. This is shown below with the full example given in [TreeDMVExample.js](examples/TreeDMVExample.js). An additional example is given in [SignVerifyExaple.js](examples/SignVerifyExample.js).

```javascript
// Excerp from TreeDMVExample.js
const header = hexToBytes('11223344556677889900aabbccddeeff');
const signature = await sign(sk_bytes, pk_bytes, header, msg_scalars, gens);
console.log('Signature:');
console.log(bytesToHex(signature));

const verified = await verify(pk_bytes, signature, header, msg_scalars, gens);
console.log(`Algorithm verified: ${verified}`);
```

### Proof Generation and Verification

For proof generation the *holder* needs the signature, messages, and public key. Then they need to decide which messages they want to disclose. This can be done in code as shown below with the full example given in [TreeDMVExample.js](examples/TreeDMVExample.js). An additional example is contained in [ProofGenVerifyExample.js](examples/ProofGenVerifyExample.js).

```javascript
const ph = new Uint8Array();
const disclosed_indexes = [3, 7]; // Selective disclosure
const proof = await proofGen(pk_bytes, signature, header, ph, msg_scalars,
  disclosed_indexes, gens);
console.log(`Proof for selective disclosure of messages ${disclosed_indexes}:`);
console.log(bytesToHex(proof));

const disclosedMsgs = msg_scalars.filter(
  (m, i) => disclosed_indexes.includes(i)); // Only the disclosed messages!
const proofValid = await proofVerify(pk_bytes, proof, header, ph, disclosedMsgs,
  disclosed_indexes, gens);
console.log(`Proof verified: ${proofValid}`);
```

# API

## Functions

<dl>
<dt><a href="#keyGen">keyGen(key_material, key_info, key_dst, hashType)</a> ⇒ <code>Uint8Array</code></dt>
<dd><p>Produces an appropriate secret key starting from initial key material. This
procedure enhances the entropy of the key material but is deterministic so
initial key material must be kept secret.</p>
</dd>
<dt><a href="#publicFromPrivate">publicFromPrivate(privateBytes)</a> ⇒ <code>Uint8Array</code></dt>
<dd></dd>
<dt><a href="#sign">sign(SK, PK, header, messages, generators, hashType)</a></dt>
<dd><p>Creates a BBS signature over a list of &quot;messages&quot;.</p>
</dd>
<dt><a href="#verify">verify(PK, signature, header, messages, generators, hashType)</a> ⇒ <code>boolean</code></dt>
<dd><p>Verify a BBS signature against a public key.</p>
</dd>
<dt><a href="#proofGen">proofGen(PK, signature, header, ph, messages, disclosed_indexes, generators, hashType, rand_scalars)</a> ⇒ <code>Uint8Array</code></dt>
<dd><p>Generates an unlinkable, selective disclosure proof based on a
signature and message set, and related information.</p>
</dd>
<dt><a href="#proofVerify">proofVerify(PK, proof, header, ph, disclosed_messages, disclosed_indexes, generators, hashType)</a> ⇒ <code>boolean</code></dt>
<dd><p>Verifies a previously generated proof against original signers public key,
and additional information.</p>
</dd>
<dt><a href="#numUndisclosed">numUndisclosed(proofOctets)</a> ⇒ <code>number</code></dt>
<dd><p>Helper function to give the number of undisclosed messages in a proof. This
can be added to the number of disclosed messages to calculate the number of
generators needed in proof verification.</p>
</dd>
<dt><a href="#messages_to_scalars">messages_to_scalars(messages, hashType)</a> ⇒ <code>Array</code></dt>
<dd><p>This function converts (hashes) byte array messages into scalars representing
the messages for use in signature/proof operations.</p>
</dd>
<dt><a href="#prepareGenerators">prepareGenerators(L, hashType)</a> ⇒ <code>Array</code></dt>
<dd><p>Prepares the &quot;group G1 generators&quot; used by the BBS signature suite.
These values can be reused in many calls to the sign, verify, proofGen, and
proofVerify functions. You must have enough generators for the number of
messages. You do not need to know what the &quot;group G1&quot; or a &quot;generator&quot; is!
These take a while to compute so we prepare them separately and reuse them.</p>
</dd>
</dl>

<a name="keyGen"></a>

## keyGen(key_material, key_info, key_dst, hashType) ⇒ <code>Uint8Array</code>
Produces an appropriate secret key starting from initial key material. This
procedure enhances the entropy of the key material but is deterministic so
initial key material must be kept secret.

**Kind**: global function  
**Returns**: <code>Uint8Array</code> - Derived secret key as an array of bytes.  

| Param | Type | Description |
| --- | --- | --- |
| key_material | <code>Uint8Array</code> | Secret key material. Must be >= 32 bytes long. |
| key_info | <code>Uint8Array</code> | Optional key information. |
| key_dst | <code>string</code> | Key domain separation tag, defaults to 'KEYGEN_DST_'. |
| hashType | <code>string</code> | The hash type for the signature suite. |

<a name="publicFromPrivate"></a>

## publicFromPrivate(privateBytes) ⇒ <code>Uint8Array</code>
**Kind**: global function  
**Returns**: <code>Uint8Array</code> - Containing encoded public key in G2.  

| Param | Type | Description |
| --- | --- | --- |
| privateBytes | <code>Uint8Array</code> | Private key bytes must have length 32. |

<a name="sign"></a>

## sign(SK, PK, header, messages, generators, hashType)
Creates a BBS signature over a list of "messages".

**Kind**: global function  

| Param | Type | Description |
| --- | --- | --- |
| SK | <code>bigint</code> \| <code>Uint8Array</code> | A scalar or byte array for the secret key. |
| PK | <code>Uint8Array</code> | Public key as a compressed G2 point raw bytes. |
| header | <code>Uint8Array</code> | Header as a byte array. |
| messages | <code>Array</code> | Array of scalars (bigint) derived from actual  messages. Computed by [messages_to_scalars](#messages_to_scalars). |
| generators | <code>Array</code> | Array of group G1 generators created by the  [prepareGenerators](#prepareGenerators) function. |
| hashType | <code>string</code> | The hash type for the signature suite. |

<a name="verify"></a>

## verify(PK, signature, header, messages, generators, hashType) ⇒ <code>boolean</code>
Verify a BBS signature against a public key.

**Kind**: global function  
**Returns**: <code>boolean</code> - - True or False depending on whether the signature
 is valid.  

| Param | Type | Description |
| --- | --- | --- |
| PK | <code>Uint8Array</code> | Public key as a compressed G2 point raw bytes. |
| signature | <code>Uint8Array</code> | A previously computed signature. |
| header | <code>Uint8Array</code> | Header used when signature was created. |
| messages | <code>Array</code> | Array of scalars (bigint) derived from actual  messages. Computed by [messages_to_scalars](#messages_to_scalars). |
| generators | <code>Array</code> | Array of group G1 generators created by the  [prepareGenerators](#prepareGenerators) function. |
| hashType | <code>string</code> | The hash type for the signature suite. |

<a name="proofGen"></a>

## proofGen(PK, signature, header, ph, messages, disclosed_indexes, generators, hashType, rand_scalars) ⇒ <code>Uint8Array</code>
Generates an unlinkable, selective disclosure proof based on a
signature and message set, and related information.

**Kind**: global function  
**Returns**: <code>Uint8Array</code> - - The proof as an byte array.  

| Param | Type | Description |
| --- | --- | --- |
| PK | <code>Uint8Array</code> | Public key as a compressed G2 point raw bytes. |
| signature | <code>Uint8Array</code> | A previously computed signature. |
| header | <code>Uint8Array</code> | Header used when signature was created. |
| ph | <code>Uint8Array</code> | Presentation header, used during proof creation. |
| messages | <code>Array</code> | Array of scalars (bigint) derived from actual  messages. Computed by [messages_to_scalars](#messages_to_scalars). |
| disclosed_indexes | <code>Array</code> | Array of sorted (non-repeating) zero based indices of the messages to be disclosed. |
| generators | <code>Array</code> | Array of group G1 generators created by the  [prepareGenerators](#prepareGenerators) function. |
| hashType | <code>string</code> | The hash type for the signature suite. |
| rand_scalars | <code>function</code> | A function for generating cryptographically  secure random or pseudo random scalars. |

<a name="proofVerify"></a>

## proofVerify(PK, proof, header, ph, disclosed_messages, disclosed_indexes, generators, hashType) ⇒ <code>boolean</code>
Verifies a previously generated proof against original signers public key,
and additional information.

**Kind**: global function  
**Returns**: <code>boolean</code> - - True or False depending on whether the proof is valid.  

| Param | Type | Description |
| --- | --- | --- |
| PK | <code>Uint8Array</code> | Public key as a compressed G2 point raw bytes. |
| proof | <code>Uint8Array</code> | The proof as a byte array. |
| header | <code>Uint8Array</code> | Header used when original signature was created. |
| ph | <code>Uint8Array</code> | Presentation header that was used during proof creation. |
| disclosed_messages | <code>Array</code> | Array of scalars (bigint) derived from  actual  disclosed messages. Computed by [messages_to_scalars](#messages_to_scalars). |
| disclosed_indexes | <code>Array</code> | Array of sorted (non-repeating) zero based indices corresponding to the disclosed messages. |
| generators | <code>Array</code> | Array of group G1 generators created by the  [prepareGenerators](#prepareGenerators) function. |
| hashType | <code>string</code> | The hash type for the signature suite. |

<a name="numUndisclosed"></a>

## numUndisclosed(proofOctets) ⇒ <code>number</code>
Helper function to give the number of undisclosed messages in a proof. This
can be added to the number of disclosed messages to calculate the number of
generators needed in proof verification.

**Kind**: global function  
**Returns**: <code>number</code> - - The number of undisclosed messages, U.  

| Param | Type | Description |
| --- | --- | --- |
| proofOctets | <code>Uint8Array</code> | Byte array containing the raw bytes of a proof. |

<a name="messages_to_scalars"></a>

## messages\_to\_scalars(messages, hashType) ⇒ <code>Array</code>
This function converts (hashes) byte array messages into scalars representing
the messages for use in signature/proof operations.

**Kind**: global function  
**Returns**: <code>Array</code> - - An array of scalars (bigint) representing the messages.  

| Param | Type | Description |
| --- | --- | --- |
| messages | <code>Array</code> | Messages as an Array of Uint8Arrays, i.e., these byte arrays not strings. |
| hashType | <code>string</code> | The hash type for the signature suite. |

<a name="prepareGenerators"></a>

## prepareGenerators(L, hashType) ⇒ <code>Array</code>
Prepares the "group G1 generators" used by the BBS signature suite.
These values can be reused in many calls to the sign, verify, proofGen, and
proofVerify functions. You must have enough generators for the number of
messages. You do not need to know what the "group G1" or a "generator" is!
These take a while to compute so we prepare them separately and reuse them.

**Kind**: global function  
**Returns**: <code>Array</code> - - A array of group generators used by the signature/proof
 suite.  

| Param | Type | Description |
| --- | --- | --- |
| L | <code>number</code> | An integer that indicates the number of generators to be created. This number must be large than the total number of messages in a signature or proof. |
| hashType | <code>string</code> | The hash type for the signature suite. |

