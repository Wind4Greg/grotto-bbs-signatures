/*
  Walkthrough steps of Blind BBS usage from initial commit through proof verify.
  Only library functions used. No external files used.
*/
/* eslint-disable max-len */
/* global console, TextEncoder*/
import {API_ID_BLIND_BBS_SHA, bytesToHex, hexToBytes} from '../../lib/BBS.js';
import {BlindProofGen, BlindProofVerify, BlindSign, BlindVerify, Commit}
  from '../../lib/BlindBBS.js';

const api_id = API_ID_BLIND_BBS_SHA;
const te = new TextEncoder(); // To convert strings to byte arrays

// **Prover** or **Holder**: commits to messages the signer will not see.
// Messages are [flag, value] pairs, the flag is 'HASH' or 'RAW'.
const blind_messages = [
  ['HASH', te.encode('Holder binding: tree ring pattern 4711')],
  ['HASH', te.encode('Secret nickname: Big Red')]
];
const [commit_with_proof, secret_prover_blind] =
  await Commit(blind_messages, api_id);
console.log('To be sent from prover to signer:');
console.log(`commit with proof (hex): ${bytesToHex(commit_with_proof)}`);
console.log('To be retained and kept secret by prover:');
console.log(`secret prover blind (hex): ${secret_prover_blind.toString(16)}`);

// **Signer** or **Issuer**: signs its own messages and the committed messages.
// Signer knows: PK, SK. Signer sets: messages, header.
const SK = BigInt('0x' + '60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc');
const PK = hexToBytes('a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c');
const messageStrings = [
  'FirstName: Sequoia',
  'LastName: Sempervirens',
  'Address: Jedediah Smith Redwoods State Park, California',
  'Date of Birth: 1200/03/21',
  'Height: 296 feet'
];
const messages = messageStrings.map(msg => ['HASH', te.encode(msg)]);
const header = hexToBytes('11223344556677889900aabbccddeeff');
// BlindSign throws if the commitment with proof is invalid.
const signature = await BlindSign(SK, PK, commit_with_proof, header, messages,
  api_id);
console.log('To be sent from signer to prover:');
console.log(`signature (hex): ${bytesToHex(signature)}`);

// **Prover** or **Holder** verifies the signature.
const sigValid = await BlindVerify(PK, signature, header, messages,
  blind_messages, secret_prover_blind, api_id);
console.log(`Prover on receiving signature: signature is valid: ${sigValid}`);

// **Prover** or **Holder** selective disclosure proof.
// Each message is "DISCLOSE", "HIDE" or "COMMIT" (committed disclosure).
const ph = te.encode('Presentation to the Water4Redwoods service');
const message_disclosures = ['HIDE', 'HIDE', 'DISCLOSE', 'HIDE', 'COMMIT'];
const blind_message_disclosures = ['HIDE', 'DISCLOSE'];
const [proof, add_zkp_info] = await BlindProofGen(PK, signature, header, ph,
  messages, blind_messages, message_disclosures, blind_message_disclosures,
  secret_prover_blind, api_id);
console.log('Sent by prover to verifier:');
console.log(`proof: ${bytesToHex(proof)}`);
// add_zkp_info holds the committed message scalars and the randomness used
// in their commitments, for use in additional zero knowledge proofs.
console.log(`committed disclosures: ${add_zkp_info.committed_message_scalars.length}`);

// **Verifier** verifies! Gets from prover: the number of signer messages, the
// disclosed messages, the disclosures for all messages, and the proof.
// Knows: issuer's PK, header.
const allDisclosures = [...message_disclosures, ...blind_message_disclosures];
const disclosedMessages = [...messages, ...blind_messages].filter((msg, i) =>
  allDisclosures[i] === 'DISCLOSE');
const proofValid = await BlindProofVerify(PK, proof, header, ph,
  messages.length, disclosedMessages, allDisclosures, api_id);
console.log(`Proof is valid: ${proofValid}`);
