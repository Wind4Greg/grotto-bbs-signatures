/*
  Walkthrough steps of pseudonym usage from initial commit through proof verify.
  Only library functions used. No external files used.
*/
/* eslint-disable max-len */
/* global console, TextEncoder*/
import {API_ID_PSEUDONYM_BBS_SHA, hexToBytes} from '../../lib/BBS.js';
import {BlindSignWithNym, CommitWithNym, ProofGenWithNym, ProofVerifyWithNym,
  VerifyFinalizeWithNym} from '../../lib/PseudonymBBS.js';
import {bytesToHex} from '@noble/hashes/utils.js';

const api_id = API_ID_PSEUDONYM_BBS_SHA;
const te = new TextEncoder(); // To convert strings to byte arrays

// **Prover** or **Holder**: commits to their prover_nyms
// Simple case: no additional blind (committed) messages, e.g., no holder binding.
const blind_messages = [];
// The prover's part of the nym_secrets, a vector of one or more random scalars
const prover_nyms = [BigInt('0x6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418')];
const [commit_with_proof_octs, secret_prover_blind] =
  await CommitWithNym(blind_messages, prover_nyms, api_id);
console.log('To be sent from prover to signer:');
console.log(`commit with proof (hex): ${bytesToHex(commit_with_proof_octs)}`);
console.log(`length_nym_vector: ${prover_nyms.length}`);
console.log('To be retained and kept secret by prover:');
console.log(`secret prover blind (hex): ${secret_prover_blind.toString(16)}`);

// **Signer** or **Issuer**: issues signature over messages, with signer_nym_entropy added
// Signer knows: PK, SK
// Signer sets: messages, header, signer_nym_entropy
// Signer gets commitment_with_proof and length_nym_vector from prover
const SK = BigInt('0x' + '60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc');
const PK = hexToBytes('a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c');
const messageStrings = [
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
// Messages are [flag, value] pairs, the flag is 'HASH' or 'RAW'
const messages = messageStrings.map(msg => ['HASH', te.encode(msg)]);
// Signer's contribution to nym_secrets
const signer_nym_entropy = BigInt('0x' + '3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5');
const header = hexToBytes('11223344556677889900aabbccddeeff');
const sig = await BlindSignWithNym(SK, PK, commit_with_proof_octs, prover_nyms.length,
  signer_nym_entropy, header, messages, api_id);
console.log('To be sent from signer to prover:');
console.log(`signature (hex): ${bytesToHex(sig)}`);
console.log(`signer_nym_entropy (hex): ${signer_nym_entropy.toString(16)}`);

// **Prover** or **Holder** verifies the signature and obtains nym_secrets
// Prover gets from Signer: PK, sig, header, messages, signer_nym_entropy
// Prover knows: prover_nyms, blind messages, secret_prover_blind
// VerifyFinalizeWithNym throws if the signature is INVALID.
const nym_secrets = await VerifyFinalizeWithNym(PK, sig, header, messages, blind_messages,
  prover_nyms, signer_nym_entropy, secret_prover_blind, api_id);
console.log('Prover on receiving signature: signature is valid');
console.log(`nym_secrets: ${nym_secrets.map(nym => nym.toString(16))}`);

// **Prover** or **Holder** selective disclosure proof with pseudonym
// Prover gets: PK, sig, header, messages from Signer
// Prover gets: context_id from verifier
// Prover knows or sets: ph, nym_secrets, blind messages, secret_prover_blind
const ph = hexToBytes('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501');
// Tree reveals approximate address (message 2), hides everything else
const message_disclosures = messages.map((msg, i) => (i === 2 ? 'DISCLOSE' : 'HIDE'));
const blind_message_disclosures = [];
// Context id is from the verifier, the water supply service to the tree
const context_id = te.encode('Water4Redwoods.com/context');
const [proof, pseudonym] = await ProofGenWithNym(PK, sig, header, ph, nym_secrets, context_id,
  messages, blind_messages, message_disclosures, blind_message_disclosures,
  secret_prover_blind, api_id);
console.log('Sent by prover to verifier:');
console.log(`message(s): ${messageStrings.filter((val, i) => message_disclosures[i] === 'DISCLOSE')}`);
console.log(`pseudonym: ${bytesToHex(pseudonym.toBytes(true))}`);
console.log(`proof: ${bytesToHex(proof)}`);

// **Verifier** verifies! Gets from prover: L, length_nym_vector, pseudonym,
// disclosed messages, the disclosures for all messages, and the proof.
// Knows: issuer's PK, context_id
const L = messages.length;
const disclosedMessages = messages.filter((msg, i) => message_disclosures[i] === 'DISCLOSE');
const proofValid = await ProofVerifyWithNym(PK, proof, header, ph, pseudonym.toBytes(true),
  context_id, nym_secrets.length, L, disclosedMessages,
  [...message_disclosures, ...blind_message_disclosures], api_id);
console.log(`Proof with pseudonym is valid: ${proofValid}`);
