/*
  Walkthrough steps of pseudonym usage from initial commit through proof verify.
  Only library functions used. No external files used.
*/
/* eslint-disable max-len */
/* global console, TextEncoder*/
import {API_ID_PSEUDONYM_BBS_SHA, hexToBytes} from '../../lib/BBS.js';
import {BlindSignWithNym, BlindVerifyWithNym, NymCommit, ProofGenWithNym, ProofVerifyWithNym} from '../../lib/PseudonymBBS.js';
import {bytesToHex} from '@noble/hashes/utils';

const api_id = API_ID_PSEUDONYM_BBS_SHA;

// **Prover** or **Holder**: commits and proves prover_nym
// Prover knows their prover_nym. Generates commitment with proof.
// Simple case no additional committed messages, e.g., no holder binding
const committed_msgs = [];
// To create the nym_secret the prover starts with their prover_nym
const prover_nym_hex = '6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418';
const prover_nym = BigInt('0x' + prover_nym_hex);
// Prover commits to their prover_nym
const [commit_with_proof_octs, secret_prover_blind] = await NymCommit(committed_msgs, prover_nym, api_id);
console.log('To be sent from prover to signer:');
console.log(`commit with proof (hex): ${bytesToHex(commit_with_proof_octs)}`);
console.log('To be retained and kept secret by prover:');
console.log(`secret prover blind (hex): ${secret_prover_blind.toString(16)}`);

// **Signer** or **Issuer**: issues signature over messages, with nym_entropy added
// Signer knows: PK, SK
// Signer sets: messages, header, nym_entropy
// Signer gets commitment_with_proof from prover
const SK = BigInt('0x' + '60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc');
const PK = hexToBytes('a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c');
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
// Signer's contribution to nym_secret
const nym_entropy = BigInt('0x' + '3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5');
const header = hexToBytes('11223344556677889900aabbccddeeff');
const res = await BlindSignWithNym(SK, PK, commit_with_proof_octs, header, messagesOctets, nym_entropy, api_id);
const [sig, back_entropy] = res;
console.log('To be sent from signer to prover:');
console.log(`signature (hex): ${bytesToHex(sig)}`);
console.log(`nym_entropy (hex): ${nym_entropy.toString(16)}`);

// **Prover** or **Holder** verifies the signature and obtains nym_secret
// Prover gets from Signer: PK, sig, header, messages, nym_entropy
// Prover knows: prover_nym, committed messages, secret_prover_blind
const result = await BlindVerifyWithNym(PK, sig, header, messagesOctets, committed_msgs,
  prover_nym, nym_entropy, secret_prover_blind, api_id);
const [valid, nym_secret] = result;
console.log('Prover on receiving signature:');
console.log(`Is signature valid: ${valid}`);
console.log(`nym_secret: ${nym_secret.toString(16)}`);

// **Prover** or **Holder** selective disclosure proof with pseudonym
// Prover gets: PK, sig, header, messages from Signer
// Prover gets: context_id from verifier
// Prover knows or sets: ph, nym_secret, committed messages/indexes, secret_prover_blind
const ph = hexToBytes('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501');
const disclosedIndexes = [2]; // Tree reveals approximate address, see messages
const disclosedComIndexes = [];
// Context id is from the verifier, the water supply service to the tree
const context_id = te.encode('Water4Redwoods.com/context');
const [proof, pseudonym] = await ProofGenWithNym(PK, sig, header, ph, nym_secret, context_id,
  messagesOctets, committed_msgs, disclosedIndexes, disclosedComIndexes, secret_prover_blind, api_id);
console.log('Sent by prover to verifier:');
console.log(`message(s): ${messages.filter((val, i) => disclosedIndexes.includes(i))}`);
console.log(`pseudonym: ${bytesToHex(pseudonym.toRawBytes(true))}`);
console.log(`proof: ${bytesToHex(proof)}`);

// Verifier verifies! Gets: L, pseudonym, disclosed messages/indexes, proof from prover.
// Knows: issuers PK, context_id
const disComMsgs = []; // disclosed committed mesages
const disComIndxs = []; // disclosed committed indexes
const L = messages.length;
const pseudonym_bytes = pseudonym.toRawBytes(true);
const disclosedMessages = messagesOctets.filter((val, i) => disclosedIndexes.includes(i));
const proofValid = await ProofVerifyWithNym(PK, proof, header, ph, pseudonym_bytes, context_id,
  L, disclosedMessages, disComMsgs, disclosedIndexes, disComIndxs, api_id);
console.log(`Proof with pseudonym is valid: ${proofValid}`);
