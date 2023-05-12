/*global TextEncoder, console*/
/*eslint max-len: ["error", { "ignoreStrings": true, "ignoreComments": true }]*/
import {bytesToHex, hexToBytes, messages_to_scalars, prepareGenerators,
  proofGen, proofVerify, publicFromPrivate, sign, verify} from '../lib/BBS.js';

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

const gens = await prepareGenerators(messages.length); // Generate enough for all messages

// Prepare private and public keys
const sk_bytes = hexToBytes('47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56');
const pk_bytes = publicFromPrivate(sk_bytes);

const header = hexToBytes('11223344556677889900aabbccddeeff');
const signature = await sign(sk_bytes, pk_bytes, header, msg_scalars, gens);
console.log('Signature:');
console.log(bytesToHex(signature));

const verified = await verify(pk_bytes, signature, header, msg_scalars, gens);
console.log(`Algorithm verified: ${verified}`);

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
