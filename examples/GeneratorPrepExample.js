/*global console*/
import {prepareGenerators} from '../lib/BBS.js';

const L = 10;
const gens = await prepareGenerators(L); // Default SHA-256 hash
console.log(`Q1:${gens.Q1.toHex(true)}`); // Elliptic point to compressed hex
for(let i = 0; i < gens.H.length; i++) {
  console.log(`H${i}:${gens.H[i].toHex(true)}`);
}
