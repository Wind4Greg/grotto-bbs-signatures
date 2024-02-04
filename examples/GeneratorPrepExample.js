/*global console*/
import {API_ID_BBS_SHAKE, prepareGenerators} from '../lib/BBS.js';

const L = 10;
const gens = await prepareGenerators(L + 1, API_ID_BBS_SHAKE);
const [Q1, ...H] = gens.generators;
console.log(`Q1:${Q1.toHex(true)}`); // Elliptic point to compressed hex
for(let i = 0; i < H.length; i++) {
  console.log(`H${i}:${H[i].toHex(true)}`);
}
