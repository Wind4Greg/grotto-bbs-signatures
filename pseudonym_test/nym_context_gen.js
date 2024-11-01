/* global console */
/* eslint-disable max-len */
import {API_ID_PSEUDONYM_BBS_SHAKE, bytesToHex, hash_to_scalar} from '../lib/BBS.js';
import {randomBytes} from '../lib/randomBytes.js';

const prover_nym = await hash_to_scalar(randomBytes(), randomBytes(), 
  API_ID_PSEUDONYM_BBS_SHAKE);
const context_id = randomBytes();
console.log(`pid (scalar): ${prover_nym}`);
console.log(`context_id (byte string): ${bytesToHex(context_id)}`);