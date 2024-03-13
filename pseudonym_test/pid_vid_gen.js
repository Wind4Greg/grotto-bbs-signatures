import {bytesToHex} from '../lib/BBS.js';
import {randomBytes} from '../lib/randomBytes.js';

const pid = randomBytes();
const verifier_id = randomBytes();
console.log(`pid: ${bytesToHex(pid)}`);
console.log(`verifier_id: ${bytesToHex(verifier_id)}`);