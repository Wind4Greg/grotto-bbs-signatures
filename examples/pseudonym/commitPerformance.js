/* global console*/
/* eslint-disable max-len */
import {API_ID_BLIND_BBS_SHA} from '../../lib/BBS.js';
import {Commit} from '../../lib/BlindBBS.js';
import {randomBytes} from '../../lib/randomBytes.js';

const api_id = API_ID_BLIND_BBS_SHA;
const testLengths = [10, 20, 100, 1000];

for(const test of testLengths) {
  // Random RAW messages, as [flag, value] pairs. A RAW message must be less
  // than the group order r, so use 31 bytes.
  const messages = [];
  for(let i = 0; i < test; i++) {
    messages.push(['RAW', randomBytes(31)]);
  }
  const timeStart = new Date();
  const [commit_with_proof_octs, secret_prover_blind] =
            await Commit(messages, api_id);
  const timeEnd = new Date();
  const proofSize = commit_with_proof_octs.length;
  const seconds = timeEnd - timeStart;
  console.log(`N = ${test}, time = ${seconds}ms, size = ${proofSize}, blind = ${secret_prover_blind.toString(16)}`);
}

