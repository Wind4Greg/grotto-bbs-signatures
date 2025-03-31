/* global describe, URL, it, before, TextEncoder, console*/
/* eslint-disable max-len */
import {API_ID_BLIND_BBS_SHA, API_ID_BLIND_BBS_SHAKE, hexToBytes,
  calculate_random_scalars} from '../../lib/BBS.js';
import { randomBytes } from '../../lib/randomBytes.js'
import {readdir, readFile} from 'fs/promises';
import {bytesToHex} from '@noble/hashes/utils';
import {commit} from '../../lib/BlindBBS.js';

const api_id = API_ID_BLIND_BBS_SHA;
const testLengths = [10, 20, 100, 1000];

for(const test of testLengths) {
  const randScalars = []; // calculate_random_scalars(test);
  for(let i = 0; i < test; i++) {
    randScalars.push(randomBytes());
  }
  const timeStart = new Date();
  const [commit_with_proof_octs, secret_prover_blind] =
            await commit(randScalars, api_id);
  const timeEnd = new Date();
  const proofSize = commit_with_proof_octs.length;
  const seconds = timeEnd - timeStart;
  console.log(`N = ${test}, time = ${seconds}ms, size = ${proofSize}, blind = ${secret_prover_blind.toString(16)}`);
}

