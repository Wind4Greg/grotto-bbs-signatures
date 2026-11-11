/* global console */
/* eslint-disable max-len */
// Generates the generators.json test vectors for the BBS pseudonym interface.
// The counts match the spec's signature and proof test vectors: L = 10 signer
// messages, M = 5 blind messages and N = 1 nym secret, i.e., L + 1 generators
// and M + N + 1 blind generators, plus the committed disclosure generators.
import {API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE, prepareGenerators} from '../lib/BBS.js';
import {mkdir, writeFile} from 'fs/promises';
import {bytesToHex} from '@noble/hashes/utils.js';
import {dirname} from 'path';
import {fileURLToPath} from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const L = 10;
const M = 5;
const N = 1;

/**
 * Formats a set of generators as used in the test vector files.
 *
 * @param {object} gens - Generators as produced by prepareGenerators.
 * @param {string} gen_api_id - The api_id (DST) used to create them.
 * @returns {object} - Hex encoded generators.
 */
function formatGens(gens, gen_api_id) {
  const [Q1, ...H] = gens.generators;
  return {
    api_id: gen_api_id,
    P1: bytesToHex(gens.P1.toBytes(true)),
    Q1: bytesToHex(Q1.toBytes(true)),
    MsgGenerators: H.map(h => bytesToHex(h.toBytes(true)))
  };
}

for(const api_id of [API_ID_PSEUDONYM_BBS_SHA, API_ID_PSEUDONYM_BBS_SHAKE]) {
  const suite = api_id.includes('SHAKE-256') ? 'bls12-381-shake-256' : 'bls12-381-sha-256';
  console.log(`Generating generators for API ID: ${api_id}`);
  const gens = await prepareGenerators(L + 1, api_id);
  const blindGens = await prepareGenerators(M + N + 1, 'BLIND_' + api_id);
  const comGens = await prepareGenerators(2, 'COM_DIS_' + api_id);
  const output = {
    generators: formatGens(gens, api_id),
    blindGenerators: formatGens(blindGens, 'BLIND_' + api_id),
    commitmentGenerators: {
      api_id: 'COM_DIS_' + api_id,
      Y_0: bytesToHex(comGens.generators[0].toBytes(true)),
      Y_1: bytesToHex(comGens.generators[1].toBytes(true))
    }
  };
  const outputPath = `${__dirname}/outputs/${suite}/`;
  await mkdir(outputPath, {recursive: true});
  await writeFile(outputPath + 'generators.json', JSON.stringify(output, null, 2));
}
