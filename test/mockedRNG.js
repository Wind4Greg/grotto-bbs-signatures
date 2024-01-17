/* global describe, it */
/*eslint max-len: ["error", { "ignoreStrings": true, "ignoreComments": true }]*/
/*
  Checks the generation of mocked random scalars.
*/
import {API_ID_BBS_SHA, API_ID_BBS_SHAKE, hexToBytes, seeded_random_scalars}
  from '../lib/BBS.js';
import {assert} from 'chai';
import {readFile} from 'fs/promises';

// These are signature files for 10 messages
const SHA_PATH = './test/fixture_data/bls12-381-sha-256/mockedRng.json';
const SHAKE_PATH = './test/fixture_data/bls12-381-shake-256/mockedRng.json';

const testScalarsSHA = JSON.parse(await readFile(SHA_PATH));
const testScalarsSHAKE = JSON.parse(await readFile(SHAKE_PATH));

// console.log(testScalarsSHA);
describe('Mocked Random Scalars ', function() {
  let testScalars;

  it('SHA-256 Mocked Scalars', async function() {
    testScalars = testScalarsSHA;
    const seed = hexToBytes(testScalars.seed);
    const count = testScalars.count;
    const scalars = await seeded_random_scalars(seed, API_ID_BBS_SHA, count);
    // console.log(scalars.map(x => x.toString(16)));

    const testScalarsBig = testScalars.mockedScalars.map(tst => BigInt('0x' + tst));
    assert.deepEqual(testScalarsBig, scalars);
  });

  it('SHAKE-256 Mocked Scalars', async function() {
    testScalars = testScalarsSHAKE;
    const seed = hexToBytes(testScalars.seed);
    const count = testScalars.count;
    const scalars = await seeded_random_scalars(seed, API_ID_BBS_SHAKE, count);
    // console.log(scalars.map(x => x.toString(16)));

    const testScalarsBig = testScalars.mockedScalars.map(tst => BigInt('0x' + tst));
    assert.deepEqual(testScalarsBig, scalars);
  });

});
