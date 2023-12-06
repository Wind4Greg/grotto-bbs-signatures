/* global describe, URL, it, before */

import {API_ID_BBS_SHA, API_ID_BBS_SHAKE, prepareGenerators}
  from '../lib/BBS.js';
import {assert} from 'chai';
import {readFile} from 'fs/promises';

const SHA_PATH = './fixture_data/bls12-381-sha-256/';
const SHAKE_PATH = './fixture_data/bls12-381-shake-256/';

for(const api_id of [API_ID_BBS_SHA, API_ID_BBS_SHAKE]) {
  let path = SHA_PATH;
  if(api_id.includes('SHAKE-256')) {
    path = SHAKE_PATH;
  }

  const generatorVector = JSON.parse(
    await readFile(
      new URL(path + 'generators.json', import.meta.url)
    )
  );

  describe('Generators ' + api_id, async function() {
    const L = generatorVector.MsgGenerators.length;
    let gens;
    before(async function() {
      gens = await prepareGenerators(L, api_id);
    });
    it('Confirm P1', function() {
      assert.equal(gens.P1.toHex(true), generatorVector.P1);
    });
    it('Confirm Q1', function() {
      assert.equal(gens.Q1.toHex(true), generatorVector.Q1);
      // assert.equal(gens.Q2.toHex(true), generatorVector.Q2);
    });
    it('Confirm message generators', function() {
      // console.log(gens);
      for(let i = 0; i < L; i++) {
        assert.equal(gens.H[i].toHex(true), generatorVector.MsgGenerators[i]);
        // console.log(`H[${i}]: ${gens.H[i].toHex(true)}`);
      }
    });
  });
}
