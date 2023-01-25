import { assert } from 'chai';
import { prepareGenerators } from '../lib/BBS.js';
import { readFile } from 'fs/promises';

const generatorVector = JSON.parse(
  await readFile(
    new URL('./fixture_data/bls12-381-sha-256//generators.json', import.meta.url)
  )
);

describe('Generators', async function () {
  const L = generatorVector.MsgGenerators.length;
  let gens;
  before(async function () {
    gens = await prepareGenerators(L);
  });
  it('Confirm Base Point', function () {
    assert.equal(gens.P1.toHex(true), generatorVector.BP);
  });
  it('Confirm Q1 and Q2', function () {
    assert.equal(gens.Q1.toHex(true), generatorVector.Q1);
    assert.equal(gens.Q2.toHex(true), generatorVector.Q2);
  });
  it('Confirm message generators', function () {
    // console.log(gens);
    for (let i = 0; i < L; i++) {
      assert.equal(gens.H[i].toHex(true), generatorVector.MsgGenerators[i]);
      // console.log(`H[${i}]: ${gens.H[i].toHex(true)}`);
    }
  });
});
