import { assert } from 'chai';
import { prepareGenerators } from '../lib/BBS.js';
import { readFile } from 'fs/promises';

const SHA_PATH = './fixture_data/bls12-381-sha-256/';
const SHAKE_PATH = './fixture_data/bls12-381-shake-256/';

for (let hash of ["SHA-256", "SHAKE-256"]) {
  let path = SHA_PATH;
  if (hash == "SHAKE-256") {
    path = SHAKE_PATH;
  }

  const generatorVector = JSON.parse(
    await readFile(
      new URL(path + 'generators.json', import.meta.url)
    )
  );

  describe('Generators ' + hash, async function () {
    const L = generatorVector.MsgGenerators.length;
    let gens;
    before(async function () {
      gens = await prepareGenerators(L, hash);
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
}
