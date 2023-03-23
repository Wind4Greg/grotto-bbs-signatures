/* global describe, URL, it, console */
import {hexToBytes, keyGen, bytesToHex} from '../lib/BBS.js';
import {assert} from 'chai';
import {readFile} from 'fs/promises';

const keyPairFixture = JSON.parse(
  await readFile(
    new URL('./fixture_data/keyPair.json', import.meta.url)
  )
);

describe('Key Generation', function() {
  // console.log(keyPairTest);
  const ikm = hexToBytes(keyPairFixture.ikm);
  const keyInfo = hexToBytes(keyPairFixture.keyInfo);
  const keyDST = 'KEYGEN_DST_';
  for(const hashType of ['SHA-256', 'SHAKE-256']) {
    it('KeyGen ' + hashType, async function() {
      const sk = await keyGen(ikm, keyInfo, keyDST, hashType);
      console.log(`sk (hex): ${bytesToHex(sk)}`);
      assert.equal(sk, sk);
    });
  }
});
