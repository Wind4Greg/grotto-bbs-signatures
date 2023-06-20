/* global describe, URL, it, console */
import {bytesToHex, hexToBytes, keyGen, publicFromPrivate} from '../lib/BBS.js';
import {assert} from 'chai';
import {readFile} from 'fs/promises';

const SHA_PATH = './fixture_data/bls12-381-sha-256/';
const SHAKE_PATH = './fixture_data/bls12-381-shake-256/';

for(const hashType of ['SHA-256', 'SHAKE-256']) {
  let path = SHA_PATH;
  if(hashType == 'SHAKE-256') {
    path = SHAKE_PATH;
  }
  const keyPairFixture = JSON.parse(
    await readFile(
      new URL(path + 'keypair.json', import.meta.url)
    )
  );

  describe('Key Generation', function() {
    // console.log(keyPairFixture);
    const ikm = hexToBytes(keyPairFixture.keyMaterial);
    const keyInfo = hexToBytes(keyPairFixture.keyInfo);
    const keyDST = 'KEYGEN_DST_';

    it('KeyGen ' + hashType, async function() {
      const sk = await keyGen(ikm, keyInfo, keyDST, hashType);
      // console.log(`sk (hex): ${bytesToHex(sk)}`);
      assert.equal(bytesToHex(sk), keyPairFixture.keyPair.secretKey);
    });
  });

  describe('Public from private ' + hashType, function() {
    const keyPairTest = keyPairFixture.keyPair;
    // console.log(keyPairTest);
    const privateBytes = hexToBytes(keyPairTest.secretKey);
    const publicBytes = publicFromPrivate(privateBytes);
    const publicHex = bytesToHex(publicBytes);
    it('confirm test vector', function() {
      assert.equal(publicHex, keyPairTest.publicKey);
    });
  });
}
