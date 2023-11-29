/* global describe, URL, it, console */
import {API_ID_BBS_SHA, API_ID_BBS_SHAKE, bytesToHex, hexToBytes, keyGen,
  publicFromPrivate} from '../lib/BBS.js';
import {assert} from 'chai';
import {readFile} from 'fs/promises';

const SHA_PATH = './fixture_data/bls12-381-sha-256/';
const SHAKE_PATH = './fixture_data/bls12-381-shake-256/';

for(const api_id of [API_ID_BBS_SHA, API_ID_BBS_SHAKE]) {
  let path = SHA_PATH;
  if(api_id.includes('SHAKE-256')) {
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
    const keyDST = ''; //'KEYGEN_DST_';

    it('KeyGen ' + api_id, async function() {
      const sk = await keyGen(ikm, keyInfo, keyDST, api_id);
      // console.log(`sk (hex): ${bytesToHex(sk)}`);
      assert.equal(bytesToHex(sk), keyPairFixture.keyPair.secretKey);
    });
  });

  describe('Public from private ' + api_id, function() {
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
