/* global describe, URL, it */
import {bytesToHex, hexToBytes, publicFromPrivate} from '../lib/BBS.js';
import {assert} from 'chai';
import {readFile} from 'fs/promises';

const keyPairFixture = JSON.parse(
  await readFile(
    new URL('./fixture_data/keyPair.json', import.meta.url)
  )
);

describe('Public from private', function() {
  const keyPairTest = keyPairFixture.keyPair;
  // console.log(keyPairTest);
  const privateBytes = hexToBytes(keyPairTest.secretKey);
  const publicBytes = publicFromPrivate(privateBytes);
  const publicHex = bytesToHex(publicBytes);
  it('confirm test vector', function() {
    assert.equal(publicHex, keyPairTest.publicKey);
  });
});
