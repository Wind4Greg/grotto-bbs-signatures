import {assert} from 'chai';
import {bytesToHex, hexToBytes, publicFromPrivate} from '../lib/BBS.js';
import { readFile } from 'fs/promises';

const keyPairFixture = JSON.parse(
  await readFile(
    new URL('./fixture_data/keyPair.json', import.meta.url)
  )
);

describe('Public from private', function() {
    let keyPairTest = keyPairFixture.keyPair;
    // console.log(keyPairTest);
    const privateBytes = hexToBytes(keyPairTest.secretKey);
    let publicBytes = publicFromPrivate(privateBytes);
    let publicHex = bytesToHex(publicBytes);
    it('confirm test vector', function(){
        assert.equal(publicHex, keyPairTest.publicKey);
    });
});
