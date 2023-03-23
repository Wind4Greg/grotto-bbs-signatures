/* global describe, URL, it*/
import {hash_to_scalar, hexToBytes, os2ip} from '../lib/BBS.js';
import {assert} from 'chai';
import {readFile} from 'fs/promises';

const SHA_PATH = './fixture_data/bls12-381-sha-256/';
const SHAKE_PATH = './fixture_data/bls12-381-shake-256/';

for(const hash of ['SHA-256', 'SHAKE-256']) {
  let path = SHA_PATH;
  if(hash == 'SHAKE-256') {
    path = SHAKE_PATH;
  }
  const h2s = JSON.parse(
    await readFile(
      new URL(path + 'h2s.json', import.meta.url)
    )
  );

  describe('Hash to Scalar ' + hash, function() {
    it(h2s.caseName, async function() {
      // console.log(h2s);
      const msg_octets = hexToBytes(h2s.message);
      const dst = hexToBytes(h2s.dst);
      const result = await hash_to_scalar(msg_octets, dst, hash);
      // console.log("Computed scalar:");
      // console.log(result.toString(16));
      const expected = os2ip(hexToBytes(h2s.scalar));
      assert.equal(result, expected);
    });
  });
}
