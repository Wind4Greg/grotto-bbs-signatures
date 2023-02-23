import { assert } from 'chai';
import { hexToBytes, hash_to_scalar, os2ip } from '../lib/BBS.js';
import { readFile } from 'fs/promises';

const SHA_PATH = './fixture_data/bls12-381-sha-256/';
const SHAKE_PATH = './fixture_data/bls12-381-shake-256/';

for (let hash of ["SHA-256", "SHAKE-256"]) {
  let path = SHA_PATH;
  if (hash == "SHAKE-256") {
    path = SHAKE_PATH;
  }
  const h2s001 = JSON.parse(
    await readFile(
      new URL(path + 'h2s/h2s001.json', import.meta.url)
    )
  );

  const h2s002 = JSON.parse(
    await readFile(
      new URL(path + 'h2s/h2s002.json', import.meta.url)
    )
  );

  describe('Hash to Scalar ' + hash, function () {
    it(h2s001.caseName, async function () {
      // console.log(h2s001);
      let msg_octets = hexToBytes(h2s001.message);
      let dst = hexToBytes(h2s001.dst);
      let count = h2s001.count;
      let result = await hash_to_scalar(msg_octets, count, dst, hash);
      let expected = os2ip(hexToBytes(h2s001.scalars[0]));
      assert.equal(result, expected);
    });
    it(h2s002.caseName, async function () {
      // console.log(h2s002);
      let msg_octets = hexToBytes(h2s002.message);
      let dst = hexToBytes(h2s002.dst);
      let count = h2s002.count;
      let result = await hash_to_scalar(msg_octets, count, dst, hash);
      for (let i = 0; i < count; i++) {
        let expected = os2ip(hexToBytes(h2s002.scalars[i]));
        assert.equal(result[i], expected);
      }
    });
  });
}
