import {assert} from 'chai';
import {hexToBytes, hash_to_scalar, os2ip} from '../lib/BBS.js';
import { readFile } from 'fs/promises';

const h2s001 = JSON.parse(
  await readFile(
    new URL('./fixture_data/bls12-381-sha-256/h2s/h2s001.json', import.meta.url)
  )
);

const h2s002 = JSON.parse(
  await readFile(
    new URL('./fixture_data/bls12-381-sha-256/h2s/h2s002.json', import.meta.url)
  )
);

describe('Hash to Scalar', function() {
    it(h2s001.caseName, async function(){
      let msg_octets = hexToBytes(h2s001.message);
      let dst = hexToBytes(h2s001.dst);
      let count = h2s001.count;
      let result = await hash_to_scalar(msg_octets, count, dst);
      let expected = os2ip(hexToBytes(h2s001.scalars[0]));
        assert.equal(result, expected);
    });
    it(h2s002.caseName, async function(){
      let msg_octets = hexToBytes(h2s002.message);
      let dst = hexToBytes(h2s002.dst);
      let count = h2s002.count;
      let result = await hash_to_scalar(msg_octets, count, dst);
      for (let i = 0; i < count; i++) {
        let expected = os2ip(hexToBytes(h2s002.scalars[i]));
        assert.equal(result[i], expected);
      }
    });
});
