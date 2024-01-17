/* global describe, URL, it, before */
import {API_ID_BBS_SHA, API_ID_BBS_SHAKE, hexToBytes, messages_to_scalars}
  from '../lib/BBS.js';
import {assert} from 'chai';
import {readFile} from 'fs/promises';

const SHA_PATH = './fixture_data/bls12-381-sha-256/';
const SHAKE_PATH = './fixture_data/bls12-381-shake-256/';

for(const api_id of [API_ID_BBS_SHA, API_ID_BBS_SHAKE]) {
  let path = SHA_PATH;
  if(api_id.includes('SHAKE-256')) {
    path = SHAKE_PATH;
  }
  const msgs2scalarsVector = JSON.parse(
    await readFile(
      new URL(path + 'MapMessageToScalarAsHash.json', import.meta.url)
    )
  );

  describe('Messages to Scalars ' + api_id, function() {
    let msgs_in_octets;
    let test_scalars;
    let result_scalars;
    before(async function() {
      msgs_in_octets = msgs2scalarsVector.cases.map(
        tst => hexToBytes(tst.message));
      test_scalars = msgs2scalarsVector.cases.map(
        tst => BigInt('0x' + tst.scalar));
      result_scalars = await messages_to_scalars(msgs_in_octets, api_id);
    });
    it('Confirm messages to scalars', async function() {
      for(let i = 0; i < test_scalars.length; i++) {
        assert.equal(result_scalars[i], test_scalars[i]);
        // console.log(`computed scalar: ${result_scalars[i]}`);
        // console.log(`test scalar: ${test_scalars[i]}`);
        // console.log(`test scalar hex: ${test_scalars[i].toString(16)}`);
      }
    });
  });
}
