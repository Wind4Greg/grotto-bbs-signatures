/*global describe, it*/
import {bytesToHex, hexToBytes} from '../lib/BBS.js';
import {assert} from 'chai';

describe('Utilities', function() {
  describe('Hex to Bytes', function() {
    const hexString = '0432ab';
    const badByteString = '0432ab1'; // odd number of hex characters
    it('create bytes from string', function() {
      const result = hexToBytes(hexString);
      assert.typeOf(result, 'Uint8Array', 'is byte array');
      assert.lengthOf(result, hexString.length / 2);
    });
    it('odd number of hex chars', function() {
      assert.throws(hexToBytes.bind(null, badByteString), Error);
    });
  });

  describe('Bytes to Hex', function() {
    const testByteArray = new Uint8Array([1, 2, 3, 4, 5]);
    it('is a string', function() {
      const result = bytesToHex(testByteArray);
      assert.isString(result, 'is string');
    });
    it('is double the byte array length', function() {
      const result = bytesToHex(testByteArray);
      assert.lengthOf(result, 2 * testByteArray.length);
    });
  });
});
