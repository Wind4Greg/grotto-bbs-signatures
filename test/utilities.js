import { assert } from 'chai';
import { bytesToHex, hexToBytes } from '../lib/BBS.js';

describe('Utilities', function () {
    describe('Hex to Bytes', function () {
        const hexString = "0432ab";
        const badByteString = "0432ab1"; // odd number of hex characters
        it('create bytes from string', function () {
            let result = hexToBytes(hexString);
            assert.typeOf(result, 'Uint8Array', 'is byte array');
            assert.lengthOf(result, hexString.length / 2);
        });
        it('odd number of hex chars', function () {
            assert.throws(hexToBytes.bind(null, badByteString), Error);
        });
    });

    describe('Bytes to Hex', function () {
        const testByteArray = new Uint8Array([1, 2, 3, 4, 5]);
        it('is a string', function () {
            let result = bytesToHex(testByteArray);
            assert.isString(result, 'is string');
        });
        it('is double the byte array length', function () {
            let result = bytesToHex(testByteArray);
            assert.lengthOf(result, 2 * testByteArray.length);
        });
    });
})
