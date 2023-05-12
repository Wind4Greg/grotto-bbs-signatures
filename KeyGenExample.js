/*global TextEncoder, console*/
import {bytesToHex, keyGen, publicFromPrivate} from '../lib/BBS.js';
import crypto from 'crypto';

const bytesLength = 40; // >= 32 bytes
// Generate random initial key material -- Node.js
const keyMaterial = new Uint8Array(crypto.randomBytes(bytesLength).buffer);
const keyInfo = new TextEncoder().encode('BBS-Example Key info');
const sk_bytes = await keyGen(keyMaterial, keyInfo);
console.log(`Private key, length ${sk_bytes.length}, (hex):`);
console.log(bytesToHex(sk_bytes));
const pub_bytes = publicFromPrivate(sk_bytes);
console.log(`Public key, length ${pub_bytes.length}, (hex):`);
console.log(bytesToHex(pub_bytes));

