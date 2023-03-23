import crypto from 'crypto';

export function randomBytes(bytesLength = 32) {
  return new Uint8Array(crypto.randomBytes(bytesLength).buffer);
}
