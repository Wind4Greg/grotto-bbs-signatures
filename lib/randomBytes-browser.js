const crypto = self && (self.crypto || self.msCrypto);

export function randomBytes(bytesLength = 32) {
    return crypto.getRandomValues(new Uint8Array(bytesLength));
}