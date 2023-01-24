import crypto from "crypto";

export function randomBytes(bytesLength = 32) {
        return new Uint8Array(crypto_1.crypto.node.randomBytes(bytesLength).buffer);
}