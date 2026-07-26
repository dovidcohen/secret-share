import type { DerivedKeys } from "./kdf.js";
import { concatBytes, randomBytes, utf8 } from "./encoding.js";

export const BLOB_VERSION = 0x01;
export const MAX_SECRET_BYTES = 10_240;
const IV_BYTES = 12;

export class SecretTooLargeError extends Error {
  override name = "SecretTooLargeError";
}

function aad(mailboxId: string): Uint8Array {
  return utf8(`secret-share/v1/blob/${mailboxId}`);
}

/** Output layout: [1B version][12B IV][AES-256-GCM ciphertext+tag]. */
export async function encryptSecret(
  keys: Pick<DerivedKeys, "kBlob" | "mailboxId">,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  if (plaintext.length > MAX_SECRET_BYTES) {
    throw new SecretTooLargeError(`Secret exceeds ${MAX_SECRET_BYTES} bytes`);
  }
  const iv = randomBytes(IV_BYTES);
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv as BufferSource, additionalData: aad(keys.mailboxId) as BufferSource },
    keys.kBlob,
    plaintext as BufferSource,
  );
  return concatBytes(new Uint8Array([BLOB_VERSION]), iv, new Uint8Array(ct));
}

export class BlobFormatError extends Error {
  override name = "BlobFormatError";
}

/** Throws (WebCrypto OperationError) on any tamper — wrong key, flipped bit, wrong mailbox. */
export async function decryptSecret(
  keys: Pick<DerivedKeys, "kBlob" | "mailboxId">,
  blob: Uint8Array,
): Promise<Uint8Array> {
  if (blob.length < 1 + IV_BYTES + 16 || blob[0] !== BLOB_VERSION) {
    throw new BlobFormatError("Unrecognized blob format");
  }
  const iv = blob.subarray(1, 1 + IV_BYTES);
  const ct = blob.subarray(1 + IV_BYTES);
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv as BufferSource, additionalData: aad(keys.mailboxId) as BufferSource },
    keys.kBlob,
    ct as BufferSource,
  );
  return new Uint8Array(pt);
}
