import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';

/**
 * generate key function
 * @returns {string} a 32 byte random value
 */
export function generateKey() {
  return randomBytes(32);
}

/**
 * generate initialization vector function
 * @returns {string} a 16 byte random value
 */
export function generateIV() {
  return randomBytes(16);
}

/**
 * generate cipher function
 * @param {import('crypto').CipherKey} key the key to be used
 * @param {import('crypto').BinaryLike} iv the initial vector to be used
 * @returns {import('crypto').Cipher} a cipher
 */
export function generateCipher(key, iv) {
  const cipher = createCipheriv('aes256', key, iv);
  return cipher;
}

/**
 * encrypt message function
 * @param {import('crypto').Cipher} cipher the cipher to be used
 * @param {string} input the message to be encrypted
 * @returns {string}
 */
export function encrypt(cipher, input) {
  const encyptedMessage =
    cipher.update(input, 'utf8', 'hex') + cipher.final('hex');
  return encyptedMessage;
}

/**
 * generate decipher function
 * @param {import('crypto').CipherKey} key the key to be used
 * @param {import('crypto').BinaryLike} iv the initial vector to be used
 * @returns {import('crypto').Decipher} a decipher
 */
export function generateDecipher(key, iv) {
  const decipher = createDecipheriv('aes256', key, iv);
  return decipher;
}

/**
 * decrypt message function
 * @param {import('crypto').Decipher} decipher the decipher to be used
 * @param {string} encryptedMessage the message to be decrypted
 * @returns {string}
 */
export function decrypt(decipher, encryptedMessage) {
  const decryptedMessage =
    decipher.update(encryptedMessage, 'hex', 'utf8') + decipher.final('utf8');
  return decryptedMessage.toString('utf8');
}
