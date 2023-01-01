import {
  generateKeyPairSync,
  KeyObject,
  privateDecrypt,
  publicEncrypt,
} from 'crypto';

/**
 * generate key pairs function
 * @param {string} passphrase optionally provide a passphrase for the private key
 * @returns {{ publicKey: KeyObject, privateKey: KeyObject }}
 */
export function generateKeyPair(passphrase = '') {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
      cipher: 'aes-256-cbc',
      passphrase,
    },
  });
  return { publicKey, privateKey };
}

/**
 * public encrypt function
 * @param {import('crypto').RsaPublicKey} publicKey the public key used to encrypt the mssage
 * @param {Buffer} message the message to encrypt
 * @returns {string} the encrypted string
 */
export function encryptWithPublicKey(publicKey, message) {
  const encryptedMessage = publicEncrypt(publicKey, Buffer.from(message));
  return encryptedMessage.toString('hex');
}

/**
 * private decrypt function
 * @param {import('crypto').RsaPrivateKey} privateKey the private key used to decrypt the mssage
 * @param {Buffer} encryptedMessage the encrypted message to decrypt
 * @param {string} passphrase optionally provide a passphrase for the private key
 * @returns {string} the decrypted message
 */
export function decryptWithPrivateKey(
  privateKey,
  encryptedMessage,
  passphrase = ''
) {
  const decryptedData = privateDecrypt(
    { key: privateKey, passphrase },
    Buffer.from(encryptedMessage, 'hex')
  );
  return decryptedData.toString('utf8');
}
