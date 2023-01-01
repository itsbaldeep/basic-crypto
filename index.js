import {
  decryptWithPrivateKey,
  encryptWithPublicKey,
  generateKeyPair,
} from './asymmetric.js';
import { hash } from './hash.js';
import { hmac } from './hmac.js';
import { compareHash, generateSalt, hashWithSalt } from './salt.js';
import {
  decrypt,
  encrypt,
  generateCipher,
  generateDecipher,
  generateIV,
  generateKey,
} from './symmetric.js';

const password = 'hello@1234';

const hashedPassword = hash(password);
console.log({ password, hashedPassword });

const salt = generateSalt();
const hashedPasswordWithSalt = hashWithSalt(password, salt);
console.log({ password, hashedPasswordWithSalt });

const passwordInput = 'hello@123';
const match = compareHash(passwordInput, hashedPasswordWithSalt, salt);
console.log({ password, passwordInput, match });

const key = 'some-key';
const hmacHash = hmac(password, key);
console.log({ password, key, hmacHash });

const otherKey = 'other-key';
const otherHmacHash = hmac(password, otherKey);
console.log({ password, otherKey, otherHmacHash });

const message = 'hey';
const encryptionKey = generateKey();
const iv = generateIV();

const cipher = generateCipher(encryptionKey, iv);
const decipher = generateDecipher(encryptionKey, iv);

const encryptedMessage = encrypt(cipher, message);
const decryptedMessage = decrypt(decipher, encryptedMessage);

console.log({ message, encryptedMessage, decryptedMessage });

const passphrase = 'top-secret';
const { publicKey, privateKey } = generateKeyPair(passphrase);
console.log({ publicKey, privateKey });

const data = 'secret-data';
const publicEncryptedMessage = encryptWithPublicKey(publicKey, data);
const privateDecryptedMessage = decryptWithPrivateKey(
  privateKey,
  publicEncryptedMessage,
  passphrase
);

console.log({
  passphrase,
  data,
  publicEncryptedMessage,
  privateDecryptedMessage,
});
