import { randomBytes, scryptSync, timingSafeEqual } from 'crypto';

/**
 * generate salt function - creates a random value to
 * be used as a salt
 * @returns {string} a random 16 byte hex value
 */
export function generateSalt() {
  const salt = randomBytes(16).toString('hex');
  return salt;
}

/**
 * hashing with salt function - it gives different output given the
 * same input and different salt
 * @param {import('crypto').BinaryLike} input the value to be hashed
 * @param {string} salt the salt to be used for hasing
 * @returns {string} hashed output
 */
export function hashWithSalt(input, salt) {
  const hashed = scryptSync(input, salt, 64).toString('hex');
  return hashed;
}

/**
 * compare hash function - it compares two values to check
 * if they are hashed with the same salt
 * @param {string} input the raw input value to be compared
 * @param {string} hash the hash to compare the value with
 * @param {string} salt the salt used for hashing the values
 * @returns {boolean} true if the salt matches
 */
export function compareHash(input, hash, salt) {
  const hashedInputBuffer = scryptSync(input, salt, 64);
  const hashedStoredBuffer = Buffer.from(hash, 'hex');

  // to prevent timing attacks
  const match = timingSafeEqual(hashedStoredBuffer, hashedInputBuffer);
  return match;
}
