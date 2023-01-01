import { createHash } from 'crypto';

/**
 * sha256 hash function - it always gives the same output
 * given the same input
 * @param {import('crypto').BinaryLike} input the value to be hashed
 * @returns {string} the hashed output
 */
export function hash(input) {
  const hashed = createHash('sha256').update(input).digest('base64');
  return hashed;
}
