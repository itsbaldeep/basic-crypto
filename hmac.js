import { createHmac } from 'crypto';

/**
 * sha256 hmac function - it always gives the same output
 * given the same input
 * @param {import('crypto').BinaryLike} input the value to be hashed
 * @param {import('crypto').BinaryLike | import('crypto').KeyObject} key the key to be used for creating hmac
 * @returns {string} the hashed output
 */
export function hmac(input, key) {
  const hashed = createHmac('sha256', key).update(input).digest('base64');
  return hashed;
}
