//
// Set up dependencies for TP-LINK's encrypt script
//
const $ = global.jQuery = {};
global.window = global.navigator = {};

require('./helpers/tplink-encrypt');

export function encrypt(plaintext, { modulus, exponent }) {
  return $.su.encrypt(plaintext, [modulus, exponent]);
}
