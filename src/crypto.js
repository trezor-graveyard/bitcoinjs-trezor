const createHash = require('create-hash');

// used only in hash160
function ripemd160(buffer) {
  return createHash('rmd160').update(buffer).digest();
}

// used in ecdsa test + below in hash256
function sha256(buffer) {
  return createHash('sha256').update(buffer).digest();
}

// used in tx tests + getting xpub out of hdnode
// HDNode.toBase58
// + HDNode.derive
// (that could be refactored out eventually,
// since we do that mostly in hd-wallet in wasm,
// but keep it also in hdnode.js so it works in older
// browsers without wasm)
function hash160(buffer) {
  return ripemd160(sha256(buffer));
}

// used in Transaction.getId
// = getting txid from tx
function hash256(buffer) {
  return sha256(sha256(buffer));
}

module.exports = {
  hash160,
  hash256,
  sha256,
};
