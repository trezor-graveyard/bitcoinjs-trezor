// OP_DUP OP_HASH160 {pubKeyHash} OP_EQUALVERIFY OP_CHECKSIG

const typeforce = require('typeforce');
const OPS = require('bitcoin-ops');
const bscript = require('../../script');
const types = require('../../types');

// used in address.fromOutputScript
function check(script) {
  const buffer = bscript.compile(script);

  return buffer.length === 25
    && buffer[0] === OPS.OP_DUP
    && buffer[1] === OPS.OP_HASH160
    && buffer[2] === 0x14
    && buffer[23] === OPS.OP_EQUALVERIFY
    && buffer[24] === OPS.OP_CHECKSIG;
}
check.toJSON = function () { return 'pubKeyHash output'; };

// used for sanity checks
// after Trezor signs transaction, we encode the expected outputs
// and compare from what came from Trezor
function encode(pubKeyHash) {
  typeforce(types.Hash160bit, pubKeyHash);

  return bscript.compile([
    OPS.OP_DUP,
    OPS.OP_HASH160,
    pubKeyHash,
    OPS.OP_EQUALVERIFY,
    OPS.OP_CHECKSIG,
  ]);
}

module.exports = {
  check,
  encode,
};
