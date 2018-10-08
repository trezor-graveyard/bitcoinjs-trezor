// OP_HASH160 {scriptHash} OP_EQUAL

const typeforce = require('typeforce');
const OPS = require('bitcoin-ops');
const bscript = require('../../script');
const types = require('../../types');

// used in address.fromOutputScript
function check(script) {
  const buffer = bscript.compile(script);

  return buffer.length === 23
    && buffer[0] === OPS.OP_HASH160
    && buffer[1] === 0x14
    && buffer[22] === OPS.OP_EQUAL;
}
check.toJSON = function () { return 'scriptHash output'; };

// used for sanity checks
// after Trezor signs transaction, we encode the expected outputs
// and compare from what came from Trezor
function encode(scriptHash) {
  typeforce(types.Hash160bit, scriptHash);

  return bscript.compile([OPS.OP_HASH160, scriptHash, OPS.OP_EQUAL]);
}

module.exports = {
  check,
  encode,
};
