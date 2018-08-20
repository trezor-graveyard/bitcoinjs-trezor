// OP_0 {pubKeyHash}

var bscript = require('../../script')
var types = require('../../types')
var typeforce = require('typeforce')
var OPS = require('bitcoin-ops')

// used in address.fromOutputScript
function check (script) {
  var buffer = bscript.compile(script)

  return buffer.length === 22 &&
    buffer[0] === OPS.OP_0 &&
    buffer[1] === 0x14
}
check.toJSON = function () { return 'Witness pubKeyHash output' }

// used for sanity checks
// after Trezor signs transaction, we encode the expected outputs
// and compare from what came from Trezor
function encode (pubKeyHash) {
  typeforce(types.Hash160bit, pubKeyHash)

  return bscript.compile([OPS.OP_0, pubKeyHash])
}

module.exports = {
  check: check,
  encode: encode
}
