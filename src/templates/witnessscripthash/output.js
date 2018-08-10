// OP_0 {scriptHash}

var bscript = require('../../script')
var types = require('../../types')
var typeforce = require('typeforce')
var OPS = require('bitcoin-ops')

// used in address.fromOutputScript
function check (script) {
  var buffer = bscript.compile(script)

  return buffer.length === 34 &&
    buffer[0] === OPS.OP_0 &&
    buffer[1] === 0x20
}
check.toJSON = function () { return 'Witness scriptHash output' }

// used for sanity checks
// after Trezor signs transaction, we encode the expected outputs
// and compare from what came from Trezor
function encode (scriptHash) {
  typeforce(types.Hash256bit, scriptHash)

  return bscript.compile([OPS.OP_0, scriptHash])
}

module.exports = {
  check: check,
  encode: encode
}
