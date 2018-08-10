// OP_RETURN {data}

var bscript = require('../script')
var types = require('../types')
var typeforce = require('typeforce')
var OPS = require('bitcoin-ops')

// used in hd-wallet for decoding OP_RETURN
function check (script) {
  var chunks = bscript.decompile(script)
  return chunks.length === 2 &&
     chunks[0] === OPS.OP_RETURN
}
check.toJSON = function () { return 'null data output' }

// used in hd-wallet for reading OP_RETURN data
function decode (buffer) {
  var script = bscript.decompile(buffer)
  typeforce(check, script)

  return script[1]
}

// used for sanity checks
// after Trezor signs transaction, we encode the expected outputs
// and compare from what came from Trezor
function encode (data) {
  typeforce(types.Buffer, data)

  return bscript.compile([OPS.OP_RETURN, data])
}


module.exports = {
  output: {
    check: check,
    decode: decode,
    encode: encode
  }
}
