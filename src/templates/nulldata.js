// OP_RETURN {data}

var bscript = require('../script')
var types = require('../types')
var typeforce = require('typeforce')
var OPS = require('bitcoin-ops')

function check (script) {
  return script.length === 2 &&
     script[0] === OPS.OP_RETURN
}
check.toJSON = function () { return 'null data output' }

function encode (data) {
  typeforce(types.Buffer, data)

  return bscript.compile([OPS.OP_RETURN, data])
}


module.exports = {
  output: {
    check: check,
    encode: encode
  }
}
