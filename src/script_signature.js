var bip66 = require('bip66')
var BigInteger = require('bigi')

// BIP62: 1 byte hashType flag (only 0x01, 0x02, 0x03, 0x81, 0x82 and 0x83 are allowed)
function decode (buffer) {
  var hashType = buffer.readUInt8(buffer.length - 1)
  var hashTypeMod = hashType & ~0x80
  if (hashTypeMod <= 0 || hashTypeMod >= 4) throw new Error('Invalid hashType ' + hashType)

  var decode = bip66.decode(buffer.slice(0, -1))

  return {
    signature: {
      r: BigInteger.fromDERInteger(decode.r),
      s: BigInteger.fromDERInteger(decode.s)
    },
    hashType: hashType
  }
}

function encode (signature, hashType) {
  var hashTypeMod = hashType & ~0x80
  if (hashTypeMod <= 0 || hashTypeMod >= 4) throw new Error('Invalid hashType ' + hashType)

  var hashTypeBuffer = new Buffer(1)
  hashTypeBuffer.writeUInt8(hashType, 0)

  var r = new Buffer(signature.r.toDERInteger())
  var s = new Buffer(signature.s.toDERInteger())

  return Buffer.concat([
    bip66.encode(r, s),
    hashTypeBuffer
  ])
}

module.exports = {
  decode: decode,
  encode: encode
}
