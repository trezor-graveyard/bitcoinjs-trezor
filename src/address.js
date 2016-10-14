var bs58check = require('bs58check')
var bscript = require('./script')
var networks = require('./networks')
var typeforce = require('typeforce')
var types = require('./types')

function fromBase58Check (address) {
  var payload = bs58check.decode(address)
  if (payload.length < 21) throw new TypeError(address + ' is too short')
  if (payload.length > 22) throw new TypeError(address + ' is too long')

  var multibyte = payload.length === 22
  var offset = multibyte ? 2 : 1

  var version = multibyte ? payload.readUInt16BE(0) : payload[0]
  var hash = payload.slice(offset)

  return { hash: hash, version: version }
}

function toBase58Check (hash, version) {
  typeforce(types.tuple(types.Hash160bit, types.UInt16), arguments)

  var multibyte = version > 0xff
  var size = multibyte ? 22 : 21
  var offset = multibyte ? 2 : 1

  var payload = new Buffer(size)
  multibyte ? payload.writeUInt16BE(version, 0) : payload.writeUInt8(version, 0)
  hash.copy(payload, offset)

  return bs58check.encode(payload)
}

function fromOutputScript (outputScript, network) {
  network = network || networks.bitcoin

  if (bscript.pubKeyHash.output.check(outputScript)) return toBase58Check(bscript.compile(outputScript).slice(3, 23), network.pubKeyHash)
  if (bscript.scriptHash.output.check(outputScript)) return toBase58Check(bscript.compile(outputScript).slice(2, 22), network.scriptHash)

  throw new Error(bscript.toASM(outputScript) + ' has no matching Address')
}

function toOutputScript (address, network) {
  network = network || networks.bitcoin

  var decode = fromBase58Check(address)
  if (decode.version === network.pubKeyHash) return bscript.pubKeyHash.output.encode(decode.hash)
  if (decode.version === network.scriptHash) return bscript.scriptHash.output.encode(decode.hash)

  throw new Error(address + ' has no matching Script')
}

module.exports = {
  fromBase58Check: fromBase58Check,
  fromOutputScript: fromOutputScript,
  toBase58Check: toBase58Check,
  toOutputScript: toOutputScript
}
