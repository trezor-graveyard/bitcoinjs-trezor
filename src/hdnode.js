var Buffer = require('safe-buffer').Buffer
var base58check = require('bs58check')
var bcrypto = require('./crypto')
var createHmac = require('create-hmac')
var typeforce = require('typeforce')
var types = require('./types')
var NETWORKS = require('./networks')

var BigInteger = require('bigi')
var ECPubkey = require('./ecpubkey')

var ecurve = require('ecurve')
var curve = ecurve.getCurveByName('secp256k1')

function HDNode (keyPair, chainCode) {
  typeforce(types.tuple('ECPubkey', types.Buffer256bit), arguments)

  if (!keyPair.compressed) throw new TypeError('BIP32 only allows compressed keyPairs')

  this.keyPair = keyPair
  this.chainCode = chainCode
  this.depth = 0
  this.index = 0
  this.parentFingerprint = 0x00000000
}

HDNode.HIGHEST_BIT = 0x80000000
HDNode.LENGTH = 78
HDNode.MASTER_SECRET = Buffer.from('Bitcoin seed', 'utf8')

// Used in import from XPuB
HDNode.fromBase58 = function (string, networks) {
  var buffer = base58check.decode(string)
  if (buffer.length !== 78) throw new Error('Invalid buffer length')

  // 4 bytes: version bytes
  var version = buffer.readUInt32BE(0)
  var network

  // list of networks?
  if (Array.isArray(networks)) {
    network = networks.filter(function (x) {
      return version === x.bip32.private ||
             version === x.bip32.public
    }).pop()

    if (!network) throw new Error('Unknown network version')

  // otherwise, assume a network object (or default to bitcoin)
  } else {
    network = networks || NETWORKS.bitcoin
  }

  if (version !== network.bip32.public) throw new Error('Invalid network version')

  // 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 descendants, ...
  var depth = buffer[4]

  // 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
  var parentFingerprint = buffer.readUInt32BE(5)
  if (depth === 0) {
    if (parentFingerprint !== 0x00000000) throw new Error('Invalid parent fingerprint')
  }

  // 4 bytes: child number. This is the number i in xi = xpar/i, with xi the key being serialized.
  // This is encoded in MSB order. (0x00000000 if master key)
  var index = buffer.readUInt32BE(9)
  if (depth === 0 && index !== 0) throw new Error('Invalid index')

  // 32 bytes: the chain code
  var chainCode = buffer.slice(13, 45)

  // 33 bytes: private key data (0x00 + k)
  var Q = ecurve.Point.decodeFrom(curve, buffer.slice(45, 78))
  // Q.compressed is assumed, if somehow this assumption is broken, `new HDNode` will throw

  var keyPair = new ECPubkey(Q, { network: network })

  var hd = new HDNode(keyPair, chainCode)
  hd.depth = depth
  hd.index = index
  hd.parentFingerprint = parentFingerprint

  return hd
}

// used in hd-wallet if we dont have emscripten
HDNode.prototype.getAddress = function () {
  return this.keyPair.getAddress()
}

// maybe used in hd-wallet if we dont have emscripten
HDNode.prototype.toBase58 = function () {
  // Version
  var network = this.keyPair.network
  var version = network.bip32.public
  var buffer = Buffer.allocUnsafe(78)

  // 4 bytes: version bytes
  buffer.writeUInt32BE(version, 0)

  // 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 descendants, ....
  buffer.writeUInt8(this.depth, 4)

  // 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
  buffer.writeUInt32BE(this.parentFingerprint, 5)

  // 4 bytes: child number. This is the number i in xi = xpar/i, with xi the key being serialized.
  // This is encoded in big endian. (0x00000000 if master key)
  buffer.writeUInt32BE(this.index, 9)

  // 32 bytes: the chain code
  this.chainCode.copy(buffer, 13)

  // 33 bytes: the public key or private key data
  // X9.62 encoding for public keys
  this.keyPair.getPublicKeyBuffer().copy(buffer, 45)

  return base58check.encode(buffer)
}

// maybe used in hd-wallet if we dont have emscripten
HDNode.prototype.derive = function (index) {
  typeforce(types.UInt32, index)

  var isHardened = index >= HDNode.HIGHEST_BIT
  var data = Buffer.allocUnsafe(37)

  // Hardened child
  if (isHardened) {
    throw new TypeError('Could not derive hardened child key')
  }

  // data = serP(point(kpar)) || ser32(index)
  //      = serP(Kpar) || ser32(index)
  this.keyPair.getPublicKeyBuffer().copy(data, 0)
  data.writeUInt32BE(index, 33)

  var I = createHmac('sha512', this.chainCode).update(data).digest()
  var IL = I.slice(0, 32)
  var IR = I.slice(32)

  var pIL = BigInteger.fromBuffer(IL)

  // In case parse256(IL) >= n, proceed with the next value for i
  if (pIL.compareTo(curve.n) >= 0) {
    return this.derive(index + 1)
  }

  // Private parent key -> private child key
  var derivedKeyPair
  // Ki = point(parse256(IL)) + Kpar
  //    = G*IL + Kpar
  var Ki = curve.G.multiply(pIL).add(this.keyPair.Q)

  // In case Ki is the point at infinity, proceed with the next value for i
  if (curve.isInfinity(Ki)) {
    return this.derive(index + 1)
  }

  derivedKeyPair = new ECPubkey(Ki, {
    network: this.keyPair.network
  })

  var hd = new HDNode(derivedKeyPair, IR)
  hd.depth = this.depth + 1
  hd.index = index

  var identifier = bcrypto.hash160(this.keyPair.getPublicKeyBuffer())
  var fingerprint = identifier.slice(0, 4)

  hd.parentFingerprint = fingerprint.readUInt32BE(0)

  return hd
}

HDNode.prototype.derivePath = function (path) {
  typeforce(types.BIP32Path, path)

  var splitPath = path.split('/')
  if (splitPath[0] === 'm') {
    if (this.parentFingerprint) {
      throw new Error('Not a master node')
    }

    splitPath = splitPath.slice(1)
  }

  return splitPath.reduce(function (prevHd, indexStr) {
    var index
    if (indexStr.slice(-1) === "'") {
      throw new Error('Cennot derive hardened')
    } else {
      index = parseInt(indexStr, 10)
      return prevHd.derive(index)
    }
  }, this)
}

module.exports = HDNode
