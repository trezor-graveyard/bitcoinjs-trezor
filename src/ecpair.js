var baddress = require('./address')
var bcrypto = require('./crypto')
var bs58check = require('bs58check')
var randomBytes = require('randombytes')
var secp256k1 = require('./ecdsa')
var typeforce = require('typeforce')
var types = require('./types')
var wif = require('wif')

var NETWORKS = require('./networks')

function ECPair (d, Q, options) {
  if (options) {
    typeforce({
      compressed: types.maybe(types.Boolean),
      network: types.maybe(types.Network),
      validate: types.maybe(types.Boolean)
    }, options)
  } else {
    options = {}
  }

  options.network = options.network || NETWORKS.bitcoin

  if (d) {
    typeforce(types.Buffer256bit, d)

    if (Q) throw new TypeError('Unexpected public key parameter')
    if (!secp256k1.intCheck(d)) throw new TypeError('Private key must be within the interval [1, n - 1]')

    this.__d = d
    this.__compressed = options.compressed === undefined ? true : options.compressed
  } else if (Q) {
    typeforce(types.Buffer, Q)

    if (options.validate) {
      secp256k1.pointVerify(Q)
    }

    if (options.compressed && Q.length !== 65) {
      throw new TypeError('Expected compressed public key')
    } else if (Q.length !== 33) {
      throw new TypeError('Expected uncompressed public key')
    }

    this.__Q = Q

    // TODO: remove
    this.__compressed = (Q.length === 33)
  }

  typeforce(types.Network, options.network)
  this.__network = options.network
}

ECPair.fromWIF = function (string, network) {
  network = network || NETWORKS.bitcoin
  var buffer = bs58check.decode(string)

  if (types.Array(network)) {
    var version = buffer[0]

    network = network.filter(function (network) {
      return version === network.wif
    }).pop() || {}
  }

  var decoded = wif.decode(network.wif, string)

  return new ECPair(decoded.d, null, {
    compressed: decoded.compressed,
    network: network
  })
}

ECPair.makeRandom = function (options) {
  options = options || {}

  var rng = options.rng || randomBytes
  var d
  do {
    d = rng(32)
    typeforce(types.Buffer256bit, d)
  } while (!secp256k1.intCheck(d))

  return new ECPair(d, null, options)
}

ECPair.prototype.getAddress = function () {
  return baddress.toBase58Check(bcrypto.hash160(this.getPublic()), this.getNetwork().pubKeyHash)
}

ECPair.prototype.getNetwork = function () {
  return this.__network
}

ECPair.prototype.getPrivate = function () {
  if (!this.__d) throw new Error('Missing private key')
  return this.__d
}

ECPair.prototype.getPublic = function () {
  if (!this.__Q) {
    this.__Q = secp256k1.pointDerive(this.getPrivate(), this.isCompressed())
  }

  return this.__Q
}

ECPair.prototype.isCompressed = function () {
  return this.__compressed
//   return this.getPublic().length === 33
}

ECPair.prototype.sign = function (hash) {
  return secp256k1.sign(hash, this.getPrivate())
}

ECPair.prototype.toWIF = function () {
  if (!this.__d) throw new Error('Missing private key')
  return wif.encode(this.getNetwork().wif, this.getPrivate(), this.isCompressed())
}

ECPair.prototype.verify = function (hash, signature) {
  return secp256k1.verify(hash, signature, this.getPublic())
}

module.exports = ECPair
