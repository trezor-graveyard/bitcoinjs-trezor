// Note - this used to be ECPair in bitcoinjs-lib
// But since we do never use private keys in JS in trezor,
// I gutted ECPair and left it to hold just private key

var baddress = require('./address')
var bcrypto = require('./crypto')
var randomBytes = require('randombytes')
var typeforce = require('typeforce')
var types = require('./types')
var wif = require('wif')

var NETWORKS = require('./networks')
var BigInteger = require('bigi')

var ecurve = require('ecurve')
var secp256k1 = ecurve.getCurveByName('secp256k1')

function ECPair (Q, options) {
  if (options) {
    typeforce({
      compressed: types.maybe(types.Boolean),
      network: types.maybe(types.Network)
    }, options)
  }

  options = options || {}
  typeforce(types.ECPoint, Q)

  this.Q = Q

  this.compressed = options.compressed === undefined ? true : options.compressed
  this.network = options.network || NETWORKS.bitcoin
}

// used in HDNode.getAddress
// that is used in hd-wallet when we dont have emscripten
ECPair.prototype.getAddress = function () {
  return baddress.toBase58Check(bcrypto.hash160(this.getPublicKeyBuffer()), this.network.pubKeyHash)
}

// used in HDNode toBase58
// that is used in hd-wallet when we dont have emscripten
ECPair.prototype.getPublicKeyBuffer = function () {
  return this.Q.getEncoded(this.compressed)
}

module.exports = ECPair
