// Note - this used to be ECPair in bitcoinjs-lib
// But since we do never use private keys in JS in trezor,
// I gutted ECPair and left it to hold just private key

var baddress = require('./address')
var bcrypto = require('./crypto')
var typeforce = require('typeforce')
var types = require('./types')

var NETWORKS = require('./networks')

function ECPubkey (Q, options) {
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
ECPubkey.prototype.getAddress = function () {
  return baddress.toBase58Check(bcrypto.hash160(this.getPublicKeyBuffer()), this.network.pubKeyHash)
}

// used in HDNode toBase58
// that is used in hd-wallet when we dont have emscripten
ECPubkey.prototype.getPublicKeyBuffer = function () {
  return this.Q.getEncoded(this.compressed)
}

module.exports = ECPubkey
