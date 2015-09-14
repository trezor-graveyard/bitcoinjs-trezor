var base58check = require('bs58check')
var bcrypto = require('./crypto')
var createHmac = require('create-hmac')
var secp256k1 = require('./ecdsa')
var typeforce = require('typeforce')
var types = require('./types')

var ECPair = require('./ecpair')
var NETWORKS = require('./networks')

function HDNode (keyPair, chainCode) {
  typeforce(types.tuple('ECPair', types.Buffer256bit), arguments)

  if (!keyPair.__compressed) throw new TypeError('BIP32 only allows compressed keyPairs')

  this.keyPair = keyPair
  this.chainCode = chainCode
  this.depth = 0
  this.index = 0
  this.parentFingerprint = 0x00000000
}

HDNode.HIGHEST_BIT = 0x80000000
HDNode.LENGTH = 78
HDNode.MASTER_SECRET = new Buffer('Bitcoin seed')

HDNode.fromSeedBuffer = function (seed, network) {
  typeforce(types.tuple(types.Buffer, types.maybe(types.Network)), arguments)

  if (seed.length < 16) throw new TypeError('Seed should be at least 128 bits')
  if (seed.length > 64) throw new TypeError('Seed should be at most 512 bits')

  var I = createHmac('sha512', HDNode.MASTER_SECRET).update(seed).digest()
  var IL = I.slice(0, 32)
  var IR = I.slice(32)

  // if IL is <= 0 or >= n, the master key is invalid
  // checked by the ECPair constructor
  var keyPair = new ECPair(IL, null, {
    network: network
  })

  return new HDNode(keyPair, IR)
}

HDNode.fromSeedHex = function (hex, network) {
  return HDNode.fromSeedBuffer(new Buffer(hex, 'hex'), network)
}

HDNode.fromBase58 = function (string, networks) {
  var buffer = base58check.decode(string)
  if (buffer.length !== 78) throw new Error('Invalid buffer length')

  // 4 bytes: version bytes
  var version = buffer.readUInt32BE(0)
  var network

  // list of networks?
  if (Array.isArray(networks)) {
    network = networks.filter(function (network) {
      return version === network.bip32.private ||
             version === network.bip32.public
    }).pop() || {}

  // otherwise, assume a network object (or default to bitcoin)
  } else {
    network = networks || NETWORKS.bitcoin
  }

  if (version !== network.bip32.private &&
    version !== network.bip32.public) throw new Error('Invalid network')

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
  var keyPair

  // 33 bytes: private key data (0x00 + k)
  if (version === network.bip32.private) {
    if (buffer[45] !== 0x00) throw new Error('Invalid private key')

    var d = buffer.slice(46, 78)
    keyPair = new ECPair(d, null, {
      compressed: true,
      network: network
    })

  // 33 bytes: public key data (0x02 + X or 0x03 + X)
  } else {
    var Q = buffer.slice(45, 78)

    keyPair = new ECPair(null, Q, {
      compressed: true,
      network: network,

      // verify the public point corresponds to a point on the curve
      validate: true
    })
  }

  var hd = new HDNode(keyPair, chainCode)
  hd.depth = depth
  hd.index = index
  hd.parentFingerprint = parentFingerprint

  return hd
}

HDNode.prototype.getAddress = function () {
  return this.keyPair.getAddress()
}

HDNode.prototype.getIdentifier = function () {
  return bcrypto.hash160(this.keyPair.getPublic())
}

HDNode.prototype.getFingerprint = function () {
  return this.getIdentifier().slice(0, 4)
}

HDNode.prototype.getNetwork = function () {
  return this.keyPair.getNetwork()
}

HDNode.prototype.getPublicKeyBuffer = function () {
  return this.keyPair.getPublicKeyBuffer()
}

HDNode.prototype.neutered = function () {
  var neuteredKeyPair = new ECPair(null, this.keyPair.Q, {
    network: this.keyPair.network
  })

  var neutered = new HDNode(neuteredKeyPair, this.chainCode)
  neutered.depth = this.depth
  neutered.index = this.index
  neutered.parentFingerprint = this.parentFingerprint

  return neutered
}

HDNode.prototype.sign = function (hash) {
  return this.keyPair.sign(hash)
}

HDNode.prototype.verify = function (hash, signature) {
  return this.keyPair.verify(hash, signature)
}

HDNode.prototype.toBase58 = function (__isPrivate) {
  if (__isPrivate !== undefined) throw new TypeError('Unsupported argument in 2.0.0')

  // Version
  var network = this.keyPair.network
  var version = this.keyPair.d ? network.bip32.private : network.bip32.public
  var buffer = new Buffer(78)

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
  if (this.keyPair.d) {
    // 0x00 + k for private keys
    buffer.writeUInt8(0, 45)
    this.keyPair.getPrivate().copy(buffer, 46)

  // 33 bytes: the public key
  } else {
    // X9.62 encoding for public keys
    this.keyPair.getPublic().copy(buffer, 45)
  }

  return base58check.encode(buffer)
}

// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#child-key-derivation-ckd-functions
HDNode.prototype.derive = function (index) {
  var isHardened = index >= HDNode.HIGHEST_BIT
  var data = new Buffer(37)

  // hardened child
  if (isHardened) {
    if (!this.keyPair.d) throw new TypeError('Could not derive hardened child key')

    // data = 0x00 || ser256(kpar) || ser32(index)
    data[0] = 0x00
    this.keyPair.getPrivate().copy(data, 1)
    data.writeUInt32BE(index, 33)

  // normal child
  } else {
    // data = serP(point(kpar)) || ser32(index)
    //      = serP(Kpar) || ser32(index)
    this.keyPair.getPublic().copy(data, 0)
    data.writeUInt32BE(index, 33)
  }

  var I = createHmac('sha512', this.chainCode).update(data).digest()
  var IL = I.slice(0, 32)
  var IR = I.slice(32)

  // proceed for the next value of i if IL isn't within the interval
  if (!secp256k1.intCheck(IL)) {
    return this.derive(index + 1)
  }

  // private parent key -> private child key
  var derivedKeyPair
  if (this.keyPair.d) {
    // ki = parse256(IL) + kpar (mod n)
    var ki = secp256k1.intAdd(IL, this.keyPair.getPrivate())

    // in case ki == 0, proceed with the next value for i
    if (secp256k1.intSign(ki) === 0) {
      return this.derive(index + 1)
    }

    derivedKeyPair = new ECPair(ki, null, {
      compressed: true,
      network: this.keyPair.network
    })

  // public parent key -> public child key
  } else {
    // Ki = Kpar + point(parse256(IL))
    //    = Kpar + G*IL
    var Ki = secp256k1.pointAdd(this.keyPair.getPublic(), secp256k1.pointDerive(IL))

    // in case Ki is the point at infinity, proceed with the next value for i
    if (Ki === null) {
      return this.derive(index + 1)
    }

    derivedKeyPair = new ECPair(null, Ki, {
      compressed: true,
      network: this.keyPair.network
    })
  }

  var hd = new HDNode(derivedKeyPair, IR)
  hd.depth = this.depth + 1
  hd.index = index
  hd.parentFingerprint = this.getFingerprint().readUInt32BE(0)

  return hd
}

HDNode.prototype.deriveHardened = function (index) {
  // Only derives hardened private keys by default
  return this.derive(index + HDNode.HIGHEST_BIT)
}

module.exports = HDNode
