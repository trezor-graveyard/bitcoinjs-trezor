/* global describe, it */

var assert = require('assert')
var base58 = require('bs58')
var bitcoin = require('../')

var base58EncodeDecode = require('./fixtures/core/base58_encode_decode.json')
var base58KeysInvalid = require('./fixtures/core/base58_keys_invalid.json')
var base58KeysValid = require('./fixtures/core/base58_keys_valid.json')
var sigCanonical = require('./fixtures/core/sig_canonical.json')
var sigHash = require('./fixtures/core/sighash.json')
var sigNoncanonical = require('./fixtures/core/sig_noncanonical.json')
var txValid = require('./fixtures/core/tx_valid.json')

describe('Bitcoin-core', function () {
  // base58EncodeDecode
  describe('base58', function () {
    base58EncodeDecode.forEach(function (f) {
      var fhex = f[0]
      var fb58 = f[1]

      it('can decode ' + fb58, function () {
        var buffer = base58.decode(fb58)
        var actual = buffer.toString('hex')

        assert.strictEqual(actual, fhex)
      })

      it('can encode ' + fhex, function () {
        var buffer = Buffer.from(fhex, 'hex')
        var actual = base58.encode(buffer)

        assert.strictEqual(actual, fb58)
      })
    })
  })

  // base58KeysValid
  describe('address.toBase58Check', function () {
    var typeMap = {
      'pubkey': 'pubKeyHash',
      'script': 'scriptHash'
    }

    base58KeysValid.forEach(function (f) {
      var expected = f[0]
      var hash = Buffer.from(f[1], 'hex')
      var params = f[2]

      if (params.isPrivkey) return

      var network = params.isTestnet ? bitcoin.networks.testnet : bitcoin.networks.bitcoin
      var version = network[typeMap[params.addrType]]

      it('can export ' + expected, function () {
        assert.strictEqual(bitcoin.address.toBase58Check(hash, version), expected)
      })
    })
  })

  // base58KeysInvalid
  describe('address.fromBase58Check', function () {
    var allowedNetworks = [
      bitcoin.networks.bitcoin.pubkeyhash,
      bitcoin.networks.bitcoin.scripthash,
      bitcoin.networks.testnet.pubkeyhash,
      bitcoin.networks.testnet.scripthash
    ]

    base58KeysInvalid.forEach(function (f) {
      var string = f[0]

      it('throws on ' + string, function () {
        assert.throws(function () {
          var address = bitcoin.address.fromBase58Check(string)

          assert.notEqual(allowedNetworks.indexOf(address.version), -1, 'Invalid network')
        }, /(Invalid (checksum|network))|(too (short|long))/)
      })
    })
  })

  // base58KeysValid
  describe('ECPair', function () {
    base58KeysValid.forEach(function (f) {
      var string = f[0]
      var hex = f[1]
      var params = f[2]

      if (!params.isPrivkey) return

      var network = params.isTestnet ? bitcoin.networks.testnet : bitcoin.networks.bitcoin
      var keyPair = bitcoin.ECPair.fromWIF(string, network)

      it('fromWIF imports ' + string, function () {
        assert.strictEqual(keyPair.d.toHex(), hex)
        assert.strictEqual(keyPair.compressed, params.isCompressed)
      })

      it('toWIF exports ' + hex + ' to ' + string, function () {
        assert.strictEqual(keyPair.toWIF(), string)
      })
    })
  })

  // base58KeysInvalid
  describe('ECPair.fromWIF', function () {
    var allowedNetworks = [
      bitcoin.networks.bitcoin,
      bitcoin.networks.testnet
    ]

    base58KeysInvalid.forEach(function (f) {
      var string = f[0]

      it('throws on ' + string, function () {
        assert.throws(function () {
          bitcoin.ECPair.fromWIF(string, allowedNetworks)
        }, /(Invalid|Unknown) (checksum|compression flag|network version|WIF length)/)
      })
    })
  })

  // txValid
  describe('Transaction.fromHex', function () {
    txValid.forEach(function (f) {
      // Objects that are only a single string are ignored
      if (f.length === 1) return

      var inputs = f[0]
      var fhex = f[1]
      //      var verifyFlags = f[2] // TODO: do we need to test this?

      it('can decode ' + fhex, function () {
        var transaction = bitcoin.Transaction.fromHex(fhex)

        transaction.ins.forEach(function (txIn, i) {
          var input = inputs[i]

          // reverse because test data is reversed
          var prevOutHash = Buffer.from(input[0], 'hex').reverse()
          var prevOutIndex = input[1]

          assert.deepEqual(txIn.hash, prevOutHash)

          // we read UInt32, not Int32
          assert.strictEqual(txIn.index & 0xffffffff, prevOutIndex)
        })
      })
    })
  })

  describe('ECSignature.parseScriptSignature', function () {
    sigCanonical.forEach(function (hex) {
      var buffer = Buffer.from(hex, 'hex')

      it('can parse ' + hex, function () {
        var parsed = bitcoin.ECSignature.parseScriptSignature(buffer)
        var actual = parsed.signature.toScriptSignature(parsed.hashType)
        assert.strictEqual(actual.toString('hex'), hex)
      })
    })

    sigNoncanonical.forEach(function (hex, i) {
      if (i === 0) return
      if (i % 2 !== 0) return

      var description = sigNoncanonical[i - 1].slice(0, -1)
      var buffer = Buffer.from(hex, 'hex')

      it('throws on ' + description, function () {
        assert.throws(function () {
          bitcoin.ECSignature.parseScriptSignature(buffer)
        }, /Expected DER (integer|sequence)|(R|S) value (excessively padded|is negative)|(R|S|DER sequence) length is (zero|too short|too long|invalid)|Invalid hashType/)
      })
    })
  })
})
