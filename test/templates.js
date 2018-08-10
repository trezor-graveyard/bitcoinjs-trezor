/* global describe, it */

var assert = require('assert')
var bcrypto = require('../src/crypto')
var bscript = require('../src/script')
var btemplates = require('../src/templates')
var ops = require('bitcoin-ops')

var fixtures = require('./fixtures/templates.json')

function fromHex (x) { return Buffer.from(x, 'hex') }
function toHex (x) { return x.toString('hex') }

describe('script-templates', function () {

  describe('checks nulldata correctly', function () {
    fixtures.valid.forEach(function (f) {
      if (!f.output) return
      var isNulldata = f.type === 'nulldata'

      it(f.output + ' is ' + (isNulldata ? '' : 'not ') + 'nulldata', function () {
        var output = bscript.fromASM(f.output)
        var check = btemplates.nullData.output.check(output)

        assert.strictEqual(check, isNulldata)
      })
    })
  })

  describe('pubKeyHash.output', function () {
    fixtures.valid.forEach(function (f) {
      if (f.type !== 'pubkeyhash') return

      var pubKey = Buffer.from(f.pubKey, 'hex')
      var pubKeyHash = bcrypto.hash160(pubKey)
      var output = btemplates.pubKeyHash.output.encode(pubKeyHash)

      it('encodes to ' + f.output, function () {
        assert.strictEqual(bscript.toASM(output), f.output)
      })
    })

    fixtures.invalid.pubKeyHash.outputs.forEach(function (f) {
      if (!f.hash) return
      var hash = Buffer.from(f.hash, 'hex')

      it('throws on ' + f.exception, function () {
        assert.throws(function () {
          btemplates.pubKeyHash.output.encode(hash)
        }, new RegExp(f.exception))
      })
    })
  })

  describe('scriptHash.output', function () {
    fixtures.valid.forEach(function (f) {
      if (f.type !== 'scripthash') return
      if (!f.output) return

      var redeemScript = bscript.fromASM(f.redeemScript)
      var scriptHash = bcrypto.hash160(redeemScript)
      var output = btemplates.scriptHash.output.encode(scriptHash)

      it('encodes to ' + f.output, function () {
        assert.strictEqual(bscript.toASM(output), f.output)
      })
    })

    fixtures.invalid.scriptHash.outputs.forEach(function (f) {
      if (!f.hash) return
      var hash = Buffer.from(f.hash, 'hex')

      it('throws on ' + f.exception, function () {
        assert.throws(function () {
          btemplates.scriptHash.output.encode(hash)
        }, new RegExp(f.exception))
      })
    })
  })


  describe('witnessPubKeyHash.output', function () {
    fixtures.valid.forEach(function (f) {
      if (f.type !== 'witnesspubkeyhash') return
      if (!f.output) return

      var pubKey = Buffer.from(f.pubKey, 'hex')
      var pubKeyHash = bcrypto.hash160(pubKey)
      var output = btemplates.witnessPubKeyHash.output.encode(pubKeyHash)

      it('encodes to ' + f.output, function () {
        assert.strictEqual(bscript.toASM(output), f.output)
      })
    })

    fixtures.invalid.witnessPubKeyHash.outputs.forEach(function (f) {
      if (!f.hash) return
      var hash = Buffer.from(f.hash, 'hex')

      it('throws on ' + f.exception, function () {
        assert.throws(function () {
          btemplates.witnessPubKeyHash.output.encode(hash)
        }, new RegExp(f.exception))
      })
    })
  })

  describe('witnessScriptHash.output', function () {
    fixtures.valid.forEach(function (f) {
      if (f.type !== 'witnessscripthash') return
      if (!f.output) return

      var witnessScriptPubKey = bscript.fromASM(f.witnessScript)
      var scriptHash = bcrypto.hash256(witnessScriptPubKey)
      var output = btemplates.witnessScriptHash.output.encode(scriptHash)

      it('encodes to ' + f.output, function () {
        assert.strictEqual(bscript.toASM(output), f.output)
      })
    })

    fixtures.invalid.witnessScriptHash.outputs.forEach(function (f) {
      if (!f.hash) return
      var hash = Buffer.from(f.hash, 'hex')

      it('throws on ' + f.exception, function () {
        assert.throws(function () {
          btemplates.witnessScriptHash.output.encode(hash)
        }, new RegExp(f.exception))
      })
    })
  })

  describe('witnessCommitment.output', function () {
    fixtures.valid.forEach(function (f) {
      if (f.type !== 'witnesscommitment') return
      if (!f.scriptPubKey) return

      var commitment = Buffer.from(f.witnessCommitment, 'hex')
      var scriptPubKey = btemplates.witnessCommitment.output.encode(commitment)

      it('encodes to ' + f.scriptPubKey, function () {
        assert.strictEqual(bscript.toASM(scriptPubKey), f.scriptPubKey)
      })

      it('decodes to ' + commitment.toString('hex'), function () {
        assert.deepEqual(btemplates.witnessCommitment.output.decode(scriptPubKey), commitment)
      })
    })

    fixtures.invalid.witnessCommitment.outputs.forEach(function (f) {
      if (f.commitment) {
        var hash = Buffer.from(f.commitment, 'hex')
        it('throws on bad encode data', function () {
          assert.throws(function () {
            btemplates.witnessCommitment.output.encode(hash)
          }, new RegExp(f.exception))
        })
      }
    })
  })

  describe('nullData.output', function () {
    fixtures.valid.forEach(function (f) {
      if (f.type !== 'nulldata') return

      var data = Buffer.from(f.data, 'hex')
      var output = btemplates.nullData.output.encode(data)

      it('encodes to ' + f.output, function () {
        assert.strictEqual(bscript.toASM(output), f.output)
      })

      it('decodes to ' + f.data, function () {
        assert.deepEqual(btemplates.nullData.output.decode(output), data)
      })
    })
  })
})
