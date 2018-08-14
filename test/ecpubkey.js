/* global describe, it, beforeEach */
/* eslint-disable no-new */

var assert = require('assert')
var sinon = require('sinon')

var ECPubkey = require('../src/ecpubkey')

var fixtures = require('./fixtures/ecpubkey.json')
var ecurve = require('ecurve')
var curve = ecurve.getCurveByName('secp256k1')

var NETWORKS = require('../src/networks')
var NETWORKS_LIST = [] // Object.values(NETWORKS)
for (var networkName in NETWORKS) {
  NETWORKS_LIST.push(NETWORKS[networkName])
}
var dfQ = fixtures.valid[0].Q
var dQ = ecurve.Point.decodeFrom(curve, Buffer.from(dfQ, 'hex'))

describe('ECPubkey', function () {
  describe('constructor', function () {
    it('defaults to compressed', function () {
      var pubkey = new ECPubkey(dQ)

      assert.strictEqual(pubkey.compressed, true)
    })

    it('supports the uncompressed option', function () {
      var pubkey = new ECPubkey(dQ, {
        compressed: false
      })

      assert.strictEqual(pubkey.compressed, false)
    })

    it('supports the network option', function () {
      var pubkey = new ECPubkey(dQ, {
        compressed: false,
        network: NETWORKS.testnet
      })

      assert.strictEqual(pubkey.network, NETWORKS.testnet)
    })

    fixtures.invalid.constructor.forEach(function (f) {
      it('throws ' + f.exception, function () {
        var Q = f.Q && ecurve.Point.decodeFrom(curve, Buffer.from(f.Q, 'hex'))

        assert.throws(function () {
          new ECPubkey(Q, f.options)
        }, new RegExp(f.exception))
      })
    })
  })

  describe('getPublicKeyBuffer', function () {
    var pubkey 

    beforeEach(function () {
      pubkey = new ECPubkey(dQ)
    })

    it('wraps Q.getEncoded', sinon.test(function () {
      this.mock(pubkey.Q).expects('getEncoded')
        .once().withArgs(pubkey.compressed)

      pubkey.getPublicKeyBuffer()
    }))
  })

  describe('getAddress', function () {
    fixtures.valid.forEach(function (f) {
      it('returns ' + f.address + ' for ' + f.Q, function () {
        var Q = ecurve.Point.decodeFrom(curve, Buffer.from(f.Q, 'hex'))

        var pubkey = new ECPubkey(Q, {
          compressed: f.compressed,
          network: NETWORKS[f.network]
        })

        assert.strictEqual(pubkey.getAddress(), f.address)
      })
    })
  })
})
