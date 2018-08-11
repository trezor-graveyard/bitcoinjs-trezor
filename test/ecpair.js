/* global describe, it, beforeEach */
/* eslint-disable no-new */

var assert = require('assert')
var proxyquire = require('proxyquire')
var sinon = require('sinon')

var BigInteger = require('bigi')
var ECPair = require('../src/ecpair')

var fixtures = require('./fixtures/ecpair.json')
var ecurve = require('ecurve')
var curve = ecurve.getCurveByName('secp256k1')

var NETWORKS = require('../src/networks')
var NETWORKS_LIST = [] // Object.values(NETWORKS)
for (var networkName in NETWORKS) {
  NETWORKS_LIST.push(NETWORKS[networkName])
}
var dfQ = fixtures.valid[0].Q
var dQ = ecurve.Point.decodeFrom(curve, Buffer.from(dfQ, 'hex'))

describe('ECPair', function () {
  describe('constructor', function () {
    it('defaults to compressed', function () {
      var keyPair = new ECPair(dQ)

      assert.strictEqual(keyPair.compressed, true)
    })

    it('supports the uncompressed option', function () {
      var keyPair = new ECPair(dQ, {
        compressed: false
      })

      assert.strictEqual(keyPair.compressed, false)
    })

    it('supports the network option', function () {
      var keyPair = new ECPair(dQ, {
        compressed: false,
        network: NETWORKS.testnet
      })

      assert.strictEqual(keyPair.network, NETWORKS.testnet)
    })

    fixtures.invalid.constructor.forEach(function (f) {
      it('throws ' + f.exception, function () {
        var Q = f.Q && ecurve.Point.decodeFrom(curve, Buffer.from(f.Q, 'hex'))

        assert.throws(function () {
          new ECPair(Q, f.options)
        }, new RegExp(f.exception))
      })
    })
  })

  describe('getPublicKeyBuffer', function () {
    var keyPair

    beforeEach(function () {
      keyPair = new ECPair(dQ)
    })

    it('wraps Q.getEncoded', sinon.test(function () {
      this.mock(keyPair.Q).expects('getEncoded')
        .once().withArgs(keyPair.compressed)

      keyPair.getPublicKeyBuffer()
    }))
  })

  describe('getAddress', function () {
    fixtures.valid.forEach(function (f) {
      it('returns ' + f.address + ' for ' + f.Q, function () {
        var Q = ecurve.Point.decodeFrom(curve, Buffer.from(f.Q, 'hex'))


        var keyPair = new ECPair(Q, {
          compressed: f.compressed,
          network: NETWORKS[f.network]
        })

        assert.strictEqual(keyPair.getAddress(), f.address)
      })
    })
  })
})
