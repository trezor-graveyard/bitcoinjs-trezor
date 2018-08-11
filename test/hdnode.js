/* global describe, it, beforeEach */
/* eslint-disable no-new */

var assert = require('assert')
var sinon = require('sinon')

var BigInteger = require('bigi')
var ECPubkey = require('../src/ecpubkey')
var HDNode = require('../src/hdnode')

var fixtures = require('./fixtures/hdnode.json')
var ecurve = require('ecurve')
var curve = ecurve.getCurveByName('secp256k1')

var NETWORKS = require('../src/networks')
var NETWORKS_LIST = [] // Object.values(NETWORKS)
for (var networkName in NETWORKS) {
  NETWORKS_LIST.push(NETWORKS[networkName])
}

var validAll = []
fixtures.valid.forEach(function (f) {
  function addNetwork (n) {
    n.network = f.network
    return n
  }

  validAll = validAll.concat(addNetwork(f.master), f.children.map(addNetwork))
})

describe('HDNode', function () {
  describe('Constructor', function () {
    var keyPair, chainCode

    beforeEach(function () {
      var Q = ecurve.Point.decodeFrom(curve, Buffer.from('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', 'hex'))
      keyPair = new ECPubkey(Q)
      chainCode = Buffer.alloc(32, 1)
    })

    it('stores the keyPair/chainCode directly', function () {
      var hd = new HDNode(keyPair, chainCode)

      assert.strictEqual(hd.keyPair, keyPair)
      assert.strictEqual(hd.chainCode, chainCode)
    })

    it('has a default depth/index of 0', function () {
      var hd = new HDNode(keyPair, chainCode)

      assert.strictEqual(hd.depth, 0)
      assert.strictEqual(hd.index, 0)
    })

    it('throws on uncompressed keyPair', function () {
      keyPair.compressed = false

      assert.throws(function () {
        new HDNode(keyPair, chainCode)
      }, /BIP32 only allows compressed keyPairs/)
    })

    it('throws when an invalid length chain code is given', function () {
      assert.throws(function () {
        new HDNode(keyPair, Buffer.alloc(20))
      }, /Expected property "1" of type Buffer\(Length: 32\), got Buffer\(Length: 20\)/)
    })
  })

  describe('ECPubkey wrappers', function () {
    var keyPair, hd, hash

    beforeEach(function () {
      var Q = ecurve.Point.decodeFrom(curve, Buffer.from('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', 'hex'))
      keyPair = new ECPubkey(Q)
      hash = Buffer.alloc(32)

      var chainCode = Buffer.alloc(32)
      hd = new HDNode(keyPair, chainCode)
    })

    describe('getAddress', function () {
      it('wraps keyPair.getAddress', sinon.test(function () {
        this.mock(keyPair).expects('getAddress')
          .once().withArgs().returns('foobar')

        assert.strictEqual(hd.getAddress(), 'foobar')
      }))
    })
  })

  describe('fromBase58 / toBase58', function () {
    validAll.forEach(function (f) {
      it('exports ' + f.base58 + ' (public) correctly', function () {
        var hd = HDNode.fromBase58(f.base58, NETWORKS_LIST)

        assert.strictEqual(hd.toBase58(), f.base58)
      })
    })

    fixtures.invalid.fromBase58.forEach(function (f) {
      it('throws on ' + f.string, function () {
        assert.throws(function () {
          var networks = f.network ? NETWORKS[f.network] : NETWORKS_LIST

          HDNode.fromBase58(f.string, networks)
        }, new RegExp(f.exception))
      })
    })
  })

  describe('derive', function () {
    function verifyVector (hd, v) {
      assert.strictEqual(hd.toBase58(), v.base58)

      assert.strictEqual(hd.getAddress(), v.address)
      assert.strictEqual(hd.keyPair.getPublicKeyBuffer().toString('hex'), v.pubKey)
      assert.strictEqual(hd.chainCode.toString('hex'), v.chainCode)
      assert.strictEqual(hd.depth, v.depth >>> 0)
      assert.strictEqual(hd.index, v.index >>> 0)
    }

    fixtures.valid.forEach(function (f) {
      var network = NETWORKS[f.network]
      var hd = HDNode.fromBase58(f.master.base58, network)
      var master = hd

      // testing deriving path from master
      f.children.forEach(function (c) {
        it(c.path + ' from ' + f.master.fingerprint + ' by path', function () {
          var child = master.derivePath(c.path)
          var childNoM = master.derivePath(c.path.slice(2)) // no m/ on path

          verifyVector(child, c)
          verifyVector(childNoM, c)
        })
      })

      // testing deriving path from children
      f.children.forEach(function (c, i) {
        var cn = master.derivePath(c.path)

        f.children.slice(i + 1).forEach(function (cc) {
          it(cc.path + ' from ' + c.fingerprint + ' by path', function () {
            var ipath = cc.path.slice(2).split('/').slice(i + 1).join('/')
            var child = cn.derivePath(ipath)
            verifyVector(child, cc)

            assert.throws(function () {
              cn.derivePath('m/' + ipath)
            }, /Not a master node/)
          })
        })
      })

      // FIXME: test data is only testing Private -> private for now
      f.children.forEach(function (c) {
        if (c.m === undefined) return

        it(c.path + ' from ' + f.master.fingerprint, function () {
          if (c.hardened) {
            hd = hd.deriveHardened(c.m)
          } else {
            hd = hd.derive(c.m)
          }

          verifyVector(hd, c)
        })
      })
    })

   it('works for Public -> public', function () {
      var f = fixtures.valid[1]
      var c = f.children[0]

      var master = HDNode.fromBase58(f.master.base58, NETWORKS_LIST)
      var child = master.derive(c.m)

      assert.strictEqual(c.base58, child.toBase58())
    })

    it('throws on wrong types', function () {
      var f = fixtures.valid[0]
      var master = HDNode.fromBase58(f.master.base58, NETWORKS_LIST)

      fixtures.invalid.derive.forEach(function (fx) {
        assert.throws(function () {
          master.derive(fx)
        }, /Expected UInt32/)
      })

      fixtures.invalid.derivePath.forEach(function (fx) {
        assert.throws(function () {
          master.derivePath(fx)
        }, /Expected BIP32 derivation path/)
      })
    })
  })
})
