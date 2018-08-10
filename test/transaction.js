/* global describe, it, beforeEach */

var assert = require('assert')
var bscript = require('../src/script')
var fixtures = require('./fixtures/transaction')
var Transaction = require('../src/transaction')

describe('Transaction', function () {
  function fromRaw (raw, noWitness) {
    var tx = new Transaction()
    tx.version = raw.version
    tx.locktime = raw.locktime

    raw.ins.forEach(function (txIn, i) {
      var txHash = Buffer.from(txIn.hash, 'hex')
      var scriptSig

      if (txIn.data) {
        scriptSig = Buffer.from(txIn.data, 'hex')
      } else if (txIn.script) {
        scriptSig = bscript.fromASM(txIn.script)
      }

      tx.addInput(txHash, txIn.index, txIn.sequence, scriptSig)

      if (!noWitness && txIn.witness) {
        var witness = txIn.witness.map(function (x) {
          return Buffer.from(x, 'hex')
        })

        tx.setWitness(i, witness)
      }
    })

    raw.outs.forEach(function (txOut) {
      var script

      if (txOut.data) {
        script = Buffer.from(txOut.data, 'hex')
      } else if (txOut.script) {
        script = bscript.fromASM(txOut.script)
      }

      tx.addOutput(script, txOut.value)
    })

    return tx
  }

  describe('fromBuffer/fromHex', function () {
    function importExport (f) {
      var id = f.id || f.hash
      var txHex = f.hex || f.txHex

      it('imports ' + f.description + ' (' + id + ')', function () {
        var actual = Transaction.fromHex(txHex)

        assert.strictEqual(actual.toHex(), txHex)
      })

      if (f.whex) {
        it('imports ' + f.description + ' (' + id + ') as witness', function () {
          var actual = Transaction.fromHex(f.whex)

          assert.strictEqual(actual.toHex(), f.whex)
        })
      }
    }

    fixtures.valid.forEach(importExport)

    fixtures.invalid.fromBuffer.forEach(function (f) {
      it('throws on ' + f.exception, function () {
        assert.throws(function () {
          Transaction.fromHex(f.hex)
        }, new RegExp(f.exception))
      })
    })

    it('.version should be interpreted as an int32le', function () {
      var txHex = 'ffffffff0000ffffffff'
      var tx = Transaction.fromHex(txHex)
      assert.equal(-1, tx.version)
      assert.equal(0xffffffff, tx.locktime)
    })
  })

  describe('toBuffer/toHex', function () {
    fixtures.valid.forEach(function (f) {
      it('exports ' + f.description + ' (' + f.id + ')', function () {
        var actual = fromRaw(f.raw, true)
        assert.strictEqual(actual.toHex(), f.hex)
      })

      if (f.whex) {
        it('exports ' + f.description + ' (' + f.id + ') as witness', function () {
          var wactual = fromRaw(f.raw)
          assert.strictEqual(wactual.toHex(), f.whex)
        })
      }
    })

    it('accepts target Buffer and offset parameters', function () {
      var f = fixtures.valid[0]
      var actual = fromRaw(f.raw)
      var byteLength = actual.byteLength()

      var target = Buffer.alloc(byteLength * 2)
      var a = actual.toBuffer(target, 0)
      var b = actual.toBuffer(target, byteLength)

      assert.strictEqual(a.length, byteLength)
      assert.strictEqual(b.length, byteLength)
      assert.strictEqual(a.toString('hex'), f.hex)
      assert.strictEqual(b.toString('hex'), f.hex)
      assert.deepEqual(a, b)
      assert.deepEqual(a, target.slice(0, byteLength))
      assert.deepEqual(b, target.slice(byteLength))
    })
  })

  describe('hasWitnesses', function () {
    fixtures.valid.forEach(function (f) {
      it('detects if the transaction has witnesses: ' + (f.whex ? 'true' : 'false'), function () {
        assert.strictEqual(Transaction.fromHex(f.whex ? f.whex : f.hex).hasWitnesses(), !!f.whex)
      })
    })
  })

  describe('weight/virtualSize', function () {
    it('computes virtual size', function () {
      fixtures.valid.forEach(function (f) {
        var transaction = Transaction.fromHex(f.whex ? f.whex : f.hex)

        assert.strictEqual(transaction.virtualSize(), f.virtualSize)
      })
    })

    it('computes weight', function () {
      fixtures.valid.forEach(function (f) {
        var transaction = Transaction.fromHex(f.whex ? f.whex : f.hex)

        assert.strictEqual(transaction.weight(), f.weight)
      })
    })
  })

  describe('addInput', function () {
    var prevTxHash
    beforeEach(function () {
      prevTxHash = Buffer.from('ffffffff00ffff000000000000000000000000000000000000000000101010ff', 'hex')
    })

    it('returns an index', function () {
      var tx = new Transaction()
      assert.strictEqual(tx.addInput(prevTxHash, 0), 0)
      assert.strictEqual(tx.addInput(prevTxHash, 0), 1)
    })

    it('defaults to empty script, witness and 0xffffffff SEQUENCE number', function () {
      var tx = new Transaction()
      tx.addInput(prevTxHash, 0)

      assert.strictEqual(tx.ins[0].script.length, 0)
      assert.strictEqual(tx.ins[0].witness.length, 0)
      assert.strictEqual(tx.ins[0].sequence, 0xffffffff)
    })

    fixtures.invalid.addInput.forEach(function (f) {
      it('throws on ' + f.exception, function () {
        var tx = new Transaction()
        var hash = Buffer.from(f.hash, 'hex')

        assert.throws(function () {
          tx.addInput(hash, f.index)
        }, new RegExp(f.exception))
      })
    })
  })

  describe('addOutput', function () {
    it('returns an index', function () {
      var tx = new Transaction()
      assert.strictEqual(tx.addOutput(Buffer.alloc(0), 0), 0)
      assert.strictEqual(tx.addOutput(Buffer.alloc(0), 0), 1)
    })
  })

  describe('clone', function () {
    fixtures.valid.forEach(function (f) {
      var actual, expected

      beforeEach(function () {
        expected = Transaction.fromHex(f.hex)
        actual = expected.clone()
      })

      it('should have value equality', function () {
        assert.deepEqual(actual, expected)
      })

      it('should not have reference equality', function () {
        assert.notEqual(actual, expected)
      })
    })
  })

  describe('getId', function () {
    function verify (f) {
      it('should return the id for ' + f.id + '(' + f.description + ')', function () {
        var tx = Transaction.fromHex(f.whex || f.hex)

        assert.strictEqual(tx.getId(), f.id)
      })
    }

    fixtures.valid.forEach(verify)
  })

  describe('isCoinbase', function () {
    function verify (f) {
      it('should return ' + f.coinbase + ' for ' + f.id + '(' + f.description + ')', function () {
        var tx = Transaction.fromHex(f.hex)

        assert.strictEqual(tx.isCoinbase(), f.coinbase)
      })
    }

    fixtures.valid.forEach(verify)
  })

  describe('setWitness', function () {
    it('only accepts a a witness stack (Array of Buffers)', function () {
      assert.throws(function () {
        (new Transaction()).setWitness(0, 'foobar')
      }, /Expected property "1" of type \[Buffer], got String "foobar"/)
    })
  })
})
