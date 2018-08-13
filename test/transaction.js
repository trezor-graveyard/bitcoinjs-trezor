/* global describe, it */

var assert = require('assert')
var bscript = require('../src/script')
var types = require('../src/types')
var fixtures = require('./fixtures/transaction')
var Transaction = require('../src/transaction')
var EMPTY_SCRIPT = Buffer.allocUnsafe(0)
var EMPTY_WITNESS = []

describe('Transaction', function () {
  function fromRaw (raw, noWitness) {
    var tx = new Transaction(false)
    tx.version = raw.version
    tx.locktime = raw.locktime

    function addInput (hash, index, sequence, scriptSig) {
      if (types.Null(sequence)) {
        sequence = Transaction.DEFAULT_SEQUENCE
      }

      // Add the input and return the input's index
      return (tx.ins.push({
        hash: hash,
        index: index,
        script: scriptSig || EMPTY_SCRIPT,
        sequence: sequence,
        witness: EMPTY_WITNESS
      }) - 1)
    }

    function addOutput (scriptPubKey, value) {
      // Add the output and return the output's index
      return (tx.outs.push({
        script: scriptPubKey,
        value: value
      }) - 1)
    }

    raw.ins.forEach(function (txIn, i) {
      var txHash = Buffer.from(txIn.hash, 'hex')
      var scriptSig

      if (txIn.data) {
        scriptSig = Buffer.from(txIn.data, 'hex')
      } else if (txIn.script) {
        scriptSig = bscript.fromASM(txIn.script)
      }

      addInput(txHash, txIn.index, txIn.sequence, scriptSig)

      if (!noWitness && txIn.witness) {
        var witness = txIn.witness.map(function (x) {
          return Buffer.from(x, 'hex')
        })
        tx.ins[i].witness = witness
      }
    })

    raw.outs.forEach(function (txOut) {
      var script

      if (txOut.data) {
        script = Buffer.from(txOut.data, 'hex')
      } else if (txOut.script) {
        script = bscript.fromASM(txOut.script)
      }

      addOutput(script, txOut.value)
    })

    return tx
  }

  describe('fromBuffer/fromHex', function () {
    function importExport (f) {
      var id = f.id || f.hash
      var txHex = f.hex || f.txHex

      it('imports ' + f.description + ' (' + id + ')', function () {
        var actual = Transaction.fromHex(txHex, false)

        assert.strictEqual(actual.toHex(), txHex)
      })

      if (f.whex) {
        it('imports ' + f.description + ' (' + id + ') as witness', function () {
          var actual = Transaction.fromHex(f.whex, false)

          assert.strictEqual(actual.toHex(), f.whex)
        })
      }
    }

    fixtures.valid.forEach(importExport)

    fixtures.invalid.fromBuffer.forEach(function (f) {
      it('throws on ' + f.exception, function () {
        assert.throws(function () {
          Transaction.fromHex(f.hex, false)
        }, new RegExp(f.exception))
      })
    })

    it('.version should be interpreted as an int32le', function () {
      var txHex = 'ffffffff0000ffffffff'
      var tx = Transaction.fromHex(txHex, false)
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
        assert.strictEqual(Transaction.fromHex(f.whex ? f.whex : f.hex, false).hasWitnesses(), !!f.whex)
      })
    })
  })

  describe('getId', function () {
    function verify (f) {
      it('should return the id for ' + f.id + '(' + f.description + ')', function () {
        var tx = Transaction.fromHex(f.whex || f.hex, false)

        assert.strictEqual(tx.getId(), f.id)
      })
    }

    fixtures.valid.forEach(verify)
  })

  describe('isCoinbase', function () {
    function verify (f) {
      it('should return ' + f.coinbase + ' for ' + f.id + '(' + f.description + ')', function () {
        var tx = Transaction.fromHex(f.hex, false)

        var isCoinbase = tx.ins.length === 1 && Transaction.isCoinbaseHash(tx.ins[0].hash)

        assert.strictEqual(isCoinbase, f.coinbase)
      })
    }

    fixtures.valid.forEach(verify)
  })

  describe('setWitness', function () {
    it('only accepts a a witness stack (Array of Buffers)', function () {
      assert.throws(function () {
        (new Transaction(false)).setWitness(0, 'foobar')
      }, /Expected property "1" of type \[Buffer], got String "foobar"/)
    })
  })
})
