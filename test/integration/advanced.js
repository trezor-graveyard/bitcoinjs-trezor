/* global describe, it */

var assert = require('assert')
var bitcoin = require('../../')
var blockchain = require('./_blockchain')

describe('bitcoinjs-lib (advanced)', function () {
  it('can create an OP_RETURN transaction', function (done) {
    this.timeout(20000)

    var network = bitcoin.networks.testnet
    var keyPair = bitcoin.ECPair.makeRandom({ network: network })
    var address = keyPair.getAddress()

    blockchain.t.faucet(address, 2e4, function (err) {
      if (err) return done(err)

      blockchain.t.addresses.unspents(address, function (err, unspents) {
        if (err) return done(err)

        // filter small unspents
        unspents = unspents.filter(function (unspent) {
          return unspent.value > 1e4
        })

        // use the oldest unspent
        var unspent = unspents.pop()
        if (!unspent) throw new Error('Faucet didn\'t provide an unspent')

        var tx = new bitcoin.TransactionBuilder(network)
        var data = new Buffer('bitcoinjs-lib')
        var dataScript = bitcoin.script.nullDataOutput(data)

        tx.addInput(unspent.txId, unspent.vout)
        tx.addOutput(dataScript, 1000)
        tx.sign(0, keyPair)

        var txBuilt = tx.build()

        blockchain.t.transactions.propagate(txBuilt.toHex(), function (err) {
          if (err) return done(err)

          // check that the message was propagated
          blockchain.t.transactions.get(txBuilt.getId(), function (err, transaction) {
            if (err) return done(err)

            var actual = bitcoin.Transaction.fromHex(transaction.txHex)
            var dataScript2 = actual.outs[0].script
            var data2 = bitcoin.script.decompile(dataScript2)[1]

            assert.deepEqual(dataScript, dataScript2)
            assert.deepEqual(data, data2)

            done()
          })
        })
      })
    })
  })
})
