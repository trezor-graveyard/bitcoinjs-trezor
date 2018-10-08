/* global describe, it */

const assert = require('assert');
const bscript = require('../script');
const types = require('../types');
const fixtures = require('./fixtures/transaction');
const Transaction = require('../transaction');

const EMPTY_SCRIPT = Buffer.allocUnsafe(0);
const EMPTY_WITNESS = [];

describe('Transaction', () => {
    function fromRaw(raw, noWitness) {
        const tx = new Transaction(false);
        tx.version = raw.version;
        tx.locktime = raw.locktime;

        function addInput(hash, index, sequence, scriptSig) {
            if (types.Null(sequence)) {
                sequence = Transaction.DEFAULT_SEQUENCE;
            }

            // Add the input and return the input's index
            return (tx.ins.push({
                hash,
                index,
                script: scriptSig || EMPTY_SCRIPT,
                sequence,
                witness: EMPTY_WITNESS,
            }) - 1);
        }

        function addOutput(scriptPubKey, value) {
            // Add the output and return the output's index
            return (tx.outs.push({
                script: scriptPubKey,
                value,
            }) - 1);
        }

        raw.ins.forEach((txIn, i) => {
            const txHash = Buffer.from(txIn.hash, 'hex');
            let scriptSig;

            if (txIn.data) {
                scriptSig = Buffer.from(txIn.data, 'hex');
            } else if (txIn.script) {
                scriptSig = bscript.fromASM(txIn.script);
            }

            addInput(txHash, txIn.index, txIn.sequence, scriptSig);

            if (!noWitness && txIn.witness) {
                const witness = txIn.witness.map(x => Buffer.from(x, 'hex'));
                tx.ins[i].witness = witness;
            }
        });

        raw.outs.forEach((txOut) => {
            let script;

            if (txOut.data) {
                script = Buffer.from(txOut.data, 'hex');
            } else if (txOut.script) {
                script = bscript.fromASM(txOut.script);
            }

            addOutput(script, txOut.value);
        });

        return tx;
    }

    describe('fromBuffer/fromHex', () => {
        function importExport(f) {
            const id = f.id || f.hash;
            const txHex = f.hex || f.txHex;

            it(`imports ${f.description} (${id})`, () => {
                const actual = Transaction.fromHex(txHex, false);

                assert.strictEqual(actual.toHex(), txHex);
            });

            if (f.whex) {
                it(`imports ${f.description} (${id}) as witness`, () => {
                    const actual = Transaction.fromHex(f.whex, false);

                    assert.strictEqual(actual.toHex(), f.whex);
                });
            }
        }

        fixtures.valid.forEach(importExport);

        fixtures.invalid.fromBuffer.forEach((f) => {
            it(`throws on ${f.exception}`, () => {
                assert.throws(() => {
                    Transaction.fromHex(f.hex, false);
                }, new RegExp(f.exception));
            });
        });

        it('.version should be interpreted as an int32le', () => {
            const txHex = 'ffffffff0000ffffffff';
            const tx = Transaction.fromHex(txHex, false);
            assert.equal(-1, tx.version);
            assert.equal(0xffffffff, tx.locktime);
        });
    });

    describe('toBuffer/toHex', () => {
        fixtures.valid.forEach((f) => {
            it(`exports ${f.description} (${f.id})`, () => {
                const actual = fromRaw(f.raw, true);
                assert.strictEqual(actual.toHex(), f.hex);
            });

            if (f.whex) {
                it(`exports ${f.description} (${f.id}) as witness`, () => {
                    const wactual = fromRaw(f.raw);
                    assert.strictEqual(wactual.toHex(), f.whex);
                });
            }
        });

        it('accepts target Buffer and offset parameters', () => {
            const f = fixtures.valid[0];
            const actual = fromRaw(f.raw);
            const byteLength = actual.byteLength();

            const target = Buffer.alloc(byteLength * 2);
            const a = actual.toBuffer(target, 0);
            const b = actual.toBuffer(target, byteLength);

            assert.strictEqual(a.length, byteLength);
            assert.strictEqual(b.length, byteLength);
            assert.strictEqual(a.toString('hex'), f.hex);
            assert.strictEqual(b.toString('hex'), f.hex);
            assert.deepEqual(a, b);
            assert.deepEqual(a, target.slice(0, byteLength));
            assert.deepEqual(b, target.slice(byteLength));
        });
    });

    describe('hasWitnesses', () => {
        fixtures.valid.forEach((f) => {
            it(`detects if the transaction has witnesses: ${f.whex ? 'true' : 'false'}`, () => {
                assert.strictEqual(Transaction.fromHex(f.whex ? f.whex : f.hex, false).hasWitnesses(), !!f.whex);
            });
        });
    });

    describe('getId', () => {
        function verify(f) {
            it(`should return the id for ${f.id}(${f.description})`, () => {
                const tx = Transaction.fromHex(f.whex || f.hex, false);

                assert.strictEqual(tx.getId(), f.id);
            });
        }

        fixtures.valid.forEach(verify);
    });

    describe('isCoinbase', () => {
        function verify(f) {
            it(`should return ${f.coinbase} for ${f.id}(${f.description})`, () => {
                const tx = Transaction.fromHex(f.hex, false);

                const isCoinbase = tx.ins.length === 1 && Transaction.isCoinbaseHash(tx.ins[0].hash);

                assert.strictEqual(isCoinbase, f.coinbase);
            });
        }

        fixtures.valid.forEach(verify);
    });

    describe('setWitness', () => {
        it('only accepts a a witness stack (Array of Buffers)', () => {
            assert.throws(() => {
                (new Transaction(false)).setWitness(0, 'foobar');
            }, /Expected property "1" of type \[Buffer], got String "foobar"/);
        });
    });
});
