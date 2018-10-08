/* global describe, it */

const assert = require('assert');
const base58 = require('bs58');
const bitcoin = require('../');

const base58EncodeDecode = require('./fixtures/core/base58_encode_decode.json');
const base58KeysInvalid = require('./fixtures/core/base58_keys_invalid.json');
const base58KeysValid = require('./fixtures/core/base58_keys_valid.json');
const txValid = require('./fixtures/core/tx_valid.json');

describe('Bitcoin-core', () => {
    // base58EncodeDecode
    describe('base58', () => {
        base58EncodeDecode.forEach((f) => {
            const fhex = f[0];
            const fb58 = f[1];

            it(`can decode ${fb58}`, () => {
                const buffer = base58.decode(fb58);
                const actual = buffer.toString('hex');

                assert.strictEqual(actual, fhex);
            });

            it(`can encode ${fhex}`, () => {
                const buffer = Buffer.from(fhex, 'hex');
                const actual = base58.encode(buffer);

                assert.strictEqual(actual, fb58);
            });
        });
    });

    // base58KeysValid
    describe('address.toBase58Check', () => {
        const typeMap = {
            pubkey: 'pubKeyHash',
            script: 'scriptHash',
        };

        base58KeysValid.forEach((f) => {
            const expected = f[0];
            const hash = Buffer.from(f[1], 'hex');
            const params = f[2];

            if (params.isPrivkey) return;

            const network = params.isTestnet ? bitcoin.networks.testnet : bitcoin.networks.bitcoin;
            const version = network[typeMap[params.addrType]];

            it(`can export ${expected}`, () => {
                assert.strictEqual(bitcoin.address.toBase58Check(hash, version), expected);
            });
        });
    });

    // base58KeysInvalid
    describe('address.fromBase58Check', () => {
        const allowedNetworks = [
            bitcoin.networks.bitcoin.pubkeyhash,
            bitcoin.networks.bitcoin.scripthash,
            bitcoin.networks.testnet.pubkeyhash,
            bitcoin.networks.testnet.scripthash,
        ];

        base58KeysInvalid.forEach((f) => {
            const string = f[0];

            it(`throws on ${string}`, () => {
                assert.throws(() => {
                    const address = bitcoin.address.fromBase58Check(string);

                    assert.notEqual(allowedNetworks.indexOf(address.version), -1, 'Invalid network');
                }, /(Invalid (checksum|network))|(too (short|long))/);
            });
        });
    });

    // txValid
    describe('Transaction.fromHex', () => {
        txValid.forEach((f) => {
            // Objects that are only a single string are ignored
            if (f.length === 1) return;

            const inputs = f[0];
            const fhex = f[1];
            //      var verifyFlags = f[2] // TODO: do we need to test this?

            it(`can decode ${fhex}`, () => {
                const transaction = bitcoin.Transaction.fromHex(fhex, false);

                transaction.ins.forEach((txIn, i) => {
                    const input = inputs[i];

                    // reverse because test data is reversed
                    const prevOutHash = Buffer.from(input[0], 'hex').reverse();
                    const prevOutIndex = input[1];

                    assert.deepEqual(txIn.hash, prevOutHash);

                    // we read UInt32, not Int32
                    assert.strictEqual(txIn.index & 0xffffffff, prevOutIndex);
                });
            });
        });
    });
});
