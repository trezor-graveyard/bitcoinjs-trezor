/* global describe, it, beforeEach */
/* eslint-disable no-new */

const assert = require('assert');
const sinon = require('sinon');

const ecurve = require('ecurve');
const ECPubkey = require('../ecpubkey');

const fixtures = require('./fixtures/ecpubkey.json');

const curve = ecurve.getCurveByName('secp256k1');

const NETWORKS = require('../networks');

const NETWORKS_LIST = []; // Object.values(NETWORKS)
for (const networkName in NETWORKS) {
    NETWORKS_LIST.push(NETWORKS[networkName]);
}
const dfQ = fixtures.valid[0].Q;
const dQ = ecurve.Point.decodeFrom(curve, Buffer.from(dfQ, 'hex'));

describe('ECPubkey', () => {
    describe('constructor', () => {
        it('defaults to compressed', () => {
            const pubkey = new ECPubkey(dQ);

            assert.strictEqual(pubkey.compressed, true);
        });

        it('supports the uncompressed option', () => {
            const pubkey = new ECPubkey(dQ, {
                compressed: false,
            });

            assert.strictEqual(pubkey.compressed, false);
        });

        it('supports the network option', () => {
            const pubkey = new ECPubkey(dQ, {
                compressed: false,
                network: NETWORKS.testnet,
            });

            assert.strictEqual(pubkey.network, NETWORKS.testnet);
        });

        fixtures.invalid.constructor.forEach((f) => {
            it(`throws ${f.exception}`, () => {
                const Q = f.Q && ecurve.Point.decodeFrom(curve, Buffer.from(f.Q, 'hex'));

                assert.throws(() => {
                    new ECPubkey(Q, f.options);
                }, new RegExp(f.exception));
            });
        });
    });

    describe('getPublicKeyBuffer', () => {
        let pubkey;

        beforeEach(() => {
            pubkey = new ECPubkey(dQ);
        });

        it('wraps Q.getEncoded', sinon.test(function () {
            this.mock(pubkey.Q).expects('getEncoded')
                .once().withArgs(pubkey.compressed);

            pubkey.getPublicKeyBuffer();
        }));
    });

    describe('getAddress', () => {
        fixtures.valid.forEach((f) => {
            it(`returns ${f.address} for ${f.Q}`, () => {
                const Q = ecurve.Point.decodeFrom(curve, Buffer.from(f.Q, 'hex'));

                const pubkey = new ECPubkey(Q, {
                    compressed: f.compressed,
                    network: NETWORKS[f.network],
                });

                assert.strictEqual(pubkey.getAddress(), f.address);
            });
        });
    });
});
