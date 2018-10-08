/* global describe, it, beforeEach */
/* eslint-disable no-new */

const assert = require('assert');
const sinon = require('sinon');

const ecurve = require('ecurve');
const ECPubkey = require('../ecpubkey');
const HDNode = require('../hdnode');

const fixtures = require('./fixtures/hdnode.json');

const curve = ecurve.getCurveByName('secp256k1');

const NETWORKS = require('../networks');

const NETWORKS_LIST = []; // Object.values(NETWORKS)
for (const networkName in NETWORKS) {
    NETWORKS_LIST.push(NETWORKS[networkName]);
}

let validAll = [];
fixtures.valid.forEach((f) => {
    function addNetwork(n) {
        n.network = f.network;
        return n;
    }

    validAll = validAll.concat(addNetwork(f.master), f.children.map(addNetwork));
});

describe('HDNode', () => {
    describe('Constructor', () => {
        let pubkey; let
            chainCode;

        beforeEach(() => {
            const Q = ecurve.Point.decodeFrom(curve, Buffer.from('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', 'hex'));
            pubkey = new ECPubkey(Q);
            chainCode = Buffer.alloc(32, 1);
        });

        it('stores the pubkey/chainCode directly', () => {
            const hd = new HDNode(pubkey, chainCode);

            assert.strictEqual(hd.pubkey, pubkey);
            assert.strictEqual(hd.chainCode, chainCode);
        });

        it('has a default depth/index of 0', () => {
            const hd = new HDNode(pubkey, chainCode);

            assert.strictEqual(hd.depth, 0);
            assert.strictEqual(hd.index, 0);
        });

        it('throws on uncompressed pubkey', () => {
            pubkey.compressed = false;

            assert.throws(() => {
                new HDNode(pubkey, chainCode);
            }, /BIP32 only allows compressed pubkeys/);
        });

        it('throws when an invalid length chain code is given', () => {
            assert.throws(() => {
                new HDNode(pubkey, Buffer.alloc(20));
            }, /Expected property "1" of type Buffer\(Length: 32\), got Buffer\(Length: 20\)/);
        });
    });

    describe('ECPubkey wrappers', () => {
        let pubkey; let
            hd;

        beforeEach(() => {
            const Q = ecurve.Point.decodeFrom(curve, Buffer.from('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', 'hex'));
            pubkey = new ECPubkey(Q);

            const chainCode = Buffer.alloc(32);
            hd = new HDNode(pubkey, chainCode);
        });

        describe('getAddress', () => {
            it('wraps pubkey.getAddress', sinon.test(function () {
                this.mock(pubkey).expects('getAddress')
                    .once().withArgs()
                    .returns('foobar');

                assert.strictEqual(hd.getAddress(), 'foobar');
            }));
        });
    });

    describe('fromBase58 / toBase58', () => {
        validAll.forEach((f) => {
            it(`exports ${f.base58} (public) correctly`, () => {
                const hd = HDNode.fromBase58(f.base58, NETWORKS_LIST);

                assert.strictEqual(hd.toBase58(), f.base58);
            });
        });

        fixtures.invalid.fromBase58.forEach((f) => {
            it(`throws on ${f.string}`, () => {
                assert.throws(() => {
                    const networks = f.network ? NETWORKS[f.network] : NETWORKS_LIST;

                    HDNode.fromBase58(f.string, networks);
                }, new RegExp(f.exception));
            });
        });
    });

    describe('getIdentifier', () => {
        validAll.forEach((f) => {
            it(`returns the identifier for ${f.fingerprint}`, () => {
                const hd = HDNode.fromBase58(f.base58, NETWORKS_LIST);

                assert.strictEqual(hd.getIdentifier().toString('hex'), f.identifier);
            });
        });
    });

    describe('derive', () => {
        function verifyVector(hd, v) {
            assert.strictEqual(hd.toBase58(), v.base58);

            assert.strictEqual(hd.getAddress(), v.address);
            assert.strictEqual(hd.pubkey.getPublicKeyBuffer().toString('hex'), v.pubKey);
            assert.strictEqual(hd.chainCode.toString('hex'), v.chainCode);
            assert.strictEqual(hd.depth, v.depth >>> 0);
            assert.strictEqual(hd.index, v.index >>> 0);
            assert.strictEqual(hd.getIdentifier().toString('hex'), v.identifier);
        }

        fixtures.valid.forEach((f) => {
            const network = NETWORKS[f.network];
            let hd = HDNode.fromBase58(f.master.base58, network);

            // FIXME: test data is only testing Private -> private for now
            f.children.forEach((c) => {
                if (c.m === undefined) return;

                it(`${c.path} from ${f.master.fingerprint}`, () => {
                    if (c.hardened) {
                        hd = hd.deriveHardened(c.m);
                    } else {
                        hd = hd.derive(c.m);
                    }

                    verifyVector(hd, c);
                });
            });
        });

        it('works for Public -> public', () => {
            const f = fixtures.valid[1];
            const c = f.children[0];

            const master = HDNode.fromBase58(f.master.base58, NETWORKS_LIST);
            const child = master.derive(c.m);

            assert.strictEqual(c.base58, child.toBase58());
        });

        it('throws on wrong types', () => {
            const f = fixtures.valid[0];
            const master = HDNode.fromBase58(f.master.base58, NETWORKS_LIST);

            fixtures.invalid.derive.forEach((fx) => {
                assert.throws(() => {
                    master.derive(fx);
                }, /Expected UInt32/);
            });
        });
    });
});
