/* global describe, it */

const assert = require('assert');
const bcrypto = require('../crypto');
const bscript = require('../script');
const btemplates = require('../templates');

const fixtures = require('./fixtures/templates.json');

describe('script-templates', () => {
    describe('checks nulldata correctly', () => {
        fixtures.valid.forEach((f) => {
            if (!f.output) return;
            const isNulldata = f.type === 'nulldata';

            it(`${f.output} is ${isNulldata ? '' : 'not '}nulldata`, () => {
                const output = bscript.fromASM(f.output);
                const check = btemplates.nullData.output.check(output);

                assert.strictEqual(check, isNulldata);
            });
        });
    });

    describe('pubKeyHash.output', () => {
        fixtures.valid.forEach((f) => {
            if (f.type !== 'pubkeyhash') return;

            const pubKey = Buffer.from(f.pubKey, 'hex');
            const pubKeyHash = bcrypto.hash160(pubKey);
            const output = btemplates.pubKeyHash.output.encode(pubKeyHash);

            it(`encodes to ${f.output}`, () => {
                assert.strictEqual(bscript.toASM(output), f.output);
            });
        });

        fixtures.invalid.pubKeyHash.outputs.forEach((f) => {
            if (!f.hash) return;
            const hash = Buffer.from(f.hash, 'hex');

            it(`throws on ${f.exception}`, () => {
                assert.throws(() => {
                    btemplates.pubKeyHash.output.encode(hash);
                }, new RegExp(f.exception));
            });
        });
    });

    describe('scriptHash.output', () => {
        fixtures.valid.forEach((f) => {
            if (f.type !== 'scripthash') return;
            if (!f.output) return;

            const redeemScript = bscript.fromASM(f.redeemScript);
            const scriptHash = bcrypto.hash160(redeemScript);
            const output = btemplates.scriptHash.output.encode(scriptHash);

            it(`encodes to ${f.output}`, () => {
                assert.strictEqual(bscript.toASM(output), f.output);
            });
        });

        fixtures.invalid.scriptHash.outputs.forEach((f) => {
            if (!f.hash) return;
            const hash = Buffer.from(f.hash, 'hex');

            it(`throws on ${f.exception}`, () => {
                assert.throws(() => {
                    btemplates.scriptHash.output.encode(hash);
                }, new RegExp(f.exception));
            });
        });
    });

    describe('witnessPubKeyHash.output', () => {
        fixtures.valid.forEach((f) => {
            if (f.type !== 'witnesspubkeyhash') return;
            if (!f.output) return;

            const pubKey = Buffer.from(f.pubKey, 'hex');
            const pubKeyHash = bcrypto.hash160(pubKey);
            const output = btemplates.witnessPubKeyHash.output.encode(pubKeyHash);

            it(`encodes to ${f.output}`, () => {
                assert.strictEqual(bscript.toASM(output), f.output);
            });
        });

        fixtures.invalid.witnessPubKeyHash.outputs.forEach((f) => {
            if (!f.hash) return;
            const hash = Buffer.from(f.hash, 'hex');

            it(`throws on ${f.exception}`, () => {
                assert.throws(() => {
                    btemplates.witnessPubKeyHash.output.encode(hash);
                }, new RegExp(f.exception));
            });
        });
    });

    describe('witnessScriptHash.output', () => {
        fixtures.valid.forEach((f) => {
            if (f.type !== 'witnessscripthash') return;
            if (!f.output) return;

            const witnessScriptPubKey = bscript.fromASM(f.witnessScript);
            const scriptHash = bcrypto.hash256(witnessScriptPubKey);
            const output = btemplates.witnessScriptHash.output.encode(scriptHash);

            it(`encodes to ${f.output}`, () => {
                assert.strictEqual(bscript.toASM(output), f.output);
            });
        });

        fixtures.invalid.witnessScriptHash.outputs.forEach((f) => {
            if (!f.hash) return;
            const hash = Buffer.from(f.hash, 'hex');

            it(`throws on ${f.exception}`, () => {
                assert.throws(() => {
                    btemplates.witnessScriptHash.output.encode(hash);
                }, new RegExp(f.exception));
            });
        });
    });

    describe('nullData.output', () => {
        fixtures.valid.forEach((f) => {
            if (f.type !== 'nulldata') return;

            const data = Buffer.from(f.data, 'hex');
            const output = btemplates.nullData.output.encode(data);

            it(`encodes to ${f.output}`, () => {
                assert.strictEqual(bscript.toASM(output), f.output);
            });

            it(`decodes to ${f.data}`, () => {
                assert.deepEqual(btemplates.nullData.output.decode(output), data);
            });
        });
    });
});
