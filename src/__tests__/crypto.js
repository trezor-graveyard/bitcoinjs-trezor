/* global describe, it */

const assert = require('assert');
const bcrypto = require('../crypto');

const fixtures = require('./fixtures/crypto');

describe('crypto', () => {
    ['hash160', 'hash256', 'sha256'].forEach((algorithm) => {
        describe(algorithm, () => {
            fixtures.forEach((f) => {
                const fn = bcrypto[algorithm];
                const expected = f[algorithm];

                it(`returns ${expected} for ${f.hex}`, () => {
                    const data = Buffer.from(f.hex, 'hex');
                    const actual = fn(data).toString('hex');

                    assert.strictEqual(actual, expected);
                });
            });
        });
    });
});
