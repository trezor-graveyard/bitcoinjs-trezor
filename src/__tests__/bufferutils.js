/* global describe, it */

const assert = require('assert');
const bufferutils = require('../bufferutils');

const fixtures = require('./fixtures/bufferutils.json');

describe('bufferutils', () => {
    describe('pushDataSize', () => {
        fixtures.valid.forEach((f) => {
            it(`determines the pushDataSize of ${f.dec} correctly`, () => {
                if (!f.hexPD) return;

                const size = bufferutils.pushDataSize(f.dec);

                assert.strictEqual(size, f.hexPD.length / 2);
            });
        });
    });

    describe('readPushDataInt', () => {
        fixtures.valid.forEach((f) => {
            if (!f.hexPD) return;

            it(`decodes ${f.hexPD} correctly`, () => {
                const buffer = Buffer.from(f.hexPD, 'hex');
                const d = bufferutils.readPushDataInt(buffer, 0);
                const fopcode = parseInt(f.hexPD.substr(0, 2), 16);

                assert.strictEqual(d.opcode, fopcode);
                assert.strictEqual(d.number, f.dec);
                assert.strictEqual(d.size, buffer.length);
            });
        });

        fixtures.invalid.readPushDataInt.forEach((f) => {
            if (!f.hexPD) return;

            it(`decodes ${f.hexPD} as null`, () => {
                const buffer = Buffer.from(f.hexPD, 'hex');

                const n = bufferutils.readPushDataInt(buffer, 0);
                assert.strictEqual(n, null);
            });
        });
    });

    describe('readUInt64LE', () => {
        fixtures.valid.forEach((f) => {
            it(`decodes ${f.hex64} correctly`, () => {
                const buffer = Buffer.from(f.hex64, 'hex');
                const number = bufferutils.readUInt64LE(buffer, 0);

                assert.strictEqual(number, f.dec);
            });
        });

        fixtures.invalid.readUInt64LE.forEach((f) => {
            it(`throws on ${f.description}`, () => {
                const buffer = Buffer.from(f.hex64, 'hex');

                assert.throws(() => {
                    bufferutils.readUInt64LE(buffer, 0);
                }, new RegExp(f.exception));
            });
        });
    });

    describe('readVarInt', () => {
        fixtures.valid.forEach((f) => {
            it(`decodes ${f.hexVI} correctly`, () => {
                const buffer = Buffer.from(f.hexVI, 'hex');
                const d = bufferutils.readVarInt(buffer, 0);

                assert.strictEqual(d.number, f.dec);
                assert.strictEqual(d.size, buffer.length);
            });
        });

        fixtures.invalid.readUInt64LE.forEach((f) => {
            it(`throws on ${f.description}`, () => {
                const buffer = Buffer.from(f.hexVI, 'hex');

                assert.throws(() => {
                    bufferutils.readVarInt(buffer, 0);
                }, new RegExp(f.exception));
            });
        });
    });

    describe('varIntBuffer', () => {
        fixtures.valid.forEach((f) => {
            it(`encodes ${f.dec} correctly`, () => {
                const buffer = bufferutils.varIntBuffer(f.dec);

                assert.strictEqual(buffer.toString('hex'), f.hexVI);
            });
        });
    });

    describe('varIntSize', () => {
        fixtures.valid.forEach((f) => {
            it(`determines the varIntSize of ${f.dec} correctly`, () => {
                const size = bufferutils.varIntSize(f.dec);

                assert.strictEqual(size, f.hexVI.length / 2);
            });
        });
    });

    describe('writePushDataInt', () => {
        fixtures.valid.forEach((f) => {
            if (!f.hexPD) return;

            it(`encodes ${f.dec} correctly`, () => {
                const buffer = Buffer.alloc(5, 0);

                const n = bufferutils.writePushDataInt(buffer, f.dec, 0);
                assert.strictEqual(buffer.slice(0, n).toString('hex'), f.hexPD);
            });
        });
    });

    describe('writeUInt64LE', () => {
        fixtures.valid.forEach((f) => {
            it(`encodes ${f.dec} correctly`, () => {
                const buffer = Buffer.alloc(8, 0);

                bufferutils.writeUInt64LE(buffer, f.dec, 0);
                assert.strictEqual(buffer.toString('hex'), f.hex64);
            });
        });

        fixtures.invalid.readUInt64LE.forEach((f) => {
            it(`throws on ${f.description}`, () => {
                const buffer = Buffer.alloc(8, 0);

                assert.throws(() => {
                    bufferutils.writeUInt64LE(buffer, f.dec, 0);
                }, new RegExp(f.exception));
            });
        });
    });

    describe('writeVarInt', () => {
        fixtures.valid.forEach((f) => {
            it(`encodes ${f.dec} correctly`, () => {
                const buffer = Buffer.alloc(9, 0);

                const n = bufferutils.writeVarInt(buffer, f.dec, 0);
                assert.strictEqual(buffer.slice(0, n).toString('hex'), f.hexVI);
            });
        });

        fixtures.invalid.readUInt64LE.forEach((f) => {
            it(`throws on ${f.description}`, () => {
                const buffer = Buffer.alloc(9, 0);

                assert.throws(() => {
                    bufferutils.writeVarInt(buffer, f.dec, 0);
                }, new RegExp(f.exception));
            });
        });
    });
});
