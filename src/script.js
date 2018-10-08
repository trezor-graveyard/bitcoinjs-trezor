const Buffer = require('safe-buffer').Buffer;
const pushdata = require('pushdata-bitcoin');
const typeforce = require('typeforce');

const OPS = require('bitcoin-ops');
const REVERSE_OPS = require('bitcoin-ops/map');
const types = require('./types');

const OP_INT_BASE = OPS.OP_RESERVED; // OP_1 - 1

// used in script.compile
function asMinimalOP(buffer) {
    if (buffer.length === 0) return OPS.OP_0;
    if (buffer.length !== 1) return;
    if (buffer[0] >= 1 && buffer[0] <= 16) return OP_INT_BASE + buffer[0];
    if (buffer[0] === 0x81) return OPS.OP_1NEGATE;
}

// used everywhere, where we convert
// type "OP_something BUFFER OP_something"
// to buffer of hexa data
//
// It could probably be refactored away, but that would take time
function compile(chunks) {
    // TODO: remove me
    if (Buffer.isBuffer(chunks)) return chunks;

    typeforce(types.Array, chunks);

    const bufferSize = chunks.reduce((accum, chunk) => {
    // data chunk
        if (Buffer.isBuffer(chunk)) {
            // adhere to BIP62.3, minimal push policy
            if (chunk.length === 1 && asMinimalOP(chunk) !== undefined) {
                return accum + 1;
            }

            return accum + pushdata.encodingLength(chunk.length) + chunk.length;
        }

        // opcode
        return accum + 1;
    }, 0.0);

    const buffer = Buffer.allocUnsafe(bufferSize);
    let offset = 0;

    chunks.forEach((chunk) => {
    // data chunk
        if (Buffer.isBuffer(chunk)) {
            // adhere to BIP62.3, minimal push policy
            const opcode = asMinimalOP(chunk);
            if (opcode !== undefined) {
                buffer.writeUInt8(opcode, offset);
                offset += 1;
                return;
            }

            offset += pushdata.encode(buffer, chunk.length, offset);
            chunk.copy(buffer, offset);
            offset += chunk.length;

            // opcode
        } else {
            buffer.writeUInt8(chunk, offset);
            offset += 1;
        }
    });

    if (offset !== buffer.length) throw new Error('Could not decode chunks');
    return buffer;
}

// used everywhere, where we convert
// buffer of hexa data
// to type "OP_something BUFFER OP_something"
//
// It could probably be refactored away, but that would take time
function decompile(buffer) {
    // TODO: remove me
    if (types.Array(buffer)) return buffer;

    typeforce(types.Buffer, buffer);

    const chunks = [];
    let i = 0;

    while (i < buffer.length) {
        const opcode = buffer[i];

        // data chunk
        if ((opcode > OPS.OP_0) && (opcode <= OPS.OP_PUSHDATA4)) {
            const d = pushdata.decode(buffer, i);

            // did reading a pushDataInt fail? empty script
            if (d === null) return [];
            i += d.size;

            // attempt to read too much data? empty script
            if (i + d.number > buffer.length) return [];

            const data = buffer.slice(i, i + d.number);
            i += d.number;

            // decompile minimally
            const op = asMinimalOP(data);
            if (op !== undefined) {
                chunks.push(op);
            } else {
                chunks.push(data);
            }

            // opcode
        } else {
            chunks.push(opcode);

            i += 1;
        }
    }

    return chunks;
}

// ASM is the string representation of chunk format
// used in tests, too muc work to remove it now
function toASM(chunks) {
    if (Buffer.isBuffer(chunks)) {
        chunks = decompile(chunks);
    }

    return chunks.map((chunk) => {
    // data?
        if (Buffer.isBuffer(chunk)) {
            const op = asMinimalOP(chunk);
            if (op === undefined) return chunk.toString('hex');
            chunk = op;
        }

        // opcode!
        return REVERSE_OPS[chunk];
    }).join(' ');
}

// ASM is the string representation of chunk format
// used in tests, too muc work to remove it now
function fromASM(asm) {
    typeforce(types.String, asm);

    return compile(asm.split(' ').map((chunkStr) => {
    // opcode?
        if (OPS[chunkStr] !== undefined) return OPS[chunkStr];
        typeforce(types.Hex, chunkStr);

        // data!
        return Buffer.from(chunkStr, 'hex');
    }));
}

module.exports = {
    compile,
    decompile,
    fromASM,
    toASM,
};
