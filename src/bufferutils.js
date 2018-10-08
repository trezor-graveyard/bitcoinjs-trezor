const pushdata = require('pushdata-bitcoin');
const varuint = require('varuint-bitcoin');
const BigInt = require('big-integer');

// All of these are used in transaction parsing

// https://github.com/feross/buffer/blob/master/index.js#L1127
function verifuint(value, max) {
  if (typeof value !== 'number') throw new Error('cannot write a non-number as a number');
  if (value < 0) throw new Error('specified a negative value for writing an unsigned value');
  if (value > max) throw new Error('RangeError: value out of range');
  if (Math.floor(value) !== value) throw new Error('value has a fractional component');
}

function readUInt64LE(buffer, offset) {
  const a = buffer.readUInt32LE(offset);
  let b = buffer.readUInt32LE(offset + 4);
  b *= 0x100000000;

  verifuint(b + a, 0x001fffffffffffff);

  return b + a;
}

function readUInt64LEasString(buffer, offset) {
  const a = buffer.readUInt32LE(offset).toString();
  const b = buffer.readUInt32LE(offset + 4).toString();
  const bigA = BigInt(a);
  let bigB = BigInt(b);
  bigB = bigB.multiply(0x100000000);
  const result = bigA.add(bigB);

  return result.value.toString();
}

function writeUInt64LE(buffer, value, offset) {
  buffer.writeInt32LE(value & -1, offset);
  buffer.writeUInt32LE(Math.floor(value / 0x100000000), offset + 4);
  return offset + 8;
}

function writeUInt64LEasString(buffer, value, offset) {

  console.log('buffer', buffer);
  console.log('value', value);
  console.log('offset', offset);

  buffer.writeInt32LE(value & -1, offset);
  buffer.writeUInt32LE(Math.floor(value / 0x100000000), offset + 4);
  return offset + 8;
}

// TODO: remove in 4.0.0?
function readVarInt(buffer, offset) {
  const result = varuint.decode(buffer, offset);

  return {
    number: result,
    size: varuint.decode.bytes,
  };
}

// TODO: remove in 4.0.0?
function writeVarInt(buffer, number, offset) {
  varuint.encode(number, buffer, offset);
  return varuint.encode.bytes;
}

module.exports = {
  pushDataSize: pushdata.encodingLength,
  readPushDataInt: pushdata.decode,
  readUInt64LE,
  readUInt64LEasString,
  readVarInt,
  varIntBuffer: varuint.encode,
  varIntSize: varuint.encodingLength,
  writePushDataInt: pushdata.encode,
  writeUInt64LE,
  writeUInt64LEasString,
  writeVarInt,
};
