var Buffer = require('safe-buffer').Buffer
var bcrypto = require('./crypto')
var bufferutils = require('./bufferutils')
var typeforce = require('typeforce')
var types = require('./types')
var varuint = require('varuint-bitcoin')

// functions for reading bitcoin types
function varSliceSize (someScript) {
  var length = someScript.length

  return varuint.encodingLength(length) + length
}

// functions for reading bitcoin types
function vectorSize (someVector) {
  var length = someVector.length

  return varuint.encodingLength(length) + someVector.reduce(function (sum, witness) {
    return sum + varSliceSize(witness)
  }, 0)
}

function Transaction (zcash) {
  typeforce('Boolean', zcash)
  this.version = 1
  this.locktime = 0
  this.ins = []
  this.outs = []
  if (zcash) {
    this.version = 3
    this.joinsplits = []
    this.versionGroupId = '0x03c48270'
    this.expiry = 0
  }
  this.zcash = zcash
}

Transaction.DEFAULT_SEQUENCE = 0xffffffff
Transaction.SIGHASH_ALL = 0x01
Transaction.SIGHASH_NONE = 0x02
Transaction.SIGHASH_SINGLE = 0x03
Transaction.SIGHASH_ANYONECANPAY = 0x80
Transaction.ADVANCED_TRANSACTION_MARKER = 0x00
Transaction.ADVANCED_TRANSACTION_FLAG = 0x01

var EMPTY_WITNESS = []

Transaction.ZCASH_NUM_JS_INPUTS = 2
Transaction.ZCASH_NUM_JS_OUTPUTS = 2
Transaction.ZCASH_NOTECIPHERTEXT_SIZE = 1 + 8 + 32 + 32 + 512 + 16

Transaction.ZCASH_G1_PREFIX_MASK = 0x02
Transaction.ZCASH_G2_PREFIX_MASK = 0x0a

// used in any transaction parsings
Transaction.fromBuffer = function (buffer, zcash, __noStrict) {
  typeforce('Boolean', zcash)
  var offset = 0
  function readSlice (n) {
    offset += n
    return buffer.slice(offset - n, offset)
  }

  function readUInt8 () {
    var i = buffer.readUInt8(offset)
    offset += 1
    return i
  }

  function readUInt32 () {
    var i = buffer.readUInt32LE(offset)
    offset += 4
    return i
  }

  function readInt32 () {
    var i = buffer.readInt32LE(offset)
    offset += 4
    return i
  }

  function readUInt64 () {
    var i = bufferutils.readUInt64LE(buffer, offset)
    offset += 8
    return i
  }

  function readVarInt () {
    var vi = varuint.decode(buffer, offset)
    offset += varuint.decode.bytes
    return vi
  }

  function readVarSlice () {
    return readSlice(readVarInt())
  }

  function readVector () {
    var count = readVarInt()
    var vector = []
    for (var i = 0; i < count; i++) vector.push(readVarSlice())
    return vector
  }

  function readCompressedG1 () {
    var yLsb = readUInt8() & 1
    var x = readSlice(32)
    return {
      x: x,
      yLsb: yLsb
    }
  }

  function readCompressedG2 () {
    var yLsb = readUInt8() & 1
    var x = readSlice(64)
    return {
      x: x,
      yLsb: yLsb
    }
  }

  var tx = new Transaction(zcash)

  if (zcash) {
      var header = readUInt32()
      tx.version = header & 0x7ffffff
      var overwintered = header >>> 31
      if (tx.version >= 3) {
          if (!overwintered) {
              throw new Error("zcash tx v3+ not overwintered")
          }
          tx.versionGroupId = readUInt32()
      }
  } else {
      tx.version = readInt32()
  }

  var marker = buffer.readUInt8(offset)
  var flag = buffer.readUInt8(offset + 1)

  var hasWitnesses = false
  if (!zcash) {
    if (marker === Transaction.ADVANCED_TRANSACTION_MARKER &&
        flag === Transaction.ADVANCED_TRANSACTION_FLAG) {
      offset += 2
      hasWitnesses = true
    }
  }

  var vinLen = readVarInt()
  for (var i = 0; i < vinLen; ++i) {
    tx.ins.push({
      hash: readSlice(32),
      index: readUInt32(),
      script: readVarSlice(),
      sequence: readUInt32(),
      witness: EMPTY_WITNESS
    })
  }

  var voutLen = readVarInt()
  for (i = 0; i < voutLen; ++i) {
    tx.outs.push({
      value: readUInt64(),
      script: readVarSlice()
    })
  }

  if (hasWitnesses) {
    for (i = 0; i < vinLen; ++i) {
      tx.ins[i].witness = readVector()
    }

    // was this pointless?
    if (!tx.hasWitnesses()) throw new Error('Transaction has superfluous witness data')
  }

  tx.locktime = readUInt32()

  if (tx.version >= 3 && zcash) {
      tx.expiry = readUInt32()
  }

  if (tx.version >= 2 && zcash) {
    var jsLen = readVarInt()
    for (i = 0; i < jsLen; ++i) {
      var vpubOld = readUInt64()
      var vpubNew = readUInt64()
      var anchor = readSlice(32)
      var nullifiers = []
      for (var j = 0; j < Transaction.ZCASH_NUM_JS_INPUTS; j++) {
        nullifiers.push(readSlice(32))
      }
      var commitments = []
      for (j = 0; j < Transaction.ZCASH_NUM_JS_OUTPUTS; j++) {
        commitments.push(readSlice(32))
      }
      var ephemeralKey = readSlice(32)
      var randomSeed = readSlice(32)
      var macs = []
      for (j = 0; j < Transaction.ZCASH_NUM_JS_INPUTS; j++) {
        macs.push(readSlice(32))
      }
      // TODO what are those exactly? Can it be expressed by BigNum?
      var zproof = {
        gA: readCompressedG1(),
        gAPrime: readCompressedG1(),
        gB: readCompressedG2(),
        gBPrime: readCompressedG1(),
        gC: readCompressedG1(),
        gCPrime: readCompressedG1(),
        gK: readCompressedG1(),
        gH: readCompressedG1()
      }
      var ciphertexts = []
      for (j = 0; j < Transaction.ZCASH_NUM_JS_OUTPUTS; j++) {
        ciphertexts.push(readSlice(Transaction.ZCASH_NOTECIPHERTEXT_SIZE))
      }

      tx.joinsplits.push({
        vpubOld: vpubOld,
        vpubNew: vpubNew,
        anchor: anchor,
        nullifiers: nullifiers,
        commitments: commitments,
        ephemeralKey: ephemeralKey,
        randomSeed: randomSeed,
        macs: macs,
        zproof: zproof,
        ciphertexts: ciphertexts
      })
    }
    if (jsLen > 0) {
      tx.joinsplitPubkey = readSlice(32)
      tx.joinsplitSig = readSlice(64)
    }
  }

  tx.zcash = !!zcash

  if (__noStrict) return tx
  if (offset !== buffer.length) throw new Error('Transaction has unexpected data')

  return tx
}

// used in any transaction parsings
Transaction.fromHex = function (hex, zcash) {
  typeforce('Boolean', zcash)
  return Transaction.fromBuffer(new Buffer(hex, 'hex'), zcash)
}

// used in coinbase detection
Transaction.isCoinbaseHash = function (buffer) {
  typeforce(types.Hash256bit, buffer)
  for (var i = 0; i < 32; ++i) {
    if (buffer[i] !== 0) return false
  }
  return true
}

// used in toHex/toBuffer
Transaction.prototype.hasWitnesses = function () {
  return this.ins.some(function (x) {
    return x.witness.length !== 0
  })
}

// we are saving both actual tx length and
// virtual tx length; virtual comes from backend,
// we need to compute actual
Transaction.prototype.byteLength = function () {
  return this.__byteLength(true)
}

// we need to know joinsplit bytelength
// to tell the size to trezor before
Transaction.prototype.joinsplitByteLength = function () {
  if (this.version < 2) {
    return 0
  }

  if (!this.zcash) {
    return 0
  }

  var pubkeySigLength = (this.joinsplits.length > 0) ? (32 + 64) : 0
  return (
    bufferutils.varIntSize(this.joinsplits.length) +
    this.joinsplits.reduce(function (sum, joinsplit) {
      return (
        sum +
        8 + 8 + 32 +
        joinsplit.nullifiers.length * 32 +
        joinsplit.commitments.length * 32 +
        32 + 32 +
        joinsplit.macs.length * 32 +
        65 + 33 * 7 +
        joinsplit.ciphertexts.length * Transaction.ZCASH_NOTECIPHERTEXT_SIZE
      )
    }, 0) +
    pubkeySigLength
  )
}

Transaction.prototype.__byteLength = function (__allowWitness) {
  var hasWitnesses = __allowWitness && this.hasWitnesses()

  return (
    (hasWitnesses ? 10 : 8) +
    varuint.encodingLength(this.ins.length) +
    varuint.encodingLength(this.outs.length) +
    this.ins.reduce(function (sum, input) { return sum + 40 + varSliceSize(input.script) }, 0) +
    this.outs.reduce(function (sum, output) { return sum + 8 + varSliceSize(output.script) }, 0) +
    (hasWitnesses ? this.ins.reduce(function (sum, input) { return sum + vectorSize(input.witness) }, 0) : 0) +
    this.joinsplitByteLength() +
    (this.version === 3 ? 8 : 0)
  )
}

// used in webwallet on several places
// and probably connect
// Can probably be factored out
// (both trezor and hd-wallet tell txIds)
Transaction.prototype.getId = function () {
  var hash = bcrypto.hash256(this.__toBuffer(undefined, undefined, false))
  // transaction hash's are displayed in reverse order
  return hash.reverse().toString('hex')
}

// used in toHex
Transaction.prototype.toBuffer = function (buffer, initialOffset) {
  return this.__toBuffer(buffer, initialOffset, true)
}

// used in toHex
Transaction.prototype.__toBuffer = function (buffer, initialOffset, __allowWitness) {
  if (!buffer) buffer = Buffer.allocUnsafe(this.__byteLength(__allowWitness))

  var offset = initialOffset || 0
  function writeSlice (slice) { offset += slice.copy(buffer, offset) }
  function writeUInt8 (i) { offset = buffer.writeUInt8(i, offset) }
  function writeUInt32 (i) { offset = buffer.writeUInt32LE(i, offset) }
  function writeInt32 (i) { offset = buffer.writeInt32LE(i, offset) }
  function writeUInt64 (i) { offset = bufferutils.writeUInt64LE(buffer, i, offset) }
  function writeVarInt (i) {
    varuint.encode(i, buffer, offset)
    offset += varuint.encode.bytes
  }
  function writeVarSlice (slice) { writeVarInt(slice.length); writeSlice(slice) }
  function writeVector (vector) { writeVarInt(vector.length); vector.forEach(writeVarSlice) }

  function writeCompressedG1 (i) {
    writeUInt8(Transaction.ZCASH_G1_PREFIX_MASK | i.yLsb)
    writeSlice(i.x)
  }

  function writeCompressedG2 (i) {
    writeUInt8(Transaction.ZCASH_G2_PREFIX_MASK | i.yLsb)
    writeSlice(i.x)
  }
  
  if (this.versionGroupId != null) {
    writeInt32(this.version | (1 << 31));
    writeUInt32(this.versionGroupId)
  } else {
    writeInt32(this.version)
  }

  var hasWitnesses = __allowWitness && this.hasWitnesses()

  if (hasWitnesses) {
    writeUInt8(Transaction.ADVANCED_TRANSACTION_MARKER)
    writeUInt8(Transaction.ADVANCED_TRANSACTION_FLAG)
  }

  writeVarInt(this.ins.length)

  this.ins.forEach(function (txIn) {
    writeSlice(txIn.hash)
    writeUInt32(txIn.index)
    writeVarSlice(txIn.script)
    writeUInt32(txIn.sequence)
  })

  writeVarInt(this.outs.length)
  this.outs.forEach(function (txOut) {
    if (!txOut.valueBuffer) {
      writeUInt64(txOut.value)
    } else {
      writeSlice(txOut.valueBuffer)
    }

    writeVarSlice(txOut.script)
  })

  if (hasWitnesses) {
    this.ins.forEach(function (input) {
      writeVector(input.witness)
    })
  }

  writeUInt32(this.locktime)

  if (this.expiry != null) {
    writeUInt32(this.expiry)
  }

  if (this.version >= 2 && this.zcash) {
    writeVarInt(this.joinsplits.length)
    this.joinsplits.forEach(function (joinsplit) {
      writeUInt64(joinsplit.vpubOld)
      writeUInt64(joinsplit.vpubNew)
      writeSlice(joinsplit.anchor)
      joinsplit.nullifiers.forEach(function (nullifier) {
        writeSlice(nullifier)
      })
      joinsplit.commitments.forEach(function (nullifier) {
        writeSlice(nullifier)
      })
      writeSlice(joinsplit.ephemeralKey)
      writeSlice(joinsplit.randomSeed)
      joinsplit.macs.forEach(function (nullifier) {
        writeSlice(nullifier)
      })
      writeCompressedG1(joinsplit.zproof.gA)
      writeCompressedG1(joinsplit.zproof.gAPrime)
      writeCompressedG2(joinsplit.zproof.gB)
      writeCompressedG1(joinsplit.zproof.gBPrime)
      writeCompressedG1(joinsplit.zproof.gC)
      writeCompressedG1(joinsplit.zproof.gCPrime)
      writeCompressedG1(joinsplit.zproof.gK)
      writeCompressedG1(joinsplit.zproof.gH)
      joinsplit.ciphertexts.forEach(function (ciphertext) {
        writeSlice(ciphertext)
      })
    })
    if (this.joinsplits.length > 0) {
      writeSlice(this.joinsplitPubkey)
      writeSlice(this.joinsplitSig)
    }
  }

  // avoid slicing unless necessary
  if (initialOffset !== undefined) return buffer.slice(initialOffset, offset)
  return buffer
}

// used in many places
Transaction.prototype.toHex = function () {
  return this.toBuffer().toString('hex')
}

Transaction.prototype.setWitness = function (index, witness) {
  typeforce(types.tuple(types.Number, [types.Buffer]), arguments)

  this.ins[index].witness = witness
}

module.exports = Transaction
