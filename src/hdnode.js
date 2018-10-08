const Buffer = require('safe-buffer').Buffer;
const base58check = require('bs58check');
const createHmac = require('create-hmac');
const typeforce = require('typeforce');
const BigInteger = require('bigi');
const ecurve = require('ecurve');
const bcrypto = require('./crypto');
const types = require('./types');
const NETWORKS = require('./networks');

const ECPubkey = require('./ecpubkey');


const curve = ecurve.getCurveByName('secp256k1');

// we keep all internal representation
// of HD Nodes in this object
// However, we also often use emscripten and webworker
// code to make derivations faster
function HDNode(pubkey, chainCode) {
  typeforce(types.tuple('ECPubkey', types.Buffer256bit), arguments);

  if (!pubkey.compressed) throw new TypeError('BIP32 only allows compressed pubkeys');

  this.pubkey = pubkey;
  this.chainCode = chainCode;
  this.depth = 0;
  this.index = 0;
  this.parentFingerprint = 0x00000000;
}

HDNode.HIGHEST_BIT = 0x80000000;
HDNode.LENGTH = 78;
HDNode.MASTER_SECRET = Buffer.from('Bitcoin seed', 'utf8');

// Used in import from XPub
HDNode.fromBase58 = function (string, networks) {
  const buffer = base58check.decode(string);
  if (buffer.length !== 78) throw new Error('Invalid buffer length');

  // 4 bytes: version bytes
  const version = buffer.readUInt32BE(0);
  let network;

  // list of networks?
  if (Array.isArray(networks)) {
    network = networks.filter(x => version === x.bip32.private
             || version === x.bip32.public).pop();

    if (!network) throw new Error('Unknown network version');

  // otherwise, assume a network object (or default to bitcoin)
  } else {
    network = networks || NETWORKS.bitcoin;
  }

  if (version !== network.bip32.public) throw new Error('Invalid network version');

  // 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 descendants, ...
  const depth = buffer[4];

  // 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
  const parentFingerprint = buffer.readUInt32BE(5);
  if (depth === 0) {
    if (parentFingerprint !== 0x00000000) throw new Error('Invalid parent fingerprint');
  }

  // 4 bytes: child number. This is the number i in xi = xpar/i, with xi the key being serialized.
  // This is encoded in MSB order. (0x00000000 if master key)
  const index = buffer.readUInt32BE(9);
  if (depth === 0 && index !== 0) throw new Error('Invalid index');

  // 32 bytes: the chain code
  const chainCode = buffer.slice(13, 45);

  // 33 bytes: private key data (0x00 + k)
  const Q = ecurve.Point.decodeFrom(curve, buffer.slice(45, 78));
  // Q.compressed is assumed, if somehow this assumption is broken, `new HDNode` will throw

  const pubkey = new ECPubkey(Q, { network });

  const hd = new HDNode(pubkey, chainCode);
  hd.depth = depth;
  hd.index = index;
  hd.parentFingerprint = parentFingerprint;

  return hd;
};

// used in conversion from trezor result to HDNode
// (faster than parsing xpub)
HDNode.fromInternal = function (chainCode, publicKey, network, depth, index, parentFingerprint) {
  const Q = ecurve.Point.decodeFrom(curve, publicKey);
  const pubkey = new ECPubkey(Q, { network });
  const node = new HDNode(pubkey, chainCode);
  node.depth = depth;
  node.index = index;
  node.parentFingerprint = parentFingerprint;
  return node;
};

// used in hd-wallet if we dont have emscripten
HDNode.prototype.getAddress = function () {
  return this.pubkey.getAddress();
};

// used when we change xpub prefix
// and we want to export the xpub as string
HDNode.prototype.setNetwork = function (network) {
  this.pubkey.network = network;
};

// used for sending HDNode data to emscripten worker
// (we need pure JS object)
HDNode.prototype.getPublicKeyBuffer = function () {
  return this.pubkey.getPublicKeyBuffer();
};

// maybe used in hd-wallet if we dont have emscripten
HDNode.prototype.toBase58 = () => {
  // Version
  const { network } = this.pubkey;
  const version = network.bip32.public;
  const buffer = Buffer.allocUnsafe(78);

  // 4 bytes: version bytes
  buffer.writeUInt32BE(version, 0);

  // 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 descendants, ....
  buffer.writeUInt8(this.depth, 4);

  // 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
  buffer.writeUInt32BE(this.parentFingerprint, 5);

  // 4 bytes: child number. This is the number i in xi = xpar/i, with xi the key being serialized.
  // This is encoded in big endian. (0x00000000 if master key)
  buffer.writeUInt32BE(this.index, 9);

  // 32 bytes: the chain code
  this.chainCode.copy(buffer, 13);

  // 33 bytes: the public key or private key data
  // X9.62 encoding for public keys
  this.pubkey.getPublicKeyBuffer().copy(buffer, 45);

  return base58check.encode(buffer);
};

// maybe used in hd-wallet if we dont have emscripten
HDNode.prototype.derive = function (index) {
  typeforce(types.UInt32, index);

  const isHardened = index >= HDNode.HIGHEST_BIT;
  const data = Buffer.allocUnsafe(37);

  // Hardened child
  if (isHardened) {
    throw new TypeError('Could not derive hardened child key');
  }

  // data = serP(point(kpar)) || ser32(index)
  //      = serP(Kpar) || ser32(index)
  this.pubkey.getPublicKeyBuffer().copy(data, 0);
  data.writeUInt32BE(index, 33);

  const I = createHmac('sha512', this.chainCode).update(data).digest();
  const IL = I.slice(0, 32);
  const IR = I.slice(32);

  const pIL = BigInteger.fromBuffer(IL);

  // In case parse256(IL) >= n, proceed with the next value for i
  if (pIL.compareTo(curve.n) >= 0) {
    return this.derive(index + 1);
  }

  // Private parent key -> private child key
  let derivedPubkey;
  // Ki = point(parse256(IL)) + Kpar
  //    = G*IL + Kpar
  const Ki = curve.G.multiply(pIL).add(this.pubkey.Q);

  // In case Ki is the point at infinity, proceed with the next value for i
  if (curve.isInfinity(Ki)) {
    return this.derive(index + 1);
  }

  derivedPubkey = new ECPubkey(Ki, {
    network: this.pubkey.network,
  });

  const hd = new HDNode(derivedPubkey, IR);
  hd.depth = this.depth + 1;
  hd.index = index;

  const identifier = bcrypto.hash160(this.pubkey.getPublicKeyBuffer());
  const fingerprint = identifier.slice(0, 4);

  hd.parentFingerprint = fingerprint.readUInt32BE(0);

  return hd;
};

// used when directly accessing scripthash bytes
// from derived HDNode
HDNode.prototype.getIdentifier = function () {
  return bcrypto.hash160(this.getPublicKeyBuffer());
};

module.exports = HDNode;
