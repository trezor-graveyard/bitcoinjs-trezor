const nullData = require('./nulldata');
const pubKeyHash = require('./pubkeyhash');
const scriptHash = require('./scripthash');
const witnessPubKeyHash = require('./witnesspubkeyhash');
const witnessScriptHash = require('./witnessscripthash');

const types = {
    MULTISIG: 'multisig',
    NONSTANDARD: 'nonstandard',
    NULLDATA: 'nulldata',
    P2PK: 'pubkey',
    P2PKH: 'pubkeyhash',
    P2SH: 'scripthash',
    P2WPKH: 'witnesspubkeyhash',
    P2WSH: 'witnessscripthash',
    WITNESS_COMMITMENT: 'witnesscommitment',
};

module.exports = {
    nullData,
    pubKeyHash,
    scriptHash,
    witnessPubKeyHash,
    witnessScriptHash,
    types,
};
