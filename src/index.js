const script = require('./script');

const templates = require('./templates');

for (const key in templates) {
  script[key] = templates[key];
}

module.exports = {
  bufferutils: require('./bufferutils'), // TODO: remove in 4.0.0

  ECPubkey: require('./ecpubkey'),
  HDNode: require('./hdnode'),
  Transaction: require('./transaction'),

  address: require('./address'),
  crypto: require('./crypto'),
  networks: require('./networks'),
  opcodes: require('bitcoin-ops'),
  script,
};
