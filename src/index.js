var script = require('./script')

var templates = require('./templates')
for (var key in templates) {
  script[key] = templates[key]
}

module.exports = {
  bufferutils: require('./bufferutils'), // TODO: remove in 4.0.0

  ECPair: require('./ecpair'),
  ECSignature: require('./ecsignature'),
  HDNode: require('./hdnode'),
  Transaction: require('./transaction'),

  address: require('./address'),
  crypto: require('./crypto'),
  networks: require('./networks'),
  opcodes: require('bitcoin-ops'),
  script: script
}
