var createHash = require('create-hash')

// used only in hash160
function ripemd160 (buffer) {
  return createHash('rmd160').update(buffer).digest()
}

function sha256 (buffer) {
  return createHash('sha256').update(buffer).digest()
}

function hash160 (buffer) {
  return ripemd160(sha256(buffer))
}

function hash256 (buffer) {
  return sha256(sha256(buffer))
}

module.exports = {
  hash160: hash160,
  hash256: hash256,
  sha256: sha256
}
