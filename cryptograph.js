const crypto = require('crypto')
const NodeRSA = require('node-rsa')

const TXT_TO_REPLACE = [
  '-----BEGIN PRIVATE KEY-----',
  '-----END PRIVATE KEY-----',
  '-----BEGIN PUBLIC KEY-----',
  '-----END PUBLIC KEY-----',
]

class RSA {
  constructor({
    publicKey,
    privateKey,
  }) {
    this.publicKey = publicKey
    this.privateKey = privateKey
  }

  generate() {
    const key = new NodeRSA()
    
    key.generateKeyPair(2048, 65537)

    this.publicKey = key.exportKey('pkcs8-public-pem')
    this.privateKey = key.exportKey('pkcs8-private-pem')
  }

  encrypt(data) {
    const encoded = crypto.publicEncrypt({
      key: this.publicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
    }, Buffer.from(data))

    return encoded.toString('base64');
  }

  decrypt(data) {
    const encoded = crypto.privateDecrypt({
      key: this.privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
    }, Buffer.from(data, 'base64'))
    
    return encoded.toString()
  }

  static toBase64(key) {
    return TXT_TO_REPLACE.reduce(
      (text, txt) => text.replace(txt, ''), key
    ).replace(/\n/g, '')
  }
}

module.exports = RSA