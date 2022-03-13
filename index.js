const path = require('path')
const express = require('express')
const app = express()
const RSA = require('./cryptograph')

const store = {}

app.use(express.json())

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, './index.html'))
})

app.get('/publicKey', (req, res) => {
  
  const rsa = new RSA(store)

  if (!rsa.privateKey) {
    rsa.generate()
  }

  store.publicKey = rsa.publicKey
  store.privateKey = rsa.privateKey

  return res.json({
    publicKey: rsa.publicKey
  })
})

app.post('/decode', (req, res) => {
  const message = req.body.message
  const rsa = new RSA(store)

  return res.json({
    decode: rsa.decrypt(message)
  })
})

app.listen(3010)