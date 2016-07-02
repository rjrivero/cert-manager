'use strict'

const winston = require('winston')
const nconf = require('nconf')

const countdown = require('./lib/countdown.js')
const scanners = require('./lib/scanners.js')
const providers = require('./lib/providers.js')

winston.level = 'debug'

nconf.argv().env().file({ file: 'config.json' })
nconf.defaults({

  concurrency: 5,

  // Scanners config section
  scanners: {
    // named file scanners
    file: {

      // First named scanner: myFileScanner
      myFileScanner: {
        path: '**/*-csr.json',
        maps: {
          crt: [ '-csr.json', '-chain.pem' ],
          key: [ '-csr.json', '-key.pem' ]
        }
      }
    }
  },

  // Providers
  providers: {
    // Vault providers
    vault: {

      myVaultProvider: {
        host: 'vault.server.domain',
        port: '8200',
        path: 'pki',
        token: '<vault-token>',
        role: '<role>'
      }
    }
  },

  // Mappings of scanners to providers
  maps: [
    {
      scanner: 'myFileScanner',
      provider: 'myVaultProvider',
      expire: 24,
      threshold: 12
    }
  ]
})

// Load file scanners
let scannerCfg = nconf.get('scanners')
let scannerMap = new Map()
for (let key of Object.keys(scannerCfg.file)) {
  scannerMap[key] = new scanners.File(scannerCfg.file[key])
}

// Load vault providers
let providerCfg = nconf.get('providers')
let providerMap = new Map()
for (let key of Object.keys(providerCfg.vault)) {
  providerMap[key] = new providers.Vault(providerCfg.vault[key])
}

// Iterate over mappings
let concurrency = nconf.get('concurrency')
nconf.get('maps').forEach((mapping) => {
  let scanner = scannerMap[mapping.scanner]
  let provider = providerMap[mapping.provider]
  let expire = mapping.expire
  let threshold = mapping.threshold
  if (scanner !== undefined && provider !== undefined && expire !== undefined && threshold !== undefined) {
    scanner.scan(threshold).then((certs) => {
      return new Promise((resolve, reject) => {
        let cd = new countdown.List(resolve)
        cd.pack(certs, concurrency, (cert) => {
          provider.sign(cert, expire)
          .catch((err) => {
            winston.warn('Error signing cert %s: %j', cert.id, err, {})
          })
          .then(() => { return scanner.push(cert) })
          .then(() => {
            winston.info('Renewed certificate %s', cert.id)
          })
          .catch((err) => {
            winston.warn('Error pushing cert %s: %j', cert.id, err, {})
          })
        })
      })
    })
    .catch((err) => {
      winston.warn('Error processing mapping', JSON.stringify(err))
    })
  }
})
