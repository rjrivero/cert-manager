'use strict'

const winston = require('winston')
const Vault = require('node-vault')

/**
 * Vault certificate provider.
 *
 * Able to sign certificates using the Vault PKI
 */
class VaultProvider {

  /**
   * Builds a certificate provider backed by a vault PKI.
   *
   * @params providerConfig object {
   *   server: URL of the vault server
   *   path: path where the PKI is mounted at vault
   *   role: role for which the cert is generated.
   *   token: token to be used to access to the server.
   * }
   */
  constructor (providerConfig) {
    this.host = providerConfig.host
    this.port = providerConfig.port
    this.path = providerConfig.path
    this.role = providerConfig.role
    this.token = providerConfig.token
    this.vault = new Vault({
      apiVersion: 'v1',
      endpoint: 'https://' + this.host + ':' + this.port,
      token: this.token
    })
  }

  /**
   * Signs a certificate request object with the following fields:
   *
   * {
   *   id: unique certificate id
   *   cn: certificate's common name
   *   ip_sans: certificate's IP sans
   *   sans: certificate's SANs
   * }
   *
   * Returns a promise that adds the following properties to the
   * object:
   * {
   *   serial: certificate serial number
   *   certPem: certificate content, PEM encoded
   *   keyPem: key content, PEM encoded
   * }
   */
  sign (req, hoursValid) {
    // Set vault parameters
    let vaultReq = {
      common_name: req.cn,
      format: 'pem',
      ttl: hoursValid + 'h'
    }
    if (req.sans) {
      vaultReq.alt_names = req.sans.join(',')
    }
    if (req.ip_sans) {
      vaultReq.ip_sans = req.ip_sans.join(',')
    }
    winston.debug('Requesting certificate', vaultReq)
    let self = this
    let path = self.path + '/issue/' + self.role
    return new Promise((resolve, reject) => {
      winston.debug('Issuing cert at %s', path, vaultReq)
      self.vault.write(path, vaultReq, (err, result) => {
        if (err) {
          req.error = err
          reject(req)
        } else if (result.data === undefined) {
          req.error = 'Missing data field in result'
          req.result = result
          reject(err)
        } else {
          winston.debug('Generated cert S/N %s for %s', result.data.serial_number, req.id)
          req.serial = result.data.serial_number
          req.certPem = result.data.certificate
          // Chain the CA certificate
          req.certPem += '\n' + result.data.issuing_ca
          req.keyPem = result.data.private_key
          resolve(req)
        }
      })
    })
  }
}

exports.Vault = VaultProvider
