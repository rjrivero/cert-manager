'use strict'

const fs = require('fs')
const winston = require('winston')
const glob = require('glob')
const x509 = require('x509')
const moment = require('moment')
const countdown = require('./countdown.js')

/**
 * Filesystem certificate scanner.
 *
 * Manages certificates stored in a filesystem with a given
 * naming convention:
 *
 *   - CSRs are stored as json files in the CFSSL format. The
 *     filenames must match the glob given as the 'path' configuration
 *     parameter to the constructor.
 *
 *   - Certs are stored as PEM encoded files. The filenames must
 *     be derived from the CSR name, performing a simple substitution
 *     specified by the 'maps' configuration parameter to the constructor.
 */
class FileScanner {

  /**
   * @param scannerConfig object {
   *   // glob pattern that identified csr files
   *   path: '*-csr.json',
   *   // search and replacement strings to derive the
   *   // cert and key file's names from the csr file name
   *   maps: {
   *     crt: ['-csr.json', '-chain.pem']
   *     key: ['-csr.json', '-key.pem']
   *   }
   * }
   */
  constructor (scannerConfig) {
    this.maps = scannerConfig.maps
    this.path = scannerConfig.path
    this.cache = {}
  }

  /**
   * Reads the content of a file and parses it with the given parser.
   * Returns a promise that realizes the file's parsed content.
   *
   * In case of error, the promise raises the error object.
   */
  parseFile (fullName, parser) {
    return new Promise((resolve, reject) => {
      winston.debug('Trying to read file %s', fullName)
      fs.readFile(fullName, 'utf8', (err, content) => {
        if (err) {
          reject(err)
        } else {
          try {
            resolve(parser(content))
          } catch (err) {
            reject(err)
          }
        }
      })
    })
  }

  /**
   * Reads and parses both a CSR file and a CRT file.
   * Returns a promise that realizes a certificate metadata object:
   * {
   *   id: unique certificate id (full CSR filename)
   *   cert: full CRT filename
   *   expiration: expiration date
   *   cn: certificate's common name
   *   ip_sans: certificate's IP sans
   *   sans: certificate's SANs
   * }
   *
   * In case of error, this does not raise anything but returns
   * a certificate metadata object with expiration === null.
   */
  parseBoth (csrName, crtName) {
    let self = this
    // Read and parse CRT and CSR files in parallel
    return new Promise((resolve, reject) => {
      let cd = new countdown.Key(resolve)
      // Read CSR file contents
      winston.debug('Collect csr data from %s', csrName)
      cd.add('csr', self.parseFile(csrName, (content) => {
        winston.debug('Read csr file %s', csrName)
        let data = JSON.parse(content)
        return {
          expiration: moment(),
          cn: data.CN,
          sans: data.hosts
        }
      }))
      // Read CRT file contents
      winston.debug('Collect crt data from %s', crtName)
      cd.add('crt', self.parseFile(crtName, (content) => {
        winston.debug('Read crt file %s', crtName)
        let data = x509.parseCert(content)
        return {
          expiration: moment(data.notAfter),
          cn: data.subject.commonName,
          sans: data.altNames
        }
      }))
    })
    /*
    There is no code that can call 'reject' on the previous Future,
    so it always comes to the 'then' clause. In case of failure in
    the previous tasks, we just return a data item with a null
    expiration. That means we could not load or parse neither the
    csr nor the crt file.
    */
    .then((cd) => {
      // Display any error messages
      for (let key of Object.keys(cd.errset)) {
        winston.warn('Error loading %s file %s', key, cd.errset[key])
      }
      let data = { id: csrName, cert: crtName, expiration: null }
      // CSR data gets precedence over CRT data
      let csr = cd.keyset.csr
      let crt = cd.keyset.crt
      Object.assign(data, csr || crt || {})
      // However, if there is a CRT, we get expiration info from there
      if (crt !== undefined) {
        data.expiration = crt.expiration
      }
      return data
    })
  }

  /**
   * Scans CSR file and returns a future that realizes as a
   * certificate metadata object (see 'parseBoth').
   *
   * In case of unexpected exception, the future raises an error
   * object with two fields:
   *
   * {
   *   id: the full path of the file we tried to load.
   *   error: the error data.
   * }
   */
  scanFile (fname) {
    let self = this
    return new Promise((resolve, reject) => {
      // Convert relative paths to absolute paths, so they can be used
      // as ID for the CSR and Certificates.
      fs.realpath(fname, self.cache, (err, fullName) => {
        if (err) {
          reject({ id: fname, error: err })
        } else {
          try {
            // Read certificate data from CSR and current certificate
            let crtName = fullName.replace(self.maps.crt[0], self.maps.crt[1])
            self.parseBoth(fullName, crtName)
            .then((data) => {
              // data already bears an 'id' field with the full path
              // to the CSR file
              resolve(data)
            })
            .catch((err) => {
              reject({ id: fullName, error: err })
            })
          } catch (err) {
            reject({ id: fullName, error: err })
          }
        }
      })
    })
  }

  /**
   * Scan the filesysten for files that match the given glob
   * pattern and load the certificate metadata associated with
   * each file found.
   *
   * Only returns those certificates that are bound to expire
   * in less than the given hours
   */
  scan (hoursToExp) {
    let self = this
    return new Promise((resolve, reject) => {
      // Expand file names
      let cd = new countdown.List(resolve)
      glob(self.path, (err, files) => {
        if (err) reject({ id: self.path, error: err })
        // Read each file asynchronously, and gather results
        else {
          if (files.length <= 0) {
            winston.warn('No matching files found for %s', self.path)
          }
          for (let fname of files) {
            cd.push(self.scanFile(fname))
          }
        }
      })
    })
    .then((result) => {
      // Log errors. We do not do anything else for
      // certificates we failed to read.
      for (let err of result.errors) {
        winston.warn('Failed to load %s: %s', err.id, err.error)
      }
      let threshold = moment().add(hoursToExp, 'h')
      result = result.values
      // Return only certificates expiring before the threshold
      return result.filter((data) => {
        if (data.expiration !== null) {
          if (data.expiration.diff(threshold) < 0) {
            return true
          }
          winston.debug('Skipping %s [%s]', data.id, data.expiration, {})
        }
        return false
      })
    })
  }

  /**
   * Save a file to the filesystem. Easy.
   */
  savePem (fname, content) {
    return new Promise((resolve, reject) => {
      winston.debug('Saving file %s', fname)
      fs.writeFile(fname, content, 'utf8', (err, data) => {
        if (err) reject(err)
        else {
          winston.debug('File %s sucessfully saved', fname)
          resolve(data)
        }
      })
    })
  }

  /**
   * Push a certificate update.
   *
   * @param item object {
   *   id: cert id (the full path to the CSR, as returned by 'scan')
   *   certPem: certificate content, PEM encoded
   *   keyPem: key content, PEM encoded
   * }
   *
   * Returns a future that realizes the same 'item' object passed
   * in, only it includes an 'error' field if there was some problem.
   */
  push (item) {
    let self = this
    return new Promise((resolve, reject) => {
      try {
        winston.debug('Saving certificate data for %s', item.id)
        let crtName = item.id.replace(self.maps.crt[0], self.maps.crt[1])
        let keyName = item.id.replace(self.maps.key[0], self.maps.key[1])
        let cd = new countdown.Key(resolve)
        cd.add('crt', self.savePem(crtName, item.certPem))
        cd.add('key', self.savePem(keyName, item.keyPem))
      } catch (err) {
        item.error = err
        reject(item)
      }
    })
    .then((cd) => {
      // If errors saving the item, notify
      let errors = []
      if (cd.errset.crt) errors.push(cd.errset.crt)
      if (cd.errset.key) errors.push(cd.errset.key)
      if (errors.length > 0) {
        item.error = errors
        throw item
      }
      delete item.error
      return item
    })
  }
}

exports.File = FileScanner
