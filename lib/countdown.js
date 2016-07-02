'use strict'

/**
 * Promise manager.
 *
 * Manages the execution of several concurrent promises. It is
 * intended to let them run and collect the final results and
 * errors in internal arrays or dicts (those are specific implementations
 * of this 'abstract' base class).
 */
class Countdown {

  /**
   * @param resolve: callback called when all futures have
   * been realized.
   *
   * The only parameter to the callback is the countdown instance.
   */
  constructor (resolve) {
    this.pending = 0
    this.resolve = resolve
  }

  /**
   * @param count: number of tasks to decrement the
   *   count of pending futures.
   *
   * When the count reaches 0, the object's callback
   * is invoked.
   */
  end (count) {
    this.pending -= count
    if (this.pending === 0) {
      this.resolve(this)
    }
  }
}

/**
 * Concrete implementation of a Countdown object that stores
 * the results and errors of the futures in two arrays:
 *
 * .values: values returned by successfull futures.
 * .errors: errors raised by failed futures.
 */
class ListCountdown extends Countdown {

  constructor (resolve) {
    super(resolve)
    this.values = []
    this.errors = []
  }

  /**
   * Adds a future to the countdown.
   */
  push (promise) {
    let self = this
    self.pending += 1
    return promise.then((data) => {
      self.values.push(data)
      self.end(1)
    })
    .catch((err) => {
      self.errors.push(err)
      self.end(1)
    })
  }

  /**
   * Packs a list in groups processed in parallel
   *
   * @param items: list of items to group in bundles.
   * @param count: size of each bundle
   * @param promiser: function that receives an item and returns a Promise.
   */
  pack (items, count, promiser) {
    let self = this
    let prom = Promise.resolve()
    let pack = []
    for (let item of items) {
      // Group items in packs
      pack.push(item)
      // When packs have reached the max length,
      // chain them to the promise
      if (pack.length >= count) {
        prom = self._chain(prom, pack, promiser)
        pack = []
      }
    }
    // If remaining items in the pack, wrap them
    if (pack) {
      prom = self._chain(prom, pack, promiser)
    }
    // If there is an error in the chaining, notify using the regular
    // method (the .errors list)
    prom.catch((err) => {
      self.errors.push(err)
    })
    // Last, when everything is finished, fire the resolver
    .then(() => {
      self.resolve(self)
    })
  }

  /**
   * Chains a pack to the promise.
   *
   * When the given promise completes, runs the items of the pack
   * through the promiser to get a new set of promises that are
   * run concurrently.
   */
  _chain (promise, pack, promiser) {
    let self = this
    return promise.then(() => {
      return new Promise((resolve, reject) => {
        let cd = new ListCountdown(resolve)
        for (let item of pack) {
          try {
            cd.push(promiser(item))
          } catch (err) {
            reject(err)
          }
        }
      })
      .then((cd) => {
        // Concatenate errors and results
        Array.prototype.push.apply(self.errors, cd.errors)
        Array.prototype.push.apply(self.values, cd.values)
      })
    })
  }
}

/**
 * Concrete implementation of a Countdown object that stores
 * the results and errors of the futures in two hashes:
 *
 * .keyset: values returned by successfull futures.
 * .errset: errors raised by failed futures.
 */
class KeyCountdown extends Countdown {

  constructor (resolve) {
    super(resolve)
    this.keyset = {}
    this.errset = {}
  }

  /**
   * Adds a promise to the countdown, stores the result
   * at the given key either in the .keyset or .errset
   * hashes (depending on the future's outcome)
   */
  add (key, promise) {
    let self = this
    self.pending += 1
    return promise.then((data) => {
      self.keyset[key] = data
      self.end(1)
    })
    .catch((err) => {
      self.errset[key] = err
      self.end(1)
    })
  }
}

// Module exports
exports.List = ListCountdown
exports.Key = KeyCountdown
