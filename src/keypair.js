const { ethers } = require('hardhat')
const { BigNumber } = ethers
const { poseidonHash, toFixedHex } = require('./utils')

class Keypair {
  /**
   * Initialize a new keypair. Generates a random private key if not defined.
   *
   * @param {string} privkey hex-encoded private key
   */
  constructor(privkey = ethers.Wallet.createRandom().privateKey) {
    this.privkey = privkey
    this.pubkey = poseidonHash([this.privkey])
  }

  toString() {
    return toFixedHex(this.pubkey)
  }

  /**
   * Key address for this keypair, alias to {@link toString}
   *
   * @returns {string}
   */
  address() {
    return this.toString()
  }

  /**
   * Sign a message using keypair private key
   *
   * @param {string|number|BigNumber} commitment a hex string with commitment
   * @param {string|number|BigNumber} merklePath a hex string with merkle path
   * @returns {BigNumber} a hex string with signature
   */
  sign(commitment, merklePath) {
    return poseidonHash([this.privkey, commitment, merklePath])
  }
}

module.exports = { Keypair }
