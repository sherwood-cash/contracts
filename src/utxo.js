const { ethers } = require('hardhat')
const { BigNumber } = ethers
const { randomBN, poseidonHash, toBuffer } = require('./utils')
const { Keypair } = require('./keypair')
const { encrypt, decrypt } = require('./encryption')

// we use 1 smart contract for 1 token, thus we don't need mint address inside UTXO.
// however, we reuse the same circuit from Solana codebase, thus we need to pass a dummy mint address.
const DUMMY_MINT = BigNumber.from(0)

class Utxo {
  /** Initialize a new UTXO - unspent transaction output or input. Note, a full TX consists of 2 inputs and 2 outputs
   *
   * @param {BigNumber | BigInt | number | string} amount UTXO amount
   * @param {BigNumber | BigInt | number | string} blinding Blinding factor
   * @param {Keypair} keypair
   * @param {number|null} index UTXO index in the merkle tree
   * @param {BigNumber | BigInt | number | string} mintAddress Token mint address (0 for native ETH)
   */
  constructor({ amount = 0, keypair = new Keypair(), blinding = randomBN(), index = null, mintAddress = DUMMY_MINT } = {}) {
    this.amount = BigNumber.from(amount)
    this.blinding = BigNumber.from(blinding)
    this.keypair = keypair
    this.index = index
    this.mintAddress = BigNumber.from(mintAddress)
  }

  /**
   * Returns commitment for this UTXO
   *
   * @returns {BigNumber}
   */
  getCommitment() {
    return poseidonHash([this.amount, this.keypair.pubkey, this.blinding, this.mintAddress])
  }

  /**
   * Returns nullifier for this UTXO
   *
   * @returns {BigNumber}
   */
  getNullifier() {
    if (this.amount.gt(0)) {
      if (this.index == null) {
        console.log({ amount: this.amount.toString(), blinding: '...', keypair: '...', index: this.index, mintAddress: this.mintAddress.toString() })
        throw new Error('Can not compute nullifier without utxo index')
      }
      if (this.keypair.privkey == null) {
        throw new Error('Can not compute nullifier without utxo private key')
      }
    }
    const commitment = this.getCommitment()
    const idx = this.index || 0
    const signature = this.keypair.sign(commitment, idx)
    return poseidonHash([commitment, idx, signature])
  }

  /**
   * Encrypt UTXO data using AES-256-GCM.
   * Format: pipe-delimited `amount|blinding|index|mintAddress`
   *
   * @param {Buffer} encryptionKey 32-byte AES key
   * @returns {string} `0x`-prefixed hex string with encrypted data
   */
  encrypt(encryptionKey) {
    const utxoString = `${this.amount.toString()}|${this.blinding.toString()}|${this.index || 0}|${this.mintAddress.toString()}`
    return encrypt(utxoString, encryptionKey)
  }

  /**
   * Decrypt an encrypted UTXO
   *
   * @param {Buffer} encryptionKey 32-byte AES key
   * @param {string} data hex string with encrypted data
   * @param {number} index UTXO index in merkle tree
   * @param {Keypair} keypair keypair for the decrypted UTXO
   * @returns {Utxo}
   */
  static decrypt(encryptionKey, data, index, keypair) {
    const decrypted = decrypt(data, encryptionKey)
    const parts = decrypted.toString().split('|')
    if (parts.length !== 4) {
      throw new Error('Invalid UTXO format after decryption')
    }
    const [amount, blinding, , mintAddress] = parts
    return new Utxo({
      amount: BigNumber.from(amount),
      blinding: BigNumber.from(blinding),
      keypair,
      index,
      mintAddress: BigNumber.from(mintAddress),
    })
  }
}

module.exports = Utxo
