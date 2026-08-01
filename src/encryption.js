const crypto = require('crypto')
const { ethers } = require('hardhat')
const { Keypair } = require('./keypair')

const SIGN_IN_MESSAGE = 'Sherwood Cash account sign in'

/**
 * Derive encryption key and UTXO keypair from an EIP-191 signature.
 * Matches the SDK's V2 key derivation: keccak256(sig) → encryptionKey, keccak256(encryptionKey) → utxoPrivateKey
 */
function deriveKeys(signature) {
  const encryptionKeyHex = ethers.utils.keccak256(signature)
  const encryptionKey = Buffer.from(encryptionKeyHex.slice(2), 'hex')
  const utxoPrivateKey = ethers.utils.keccak256(encryptionKey)
  const keypair = new Keypair(utxoPrivateKey)
  return { encryptionKey, utxoPrivateKey, keypair }
}

/**
 * Sign the canonical message and derive all keys.
 * @param {ethers.Signer} signer
 */
async function signIn(signer) {
  const signature = await signer.signMessage(SIGN_IN_MESSAGE)
  return deriveKeys(signature)
}

/**
 * AES-256-GCM authenticated encryption.
 * Output format: [IV(12)] + [authTag(16)] + [ciphertext]
 * @returns {string} 0x-prefixed hex string
 */
function encrypt(data, encryptionKey) {
  const dataBuffer = typeof data === 'string' ? Buffer.from(data) : data
  const iv = crypto.randomBytes(12)
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv)
  const encrypted = Buffer.concat([cipher.update(dataBuffer), cipher.final()])
  const authTag = cipher.getAuthTag()
  const result = Buffer.concat([iv, authTag, encrypted])
  return '0x' + result.toString('hex')
}

/**
 * AES-256-GCM authenticated decryption.
 * @param {string|Buffer} encryptedData 0x-prefixed hex string or Buffer
 * @param {Buffer} encryptionKey 32-byte key
 * @returns {Buffer}
 */
function decrypt(encryptedData, encryptionKey) {
  const buf = typeof encryptedData === 'string'
    ? Buffer.from(encryptedData.replace(/^0x/, ''), 'hex')
    : encryptedData

  const iv = buf.slice(0, 12)
  const authTag = buf.slice(12, 28)
  const data = buf.slice(28)

  const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey, iv)
  decipher.setAuthTag(authTag)
  return Buffer.concat([decipher.update(data), decipher.final()])
}

module.exports = {
  SIGN_IN_MESSAGE,
  deriveKeys,
  signIn,
  encrypt,
  decrypt,
}
