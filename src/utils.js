/* global network */
const crypto = require('crypto')
const { ethers } = require('hardhat')
const BigNumber = ethers.BigNumber
const { poseidon1, poseidon2, poseidon3, poseidon4 } = require('poseidon-lite')

function poseidonHash(items) {
  if (items.length === 1) return BigNumber.from(poseidon1(items))
  if (items.length === 2) return BigNumber.from(poseidon2(items))
  if (items.length === 3) return BigNumber.from(poseidon3(items))
  if (items.length === 4) return BigNumber.from(poseidon4(items))
  throw new Error(`Unsupported poseidon input length: ${items.length}`)
}
const poseidonHash2 = (a, b) => poseidonHash([a, b])

const FIELD_SIZE = BigNumber.from(
  '21888242871839275222246405745257275088548364400416034343698204186575808495617',
)

/** Generate random number of specified byte length */
const randomBN = (nbytes = 31) => BigNumber.from(crypto.randomBytes(nbytes))

// keccak256(abi.encode(SherwoodVault.SwapParams)) — the digest that goes into
// ExtData.swapParamsHash, binding a swap's destination/route/slippage to the proof.
const SWAP_PARAMS_TUPLE =
  'tuple(uint256 assetIn,address tokenOut,uint8 version,bytes routeData,uint256 minOut,uint256 deadline,bytes32 outPubkey,bytes32 outBlinding,bytes encryptedOutput)'

function hashSwapParams(p) {
  return ethers.utils.keccak256(new ethers.utils.AbiCoder().encode([SWAP_PARAMS_TUPLE], [p]))
}

const ZERO_HASH = '0x' + '0'.repeat(64)

function getExtDataHash({
  recipient,
  extAmount,
  feeRecipient,
  fee,
  encryptedOutput1,
  encryptedOutput2,
  swapParamsHash,
}) {
  const abi = new ethers.utils.AbiCoder()

  const encodedData = abi.encode(
    [
      'tuple(address recipient,int256 extAmount,address feeRecipient,uint256 fee,bytes encryptedOutput1,bytes encryptedOutput2,bytes32 swapParamsHash)',
    ],
    [
      {
        recipient: toFixedHex(recipient, 20),
        extAmount: toFixedHex(extAmount),
        feeRecipient: toFixedHex(feeRecipient, 20),
        fee: toFixedHex(fee),
        encryptedOutput1: encryptedOutput1,
        encryptedOutput2: encryptedOutput2,
        swapParamsHash: swapParamsHash || ZERO_HASH,
      },
    ],
  )
  const hash = ethers.utils.keccak256(encodedData)
  return BigNumber.from(hash).mod(FIELD_SIZE)
}

/** BigNumber to hex string of specified length */
function toFixedHex(number, length = 32) {
  let result =
    '0x' +
    (number instanceof Buffer
      ? number.toString('hex')
      : BigNumber.from(number).toHexString().replace('0x', '')
    ).padStart(length * 2, '0')
  if (result.indexOf('-') > -1) {
    result = '-' + result.replace('-', '')
  }
  return result
}

/** Convert value into buffer of specified byte length */
const toBuffer = (value, length) =>
  Buffer.from(
    BigNumber.from(value)
      .toHexString()
      .slice(2)
      .padStart(length * 2, '0'),
    'hex',
  )

module.exports = {
  FIELD_SIZE,
  randomBN,
  toFixedHex,
  toBuffer,
  poseidonHash,
  poseidonHash2,
  getExtDataHash,
  hashSwapParams,
  SWAP_PARAMS_TUPLE,
  ZERO_HASH,
}
