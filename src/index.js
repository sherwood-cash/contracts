/* eslint-disable no-console */
const { ethers } = require('hardhat')
const { BigNumber } = ethers
const { toFixedHex, poseidonHash2, getExtDataHash, FIELD_SIZE } = require('./utils')
const Utxo = require('./utxo')

const { prove } = require('./prover')

async function getProof({
  inputs,
  outputs,
  extAmount,
  fee,
  recipient,
  feeRecipient,
  encryptionKey,
}) {
  let inputMerklePathIndices = []
  let inputMerklePathElements = []
  // fetch /merkle/root from indexer url
  const res = await fetch(`${process.env.INDEXER_URL}/merkle/root`)
  if (!res.ok) {
    throw new Error(`Failed to fetch merkle root: ${res.status} ${res.statusText}`)
  }
  const { root, nextIndex: initialNextIndex } = await res.json()
  let nextIndex = initialNextIndex
  for (const input of inputs) {
    if (input.amount.gt(0)) {
      // fetch commitment info by post method
      // return status must be 200, otherwise throw error
      let res = await fetch(`${process.env.INDEXER_URL}/commitment/`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          commitment: toFixedHex(input.getCommitment()),
        }),
      })
      if (!res.ok) {
        throw new Error(`Failed to fetch commitment info`)
      }
      const { index, pathElements } = await res.json()
      input.index = index
      if (input.index < 0) {
        throw new Error(`Input commitment ${toFixedHex(input.getCommitment())} was not found`)
      }
      inputMerklePathIndices.push(input.index)
      inputMerklePathElements.push(pathElements)
    } else {
      inputMerklePathIndices.push(0)
      inputMerklePathElements.push(new Array(26).fill(0))
    }
  }

  // update nextIndex to outputs
  for (let output of outputs) {
    output.index = nextIndex++
  }

  const extData = {
    recipient: toFixedHex(recipient, 20),
    extAmount: toFixedHex(extAmount),
    feeRecipient: toFixedHex(feeRecipient, 20),
    fee: toFixedHex(fee),
    encryptedOutput1: outputs[0].encrypt(encryptionKey),
    encryptedOutput2: outputs[1].encrypt(encryptionKey),
  }

  const extDataHash = getExtDataHash(extData)
  let input = {
    root,
    inputNullifier: inputs.map((x) => x.getNullifier().toString()),
    outputCommitment: outputs.map((x) => x.getCommitment().toString()),
    publicAmount: BigNumber.from(extAmount).sub(fee).add(FIELD_SIZE).mod(FIELD_SIZE).toString(),
    extDataHash: extDataHash.toString(),
    mintAddress: inputs[0].mintAddress.toString(),

    // data for 2 transaction inputs
    inAmount: inputs.map((x) => x.amount.toString()),
    inPrivateKey: inputs.map((x) => x.keypair.privkey.toString()),
    inBlinding: inputs.map((x) => x.blinding.toString()),
    inPathIndices: inputMerklePathIndices,
    inPathElements: inputMerklePathElements,

    // data for 2 transaction outputs
    outAmount: outputs.map((x) => x.amount.toString()),
    outBlinding: outputs.map((x) => x.blinding.toString()),
    outPubkey: outputs.map((x) => x.keypair.pubkey.toString()),
  }

  const { pA, pB, pC } = await prove(input, `./build/circuits/transaction${inputs.length}`)

  const args = {
    pA,
    pB,
    pC,
    root: toFixedHex(input.root),
    inputNullifiers: inputs.map((x) => toFixedHex(x.getNullifier())),
    outputCommitments: outputs.map((x) => toFixedHex(x.getCommitment())),
    publicAmount: toFixedHex(input.publicAmount),
    extDataHash: toFixedHex(extDataHash),
  }

  return {
    extData,
    args,
  }
}

async function prepareTransaction({
  etherPool,
  inputs = [],
  outputs = [],
  fee = 0,
  recipient = 0,
  feeRecipient = 0,
  fromBlock = 0,
  encryptionKey,
}) {
  if (inputs.length > 2 || outputs.length > 2) {
    throw new Error('Incorrect inputs/outputs count')
  }
  while (inputs.length < 2) {
    inputs.push(new Utxo())
  }
  while (outputs.length < 2) {
    outputs.push(new Utxo())
  }

  let extAmount = BigNumber.from(fee)
    .add(outputs.reduce((sum, x) => sum.add(x.amount), BigNumber.from(0)))
    .sub(inputs.reduce((sum, x) => sum.add(x.amount), BigNumber.from(0)))

  const { args, extData } = await getProof({
    inputs,
    outputs,
    extAmount,
    fee,
    recipient,
    feeRecipient,
    encryptionKey,
  })

  return {
    args,
    extData,
  }
}

async function transaction({ etherPool, ...rest }) {
  const { args, extData } = await prepareTransaction({
    etherPool,
    ...rest,
  })

  const overrides = { gasLimit: 3000000 }
  const extAmount = BigNumber.from(extData.extAmount)
  if (extAmount.gt(0)) {
    overrides.value = extAmount
  }

  const receipt = await etherPool.transact(args, extData, overrides)
  return await receipt.wait()
}

/**
 * Scan all utxos from relayer and try to decrypt each encrypted output.
 * Successfully decrypted outputs belong to the user. Returns unspent UTXOs.
 */
async function findUnspentUtxos({ etherPool, encryptionKey, keypair, fromBlock = 0 }) {
  let res = await fetch(`${process.env.INDEXER_URL}/all_encrypted`)
  const allEncrypted = await res.json()
  console.log(`Total UTXOs in indexer: ${allEncrypted.length}`)

  const unspent = []

  for (const encrypted of allEncrypted) {
    const { index, encryptedOutput } = encrypted
    try {
      const utxo = Utxo.decrypt(encryptionKey, encryptedOutput, Number(index), keypair)
      if (utxo.amount.isZero()) continue

      const commitment = toFixedHex(utxo.getCommitment())
      const onChainCommitment = toFixedHex(encrypted.commitment)
      if (commitment !== onChainCommitment) {
        console.log(`Decryption failed: commitment mismatch (calculated ${commitment}, on-chain ${onChainCommitment})`)
        continue
      }

      const nullifier = toFixedHex(utxo.getNullifier())
      const isSpent = await etherPool.isSpent(nullifier)
      if (!isSpent) {
        unspent.push(utxo)
      }
    } catch {
      // Decryption failed — this output belongs to someone else
    }
  }

  return unspent
}

module.exports = { transaction, prepareTransaction, findUnspentUtxos }
