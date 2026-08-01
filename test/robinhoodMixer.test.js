const hre = require('hardhat')
const { ethers, waffle } = hre
const { loadFixture } = waffle
const { expect } = require('chai')
const { BigNumber } = ethers

const { MerkleTree } = require('fixed-merkle-tree')
const Utxo = require('../src/utxo')
const { toFixedHex, poseidonHash2, getExtDataHash, FIELD_SIZE, hashSwapParams, ZERO_HASH } = require('../src/utils')
const { signIn } = require('../src/encryption')
const { prove } = require('../src/prover')
const { poseidon4 } = require('poseidon-lite')

const MERKLE_TREE_HEIGHT = 26
const MERKLE_TREE_ZERO_VALUE = '2795675251356313514992617062594790716374808130983166135938897961178374655502'
const NATIVE_ASSET_ID = BigNumber.from(1)
const CONFIG_TIMELOCK = 2 * 24 * 3600

// Two fresh, checksum-valid recipient addresses.
const BOB = ethers.utils.getAddress('0xdead00000000000000000000000000000000beef')
const CAROL = ethers.utils.getAddress('0x000000000000000000000000000000000000dead')

function createEmptyTree() {
  return new MerkleTree(MERKLE_TREE_HEIGHT, [], { hashFunction: poseidonHash2, zeroElement: MERKLE_TREE_ZERO_VALUE })
}

function pubkeyBig(keypair) {
  return BigInt(keypair.pubkey.toString())
}

// The empty second leaf inserted by executeSwap(): Poseidon4(0, P, 0, assetOut).
function emptyLeafCommit(keypair, assetOut) {
  return toFixedHex(BigNumber.from(poseidon4([0n, pubkeyBig(keypair), 0n, BigInt(BigNumber.from(assetOut).toString())]).toString()))
}

async function getProof({ inputs, outputs, tree, extAmount, fee, recipient, feeRecipient, encryptionKey, swapParamsHash }) {
  const inputMerklePathIndices = []
  const inputMerklePathElements = []

  for (const input of inputs) {
    if (input.amount.gt(0)) {
      input.index = tree.indexOf(toFixedHex(input.getCommitment()))
      if (input.index < 0) {
        throw new Error(`Input commitment ${toFixedHex(input.getCommitment())} was not found`)
      }
      inputMerklePathIndices.push(input.index)
      inputMerklePathElements.push(tree.path(input.index).pathElements)
    } else {
      inputMerklePathIndices.push(0)
      inputMerklePathElements.push(new Array(MERKLE_TREE_HEIGHT).fill(0))
    }
  }

  let nextIdx = tree._layers[0].length
  for (const output of outputs) {
    output.index = nextIdx++
  }

  const extData = {
    recipient: toFixedHex(recipient, 20),
    extAmount: toFixedHex(extAmount),
    feeRecipient: toFixedHex(feeRecipient, 20),
    fee: toFixedHex(fee),
    encryptedOutput1: outputs[0].encrypt(encryptionKey),
    encryptedOutput2: outputs[1].encrypt(encryptionKey),
    swapParamsHash: swapParamsHash || ZERO_HASH,
  }

  const extDataHash = getExtDataHash(extData)
  const input = {
    root: toFixedHex(tree.root),
    inputNullifier: inputs.map((x) => x.getNullifier().toString()),
    outputCommitment: outputs.map((x) => x.getCommitment().toString()),
    publicAmount: BigNumber.from(extAmount).sub(fee).add(FIELD_SIZE).mod(FIELD_SIZE).toString(),
    extDataHash: extDataHash.toString(),
    mintAddress: inputs[0].mintAddress.toString(),
    inAmount: inputs.map((x) => x.amount.toString()),
    inPrivateKey: inputs.map((x) => x.keypair.privkey.toString()),
    inBlinding: inputs.map((x) => x.blinding.toString()),
    inPathIndices: inputMerklePathIndices,
    inPathElements: inputMerklePathElements,
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

  return { extData, args, outputs }
}

// The transaction2 circuit uses ONE mintAddress signal for every input AND output.
// All padding UTXOs must therefore carry the SAME mint label (the asset id).
async function prepareTransaction({ tree, inputs = [], outputs = [], fee = 0, recipient = 0, feeRecipient = 0, encryptionKey, mintAddress, swapParamsHash }) {
  const assetMint =
    (inputs[0] && inputs[0].mintAddress) || (outputs[0] && outputs[0].mintAddress) || BigNumber.from(mintAddress || 0)
  while (inputs.length < 2) inputs.push(new Utxo({ mintAddress: assetMint }))
  while (outputs.length < 2) outputs.push(new Utxo({ mintAddress: assetMint }))

  const extAmount = BigNumber.from(fee)
    .add(outputs.reduce((sum, x) => sum.add(x.amount), BigNumber.from(0)))
    .sub(inputs.reduce((sum, x) => sum.add(x.amount), BigNumber.from(0)))

  return getProof({ inputs, outputs, tree, extAmount, fee, recipient, feeRecipient, encryptionKey, swapParamsHash })
}

async function deploy(contractName, ...args) {
  const Factory = await ethers.getContractFactory(contractName)
  const instance = await Factory.deploy(...args)
  return instance.deployed()
}

// Deploy SwapLogic behind a UUPS ERC1967 proxy (the stable address the vault points to).
async function deploySwapLogicProxy(admin) {
  const Logic = await ethers.getContractFactory('SwapLogic')
  const impl = await Logic.deploy()
  await impl.deployed()
  const initData = Logic.interface.encodeFunctionData('initialize', [admin.address])
  const Proxy = await ethers.getContractFactory('ERC1967Proxy')
  const proxy = await Proxy.deploy(impl.address, initData)
  await proxy.deployed()
  return { proxy: Logic.attach(proxy.address), impl }
}

// Enable a router on the vault, respecting the 2-step timelock.
async function enableRouter(vault, admin, version, router) {
  await vault.connect(admin).proposeRouter(version, router)
  await ethers.provider.send('evm_increaseTime', [CONFIG_TIMELOCK + 1])
  await ethers.provider.send('evm_mine', [])
  await vault.connect(admin).enableRouter(version, router)
}

async function vaultTransact({ vault, assetId, token, tree, signer, ...rest }) {
  const mintAddress = BigNumber.from(assetId) // canonical: mintAddress == assetId (native = 1)
  const { args, extData, outputs } = await prepareTransaction({ tree, mintAddress, ...rest })
  const extAmount = BigNumber.from(extData.extAmount)
  const s = signer || (await ethers.getSigners())[0]
  const overrides = { gasLimit: 3_000_000 }
  if (extAmount.gt(0)) {
    if (token) {
      await token.connect(s).approve(vault.address, extAmount)
    } else {
      overrides.value = extAmount
    }
  }
  await (await vault.connect(s).transact(assetId, args, extData, overrides)).wait()
  for (const o of outputs) tree.insert(toFixedHex(o.getCommitment()))
  return { args, extData, outputs }
}

// Build a swap: spend `inputUtxo` (recipient = vault), swap into `tokenOut`.
async function buildSwap({ vault, tree, assetIn, inputUtxo, keypair, encryptionKey, tokenOut, version, routeData, minOut, outNote }) {
  // params MUST be assembled before proving: the proof commits to their hash via
  // extData.swapParamsHash, which is what stops a submitter from redirecting the
  // swap proceeds to a note of their own.
  const deadline = (await ethers.provider.getBlock('latest')).timestamp + 3600
  const params = {
    assetIn,
    tokenOut,
    version,
    routeData,
    minOut,
    deadline,
    outPubkey: toFixedHex(outNote.keypair.pubkey),
    outBlinding: toFixedHex(outNote.blinding),
    encryptedOutput: outNote.encrypt(encryptionKey),
  }
  const { args, extData } = await prepareTransaction({
    tree,
    inputs: [inputUtxo],
    outputs: [],
    recipient: vault.address,
    encryptionKey,
    mintAddress: inputUtxo.mintAddress,
    swapParamsHash: hashSwapParams(params),
  })
  return { args, extData, params }
}

describe('SherwoodVault + SwapLogic (rug-proof split: immutable vault, UUPS logic)', function () {
  async function fixture() {
    require('../scripts/compileHasher')
    const [deployer, admin, alice] = await ethers.getSigners()

    const verifier2 = await deploy('Verifier2')
    const hasher = await deploy('Hasher')
    const hasher4 = await deploy('Hasher4')
    const weth = await deploy('MockWETH')

    // Immutable custody vault (no proxy).
    const vault = await deploy(
      'SherwoodVault',
      verifier2.address,
      MERKLE_TREE_HEIGHT,
      hasher.address,
      hasher4.address,
      weth.address,
      admin.address,
    )

    // UUPS-upgradable logic behind an ERC1967 proxy.
    const { proxy: swapLogic, impl: swapLogicImpl } = await deploySwapLogicProxy(admin)

    // Point the vault at the logic (2-step + timelock).
    await vault.connect(admin).proposeSwapLogic(swapLogic.address)
    await ethers.provider.send('evm_increaseTime', [CONFIG_TIMELOCK + 1])
    await ethers.provider.send('evm_mine', [])
    await vault.connect(admin).setSwapLogic()

    const usdg = await deploy('MockERC20')
    const meme = await deploy('MockERC20')
    await vault.connect(admin).registerToken(usdg.address)
    await vault.connect(admin).registerToken(meme.address)

    const usdgAssetId = BigNumber.from(usdg.address)
    const memeAssetId = BigNumber.from(meme.address)

    const v2 = await deploy('MockUniswapV2Router')
    const v3 = await deploy('MockUniswapV3Router')
    await enableRouter(vault, admin, 0, v2.address) // V2
    await enableRouter(vault, admin, 1, v3.address) // V3

    const { encryptionKey, keypair } = await signIn(alice)

    return {
      deployer, admin, alice, verifier2, hasher, hasher4, weth, vault, swapLogic, swapLogicImpl,
      usdg, meme, usdgAssetId, memeAssetId, v2, v3, encryptionKey, keypair,
    }
  }

  // ---------------------------------------------------------------- (a) ETH
  it('(a) deposit and withdraw ETH', async function () {
    const { vault, encryptionKey, keypair } = await loadFixture(fixture)
    const tree = createEmptyTree()

    const depositAmount = ethers.utils.parseEther('0.1')
    const depositUtxo = new Utxo({ amount: depositAmount, keypair, mintAddress: NATIVE_ASSET_ID })
    await vaultTransact({ vault, assetId: NATIVE_ASSET_ID, token: null, tree, outputs: [depositUtxo], encryptionKey })
    expect(await ethers.provider.getBalance(vault.address)).to.equal(depositAmount)

    const withdrawAmount = ethers.utils.parseEther('0.06')
    const change = new Utxo({ amount: depositAmount.sub(withdrawAmount), keypair, mintAddress: NATIVE_ASSET_ID })
    await vaultTransact({
      vault, assetId: NATIVE_ASSET_ID, token: null, tree,
      inputs: [depositUtxo], outputs: [change], recipient: BOB, encryptionKey,
    })
    expect(await ethers.provider.getBalance(BOB)).to.equal(withdrawAmount)

    await vaultTransact({
      vault, assetId: NATIVE_ASSET_ID, token: null, tree,
      inputs: [change], outputs: [], recipient: CAROL, encryptionKey,
    })
    expect(await ethers.provider.getBalance(CAROL)).to.equal(depositAmount.sub(withdrawAmount))
    expect(await ethers.provider.getBalance(vault.address)).to.equal(0)
  })

  // ---------------------------------------------------------------- (b) ERC20
  it('(b) deposit and withdraw ERC20', async function () {
    const { vault, usdg, usdgAssetId, encryptionKey, keypair } = await loadFixture(fixture)
    const [deployer] = await ethers.getSigners()
    const tree = createEmptyTree()

    const amount = BigNumber.from(1000)
    await usdg.mint(deployer.address, amount)
    const depositUtxo = new Utxo({ amount, keypair, mintAddress: usdgAssetId })
    await vaultTransact({ vault, assetId: usdgAssetId, token: usdg, tree, outputs: [depositUtxo], encryptionKey })
    expect(await usdg.balanceOf(vault.address)).to.equal(amount)

    await vaultTransact({
      vault, assetId: usdgAssetId, token: usdg, tree,
      inputs: [depositUtxo], outputs: [], recipient: BOB, encryptionKey,
    })
    expect(await usdg.balanceOf(BOB)).to.equal(amount)
    expect(await usdg.balanceOf(vault.address)).to.equal(0)
  })

  // ---------------------------------------------------------------- (c) isolation
  it('(c) cross-asset isolation: an ETH-note root is unknown in an ERC20 tree', async function () {
    const { vault, usdgAssetId, encryptionKey, keypair } = await loadFixture(fixture)
    const ethTree = createEmptyTree()

    const depositUtxo = new Utxo({ amount: ethers.utils.parseEther('0.1'), keypair, mintAddress: NATIVE_ASSET_ID })
    await vaultTransact({ vault, assetId: NATIVE_ASSET_ID, token: null, tree: ethTree, outputs: [depositUtxo], encryptionKey })

    const { args, extData } = await prepareTransaction({
      tree: ethTree, inputs: [depositUtxo], outputs: [], recipient: BOB, encryptionKey,
    })
    await expect(
      vault.transact(usdgAssetId, args, extData, { gasLimit: 3_000_000 }),
    ).to.be.revertedWith('Invalid merkle root')
  })

  // ---------------------------------------------------------------- (h) Poseidon-4
  it('(h) on-chain Poseidon-4 equals the circomlibjs/poseidon-lite reference', async function () {
    const { vault, hasher4 } = await loadFixture(fixture)
    const cases = [
      [0n, 0n, 0n, 0n],
      [1n, 2n, 3n, 4n],
      [123456789n, 987654321n, 555n, BigInt(BigNumber.from('0x' + 'ab'.repeat(20)).toString())],
    ]
    for (const vals of cases) {
      const arg = vals.map((v) => ethers.utils.hexZeroPad(BigNumber.from(v).toHexString(), 32))
      const onchainVault = await vault.poseidon4(arg[0], arg[1], arg[2], arg[3])
      const onchainHasher = await hasher4['poseidon(bytes32[4])'](arg)
      const ref = poseidon4(vals).toString()
      expect(BigNumber.from(onchainVault).toString()).to.equal(ref)
      expect(BigNumber.from(onchainHasher).toString()).to.equal(ref)
    }
  })

  // ---------------------------------------------------------------- (d) swap ETH->token (v2)
  it('(d) MOCK v2: swap ETH-note -> MEME-note, then withdraw the MEME note (real proof)', async function () {
    const { vault, meme, memeAssetId, weth, v2, encryptionKey, keypair } = await loadFixture(fixture)
    const ethTree = createEmptyTree()
    const memeTree = createEmptyTree()

    await v2.setPrice(weth.address, meme.address, ethers.utils.parseUnits('3000', 18))
    await meme.mint(v2.address, ethers.utils.parseUnits('1000000', 18))

    const depositAmount = ethers.utils.parseEther('0.1')
    const depositUtxo = new Utxo({ amount: depositAmount, keypair, mintAddress: NATIVE_ASSET_ID })
    await vaultTransact({ vault, assetId: NATIVE_ASSET_ID, token: null, tree: ethTree, outputs: [depositUtxo], encryptionKey })

    const expectedOut = depositAmount.mul(3000)
    const outNote = new Utxo({ amount: expectedOut, keypair, mintAddress: memeAssetId })
    const routeData = ethers.utils.defaultAbiCoder.encode(['address[]'], [[weth.address, meme.address]])
    const { args, extData, params } = await buildSwap({
      vault, tree: ethTree, assetIn: NATIVE_ASSET_ID, inputUtxo: depositUtxo,
      keypair, encryptionKey, tokenOut: meme.address, version: 0, routeData, minOut: expectedOut, outNote,
    })

    await expect(vault.executeSwap(args, extData, params, { gasLimit: 5_000_000 })).to.emit(vault, 'Swap')
    expect(await meme.balanceOf(vault.address)).to.equal(expectedOut)
    expect(await ethers.provider.getBalance(vault.address)).to.equal(0)

    memeTree.insert(toFixedHex(outNote.getCommitment()))
    memeTree.insert(emptyLeafCommit(keypair, memeAssetId))

    await vaultTransact({
      vault, assetId: memeAssetId, token: meme, tree: memeTree,
      inputs: [outNote], outputs: [], recipient: BOB, encryptionKey,
    })
    expect(await meme.balanceOf(BOB)).to.equal(expectedOut)
    expect(await meme.balanceOf(vault.address)).to.equal(0)
  })

  // ------------------------------------------------ (d-auto) auto-register on first swap
  it('(d-auto) swap into an UNregistered token auto-registers its tree and emits TokenRegistered', async function () {
    const { vault, admin, weth, v2, encryptionKey, keypair } = await loadFixture(fixture)
    const ethTree = createEmptyTree()

    // A brand-new token the admin has NEVER registered.
    const fresh = await deploy('MockERC20')
    const freshAssetId = BigNumber.from(fresh.address)
    expect(await vault.assetRegistered(freshAssetId)).to.equal(false)

    await v2.setPrice(weth.address, fresh.address, ethers.utils.parseUnits('1000', 18))
    await fresh.mint(v2.address, ethers.utils.parseUnits('1000000', 18))

    const depositAmount = ethers.utils.parseEther('0.1')
    const depositUtxo = new Utxo({ amount: depositAmount, keypair, mintAddress: NATIVE_ASSET_ID })
    await vaultTransact({ vault, assetId: NATIVE_ASSET_ID, token: null, tree: ethTree, outputs: [depositUtxo], encryptionKey })

    const expectedOut = depositAmount.mul(1000)
    const outNote = new Utxo({ amount: expectedOut, keypair, mintAddress: freshAssetId })
    const routeData = ethers.utils.defaultAbiCoder.encode(['address[]'], [[weth.address, fresh.address]])
    const { args, extData, params } = await buildSwap({
      vault, tree: ethTree, assetIn: NATIVE_ASSET_ID, inputUtxo: depositUtxo,
      keypair, encryptionKey, tokenOut: fresh.address, version: 0, routeData, minOut: expectedOut, outNote,
    })

    // The swap both registers the token (tree init) and emits Swap — no prior admin call.
    await expect(vault.executeSwap(args, extData, params, { gasLimit: 5_000_000 }))
      .to.emit(vault, 'TokenRegistered').withArgs(freshAssetId, fresh.address)
      .and.to.emit(vault, 'Swap')

    expect(await vault.assetRegistered(freshAssetId)).to.equal(true)
    expect(await vault.assetToken(freshAssetId)).to.equal(fresh.address)
    expect(await fresh.balanceOf(vault.address)).to.equal(expectedOut)

    // And the freshly-created tree is fully usable: withdraw the output note.
    const freshTree = createEmptyTree()
    freshTree.insert(toFixedHex(outNote.getCommitment()))
    freshTree.insert(emptyLeafCommit(keypair, freshAssetId))
    await vaultTransact({
      vault, assetId: freshAssetId, token: fresh, tree: freshTree,
      inputs: [outNote], outputs: [], recipient: BOB, encryptionKey,
    })
    expect(await fresh.balanceOf(BOB)).to.equal(expectedOut)

    // registerToken stays admin-only and now rejects the already-(auto)-registered token.
    await expect(vault.connect(admin).registerToken(fresh.address)).to.be.revertedWith('already registered')
  })

  // ---------------------------------------------------------------- (d') swap ETH->token (v3)
  it("(d') MOCK v3: swap ETH-note -> MEME-note via exactInputSingle", async function () {
    const { vault, meme, memeAssetId, weth, v3, encryptionKey, keypair } = await loadFixture(fixture)
    const ethTree = createEmptyTree()
    const memeTree = createEmptyTree()

    await v3.setPrice(weth.address, meme.address, ethers.utils.parseUnits('2500', 18))
    await meme.mint(v3.address, ethers.utils.parseUnits('1000000', 18))

    const depositAmount = ethers.utils.parseEther('0.2')
    const depositUtxo = new Utxo({ amount: depositAmount, keypair, mintAddress: NATIVE_ASSET_ID })
    await vaultTransact({ vault, assetId: NATIVE_ASSET_ID, token: null, tree: ethTree, outputs: [depositUtxo], encryptionKey })

    const expectedOut = depositAmount.mul(2500)
    const outNote = new Utxo({ amount: expectedOut, keypair, mintAddress: memeAssetId })
    const routeData = ethers.utils.defaultAbiCoder.encode(['address', 'address', 'uint24'], [weth.address, meme.address, 3000])
    const { args, extData, params } = await buildSwap({
      vault, tree: ethTree, assetIn: NATIVE_ASSET_ID, inputUtxo: depositUtxo,
      keypair, encryptionKey, tokenOut: meme.address, version: 1, routeData, minOut: expectedOut, outNote,
    })
    await expect(vault.executeSwap(args, extData, params, { gasLimit: 5_000_000 })).to.emit(vault, 'Swap')
    expect(await meme.balanceOf(vault.address)).to.equal(expectedOut)

    memeTree.insert(toFixedHex(outNote.getCommitment()))
    memeTree.insert(emptyLeafCommit(keypair, memeAssetId))
    await vaultTransact({
      vault, assetId: memeAssetId, token: meme, tree: memeTree,
      inputs: [outNote], outputs: [], recipient: BOB, encryptionKey,
    })
    expect(await meme.balanceOf(BOB)).to.equal(expectedOut)
  })

  // ---------------------------------------------------------------- (e) re-swap back token -> ETH
  it('(e) MOCK v2: re-swap MEME-note -> ETH-note, then withdraw the ETH note', async function () {
    const { vault, meme, memeAssetId, weth, v2, encryptionKey, keypair } = await loadFixture(fixture)
    const [deployer] = await ethers.getSigners()
    const memeTree = createEmptyTree()
    const ethTree = createEmptyTree()

    const memeAmount = ethers.utils.parseUnits('300', 18)
    await meme.mint(deployer.address, memeAmount)
    const memeUtxo = new Utxo({ amount: memeAmount, keypair, mintAddress: memeAssetId })
    await vaultTransact({ vault, assetId: memeAssetId, token: meme, tree: memeTree, outputs: [memeUtxo], encryptionKey })

    // price so 300 MEME -> 0.1 WETH
    const PRICE = ethers.utils.parseEther('0.1').mul(BigNumber.from(10).pow(18)).div(memeAmount)
    await v2.setPrice(meme.address, weth.address, PRICE)
    await weth.deposit({ value: ethers.utils.parseEther('10') })
    await weth.transfer(v2.address, ethers.utils.parseEther('10'))

    const expectedEth = memeAmount.mul(PRICE).div(BigNumber.from(10).pow(18))
    const outNote = new Utxo({ amount: expectedEth, keypair, mintAddress: NATIVE_ASSET_ID })
    const routeData = ethers.utils.defaultAbiCoder.encode(['address[]'], [[meme.address, weth.address]])
    const { args, extData, params } = await buildSwap({
      vault, tree: memeTree, assetIn: memeAssetId, inputUtxo: memeUtxo,
      keypair, encryptionKey, tokenOut: ethers.constants.AddressZero, version: 0, routeData, minOut: expectedEth, outNote,
    })
    await expect(vault.executeSwap(args, extData, params, { gasLimit: 5_000_000 })).to.emit(vault, 'Swap')
    expect(await ethers.provider.getBalance(vault.address)).to.equal(expectedEth)

    ethTree.insert(toFixedHex(outNote.getCommitment()))
    ethTree.insert(emptyLeafCommit(keypair, NATIVE_ASSET_ID))
    const before = await ethers.provider.getBalance(BOB)
    await vaultTransact({
      vault, assetId: NATIVE_ASSET_ID, token: null, tree: ethTree,
      inputs: [outNote], outputs: [], recipient: BOB, encryptionKey,
    })
    expect((await ethers.provider.getBalance(BOB)).sub(before)).to.equal(expectedEth)
  })

  // ---------------------------------------------------------------- (f) router whitelist revert
  it('(f) swap reverts when router not whitelisted (allowlist enforced at the VAULT)', async function () {
    const { vault, admin, meme, memeAssetId, weth, v2, encryptionKey, keypair } = await loadFixture(fixture)
    const ethTree = createEmptyTree()

    await vault.connect(admin).disableRouter(0, v2.address)

    const depositAmount = ethers.utils.parseEther('0.1')
    const depositUtxo = new Utxo({ amount: depositAmount, keypair, mintAddress: NATIVE_ASSET_ID })
    await vaultTransact({ vault, assetId: NATIVE_ASSET_ID, token: null, tree: ethTree, outputs: [depositUtxo], encryptionKey })

    const outNote = new Utxo({ amount: depositAmount.mul(3000), keypair, mintAddress: memeAssetId })
    const routeData = ethers.utils.defaultAbiCoder.encode(['address[]'], [[weth.address, meme.address]])
    const { args, extData, params } = await buildSwap({
      vault, tree: ethTree, assetIn: NATIVE_ASSET_ID, inputUtxo: depositUtxo,
      keypair, encryptionKey, tokenOut: meme.address, version: 0, routeData, minOut: 0, outNote,
    })
    await expect(vault.executeSwap(args, extData, params, { gasLimit: 5_000_000 })).to.be.revertedWith('router not whitelisted')
  })

  // ---------------------------------------------------------------- (g) minOut revert
  it('(g) swap reverts (whole tx) when output < minOut; input note not consumed', async function () {
    const { vault, meme, memeAssetId, weth, v2, encryptionKey, keypair } = await loadFixture(fixture)
    const ethTree = createEmptyTree()

    await v2.setPrice(weth.address, meme.address, ethers.utils.parseUnits('3000', 18))
    await meme.mint(v2.address, ethers.utils.parseUnits('1000000', 18))

    const depositAmount = ethers.utils.parseEther('0.1')
    const depositUtxo = new Utxo({ amount: depositAmount, keypair, mintAddress: NATIVE_ASSET_ID })
    await vaultTransact({ vault, assetId: NATIVE_ASSET_ID, token: null, tree: ethTree, outputs: [depositUtxo], encryptionKey })

    const realOut = depositAmount.mul(3000)
    const outNote = new Utxo({ amount: realOut, keypair, mintAddress: memeAssetId })
    const routeData = ethers.utils.defaultAbiCoder.encode(['address[]'], [[weth.address, meme.address]])
    const { args, extData, params } = await buildSwap({
      vault, tree: ethTree, assetIn: NATIVE_ASSET_ID, inputUtxo: depositUtxo,
      keypair, encryptionKey, tokenOut: meme.address, version: 0, routeData, minOut: realOut.add(1), outNote,
    })
    await expect(vault.executeSwap(args, extData, params, { gasLimit: 5_000_000 })).to.be.reverted
    expect(await ethers.provider.getBalance(vault.address)).to.equal(depositAmount)
    expect(await vault.isSpent(args.inputNullifiers[0])).to.equal(false)
  })

  // ------------------------------------------------- (i) swap params are proof-bound
  // Without extData.swapParamsHash, SwapParams is unauthenticated: the relayer (or any
  // searcher front-running the mempool) can replay a victim's proof verbatim while
  // substituting its own p, nullifying the victim's note and taking the proceeds.
  describe('(i) SwapParams are bound to the proof', function () {
    async function victimSwap() {
      const f = await loadFixture(fixture)
      const { vault, meme, memeAssetId, weth, v2, encryptionKey, keypair } = f
      const ethTree = createEmptyTree()
      await v2.setPrice(weth.address, meme.address, ethers.utils.parseUnits('3000', 18))
      await meme.mint(v2.address, ethers.utils.parseUnits('1000000', 18))

      const depositAmount = ethers.utils.parseEther('0.1')
      const depositUtxo = new Utxo({ amount: depositAmount, keypair, mintAddress: NATIVE_ASSET_ID })
      await vaultTransact({ vault, assetId: NATIVE_ASSET_ID, token: null, tree: ethTree, outputs: [depositUtxo], encryptionKey })

      const expectedOut = depositAmount.mul(3000)
      const outNote = new Utxo({ amount: expectedOut, keypair, mintAddress: memeAssetId })
      const routeData = ethers.utils.defaultAbiCoder.encode(['address[]'], [[weth.address, meme.address]])
      const built = await buildSwap({
        vault, tree: ethTree, assetIn: NATIVE_ASSET_ID, inputUtxo: depositUtxo,
        keypair, encryptionKey, tokenOut: meme.address, version: 0, routeData, minOut: expectedOut, outNote,
      })
      return { ...f, ...built, depositAmount, expectedOut }
    }

    it('rejects a relayer substituting its own output pubkey (proceeds theft)', async function () {
      const { vault, args, extData, params, depositAmount } = await victimSwap()
      const attacker = new Utxo({ mintAddress: BigNumber.from(1) })
      const stolen = { ...params, outPubkey: toFixedHex(attacker.keypair.pubkey), outBlinding: toFixedHex(attacker.blinding) }
      await expect(vault.executeSwap(args, extData, stolen, { gasLimit: 5_000_000 })).to.be.revertedWith('swap params tampered')
      // The victim's note survives: nothing was nullified, funds are still in the vault.
      expect(await vault.isSpent(args.inputNullifiers[0])).to.equal(false)
      expect(await ethers.provider.getBalance(vault.address)).to.equal(depositAmount)
    })

    it('rejects stripping the slippage floor (minOut -> 0)', async function () {
      const { vault, args, extData, params } = await victimSwap()
      await expect(
        vault.executeSwap(args, extData, { ...params, minOut: 0 }, { gasLimit: 5_000_000 }),
      ).to.be.revertedWith('swap params tampered')
    })

    it('rejects rerouting through different routeData', async function () {
      const { vault, args, extData, params, weth, meme } = await victimSwap()
      const evil = ethers.utils.defaultAbiCoder.encode(['address[]'], [[weth.address, meme.address, weth.address]])
      await expect(
        vault.executeSwap(args, extData, { ...params, routeData: evil }, { gasLimit: 5_000_000 }),
      ).to.be.revertedWith('swap params tampered')
    })

    it('rejects garbling the encrypted output (unspendable-note grief)', async function () {
      const { vault, args, extData, params } = await victimSwap()
      await expect(
        vault.executeSwap(args, extData, { ...params, encryptedOutput: '0xdeadbeef' }, { gasLimit: 5_000_000 }),
      ).to.be.revertedWith('swap params tampered')
    })

    it('honest params still pass, and transact rejects a non-zero swapParamsHash', async function () {
      const { vault, args, extData, params } = await victimSwap()
      await expect(vault.executeSwap(args, extData, params, { gasLimit: 5_000_000 })).to.emit(vault, 'Swap')
      // Domain separation: a swap-bound extData must not be usable on the transact path.
      await expect(
        vault.transact(NATIVE_ASSET_ID, args, extData, { gasLimit: 3_000_000 }),
      ).to.be.revertedWith('swapParamsHash must be zero')
    })
  })

  // ---------------------------------------------------------------- admin / access
  it('registerToken and swaplogic/router config are admin-only', async function () {
    const { vault, alice, swapLogic, meme, v2 } = await loadFixture(fixture)
    await expect(vault.connect(alice).registerToken(meme.address)).to.be.revertedWith('only admin')
    await expect(vault.connect(alice).proposeSwapLogic(swapLogic.address)).to.be.revertedWith('only admin')
    await expect(vault.connect(alice).proposeRouter(0, v2.address)).to.be.revertedWith('only admin')
    await expect(vault.connect(alice).enableRouter(0, v2.address)).to.be.revertedWith('only admin')
  })

  // ================================================================
  //                       PROTOCOL FEE TESTS
  // ================================================================

  it('FEE-1: withdraw charges the protocol fee in the withdrawn asset (ETH)', async function () {
    const { vault, admin, encryptionKey, keypair } = await loadFixture(fixture)
    const collector = (await ethers.getSigners())[5]
    await vault.connect(admin).setProtocolFeeRecipient(collector.address)
    await vault.connect(admin).setProtocolFee(100) // 1%

    const tree = createEmptyTree()
    const depositAmount = ethers.utils.parseEther('0.1')
    const depositUtxo = new Utxo({ amount: depositAmount, keypair, mintAddress: NATIVE_ASSET_ID })
    await vaultTransact({ vault, assetId: NATIVE_ASSET_ID, token: null, tree, outputs: [depositUtxo], encryptionKey })

    const withdrawAmount = ethers.utils.parseEther('0.06')
    const fee = withdrawAmount.mul(100).div(10000)
    const net = withdrawAmount.sub(fee)
    const feeBefore = await ethers.provider.getBalance(collector.address)
    const change = new Utxo({ amount: depositAmount.sub(withdrawAmount), keypair, mintAddress: NATIVE_ASSET_ID })
    await vaultTransact({
      vault, assetId: NATIVE_ASSET_ID, token: null, tree,
      inputs: [depositUtxo], outputs: [change], recipient: BOB, encryptionKey,
    })
    expect(await ethers.provider.getBalance(BOB)).to.equal(net)
    expect((await ethers.provider.getBalance(collector.address)).sub(feeBefore)).to.equal(fee)
  })

  it('FEE-2: withdraw charges the protocol fee in the withdrawn asset (ERC20)', async function () {
    const { vault, admin, usdg, usdgAssetId, encryptionKey, keypair } = await loadFixture(fixture)
    const [deployer] = await ethers.getSigners()
    const collector = (await ethers.getSigners())[5]
    await vault.connect(admin).setProtocolFeeRecipient(collector.address)
    await vault.connect(admin).setProtocolFee(250) // 2.5%

    const tree = createEmptyTree()
    const amount = BigNumber.from(1000)
    await usdg.mint(deployer.address, amount)
    const depositUtxo = new Utxo({ amount, keypair, mintAddress: usdgAssetId })
    await vaultTransact({ vault, assetId: usdgAssetId, token: usdg, tree, outputs: [depositUtxo], encryptionKey })

    const fee = amount.mul(250).div(10000) // 25
    await vaultTransact({
      vault, assetId: usdgAssetId, token: usdg, tree,
      inputs: [depositUtxo], outputs: [], recipient: BOB, encryptionKey,
    })
    expect(await usdg.balanceOf(BOB)).to.equal(amount.sub(fee))
    expect(await usdg.balanceOf(collector.address)).to.equal(fee)
  })

  it('FEE-3: swap ETH->token takes the fee in ETH from the INPUT, before swapping', async function () {
    const { vault, admin, meme, memeAssetId, weth, v2, encryptionKey, keypair } = await loadFixture(fixture)
    const collector = (await ethers.getSigners())[5]
    await vault.connect(admin).setProtocolFeeRecipient(collector.address)
    await vault.connect(admin).setProtocolFee(100) // 1%

    const ethTree = createEmptyTree()
    const memeTree = createEmptyTree()
    await v2.setPrice(weth.address, meme.address, ethers.utils.parseUnits('3000', 18))
    await meme.mint(v2.address, ethers.utils.parseUnits('1000000', 18))

    const depositAmount = ethers.utils.parseEther('0.1')
    const depositUtxo = new Utxo({ amount: depositAmount, keypair, mintAddress: NATIVE_ASSET_ID })
    await vaultTransact({ vault, assetId: NATIVE_ASSET_ID, token: null, tree: ethTree, outputs: [depositUtxo], encryptionKey })

    const feeIn = depositAmount.mul(100).div(10000) // 0.001 ETH
    const swapIn = depositAmount.sub(feeIn) // 0.099 ETH
    const expectedOut = swapIn.mul(3000)
    const outNote = new Utxo({ amount: expectedOut, keypair, mintAddress: memeAssetId })
    const routeData = ethers.utils.defaultAbiCoder.encode(['address[]'], [[weth.address, meme.address]])
    const feeBefore = await ethers.provider.getBalance(collector.address)
    const { args, extData, params } = await buildSwap({
      vault, tree: ethTree, assetIn: NATIVE_ASSET_ID, inputUtxo: depositUtxo,
      keypair, encryptionKey, tokenOut: meme.address, version: 0, routeData, minOut: expectedOut, outNote,
    })
    await expect(vault.executeSwap(args, extData, params, { gasLimit: 5_000_000 })).to.emit(vault, 'Swap')
    expect((await ethers.provider.getBalance(collector.address)).sub(feeBefore)).to.equal(feeIn)
    expect(await meme.balanceOf(vault.address)).to.equal(expectedOut)
    expect(await ethers.provider.getBalance(vault.address)).to.equal(0)

    memeTree.insert(toFixedHex(outNote.getCommitment()))
    memeTree.insert(emptyLeafCommit(keypair, memeAssetId))
    await vault.connect(admin).setProtocolFee(0) // isolate: the verify-withdraw is fee-free
    await vaultTransact({
      vault, assetId: memeAssetId, token: meme, tree: memeTree,
      inputs: [outNote], outputs: [], recipient: BOB, encryptionKey,
    })
    expect(await meme.balanceOf(BOB)).to.equal(expectedOut)
  })

  it('FEE-4: swap token->ETH takes the fee in ETH from the PROCEEDS, before minting the note', async function () {
    const { vault, admin, meme, memeAssetId, weth, v2, encryptionKey, keypair } = await loadFixture(fixture)
    const [deployer] = await ethers.getSigners()
    const collector = (await ethers.getSigners())[5]
    await vault.connect(admin).setProtocolFeeRecipient(collector.address)
    await vault.connect(admin).setProtocolFee(100) // 1%

    const memeTree = createEmptyTree()
    const ethTree = createEmptyTree()
    const memeAmount = ethers.utils.parseUnits('300', 18)
    await meme.mint(deployer.address, memeAmount)
    const memeUtxo = new Utxo({ amount: memeAmount, keypair, mintAddress: memeAssetId })
    await vaultTransact({ vault, assetId: memeAssetId, token: meme, tree: memeTree, outputs: [memeUtxo], encryptionKey })

    const PRICE = ethers.utils.parseEther('0.1').mul(BigNumber.from(10).pow(18)).div(memeAmount)
    await v2.setPrice(meme.address, weth.address, PRICE)
    await weth.deposit({ value: ethers.utils.parseEther('10') })
    await weth.transfer(v2.address, ethers.utils.parseEther('10'))

    const grossEth = memeAmount.mul(PRICE).div(BigNumber.from(10).pow(18)) // 0.1 ETH
    const feeOut = grossEth.mul(100).div(10000) // 0.001 ETH
    const netEth = grossEth.sub(feeOut)
    const outNote = new Utxo({ amount: netEth, keypair, mintAddress: NATIVE_ASSET_ID })
    const routeData = ethers.utils.defaultAbiCoder.encode(['address[]'], [[meme.address, weth.address]])
    const feeBefore = await ethers.provider.getBalance(collector.address)
    const { args, extData, params } = await buildSwap({
      vault, tree: memeTree, assetIn: memeAssetId, inputUtxo: memeUtxo,
      keypair, encryptionKey, tokenOut: ethers.constants.AddressZero, version: 0, routeData, minOut: netEth, outNote,
    })
    await expect(vault.executeSwap(args, extData, params, { gasLimit: 5_000_000 })).to.emit(vault, 'Swap')
    expect((await ethers.provider.getBalance(collector.address)).sub(feeBefore)).to.equal(feeOut)
    expect(await ethers.provider.getBalance(vault.address)).to.equal(netEth)

    ethTree.insert(toFixedHex(outNote.getCommitment()))
    ethTree.insert(emptyLeafCommit(keypair, NATIVE_ASSET_ID))
    await vault.connect(admin).setProtocolFee(0) // isolate: the verify-withdraw is fee-free
    const before = await ethers.provider.getBalance(BOB)
    await vaultTransact({
      vault, assetId: NATIVE_ASSET_ID, token: null, tree: ethTree,
      inputs: [outNote], outputs: [], recipient: BOB, encryptionKey,
    })
    expect((await ethers.provider.getBalance(BOB)).sub(before)).to.equal(netEth)
  })

  it('FEE-5: protocol fee is admin-only, capped, requires a recipient, and is changeable', async function () {
    const { vault, admin, alice } = await loadFixture(fixture)
    const collector = (await ethers.getSigners())[5]
    // admin-only
    await expect(vault.connect(alice).setProtocolFee(100)).to.be.revertedWith('only admin')
    await expect(vault.connect(alice).setProtocolFeeRecipient(collector.address)).to.be.revertedWith('only admin')
    // cannot enable a fee with no recipient set
    await expect(vault.connect(admin).setProtocolFee(100)).to.be.revertedWith('recipient unset')
    await vault.connect(admin).setProtocolFeeRecipient(collector.address)
    // capped at MAX_PROTOCOL_FEE_BPS (1000)
    await expect(vault.connect(admin).setProtocolFee(1001)).to.be.revertedWith('fee too high')
    // changeable
    await vault.connect(admin).setProtocolFee(1000)
    expect(await vault.protocolFeeBps()).to.equal(1000)
    await vault.connect(admin).setProtocolFee(50)
    expect(await vault.protocolFeeBps()).to.equal(50)
    await vault.connect(admin).setProtocolFee(0)
    expect(await vault.protocolFeeBps()).to.equal(0)
  })

  it('FEE-6: swap USDG->token takes the fee in USDG from the INPUT (USDG is a base asset)', async function () {
    const { vault, admin, usdg, usdgAssetId, meme, memeAssetId, v2, encryptionKey, keypair } = await loadFixture(fixture)
    const [deployer] = await ethers.getSigners()
    const collector = (await ethers.getSigners())[5]
    await vault.connect(admin).setProtocolFeeRecipient(collector.address)
    await vault.connect(admin).setProtocolFee(100) // 1%
    await vault.connect(admin).setFeeAsset(usdg.address, true) // treat USDG like ETH

    const usdgTree = createEmptyTree()
    const memeTree = createEmptyTree()
    await v2.setPrice(usdg.address, meme.address, ethers.utils.parseUnits('2', 18))
    await meme.mint(v2.address, ethers.utils.parseUnits('1000000', 18))

    const amount = ethers.utils.parseUnits('1000', 18)
    await usdg.mint(deployer.address, amount)
    const depositUtxo = new Utxo({ amount, keypair, mintAddress: usdgAssetId })
    await vaultTransact({ vault, assetId: usdgAssetId, token: usdg, tree: usdgTree, outputs: [depositUtxo], encryptionKey })

    const feeIn = amount.mul(100).div(10000) // 10 USDG
    const swapIn = amount.sub(feeIn) // 990 USDG
    const expectedOut = swapIn.mul(2)
    const outNote = new Utxo({ amount: expectedOut, keypair, mintAddress: memeAssetId })
    const routeData = ethers.utils.defaultAbiCoder.encode(['address[]'], [[usdg.address, meme.address]])
    const { args, extData, params } = await buildSwap({
      vault, tree: usdgTree, assetIn: usdgAssetId, inputUtxo: depositUtxo,
      keypair, encryptionKey, tokenOut: meme.address, version: 0, routeData, minOut: expectedOut, outNote,
    })
    await expect(vault.executeSwap(args, extData, params, { gasLimit: 5_000_000 })).to.emit(vault, 'Swap')
    expect(await usdg.balanceOf(collector.address)).to.equal(feeIn)
    expect(await meme.balanceOf(vault.address)).to.equal(expectedOut)

    memeTree.insert(toFixedHex(outNote.getCommitment()))
    memeTree.insert(emptyLeafCommit(keypair, memeAssetId))
    await vault.connect(admin).setProtocolFee(0)
    await vaultTransact({
      vault, assetId: memeAssetId, token: meme, tree: memeTree,
      inputs: [outNote], outputs: [], recipient: BOB, encryptionKey,
    })
    expect(await meme.balanceOf(BOB)).to.equal(expectedOut)
  })

  it('FEE-7: swap token->USDG takes the fee in USDG from the PROCEEDS (USDG is a base asset)', async function () {
    const { vault, admin, usdg, usdgAssetId, meme, memeAssetId, v2, encryptionKey, keypair } = await loadFixture(fixture)
    const [deployer] = await ethers.getSigners()
    const collector = (await ethers.getSigners())[5]
    await vault.connect(admin).setProtocolFeeRecipient(collector.address)
    await vault.connect(admin).setProtocolFee(100) // 1%
    await vault.connect(admin).setFeeAsset(usdg.address, true)

    const memeTree = createEmptyTree()
    const usdgTree = createEmptyTree()
    const memeAmount = ethers.utils.parseUnits('300', 18)
    await meme.mint(deployer.address, memeAmount)
    const memeUtxo = new Utxo({ amount: memeAmount, keypair, mintAddress: memeAssetId })
    await vaultTransact({ vault, assetId: memeAssetId, token: meme, tree: memeTree, outputs: [memeUtxo], encryptionKey })

    await v2.setPrice(meme.address, usdg.address, ethers.utils.parseUnits('1', 18)) // 300 MEME -> 300 USDG
    await usdg.mint(v2.address, ethers.utils.parseUnits('1000000', 18))

    const grossUsdg = memeAmount.mul(1)
    const feeOut = grossUsdg.mul(100).div(10000) // 3 USDG
    const netUsdg = grossUsdg.sub(feeOut) // 297 USDG
    const outNote = new Utxo({ amount: netUsdg, keypair, mintAddress: usdgAssetId })
    const routeData = ethers.utils.defaultAbiCoder.encode(['address[]'], [[meme.address, usdg.address]])
    const { args, extData, params } = await buildSwap({
      vault, tree: memeTree, assetIn: memeAssetId, inputUtxo: memeUtxo,
      keypair, encryptionKey, tokenOut: usdg.address, version: 0, routeData, minOut: netUsdg, outNote,
    })
    await expect(vault.executeSwap(args, extData, params, { gasLimit: 5_000_000 })).to.emit(vault, 'Swap')
    expect(await usdg.balanceOf(collector.address)).to.equal(feeOut)
    expect(await usdg.balanceOf(vault.address)).to.equal(netUsdg)

    usdgTree.insert(toFixedHex(outNote.getCommitment()))
    usdgTree.insert(emptyLeafCommit(keypair, usdgAssetId))
    await vault.connect(admin).setProtocolFee(0)
    await vaultTransact({
      vault, assetId: usdgAssetId, token: usdg, tree: usdgTree,
      inputs: [outNote], outputs: [], recipient: BOB, encryptionKey,
    })
    expect(await usdg.balanceOf(BOB)).to.equal(netUsdg)
  })

  // ================================================================
  //                   SECURITY-MODEL TESTS (rug-proof split)
  // ================================================================

  // ---- SEC-1: end-to-end swap through the deployed vault + UUPS logic (baseline).
  it('SEC-1: vault + UUPS SwapLogic perform a swap end-to-end', async function () {
    const { vault, swapLogic, meme, memeAssetId, weth, v2, encryptionKey, keypair } = await loadFixture(fixture)
    // Sanity: logic really is a proxy with a version, and vault points at it.
    expect(await vault.swapLogic()).to.equal(swapLogic.address)
    expect((await swapLogic.logicVersion()).toNumber()).to.equal(1)

    const ethTree = createEmptyTree()
    await v2.setPrice(weth.address, meme.address, ethers.utils.parseUnits('3000', 18))
    await meme.mint(v2.address, ethers.utils.parseUnits('1000000', 18))

    const depositAmount = ethers.utils.parseEther('0.1')
    const depositUtxo = new Utxo({ amount: depositAmount, keypair, mintAddress: NATIVE_ASSET_ID })
    await vaultTransact({ vault, assetId: NATIVE_ASSET_ID, token: null, tree: ethTree, outputs: [depositUtxo], encryptionKey })

    const expectedOut = depositAmount.mul(3000)
    const outNote = new Utxo({ amount: expectedOut, keypair, mintAddress: memeAssetId })
    const routeData = ethers.utils.defaultAbiCoder.encode(['address[]'], [[weth.address, meme.address]])
    const { args, extData, params } = await buildSwap({
      vault, tree: ethTree, assetIn: NATIVE_ASSET_ID, inputUtxo: depositUtxo,
      keypair, encryptionKey, tokenOut: meme.address, version: 0, routeData, minOut: expectedOut, outNote,
    })
    await expect(vault.executeSwap(args, extData, params, { gasLimit: 5_000_000 })).to.emit(vault, 'Swap')
    expect(await meme.balanceOf(vault.address)).to.equal(expectedOut)
  })

  // ---- SEC-2: MALICIOUS SwapLogic upgrade CANNOT drain idle vault TVL.
  it('SEC-2: malicious SwapLogic upgrade cannot drain idle vault TVL; drain reverts', async function () {
    const { vault, admin, swapLogic, usdg, usdgAssetId, meme, memeAssetId, weth, encryptionKey, keypair } = await loadFixture(fixture)

    // Seed the vault with idle TVL of MULTIPLE assets that must never move via an upgrade.
    const ethTree = createEmptyTree()
    const idleEth = ethers.utils.parseEther('5')
    const idleEthUtxo = new Utxo({ amount: idleEth, keypair, mintAddress: NATIVE_ASSET_ID })
    await vaultTransact({ vault, assetId: NATIVE_ASSET_ID, token: null, tree: ethTree, outputs: [idleEthUtxo], encryptionKey })

    const [deployer] = await ethers.getSigners()
    const idleUsdg = BigNumber.from(1_000_000)
    await usdg.mint(deployer.address, idleUsdg)
    const usdgTree = createEmptyTree()
    const idleUsdgUtxo = new Utxo({ amount: idleUsdg, keypair, mintAddress: usdgAssetId })
    await vaultTransact({ vault, assetId: usdgAssetId, token: usdg, tree: usdgTree, outputs: [idleUsdgUtxo], encryptionKey })

    const ethBefore = await ethers.provider.getBalance(vault.address)
    const usdgBefore = await usdg.balanceOf(vault.address)
    expect(ethBefore).to.equal(idleEth)
    expect(usdgBefore).to.equal(idleUsdg)

    // ---- UPGRADE SwapLogic to the hostile implementation via UUPS ----
    const Mal = await ethers.getContractFactory('MaliciousSwapLogicMock')
    const malImpl = await Mal.deploy()
    await malImpl.deployed()
    // upgradeToAndCall on the proxy (UUPS). admin authorized.
    await swapLogic.connect(admin).upgradeToAndCall(malImpl.address, '0x')
    const malicious = Mal.attach(swapLogic.address)
    // Confirm the upgrade actually took effect (version signal from the hostile impl).
    expect((await malicious.logicVersion()).toString()).to.equal('667') // stored 1 + 666
    await malicious.connect(admin).setAttacker(admin.address)

    // Now try to run a swap; the malicious logic returns an attacker router + max approval.
    const depositAmount = ethers.utils.parseEther('1') // in-flight amount (part of idle 5 ETH note)
    // Build a swap spending the idle ETH note entirely (must produce a change/out note).
    const outNote = new Utxo({ amount: idleEth.mul(3000), keypair, mintAddress: memeAssetId })
    const routeData = ethers.utils.defaultAbiCoder.encode(['address[]'], [[weth.address, meme.address]])
    const { args, extData, params } = await buildSwap({
      vault, tree: ethTree, assetIn: NATIVE_ASSET_ID, inputUtxo: idleEthUtxo,
      keypair, encryptionKey, tokenOut: meme.address, version: 0, routeData, minOut: 0, outNote,
    })

    // The vault must reject the hostile route (router not on the vault allowlist).
    await expect(vault.executeSwap(args, extData, params, { gasLimit: 5_000_000 })).to.be.revertedWith('router mismatch')

    // CRITICAL INVARIANT: idle TVL is completely untouched by the malicious upgrade.
    expect(await ethers.provider.getBalance(vault.address)).to.equal(ethBefore)
    expect(await usdg.balanceOf(vault.address)).to.equal(usdgBefore)
    // And the input note is NOT consumed (atomic revert).
    expect(await vault.isSpent(args.inputNullifiers[0])).to.equal(false)

    // Even a direct approval the attacker might rely on was never granted.
    expect(await weth.allowance(vault.address, admin.address)).to.equal(0)
    void depositAmount
  })

  // ---- SEC-3: the vault is NOT upgradable (no proxy, no upgrade entrypoint).
  it('SEC-3: SherwoodVault is immutable — no UUPS/proxy upgrade entrypoint exists', async function () {
    const { vault } = await loadFixture(fixture)

    // (i) No upgrade selectors on the vault ABI.
    const fns = Object.keys(vault.interface.functions)
    for (const bad of ['upgradeTo', 'upgradeToAndCall', 'proxiableUUID']) {
      expect(fns.some((f) => f.startsWith(bad + '('))).to.equal(false)
    }

    // (ii) Calling the UUPS selectors on the vault address reverts (no such function / no fallback upgrade).
    const uups = new ethers.utils.Interface([
      'function upgradeToAndCall(address,bytes)',
      'function proxiableUUID() view returns (bytes32)',
    ])
    const [signer] = await ethers.getSigners()
    await expect(
      signer.sendTransaction({ to: vault.address, data: uups.encodeFunctionData('upgradeToAndCall', [signer.address, '0x']) }),
    ).to.be.reverted

    // (iii) The vault is NOT behind an ERC1967 proxy: its ERC1967 impl slot is empty.
    const IMPL_SLOT = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc'
    const slot = await ethers.provider.getStorageAt(vault.address, IMPL_SLOT)
    expect(BigNumber.from(slot)).to.equal(0)
  })

  // ---- SEC-4: router allowlist is enforced at the vault (2-step, no timelock).
  it('SEC-4: router allowlist lives in the vault and is 2-step (propose -> enable, no wait)', async function () {
    const { vault, admin, v2 } = await loadFixture(fixture)
    const fresh = ethers.Wallet.createRandom().address

    // Cannot enable without proposing first (2-step still enforced).
    await expect(vault.connect(admin).enableRouter(2, fresh)).to.be.revertedWith('router timelock')
    expect(await vault.isRouterAllowed(2, fresh)).to.equal(false)

    // Propose, then enable takes effect immediately (CONFIG_TIMELOCK == 0).
    await vault.connect(admin).proposeRouter(2, fresh)
    await vault.connect(admin).enableRouter(2, fresh)
    expect(await vault.isRouterAllowed(2, fresh)).to.equal(true)

    // Disabling is immediate.
    await vault.connect(admin).disableRouter(0, v2.address)
    expect(await vault.isRouterAllowed(0, v2.address)).to.equal(false)
  })

  // ---- SEC-5: SwapLogic pointer change is 2-step (no timelock) at the vault.
  it('SEC-5: SwapLogic pointer is 2-step (propose -> set, no wait) at the vault', async function () {
    const { vault, admin } = await loadFixture(fixture)
    const fresh = ethers.Wallet.createRandom().address

    // Cannot set without a pending proposal (2-step still enforced).
    await expect(vault.connect(admin).setSwapLogic()).to.be.revertedWith('no pending logic')

    // Propose, then set takes effect immediately (CONFIG_TIMELOCK == 0).
    await vault.connect(admin).proposeSwapLogic(fresh)
    await vault.connect(admin).setSwapLogic()
    expect(await vault.swapLogic()).to.equal(fresh)
  })
})
