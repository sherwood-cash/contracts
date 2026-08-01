// Fork-based end-to-end swap test against REAL Uniswap v2 & v3 on an ETH mainnet fork.
//
// This test self-enables forking via hardhat_reset. If the configured RPC cannot
// serve the fork (e.g. public RPCs that reject archive/state requests), the whole
// suite is skipped at runtime so the offline mock suite (robinhoodMixer.test.js)
// remains the source of truth. Run with an archive RPC to exercise it:
//   MAINNET_FORK_RPC=<archive-url> npx hardhat test test/robinhoodMixerFork.test.js
const hre = require('hardhat')
const { ethers } = hre
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

const WETH = '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2'
const USDC = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48'
const V2_ROUTER = '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D'
const V3_ROUTER = '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45'
const RPC = process.env.MAINNET_FORK_RPC || 'https://ethereum-rpc.publicnode.com'

const BOB = ethers.utils.getAddress('0xdead00000000000000000000000000000000beef')

function createEmptyTree() {
  return new MerkleTree(MERKLE_TREE_HEIGHT, [], { hashFunction: poseidonHash2, zeroElement: MERKLE_TREE_ZERO_VALUE })
}
function pubkeyBig(kp) {
  return BigInt(kp.pubkey.toString())
}
function emptyLeafCommit(kp, assetOut) {
  return toFixedHex(BigNumber.from(poseidon4([0n, pubkeyBig(kp), 0n, BigInt(BigNumber.from(assetOut).toString())]).toString()))
}

async function getProof({ inputs, outputs, tree, extAmount, fee, recipient, feeRecipient, encryptionKey, swapParamsHash }) {
  const idxs = []
  const els = []
  for (const input of inputs) {
    if (input.amount.gt(0)) {
      input.index = tree.indexOf(toFixedHex(input.getCommitment()))
      idxs.push(input.index)
      els.push(tree.path(input.index).pathElements)
    } else {
      idxs.push(0)
      els.push(new Array(MERKLE_TREE_HEIGHT).fill(0))
    }
  }
  let n = tree._layers[0].length
  for (const o of outputs) o.index = n++
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
    inPathIndices: idxs,
    inPathElements: els,
    outAmount: outputs.map((x) => x.amount.toString()),
    outBlinding: outputs.map((x) => x.blinding.toString()),
    outPubkey: outputs.map((x) => x.keypair.pubkey.toString()),
  }
  const { pA, pB, pC } = await prove(input, `./build/circuits/transaction${inputs.length}`)
  const args = {
    pA, pB, pC,
    root: toFixedHex(input.root),
    inputNullifiers: inputs.map((x) => toFixedHex(x.getNullifier())),
    outputCommitments: outputs.map((x) => toFixedHex(x.getCommitment())),
    publicAmount: toFixedHex(input.publicAmount),
    extDataHash: toFixedHex(extDataHash),
  }
  return { extData, args, outputs }
}

async function prepareTransaction({ tree, inputs = [], outputs = [], fee = 0, recipient = 0, feeRecipient = 0, encryptionKey, mintAddress, swapParamsHash }) {
  const assetMint = (inputs[0] && inputs[0].mintAddress) || (outputs[0] && outputs[0].mintAddress) || BigNumber.from(mintAddress || 0)
  while (inputs.length < 2) inputs.push(new Utxo({ mintAddress: assetMint }))
  while (outputs.length < 2) outputs.push(new Utxo({ mintAddress: assetMint }))
  const extAmount = BigNumber.from(fee)
    .add(outputs.reduce((s, x) => s.add(x.amount), BigNumber.from(0)))
    .sub(inputs.reduce((s, x) => s.add(x.amount), BigNumber.from(0)))
  return getProof({ inputs, outputs, tree, extAmount, fee, recipient, feeRecipient, encryptionKey, swapParamsHash })
}

async function deploy(name, ...args) {
  const F = await ethers.getContractFactory(name)
  const i = await F.deploy(...args)
  return i.deployed()
}

const CONFIG_TIMELOCK = 2 * 24 * 3600

async function deploySwapLogicProxy(admin) {
  const Logic = await ethers.getContractFactory('SwapLogic')
  const impl = await Logic.deploy()
  await impl.deployed()
  const initData = Logic.interface.encodeFunctionData('initialize', [admin.address])
  const Proxy = await ethers.getContractFactory('ERC1967Proxy')
  const proxy = await Proxy.deploy(impl.address, initData)
  await proxy.deployed()
  return Logic.attach(proxy.address)
}

async function enableRouter(vault, admin, version, router) {
  await vault.connect(admin).proposeRouter(version, router)
  await ethers.provider.send('evm_increaseTime', [CONFIG_TIMELOCK + 1])
  await ethers.provider.send('evm_mine', [])
  await vault.connect(admin).enableRouter(version, router)
}

async function mixerTransact({ mixer, assetId, token, tree, ...rest }) {
  const { args, extData, outputs } = await prepareTransaction({ tree, mintAddress: BigNumber.from(assetId), ...rest })
  const extAmount = BigNumber.from(extData.extAmount)
  const [s] = await ethers.getSigners()
  const overrides = { gasLimit: 5_000_000 }
  if (extAmount.gt(0)) {
    if (token) await token.connect(s).approve(mixer.address, extAmount)
    else overrides.value = extAmount
  }
  await (await mixer.connect(s).transact(assetId, args, extData, overrides)).wait()
  for (const o of outputs) tree.insert(toFixedHex(o.getCommitment()))
  return { args, extData, outputs }
}

describe('RobinhoodMixer FORK (real Uniswap v2/v3 on ETH mainnet fork)', function () {
  this.timeout(300000)
  let forkAvailable = false

  async function resetFork() {
    await hre.network.provider.request({
      method: 'hardhat_reset',
      params: [{ forking: { jsonRpcUrl: RPC } }],
    })
  }

  before(async function () {
    // Probe: can the RPC serve the fork? If not, skip the whole suite.
    try {
      await resetFork()
      const code = await ethers.provider.getCode(WETH)
      forkAvailable = code && code !== '0x'
    } catch (e) {
      // eslint-disable-next-line no-console
      console.log('    [fork] unavailable, skipping fork suite:', e.message.split('\n')[0])
      forkAvailable = false
    }
    if (!forkAvailable) this.skip()
  })

  beforeEach(async function () {
    if (!forkAvailable) this.skip()
    // Fresh fork per test => deterministic, no cross-test state carryover.
    await resetFork()
  })

  after(async function () {
    // Disable forking to not leak into other suites.
    try {
      await hre.network.provider.request({ method: 'hardhat_reset', params: [] })
    } catch (_) {}
  })

  async function setup() {
    require('../scripts/compileHasher')
    const [deployer, admin] = await ethers.getSigners()
    const verifier2 = await deploy('Verifier2')
    const hasher = await deploy('Hasher')
    const hasher4 = await deploy('Hasher4')
    const vault = await deploy('SherwoodVault', verifier2.address, MERKLE_TREE_HEIGHT, hasher.address, hasher4.address, WETH, admin.address)
    const swapLogic = await deploySwapLogicProxy(admin)
    await vault.connect(admin).proposeSwapLogic(swapLogic.address)
    await ethers.provider.send('evm_increaseTime', [CONFIG_TIMELOCK + 1])
    await ethers.provider.send('evm_mine', [])
    await vault.connect(admin).setSwapLogic()
    await vault.connect(admin).registerToken(USDC)
    await enableRouter(vault, admin, 0, V2_ROUTER)
    await enableRouter(vault, admin, 1, V3_ROUTER)
    const usdc = await ethers.getContractAt('@openzeppelin/contracts/token/ERC20/IERC20.sol:IERC20', USDC)
    const { encryptionKey, keypair } = await signIn(deployer)
    return { deployer, admin, mixer: vault, swapLogic, usdc, encryptionKey, keypair, usdcAssetId: BigNumber.from(USDC) }
  }

  async function swapEthToUsdc(version, routeData) {
    const { mixer, usdc, usdcAssetId, encryptionKey, keypair } = await setup()
    const ethTree = createEmptyTree()
    const usdcTree = createEmptyTree()

    const depositAmount = ethers.utils.parseEther('1')
    const depositUtxo = new Utxo({ amount: depositAmount, keypair, mintAddress: NATIVE_ASSET_ID })
    await mixerTransact({ mixer, assetId: NATIVE_ASSET_ID, token: null, tree: ethTree, outputs: [depositUtxo], encryptionKey })

    const deadline = (await ethers.provider.getBlock('latest')).timestamp + 3600
    // We don't know exact Y; use a conservative minOut (>= 1000 USDC for 1 ETH is safe historically).
    const minOut = BigNumber.from(1000).mul(1e6)
    // placeholder out note; real amount is set after we read the Swap event.
    const outNote = new Utxo({ amount: 1, keypair, mintAddress: usdcAssetId })
    const params = {
      assetIn: NATIVE_ASSET_ID, tokenOut: USDC, version, routeData, minOut, deadline,
      outPubkey: toFixedHex(outNote.keypair.pubkey),
      outBlinding: toFixedHex(outNote.blinding),
      encryptedOutput: '0x',
    }
    // params first: the proof commits to their hash (see SherwoodVault._requireSwapParams).
    const { args, extData } = await prepareTransaction({
      tree: ethTree, inputs: [depositUtxo], outputs: [], recipient: mixer.address, encryptionKey,
      swapParamsHash: hashSwapParams(params),
    })
    const tx = await mixer.executeSwap(args, extData, params, { gasLimit: 8_000_000 })
    const rc = await tx.wait()
    const ev = rc.events.find((e) => e.event === 'Swap')
    const Y = ev.args.amountOut
    expect(Y).to.be.gte(minOut)
    expect(await usdc.balanceOf(mixer.address)).to.equal(Y)

    // Reconstruct the real output note with the measured Y and withdraw it.
    const realOut = new Utxo({ amount: Y, keypair, blinding: outNote.blinding, mintAddress: usdcAssetId })
    usdcTree.insert(toFixedHex(realOut.getCommitment()))
    usdcTree.insert(emptyLeafCommit(keypair, usdcAssetId))
    await mixerTransact({ mixer, assetId: usdcAssetId, token: usdc, tree: usdcTree, inputs: [realOut], outputs: [], recipient: BOB, encryptionKey })
    expect(await usdc.balanceOf(BOB)).to.equal(Y)
  }

  it('swaps ETH-note -> USDC-note over real Uniswap V2 and withdraws it', async function () {
    const routeData = ethers.utils.defaultAbiCoder.encode(['address[]'], [[WETH, USDC]])
    await swapEthToUsdc(0, routeData)
  })

  it('swaps ETH-note -> USDC-note over real Uniswap V3 (exactInputSingle) and withdraws it', async function () {
    const routeData = ethers.utils.defaultAbiCoder.encode(['address', 'address', 'uint24'], [WETH, USDC, 500])
    await swapEthToUsdc(1, routeData)
  })
})
