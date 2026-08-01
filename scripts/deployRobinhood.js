/**
 * Deploy the FULL Robinhood privacy mixer + private DEX in one shot and wire USDG
 * as the protocol fee (base) token.
 *
 *   Verifier2 + Hasher(Poseidon-2) + Hasher4(Poseidon-4)
 *        -> SherwoodVault            (IMMUTABLE sole custodian of ETH + ERC20)
 *        -> SwapLogic (UUPS proxy)  (route builder the vault points at)
 *        -> registerToken(USDG)
 *        -> setFeeAsset(USDG, true) + protocol fee bps/recipient   <-- USDG fee token
 *        -> allowlist Uniswap v2/v3(/v4) routers
 *
 * Router allowlisting and the SwapLogic pointer are 2-step (propose -> enable) but
 * the vault's CONFIG_TIMELOCK is 0, so both halves run back-to-back here: the whole
 * system is deployed AND wired in a single run, on any network, no waiting. On a
 * local/fork run, mocks are deployed for any address left unset.
 *
 * Everything is env-driven. Addresses are written to `deployments/<network>.json`
 * in the exact shape the frontend's `deployment.json` expects.
 *
 * Usage:
 *   npx hardhat run scripts/deployRobinhood.js --network robinhood
 *   npx hardhat run scripts/deployRobinhood.js            # local, all mocks
 *
 * Env (see .env.example):
 *   ADMIN_ADDRESS            admin/multisig (defaults to deployer)
 *   WETH_ADDRESS             canonical WETH (required on live nets)
 *   USDG_ADDRESS             USDG token     (required on live nets)
 *   V2_ROUTER / V3_ROUTER / V4_ROUTER   Uniswap routers to allowlist (optional)
 *   PROTOCOL_FEE_BPS         fee rate, capped at 1000 (10%). Default 30 (0.30%).
 *   PROTOCOL_FEE_RECIPIENT   where fees accrue (defaults to admin)
 *   RPC_URL / EXPLORER_URL   written into deployment.json for the frontend
 */
const fs = require('fs')
const path = require('path')
const { ethers, network } = require('hardhat')

const MERKLE_TREE_HEIGHT = 26
const ZERO = ethers.constants.AddressZero

// ISwapLogic.Version enum ordinals.
const VERSION = { V2: 0, V3: 1, V4: 2 }

function envInt(name, fallback) {
  return process.env[name] !== undefined ? parseInt(process.env[name], 10) : fallback
}

async function deploy(name, ...args) {
  const Factory = await ethers.getContractFactory(name)
  const instance = await Factory.deploy(...args)
  await instance.deployed()
  return instance
}

// Deploy SwapLogic behind an ERC1967 UUPS proxy (the stable address the vault points at).
async function deploySwapLogicProxy(admin) {
  const Logic = await ethers.getContractFactory('SwapLogic')
  const impl = await Logic.deploy()
  await impl.deployed()
  const initData = Logic.interface.encodeFunctionData('initialize', [admin])
  const Proxy = await ethers.getContractFactory('ERC1967Proxy')
  const proxy = await Proxy.deploy(impl.address, initData)
  await proxy.deployed()
  return { proxy: Logic.attach(proxy.address), impl }
}

async function main() {
  // Generate the Poseidon-2 (Hasher) + Poseidon-4 (Hasher4) artifacts.
  require('./compileHasher')

  const [deployer] = await ethers.getSigners()
  const net = await ethers.provider.getNetwork()
  const isLocal = ['hardhat', 'localhost', 'mainnetFork'].includes(network.name)

  const ADMIN = ethers.utils.getAddress(process.env.ADMIN_ADDRESS || deployer.address)
  const adminIsDeployer = ADMIN.toLowerCase() === deployer.address.toLowerCase()

  const FEE_BPS = envInt('PROTOCOL_FEE_BPS', 30) // 0.30% default
  const FEE_RECIPIENT = ethers.utils.getAddress(process.env.PROTOCOL_FEE_RECIPIENT || ADMIN)

  console.log(`\n=== Robinhood mixer deploy on ${network.name} (chainId ${net.chainId}) ===`)
  console.log(`Deployer: ${deployer.address}`)
  console.log(`Admin:    ${ADMIN}${adminIsDeployer ? ' (deployer)' : ' (external — timelocked/admin calls will be PRINTED)'}`)

  // --------------------------------------------------------------- external addresses
  let wethAddress = process.env.WETH_ADDRESS
  let usdgAddress = process.env.USDG_ADDRESS
  let usdgDecimals = envInt('USDG_DECIMALS', 18)
  const routers = {
    v2: process.env.V2_ROUTER || '',
    v3: process.env.V3_ROUTER || '',
    v4: process.env.V4_ROUTER || '',
  }

  if (isLocal) {
    if (!wethAddress) {
      const weth = await deploy('MockWETH')
      wethAddress = weth.address
      console.log(`\nMockWETH:   ${wethAddress}`)
    }
    if (!usdgAddress) {
      const usdg = await deploy('MockERC20')
      usdgAddress = usdg.address
      console.log(`MockERC20 (USDG): ${usdgAddress}`)
    }
    if (!routers.v2) {
      const v2 = await deploy('MockUniswapV2Router')
      routers.v2 = v2.address
    }
    if (!routers.v3) {
      const v3 = await deploy('MockUniswapV3Router')
      routers.v3 = v3.address
    }
  }

  if (!wethAddress) throw new Error('Set WETH_ADDRESS for a non-local deploy')
  if (!usdgAddress) throw new Error('Set USDG_ADDRESS for a non-local deploy')

  // --------------------------------------------------------------- core libs
  const verifier2 = await deploy('Verifier2')
  console.log(`\nVerifier2:  ${verifier2.address}`)
  const hasher = await deploy('Hasher')
  console.log(`Hasher(P2): ${hasher.address}`)
  const hasher4 = await deploy('Hasher4')
  console.log(`Hasher4(P4):${hasher4.address}`)

  // --------------------------------------------------------------- immutable vault
  const vault = await deploy(
    'SherwoodVault',
    verifier2.address,
    MERKLE_TREE_HEIGHT,
    hasher.address,
    hasher4.address,
    wethAddress,
    ADMIN,
  )
  console.log(`SherwoodVault (custody): ${vault.address}`)
  const deployBlock = vault.deployTransaction.blockNumber || (await ethers.provider.getBlockNumber())

  // --------------------------------------------------------------- upgradable logic
  const { proxy: swapLogic, impl: swapLogicImpl } = await deploySwapLogicProxy(ADMIN)
  console.log(`SwapLogic proxy: ${swapLogic.address}  (impl ${swapLogicImpl.address})`)

  // --------------------------------------------------------------- wiring
  const enabledRouters = Object.entries({ V2: routers.v2, V3: routers.v3, V4: routers.v4 }).filter(
    ([, addr]) => addr && addr !== ZERO,
  )

  if (adminIsDeployer) {
    console.log('\nWiring as admin=deployer...')

    // -- immediate (non-timelocked) admin ops --
    await (await vault.registerToken(usdgAddress)).wait()
    console.log(`  registerToken(USDG=${usdgAddress})`)

    await (await vault.setProtocolFeeRecipient(FEE_RECIPIENT)).wait()
    console.log(`  setProtocolFeeRecipient(${FEE_RECIPIENT})`)

    await (await vault.setProtocolFee(FEE_BPS)).wait()
    console.log(`  setProtocolFee(${FEE_BPS} bps)`)

    // The ask: wire USDG as a base/fee token (ETH is always one).
    await (await vault.setFeeAsset(usdgAddress, true)).wait()
    console.log(`  setFeeAsset(USDG, true)   <-- USDG is now a protocol fee token`)

    // Config is 2-step (propose -> enable) but CONFIG_TIMELOCK is 0, so both halves
    // run back-to-back in this same deploy — no waiting, no second script.
    await (await vault.proposeSwapLogic(swapLogic.address)).wait()
    await (await vault.setSwapLogic()).wait()
    console.log(`  proposeSwapLogic + setSwapLogic(${swapLogic.address}) adopted`)
    for (const [name, addr] of enabledRouters) {
      await (await vault.proposeRouter(VERSION[name], addr)).wait()
      await (await vault.enableRouter(VERSION[name], addr)).wait()
      console.log(`  proposeRouter + enableRouter(${name}, ${addr}) enabled`)
    }

    console.log('\n✅ Fully wired in one pass (no timelock).')
  } else {
    // Admin is an external multisig: emit the exact calls to make (no waiting).
    console.log('\n⚠️  Admin != deployer. Have the admin call, in order:')
    console.log(`  vault.registerToken(${usdgAddress})`)
    console.log(`  vault.setProtocolFeeRecipient(${FEE_RECIPIENT})`)
    console.log(`  vault.setProtocolFee(${FEE_BPS})`)
    console.log(`  vault.setFeeAsset(${usdgAddress}, true)   <-- USDG fee token`)
    console.log(`  vault.proposeSwapLogic(${swapLogic.address}) then vault.setSwapLogic()`)
    for (const [name, addr] of enabledRouters) {
      console.log(`  vault.proposeRouter(${VERSION[name]} /*${name}*/, ${addr}) then vault.enableRouter(...)`)
    }
  }

  // --------------------------------------------------------------- output (frontend shape)
  const out = {
    network: network.name,
    chainId: net.chainId,
    rpcUrl: process.env.RPC_URL || (network.config && network.config.url) || '',
    indexerUrl: process.env.INDEXER_URL || '',
    relayerUrl: process.env.RELAYER_URL || '',
    explorer: process.env.EXPLORER_URL || '',
    deployBlock,
    logChunk: envInt('LOG_CHUNK', 1000),
    merkleTreeHeight: MERKLE_TREE_HEIGHT,
    admin: ADMIN,
    vault: vault.address,
    swapLogic: swapLogic.address,
    swapLogicImpl: swapLogicImpl.address,
    verifier2: verifier2.address,
    hasher: hasher.address,
    hasher4: hasher4.address,
    weth: wethAddress,
    routers: {
      v2: routers.v2 || ZERO,
      v3: routers.v3 || ZERO,
      v4: routers.v4 || ZERO,
    },
    nativeCurrency: {
      name: process.env.NATIVE_NAME || 'Ether',
      symbol: process.env.NATIVE_SYMBOL || 'ETH',
      decimals: 18,
    },
    protocolFee: { bps: FEE_BPS, recipient: FEE_RECIPIENT, feeAssets: ['eth', 'usdg'] },
    assets: {
      eth: { token: ZERO, decimals: 18, native: true },
      usdg: { token: usdgAddress, decimals: usdgDecimals, native: false },
    },
  }

  const dir = path.join(__dirname, '..', 'deployments')
  fs.mkdirSync(dir, { recursive: true })
  const file = path.join(dir, `${network.name}.json`)
  fs.writeFileSync(file, JSON.stringify(out, null, 2))
  console.log(`\nDeployment written to ${file}`)
  console.log('(Copy it to robinhood-mixer-frontend/src/deployment.json for the UI.)')
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error)
    process.exit(1)
  })
