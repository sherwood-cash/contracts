/* eslint-disable no-console */
/**
 * Deploy wZEC (Sherwood Wrapped Zcash) behind a UUPS proxy and record it in
 * deployments/<network>.json. The PROXY address is the token; the implementation is only
 * what it currently runs. Upgrade with scripts/upgradeWzec.js.
 *
 * Usage:
 *   WZEC_MINTER=0x<keeper address> [WZEC_OWNER=0x...] \
 *     npx hardhat run scripts/deployWzec.js --network robinhood
 *
 * Env:
 *   WZEC_MINTER  the bridge keeper's EVM address (the backend's WZEC_KEEPER_KEY). Required.
 *   WZEC_OWNER   who may rotate the minter and upgrade the token. Defaults to the vault
 *                admin from the deployment file, else the deployer.
 *
 * Then run scripts/enableWzec.js as the vault admin so the vault accepts it as a quote
 * asset, and set WZEC_TOKEN on the backend.
 */
const fs = require('fs')
const path = require('path')
const { ethers, network, run } = require('hardhat')

function deploymentFile() {
  return path.join(__dirname, '..', 'deployments', `${network.name}.json`)
}

function loadDeployment() {
  const file = deploymentFile()
  if (!fs.existsSync(file)) return null
  return JSON.parse(fs.readFileSync(file, 'utf8'))
}

async function main() {
  const dep = loadDeployment()
  const [deployer] = await ethers.getSigners()
  const minter = process.env.WZEC_MINTER
  if (!minter) throw new Error('Set WZEC_MINTER=<keeper address>')
  const minterAddr = ethers.utils.getAddress(minter)
  const ownerAddr = ethers.utils.getAddress(process.env.WZEC_OWNER || dep?.admin || deployer.address)

  console.log(`\n=== deployWzec on ${network.name} ===`)
  console.log(`deployer : ${deployer.address} (${ethers.utils.formatEther(await deployer.getBalance())} ETH)`)
  console.log(`owner    : ${ownerAddr}`)
  console.log(`minter   : ${minterAddr}\n`)

  const WZEC = await ethers.getContractFactory('WZEC')
  const impl = await WZEC.deploy()
  await impl.deployed()
  console.log(`implementation ${impl.address} (tx ${impl.deployTransaction.hash})`)

  const data = WZEC.interface.encodeFunctionData('initialize', [ownerAddr, minterAddr])
  const Proxy = await ethers.getContractFactory('ERC1967Proxy')
  const proxy = await Proxy.deploy(impl.address, data)
  await proxy.deployed()
  const wzec = WZEC.attach(proxy.address)
  console.log(`wZEC (proxy)   ${proxy.address} (tx ${proxy.deployTransaction.hash})`)
  console.log(`minter         ${await wzec.minter()}  owner ${await wzec.owner()}`)

  if (dep) {
    dep.wzec = proxy.address
    dep.wzecImpl = impl.address
    dep.wzecMinter = minterAddr
    fs.writeFileSync(deploymentFile(), JSON.stringify(dep, null, 2) + '\n')
    console.log(`recorded in ${path.relative(process.cwd(), deploymentFile())}`)
  }

  if (network.name !== 'hardhat' && network.name !== 'localhost') {
    try {
      await run('verify:verify', { address: impl.address, constructorArguments: [] })
      await run('verify:verify', { address: proxy.address, constructorArguments: [impl.address, data] })
    } catch (e) {
      console.warn(`verify skipped: ${e.message}`)
    }
  }

  console.log(`\nNext: WZEC_TOKEN=${proxy.address} npx hardhat run scripts/enableWzec.js --network ${network.name}`)
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
