/* eslint-disable no-console */
/**
 * Upgrade the wZEC proxy to a freshly compiled implementation (owner-only).
 *
 * The proxy address never changes: balances, the minter and the vault's registration all
 * stay where they are. Refuses to run once `renounceUpgradeability` has been called.
 *
 * Usage:
 *   [WZEC_TOKEN=0x...] npx hardhat run scripts/upgradeWzec.js --network robinhood
 */
const fs = require('fs')
const path = require('path')
const { ethers, network, run } = require('hardhat')

function deploymentFile() {
  return path.join(__dirname, '..', 'deployments', `${network.name}.json`)
}

async function main() {
  const file = deploymentFile()
  const dep = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : null
  const token = process.env.WZEC_TOKEN || dep?.wzec
  if (!token) throw new Error('Set WZEC_TOKEN=<wZEC proxy address> (or deploy it first)')
  const proxyAddr = ethers.utils.getAddress(token)

  const [signer] = await ethers.getSigners()
  const WZEC = await ethers.getContractFactory('WZEC')
  const wzec = WZEC.attach(proxyAddr)
  const owner = await wzec.owner()
  const supply = await wzec.totalSupply()

  console.log(`\n=== upgradeWzec on ${network.name} — proxy ${proxyAddr} ===`)
  console.log(`signer   : ${signer.address}`)
  console.log(`owner    : ${owner}`)
  console.log(`supply   : ${ethers.utils.formatEther(supply)} wZEC`)
  console.log(`frozen   : ${await wzec.upgradesFrozen()}\n`)
  if (signer.address.toLowerCase() !== owner.toLowerCase()) {
    throw new Error(`Signer ${signer.address} is not the owner ${owner} — aborting`)
  }
  if (await wzec.upgradesFrozen()) throw new Error('upgrades are frozen on this token')

  const impl = await WZEC.deploy()
  await impl.deployed()
  console.log(`  new implementation ${impl.address}`)
  const tx = await wzec.upgradeToAndCall(impl.address, '0x')
  console.log(`  upgradeToAndCall   tx ${tx.hash}`)
  await tx.wait()

  if (dep) {
    dep.wzecImpl = impl.address
    fs.writeFileSync(file, JSON.stringify(dep, null, 2) + '\n')
  }
  if (network.name !== 'hardhat' && network.name !== 'localhost') {
    try {
      await run('verify:verify', { address: impl.address, constructorArguments: [] })
    } catch (e) {
      console.warn(`verify skipped: ${e.message}`)
    }
  }
  console.log(`\n✅ Done. supply still ${ethers.utils.formatEther(await wzec.totalSupply())} wZEC, minter ${await wzec.minter()}`)
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
