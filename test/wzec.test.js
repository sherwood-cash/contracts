/* eslint-disable no-undef */
const { expect } = require('chai')
const { ethers } = require('hardhat')

// wZEC is a plain ERC-20 with one privileged key, behind a UUPS proxy. What is worth
// checking is exactly the boundary of that key: it mints, it can be rotated by the owner,
// and nothing else on the token bends to it — balances move only by their holders. And
// the proxy's own boundary: an upgrade keeps every balance, only the owner may do one, and
// the owner can give that up for good.

async function expectCustomError(promise, name) {
  try {
    await promise
  } catch (e) {
    expect(e.message, `expected custom error ${name}, got: ${e.message}`).to.contain(name)
    return
  }
  throw new Error(`expected revert with ${name}, but the call succeeded`)
}

/** Deploy the implementation behind an ERC1967 proxy, as scripts/deployWzec.js does. */
async function deployWzec(ownerAddr, minterAddr) {
  const WZEC = await ethers.getContractFactory('WZEC')
  const impl = await WZEC.deploy()
  await impl.deployed()
  const data = WZEC.interface.encodeFunctionData('initialize', [ownerAddr, minterAddr])
  const Proxy = await ethers.getContractFactory('ERC1967Proxy')
  const proxy = await Proxy.deploy(impl.address, data)
  await proxy.deployed()
  return { wzec: WZEC.attach(proxy.address), impl }
}

describe('WZEC', () => {
  let owner, keeper, alice, bob, wzec, impl

  beforeEach(async () => {
    ;[owner, keeper, alice, bob] = await ethers.getSigners()
    ;({ wzec, impl } = await deployWzec(owner.address, keeper.address))
  })

  it('is named, 18 decimals, empty at birth', async () => {
    expect(await wzec.name()).to.equal('Sherwood Wrapped Zcash')
    expect(await wzec.symbol()).to.equal('wZEC')
    expect(await wzec.decimals()).to.equal(18)
    expect(await wzec.totalSupply()).to.equal(0)
    expect(await wzec.minter()).to.equal(keeper.address)
    expect(await wzec.owner()).to.equal(owner.address)
  })

  it('refuses a zero minter or owner', async () => {
    await expectCustomError(deployWzec(owner.address, ethers.constants.AddressZero), 'ZeroAddress')
    await expectCustomError(deployWzec(ethers.constants.AddressZero, keeper.address), 'ZeroAddress')
  })

  it('cannot be initialised twice, and the bare implementation not at all', async () => {
    await expectCustomError(wzec.initialize(alice.address, alice.address), 'InvalidInitialization')
    await expectCustomError(impl.initialize(alice.address, alice.address), 'InvalidInitialization')
  })

  it('only the minter mints', async () => {
    const size = ethers.utils.parseUnits('1.9987', 18)
    await wzec.connect(keeper).mint(alice.address, size)
    expect(await wzec.balanceOf(alice.address)).to.equal(size)
    expect(await wzec.totalSupply()).to.equal(size)
    await expectCustomError(wzec.connect(owner).mint(alice.address, 1), 'NotMinter')
    await expectCustomError(wzec.connect(alice).mint(alice.address, 1), 'NotMinter')
  })

  it('holders burn their own balance and nobody else\'s', async () => {
    const size = ethers.utils.parseUnits('2', 18)
    await wzec.connect(keeper).mint(alice.address, size)
    await wzec.connect(alice).burn(ethers.utils.parseUnits('0.5', 18))
    expect(await wzec.balanceOf(alice.address)).to.equal(ethers.utils.parseUnits('1.5', 18))
    expect(await wzec.totalSupply()).to.equal(ethers.utils.parseUnits('1.5', 18))
    // The keeper has no burn-from: it cannot shrink a holder.
    expect(wzec.burnFrom).to.equal(undefined)
    await expectCustomError(wzec.connect(bob).burn(1), 'ERC20InsufficientBalance')
  })

  it('the owner rotates the minter, and the old key is out immediately', async () => {
    await expectCustomError(wzec.connect(keeper).setMinter(bob.address), 'OwnableUnauthorizedAccount')
    await expect(wzec.connect(owner).setMinter(bob.address))
      .to.emit(wzec, 'MinterChanged')
      .withArgs(keeper.address, bob.address)
    await expectCustomError(wzec.connect(keeper).mint(alice.address, 1), 'NotMinter')
    await wzec.connect(bob).mint(alice.address, 1)
    expect(await wzec.balanceOf(alice.address)).to.equal(1)
    await expectCustomError(wzec.connect(owner).setMinter(ethers.constants.AddressZero), 'ZeroAddress')
  })

  it('ownership is two-step', async () => {
    await wzec.connect(owner).transferOwnership(alice.address)
    expect(await wzec.owner()).to.equal(owner.address)
    expect(await wzec.pendingOwner()).to.equal(alice.address)
    await wzec.connect(alice).acceptOwnership()
    expect(await wzec.owner()).to.equal(alice.address)
  })

  it('an upgrade keeps every balance and the minter, and only the owner may do one', async () => {
    const size = ethers.utils.parseUnits('2.5', 18)
    await wzec.connect(keeper).mint(alice.address, size)
    const WZEC = await ethers.getContractFactory('WZEC')
    const next = await WZEC.deploy()
    await next.deployed()
    await expectCustomError(wzec.connect(keeper).upgradeToAndCall(next.address, '0x'), 'OwnableUnauthorizedAccount')
    await expectCustomError(wzec.connect(alice).upgradeToAndCall(next.address, '0x'), 'OwnableUnauthorizedAccount')
    await wzec.connect(owner).upgradeToAndCall(next.address, '0x')
    expect(await wzec.balanceOf(alice.address)).to.equal(size)
    expect(await wzec.totalSupply()).to.equal(size)
    expect(await wzec.minter()).to.equal(keeper.address)
    expect(await wzec.owner()).to.equal(owner.address)
    // the implementation slot now points at the new code
    const slot = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc'
    const stored = await ethers.provider.getStorageAt(wzec.address, slot)
    expect(ethers.utils.getAddress('0x' + stored.slice(-40))).to.equal(next.address)
    // and the token still works as before
    await wzec.connect(keeper).mint(bob.address, 1)
    await wzec.connect(alice).burn(size)
    expect(await wzec.totalSupply()).to.equal(1)
  })

  it('renouncing upgradeability is one-way and final', async () => {
    const WZEC = await ethers.getContractFactory('WZEC')
    const next = await WZEC.deploy()
    await next.deployed()
    await expectCustomError(wzec.connect(alice).renounceUpgradeability(), 'OwnableUnauthorizedAccount')
    await expect(wzec.connect(owner).renounceUpgradeability()).to.emit(wzec, 'UpgradesFrozen')
    expect(await wzec.upgradesFrozen()).to.equal(true)
    await expectCustomError(wzec.connect(owner).upgradeToAndCall(next.address, '0x'), 'UpgradesAreFrozen')
    // everything else is untouched
    await wzec.connect(keeper).mint(alice.address, 1)
    await wzec.connect(owner).setMinter(bob.address)
    expect(await wzec.minter()).to.equal(bob.address)
  })

  it('transfers are plain: no fee, no hook', async () => {
    const size = ethers.utils.parseUnits('3', 18)
    await wzec.connect(keeper).mint(alice.address, size)
    await wzec.connect(alice).transfer(bob.address, size)
    expect(await wzec.balanceOf(bob.address)).to.equal(size)
    expect(await wzec.balanceOf(alice.address)).to.equal(0)
  })
})
