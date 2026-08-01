const hre = require('hardhat')
const { ethers, waffle } = hre
const { loadFixture } = waffle
const { expect } = require('chai')

const { poseidonHash2, toFixedHex, FIELD_SIZE } = require('../src/utils')

const MERKLE_TREE_HEIGHT = 26
const ROOT_HISTORY_SIZE = 100
const { MerkleTree } = require('fixed-merkle-tree')

describe('MerkleTreeWithHistory', function () {


  async function deploy(contractName, ...args) {
    const Factory = await ethers.getContractFactory(contractName)
    const instance = await Factory.deploy(...args)
    return instance.deployed()
  }

  const MERKLE_TREE_ZERO_VALUE = '2795675251356313514992617062594790716374808130983166135938897961178374655502'

  function getNewTree(height = MERKLE_TREE_HEIGHT) {
    return new MerkleTree(height, [], { hashFunction: poseidonHash2, zeroElement: MERKLE_TREE_ZERO_VALUE })
  }

  async function fixture() {
    require('../scripts/compileHasher')
    const hasher = await deploy('Hasher')
    const merkleTreeWithHistory = await deploy(
      'MerkleTreeWithHistoryMock',
      MERKLE_TREE_HEIGHT,
      hasher.address,
    )
    await merkleTreeWithHistory.initialize()
    return { hasher, merkleTreeWithHistory }
  }

  async function smallTreeFixture() {
    require('../scripts/compileHasher')
    const hasher = await deploy('Hasher')
    const merkleTreeWithHistory = await deploy(
      'MerkleTreeWithHistoryMock',
      1,
      hasher.address,
    )
    await merkleTreeWithHistory.initialize()
    return { hasher, merkleTreeWithHistory }
  }

  describe('#constructor', () => {
    it('should correctly hash 2 leaves', async () => {
      const { merkleTreeWithHistory } = await loadFixture(fixture)
      const hash0 = await merkleTreeWithHistory.hashLeftRight(toFixedHex(123), toFixedHex(456))
      const hash2 = poseidonHash2(123, 456)
      expect(hash0).to.equal(hash2)
    })

    it('should initialize', async () => {
      const { merkleTreeWithHistory } = await loadFixture(fixture)
      const firstSubtree = await merkleTreeWithHistory.filledSubtrees(0)
      const firstZero = await merkleTreeWithHistory.zeros(0)
      expect(firstSubtree).to.be.equal(toFixedHex(MERKLE_TREE_ZERO_VALUE))
      expect(firstZero).to.be.equal(toFixedHex(MERKLE_TREE_ZERO_VALUE))
    })

    it('should have correct merkle root', async () => {
      const { merkleTreeWithHistory } = await loadFixture(fixture)
      const tree = getNewTree()
      const contractRoot = await merkleTreeWithHistory.getLastRoot()
      expect(tree.root).to.equal(contractRoot)
    })

    it('should reject levels of 0', async () => {
      require('../scripts/compileHasher')
      const hasher = await deploy('Hasher')
      await expect(deploy('MerkleTreeWithHistoryMock', 0, hasher.address)).to.be.revertedWith(
        '_levels should be greater than zero',
      )
    })

    it('should reject levels >= 32', async () => {
      require('../scripts/compileHasher')
      const hasher = await deploy('Hasher')
      await expect(deploy('MerkleTreeWithHistoryMock', 32, hasher.address)).to.be.revertedWith(
        '_levels should be less than 32',
      )
    })
  })

  describe('#zeros', () => {
    it('should have consistent zero values (each level is hash of previous level pair)', async () => {
      const { merkleTreeWithHistory } = await loadFixture(fixture)
      for (let i = 0; i < MERKLE_TREE_HEIGHT; i++) {
        const currentZero = await merkleTreeWithHistory.zeros(i)
        const nextZero = await merkleTreeWithHistory.zeros(i + 1)
        const computedNext = poseidonHash2(currentZero, currentZero)
        expect(nextZero).to.equal(computedNext)
      }
    })

    it('should return correct zeros for all levels 0 through 31', async () => {
      const { merkleTreeWithHistory } = await loadFixture(fixture)
      let current = ethers.BigNumber.from(MERKLE_TREE_ZERO_VALUE)
      for (let i = 0; i <= 31; i++) {
        const contractZero = await merkleTreeWithHistory.zeros(i)
        expect(contractZero).to.equal(toFixedHex(current), `zeros(${i}) mismatch`)
        current = poseidonHash2(current, current)
      }
    })

    it('should return correct zeros verified by on-chain hashLeftRight', async () => {
      const { merkleTreeWithHistory } = await loadFixture(fixture)
      for (let i = 0; i < 31; i++) {
        const currentZero = await merkleTreeWithHistory.zeros(i)
        const nextZero = await merkleTreeWithHistory.zeros(i + 1)
        const computed = await merkleTreeWithHistory.hashLeftRight(currentZero, currentZero)
        expect(nextZero).to.equal(computed, `zeros(${i + 1}) != hashLeftRight(zeros(${i}), zeros(${i}))`)
      }
    })

    it('should revert for out of bounds index', async () => {
      const { merkleTreeWithHistory } = await loadFixture(fixture)
      await expect(merkleTreeWithHistory.zeros(32)).to.be.revertedWith('Index out of bounds')
    })

    it('should match the off-chain tree zero element at level 0', async () => {
      const { merkleTreeWithHistory } = await loadFixture(fixture)
      const contractZero = await merkleTreeWithHistory.zeros(0)
      expect(contractZero).to.equal(toFixedHex(MERKLE_TREE_ZERO_VALUE))
    })
  })

  describe('#hashLeftRight', () => {
    it('should reject left input >= FIELD_SIZE', async () => {
      const { merkleTreeWithHistory } = await loadFixture(fixture)
      await expect(
        merkleTreeWithHistory.hashLeftRight(toFixedHex(FIELD_SIZE), toFixedHex(0)),
      ).to.be.revertedWith('_left should be inside the field')
    })

    it('should reject right input >= FIELD_SIZE', async () => {
      const { merkleTreeWithHistory } = await loadFixture(fixture)
      await expect(
        merkleTreeWithHistory.hashLeftRight(toFixedHex(0), toFixedHex(FIELD_SIZE)),
      ).to.be.revertedWith('_right should be inside the field')
    })

    it('should accept inputs just below FIELD_SIZE', async () => {
      const { merkleTreeWithHistory } = await loadFixture(fixture)
      const maxValid = FIELD_SIZE.sub(1)
      const hash = await merkleTreeWithHistory.hashLeftRight(toFixedHex(maxValid), toFixedHex(maxValid))
      const expected = poseidonHash2(maxValid, maxValid)
      expect(hash).to.equal(expected)
    })

    it('should produce the same hash for the same inputs', async () => {
      const { merkleTreeWithHistory } = await loadFixture(fixture)
      const hash1 = await merkleTreeWithHistory.hashLeftRight(toFixedHex(100), toFixedHex(200))
      const hash2 = await merkleTreeWithHistory.hashLeftRight(toFixedHex(100), toFixedHex(200))
      expect(hash1).to.equal(hash2)
    })

    it('should produce different hashes for different inputs', async () => {
      const { merkleTreeWithHistory } = await loadFixture(fixture)
      const hash1 = await merkleTreeWithHistory.hashLeftRight(toFixedHex(100), toFixedHex(200))
      const hash2 = await merkleTreeWithHistory.hashLeftRight(toFixedHex(200), toFixedHex(100))
      expect(hash1).to.not.equal(hash2)
    })

    it('hasher gas', async () => {
      const { merkleTreeWithHistory } = await loadFixture(fixture)
      const gas = await merkleTreeWithHistory.estimateGas.hashLeftRight(toFixedHex(123), toFixedHex(456))
      expect(gas - 21000).to.be.lt(100000)
    })
  })

  describe('#insert', () => {
    it('should insert and match off-chain tree', async () => {
      const { merkleTreeWithHistory } = await loadFixture(fixture)
      const tree = getNewTree()
      await merkleTreeWithHistory.insert(toFixedHex(123), toFixedHex(456))
      tree.bulkInsert([123, 456])
      expect(tree.root).to.be.equal(await merkleTreeWithHistory.getLastRoot())

      await merkleTreeWithHistory.insert(toFixedHex(678), toFixedHex(876))
      tree.bulkInsert([678, 876])
      expect(tree.root).to.be.equal(await merkleTreeWithHistory.getLastRoot())
    })

    it('should update nextIndex by 2 per insertion', async () => {
      const { merkleTreeWithHistory } = await loadFixture(fixture)
      expect(await merkleTreeWithHistory.nextIndex()).to.equal(0)

      await merkleTreeWithHistory.insert(toFixedHex(1), toFixedHex(2))
      expect(await merkleTreeWithHistory.nextIndex()).to.equal(2)

      await merkleTreeWithHistory.insert(toFixedHex(3), toFixedHex(4))
      expect(await merkleTreeWithHistory.nextIndex()).to.equal(4)

      await merkleTreeWithHistory.insert(toFixedHex(5), toFixedHex(6))
      expect(await merkleTreeWithHistory.nextIndex()).to.equal(6)
    })

    it('should update currentRootIndex on each insertion', async () => {
      const { merkleTreeWithHistory } = await loadFixture(fixture)
      expect(await merkleTreeWithHistory.currentRootIndex()).to.equal(0)

      await merkleTreeWithHistory.insert(toFixedHex(1), toFixedHex(2))
      expect(await merkleTreeWithHistory.currentRootIndex()).to.equal(1)

      await merkleTreeWithHistory.insert(toFixedHex(3), toFixedHex(4))
      expect(await merkleTreeWithHistory.currentRootIndex()).to.equal(2)
    })

    it('should stay consistent with off-chain tree after many insertions', async () => {
      const { merkleTreeWithHistory } = await loadFixture(fixture)
      const tree = getNewTree()

      for (let i = 0; i < 10; i++) {
        const leaf1 = i * 2 + 1
        const leaf2 = i * 2 + 2
        await merkleTreeWithHistory.insert(toFixedHex(leaf1), toFixedHex(leaf2))
        tree.bulkInsert([leaf1, leaf2])
        expect(tree.root).to.equal(await merkleTreeWithHistory.getLastRoot())
      }
    })

    it('should produce unique roots for different insertions', async () => {
      const { merkleTreeWithHistory } = await loadFixture(fixture)
      const roots = new Set()
      roots.add(await merkleTreeWithHistory.getLastRoot())

      for (let i = 0; i < 5; i++) {
        await merkleTreeWithHistory.insert(toFixedHex(i * 2 + 1), toFixedHex(i * 2 + 2))
        const root = await merkleTreeWithHistory.getLastRoot()
        expect(roots.has(root)).to.equal(false)
        roots.add(root)
      }
    })
  })

  describe('#tree capacity', () => {
    it('should revert when tree is full', async () => {
      const { merkleTreeWithHistory } = await loadFixture(smallTreeFixture)
      await merkleTreeWithHistory.insert(toFixedHex(1), toFixedHex(2))
      await expect(merkleTreeWithHistory.insert(toFixedHex(3), toFixedHex(4))).to.be.revertedWith(
        'Merkle tree is full. No more leaves can be added',
      )
    })

    it('should accept exactly capacity leaves before reverting', async () => {
      require('../scripts/compileHasher')
      const hasher = await deploy('Hasher')
      const levels = 2
      const merkleTreeWithHistory = await deploy('MerkleTreeWithHistoryMock', levels, hasher.address)
      await merkleTreeWithHistory.initialize()

      // capacity = 2^2 = 4 leaves = 2 pair insertions
      await merkleTreeWithHistory.insert(toFixedHex(1), toFixedHex(2))
      await merkleTreeWithHistory.insert(toFixedHex(3), toFixedHex(4))

      await expect(merkleTreeWithHistory.insert(toFixedHex(5), toFixedHex(6))).to.be.revertedWith(
        'Merkle tree is full. No more leaves can be added',
      )
    })

    it('should track nextIndex correctly up to capacity', async () => {
      require('../scripts/compileHasher')
      const hasher = await deploy('Hasher')
      const levels = 2
      const merkleTreeWithHistory = await deploy('MerkleTreeWithHistoryMock', levels, hasher.address)
      await merkleTreeWithHistory.initialize()

      expect(await merkleTreeWithHistory.nextIndex()).to.equal(0)
      await merkleTreeWithHistory.insert(toFixedHex(1), toFixedHex(2))
      expect(await merkleTreeWithHistory.nextIndex()).to.equal(2)
      await merkleTreeWithHistory.insert(toFixedHex(3), toFixedHex(4))
      expect(await merkleTreeWithHistory.nextIndex()).to.equal(4) // 2^2 = 4, tree is now full
    })
  })

  describe('#isKnownRoot', () => {
    async function fixtureFilled() {
      const { merkleTreeWithHistory, hasher } = await loadFixture(fixture)
      await merkleTreeWithHistory.insert(toFixedHex(123), toFixedHex(456))
      return { merkleTreeWithHistory, hasher }
    }

    it('should return last root', async () => {
      const { merkleTreeWithHistory } = await fixtureFilled(fixture)
      const tree = getNewTree()
      tree.bulkInsert([123, 456])
      expect(await merkleTreeWithHistory.isKnownRoot(tree.root)).to.equal(true)
    })

    it('should return older root', async () => {
      const { merkleTreeWithHistory } = await fixtureFilled(fixture)
      const tree = getNewTree()
      tree.bulkInsert([123, 456])
      await merkleTreeWithHistory.insert(toFixedHex(234), toFixedHex(432))
      expect(await merkleTreeWithHistory.isKnownRoot(tree.root)).to.equal(true)
    })

    it('should fail on unknown root', async () => {
      const { merkleTreeWithHistory } = await fixtureFilled(fixture)
      const tree = getNewTree()
      tree.bulkInsert([456, 654])
      expect(await merkleTreeWithHistory.isKnownRoot(tree.root)).to.equal(false)
    })

    it('should not return uninitialized roots', async () => {
      const { merkleTreeWithHistory } = await fixtureFilled(fixture)
      expect(await merkleTreeWithHistory.isKnownRoot(toFixedHex(0))).to.equal(false)
    })

    it('should recognize the initial empty root', async () => {
      const { merkleTreeWithHistory } = await loadFixture(fixture)
      const tree = getNewTree()
      expect(await merkleTreeWithHistory.isKnownRoot(tree.root)).to.equal(true)
    })

    it('should keep all roots within ROOT_HISTORY_SIZE', async () => {
      const { merkleTreeWithHistory } = await loadFixture(fixture)
      const roots = []
      const tree = getNewTree()

      roots.push(await merkleTreeWithHistory.getLastRoot())

      for (let i = 0; i < 20; i++) {
        const leaf1 = i * 2 + 1
        const leaf2 = i * 2 + 2
        await merkleTreeWithHistory.insert(toFixedHex(leaf1), toFixedHex(leaf2))
        tree.bulkInsert([leaf1, leaf2])
        roots.push(await merkleTreeWithHistory.getLastRoot())
      }

      // All 21 roots (initial + 20 insertions) should be recognized since < ROOT_HISTORY_SIZE
      for (const root of roots) {
        expect(await merkleTreeWithHistory.isKnownRoot(root)).to.equal(true)
      }
    })

    it('should evict oldest root after ROOT_HISTORY_SIZE insertions', async () => {
      const { merkleTreeWithHistory } = await loadFixture(fixture)
      const tree = getNewTree()
      const initialRoot = tree.root

      // Perform ROOT_HISTORY_SIZE insertions to fill the circular buffer and wrap around
      for (let i = 0; i < ROOT_HISTORY_SIZE; i++) {
        await merkleTreeWithHistory.insert(toFixedHex(i * 2 + 1), toFixedHex(i * 2 + 2))
      }

      // The initial empty root should now be evicted
      expect(await merkleTreeWithHistory.isKnownRoot(initialRoot)).to.equal(false)
    })

    it('should wrap currentRootIndex around ROOT_HISTORY_SIZE', async () => {
      const { merkleTreeWithHistory } = await loadFixture(fixture)

      for (let i = 0; i < ROOT_HISTORY_SIZE + 5; i++) {
        await merkleTreeWithHistory.insert(toFixedHex(i * 2 + 1), toFixedHex(i * 2 + 2))
      }

      const currentRootIndex = await merkleTreeWithHistory.currentRootIndex()
      expect(currentRootIndex).to.equal((ROOT_HISTORY_SIZE + 5) % ROOT_HISTORY_SIZE)
    })
  })
})
