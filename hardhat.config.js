/* eslint-disable indent, no-undef */
const { extendEnvironment } = require('hardhat/config')
require('@typechain/hardhat')
require('@nomiclabs/hardhat-ethers')
require('@nomiclabs/hardhat-waffle')
require('@nomicfoundation/hardhat-verify')
// NOTE: @openzeppelin/hardhat-upgrades is intentionally NOT required here. The
// installed plugin version references build artifacts absent from the installed
// @openzeppelin/upgrades-core, which breaks `hardhat compile`. Our contracts are
// non-upgradeable and tests deploy proxies via getContractFactory('ERC1967Proxy'),
// so the plugin is unused.
require('dotenv').config()

function normalizeRpcResult(method, result) {
  if (result == null) {
    return result
  }

  if (method === 'eth_getTransactionByHash' && result.to === '') {
    result.to = null
  }

  if (
    (method === 'eth_getBlockByNumber' || method === 'eth_getBlockByHash') &&
    Array.isArray(result.transactions)
  ) {
    for (const transaction of result.transactions) {
      if (transaction && transaction.to === '') {
        transaction.to = null
      }
    }
  }

  return result
}

extendEnvironment((hre) => {
  const provider = hre.network.provider
  if (provider.__ethersRpcNormalizePatched) {
    return
  }

  const send = provider.send.bind(provider)
  provider.send = async (method, params) =>
    normalizeRpcResult(method, await send(method, params))
  provider.__ethersRpcNormalizePatched = true
})

task('hasher', 'Compile Poseidon hasher', () => {
  require('./scripts/compileHasher')
})

const config = {
  solidity: {
    compilers: [
      {
        version: '0.8.24',
        settings: {
          optimizer: {
            enabled: true,
            runs: 200,
          },
        },
      },
    ],
  },
  networks: {
    hardhat: {
      chainId: 1,
      hardfork: 'cancun',
      initialBaseFeePerGas: 5,
      loggingEnabled: false,
      allowUnlimitedContractSize: false,
      blockGasLimit: 100000000,
    },
    rinkeby: {
      url: `https://rinkeby.infura.io/v3/${process.env.INFURA_API_KEY}`,
      accounts: process.env.PRIVATE_KEY
        ? [process.env.PRIVATE_KEY]
        : {
            mnemonic: 'test test test test test test test test test test test junk',
          },
    },
    mainnet: {
      url: `https://eth-mainnet.g.alchemy.com/v2/${process.env.ALCHEMY_KEY}`,
      chainId: 1,
      accounts: process.env.PRIVATE_KEY
        ? [process.env.PRIVATE_KEY]
        : {
            mnemonic: 'test test test test test test test test test test test junk',
          },
    },
    baseSepolia: {
      url: `https://base-sepolia.g.alchemy.com/v2/${process.env.ALCHEMY_KEY}`,
      chainId: 84532,
      accounts: process.env.PRIVATE_KEY
        ? [process.env.PRIVATE_KEY]
        : {
            mnemonic: 'test test test test test test test test test test test junk',
          },
    },
    base: {
      url: `https://base-mainnet.g.alchemy.com/v2/${process.env.ALCHEMY_KEY}`,
      chainId: 8453,
      accounts: process.env.PRIVATE_KEY
        ? [process.env.PRIVATE_KEY]
        : {
            mnemonic: 'test test test test test test test test test test test junk',
          },
    },
    localhost: {
      url: 'http://127.0.0.1:8545',
      chainId: 1,
    },
    // Fork of ETH mainnet for real-Uniswap tests. Uses a public RPC. NOTE: most free
    // public RPCs (publicnode, llamarpc, ankr) DO NOT serve archive state, so forking
    // at a pinned historical block fails; the fork test auto-skips if the RPC cannot
    // serve the fork. Set MAINNET_FORK_RPC to an archive endpoint to enable it.
    mainnetFork: {
      url: process.env.MAINNET_FORK_RPC || 'https://ethereum-rpc.publicnode.com',
      chainId: 1,
    },
    hyperevm: {
      url: process.env.HYPEREVM_RPC || 'https://rpc.hyperliquid.xyz/evm',
      chainId: 999,
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [],
    },
    hyperevmTestnet: {
      url: process.env.HYPEREVM_TESTNET_RPC || 'https://rpc.hyperliquid-testnet.xyz/evm',
      chainId: 998,
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [],
    },
    // Robinhood EVM chain. Fully env-driven so the same config works before the
    // official RPC/chainId are public. Set ROBINHOOD_RPC + ROBINHOOD_CHAIN_ID.
    robinhood: {
      url: process.env.ROBINHOOD_RPC || 'https://rpc.robinhood.invalid',
      chainId: process.env.ROBINHOOD_CHAIN_ID ? parseInt(process.env.ROBINHOOD_CHAIN_ID, 10) : undefined,
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [],
    },
  },
  etherscan: {
    // Blockscout ignores the key value but hardhat-verify requires a non-empty
    // string per network. Real Etherscan networks still use ETHERSCAN_KEY.
    apiKey: {
      mainnet: process.env.ETHERSCAN_KEY,
      base: process.env.ETHERSCAN_KEY,
      robinhood: process.env.ETHERSCAN_KEY || 'blockscout',
    },
    customChains: [
      {
        network: 'robinhood',
        chainId: 4663,
        urls: {
          apiURL: 'https://robinhoodchain.blockscout.com/api',
          browserURL: 'https://robinhoodchain.blockscout.com',
        },
      },
    ],
    enabled: true,
  },
  sourcify: {
    enabled: false,
  },
  mocha: {
    timeout: 120000,
  },
  typechain: {
    outDir: 'src/types',
  },
}

module.exports = config
