// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "./ISwapLogic.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

// --- Uniswap router interfaces (used only for calldata encoding here) ---
interface IUniswapV2Router02 {
  function swapExactTokensForTokens(
    uint256 amountIn,
    uint256 amountOutMin,
    address[] calldata path,
    address to,
    uint256 deadline
  ) external returns (uint256[] memory amounts);
}

interface ISwapRouterV3 {
  struct ExactInputSingleParams {
    address tokenIn;
    address tokenOut;
    uint24 fee;
    address recipient;
    uint256 amountIn;
    uint256 amountOutMinimum;
    uint160 sqrtPriceLimitX96;
  }

  function exactInputSingle(ExactInputSingleParams calldata params) external payable returns (uint256 amountOut);

  struct ExactInputParams {
    bytes path;
    address recipient;
    uint256 amountIn;
    uint256 amountOutMinimum;
  }

  function exactInput(ExactInputParams calldata params) external payable returns (uint256 amountOut);
}

interface IUniversalRouter {
  function execute(bytes calldata commands, bytes[] calldata inputs, uint256 deadline) external payable;
}

/**
 * @title SwapLogic
 * @notice UUPS-upgradable, NON-CUSTODIAL route builder for the SherwoodVault. It
 *         decodes `version` + `routeData` (v2/v3/v4) and returns the concrete
 *         router target + calldata + approval the vault must use. It NEVER holds
 *         user funds and NEVER performs the swap itself.
 *
 *         Security model: new DEXes / features ship here via UUPS upgrade. Because
 *         the immutable vault re-checks the returned `router` against its OWN
 *         allowlist and performs the call + balance measurement itself, no upgrade
 *         to this contract can:
 *           (i)  move idle vault TVL (this contract never touches vault balances), or
 *           (ii) introduce a router the vault hasn't allowlisted (vault re-checks).
 *
 *         Worst case a malicious logic upgrade can do is craft bad calldata for the
 *         single in-flight `amountIn`; the vault's minOut check then reverts the
 *         whole tx atomically, so even that is bounded to zero loss.
 */
contract SwapLogic is ISwapLogic, Initializable, UUPSUpgradeable {
  address public admin;
  address public pendingAdmin;
  uint256 internal _logicVersion;

  event AdminChanged(address indexed oldAdmin, address indexed newAdmin);

  modifier onlyAdmin() {
    require(msg.sender == admin, "only admin");
    _;
  }

  /// @custom:oz-upgrades-unsafe-allow constructor
  constructor() {
    _disableInitializers();
  }

  function initialize(address _admin) external initializer {
    require(_admin != address(0), "admin is zero address");
    admin = _admin;
    _logicVersion = 1;
  }

  function logicVersion() external view override returns (uint256) {
    return _logicVersion;
  }

  function transferAdmin(address _newAdmin) external onlyAdmin {
    require(_newAdmin != address(0), "new admin is zero address");
    pendingAdmin = _newAdmin;
  }

  function claimAdmin() external {
    require(msg.sender == pendingAdmin, "not pending admin");
    emit AdminChanged(admin, pendingAdmin);
    admin = pendingAdmin;
    pendingAdmin = address(0);
  }

  /**
   * @notice Build the router instruction. The vault operates purely in ERC20 terms
   *         with routers: it has already wrapped native ETH to WETH before calling,
   *         and expects WETH back (which it unwraps). So `effectiveIn/effectiveOut`
   *         substitute WETH for address(0).
   */
  function buildRoute(SwapRequest calldata req) external view override returns (RouteInstruction memory ins) {
    require(req.amountIn > 0, "zero amountIn");
    require(req.router != address(0), "no router");
    address effectiveIn = req.tokenIn == address(0) ? req.weth : req.tokenIn;
    address effectiveOut = req.tokenOut == address(0) ? req.weth : req.tokenOut;

    // The vault always holds ERC20 (WETH for ETH legs) at call time and receives
    // ERC20 back, so callValue is always 0 and the router pulls via approval.
    ins.callValue = 0;
    ins.approveToken = effectiveIn;
    ins.approveAmount = req.amountIn;
    ins.router = req.router; // vault-supplied allowlisted router; vault re-checks it after this returns

    if (req.version == Version.V2) {
      address[] memory path = abi.decode(req.routeData, (address[]));
      require(path.length >= 2, "bad v2 path");
      require(path[0] == effectiveIn && path[path.length - 1] == effectiveOut, "v2 path mismatch");
      ins.callData = abi.encodeCall(
        IUniswapV2Router02.swapExactTokensForTokens,
        (req.amountIn, req.minOut, path, req.recipient, req.deadline)
      );
    } else if (req.version == Version.V3) {
      (bool isSingle, uint24 fee, bytes memory multiPath) = _decodeV3(req.routeData);
      if (isSingle) {
        ins.callData = abi.encodeCall(
          ISwapRouterV3.exactInputSingle,
          (
            ISwapRouterV3.ExactInputSingleParams({
              tokenIn: effectiveIn,
              tokenOut: effectiveOut,
              fee: fee,
              recipient: req.recipient,
              amountIn: req.amountIn,
              amountOutMinimum: req.minOut,
              sqrtPriceLimitX96: 0
            })
          )
        );
      } else {
        ins.callData = abi.encodeCall(
          ISwapRouterV3.exactInput,
          (
            ISwapRouterV3.ExactInputParams({
              path: multiPath,
              recipient: req.recipient,
              amountIn: req.amountIn,
              amountOutMinimum: req.minOut
            })
          )
        );
      }
    } else {
      // V4: routeData = abi.encode(bytes commands, bytes[] inputs). Caller is
      // responsible for encoding a route that settles tokenOut to req.recipient.
      (bytes memory commands, bytes[] memory inputs) = abi.decode(req.routeData, (bytes, bytes[]));
      ins.callData = abi.encodeCall(IUniversalRouter.execute, (commands, inputs, req.deadline));
    }
  }

  function _decodeV3(bytes calldata routeData) internal pure returns (bool isSingle, uint24 fee, bytes memory multiPath) {
    if (routeData.length == 96) {
      (, , uint24 f) = abi.decode(routeData, (address, address, uint24));
      return (true, f, "");
    }
    bytes memory p = abi.decode(routeData, (bytes));
    return (false, 0, p);
  }

  function _authorizeUpgrade(address) internal override onlyAdmin {}

  uint256[47] private __gap;
}
