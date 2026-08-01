// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title MockUniswapV3Router
 * @notice Deterministic constant-price router mimicking Uniswap V3 SwapRouter02's
 *         `exactInputSingle` / `exactInput`. Prices are admin-set per ordered pair
 *         (1e18 fixed point). Must be pre-funded with the output token.
 */
contract MockUniswapV3Router {
  using SafeERC20 for IERC20;

  struct ExactInputSingleParams {
    address tokenIn;
    address tokenOut;
    uint24 fee;
    address recipient;
    uint256 amountIn;
    uint256 amountOutMinimum;
    uint160 sqrtPriceLimitX96;
  }

  struct ExactInputParams {
    bytes path;
    address recipient;
    uint256 amountIn;
    uint256 amountOutMinimum;
  }

  mapping(address => mapping(address => uint256)) public price; // 1e18 fixed point

  function setPrice(address tokenIn, address tokenOut, uint256 price1e18) external {
    price[tokenIn][tokenOut] = price1e18;
  }

  function exactInputSingle(ExactInputSingleParams calldata params) external payable returns (uint256 amountOut) {
    uint256 p = price[params.tokenIn][params.tokenOut];
    require(p > 0, "no price");
    IERC20(params.tokenIn).safeTransferFrom(msg.sender, address(this), params.amountIn);
    amountOut = (params.amountIn * p) / 1e18;
    require(amountOut >= params.amountOutMinimum, "insufficient output");
    IERC20(params.tokenOut).safeTransfer(params.recipient, amountOut);
  }

  // Multi-hop path encoding: tokenIn (20) [fee (3) token (20)]... We decode the
  // first and last 20-byte addresses and compose prices for intermediate hops.
  function exactInput(ExactInputParams calldata params) external payable returns (uint256 amountOut) {
    bytes memory path = params.path;
    require(path.length >= 43 && (path.length - 20) % 23 == 0, "bad path");

    uint256 hops = (path.length - 20) / 23;
    address current = _readAddress(path, 0);
    IERC20(current).safeTransferFrom(msg.sender, address(this), params.amountIn);

    uint256 amt = params.amountIn;
    for (uint256 i = 0; i < hops; i++) {
      address next = _readAddress(path, 20 + i * 23 + 3);
      uint256 p = price[current][next];
      require(p > 0, "no price");
      amt = (amt * p) / 1e18;
      current = next;
    }

    require(amt >= params.amountOutMinimum, "insufficient output");
    IERC20(current).safeTransfer(params.recipient, amt);
    return amt;
  }

  function _readAddress(bytes memory data, uint256 offset) internal pure returns (address addr) {
    require(data.length >= offset + 20, "oob");
    assembly {
      addr := shr(96, mload(add(add(data, 0x20), offset)))
    }
  }
}
