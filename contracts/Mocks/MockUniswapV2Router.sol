// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title MockUniswapV2Router
 * @notice Deterministic constant-price swap router mimicking the Uniswap V2
 *         `swapExactTokensForTokens` interface. Prices are admin-set per ordered
 *         pair with 1e18 fixed-point (out = in * priceNum / priceDen). The router
 *         must be pre-funded with the output token (its "reserve").
 */
contract MockUniswapV2Router {
  using SafeERC20 for IERC20;

  // price[in][out] scaled by 1e18: amountOut = amountIn * price / 1e18
  mapping(address => mapping(address => uint256)) public price;

  function setPrice(address tokenIn, address tokenOut, uint256 price1e18) external {
    price[tokenIn][tokenOut] = price1e18;
  }

  function getAmountOut(address tokenIn, address tokenOut, uint256 amountIn) public view returns (uint256) {
    uint256 p = price[tokenIn][tokenOut];
    require(p > 0, "no price");
    return (amountIn * p) / 1e18;
  }

  function swapExactTokensForTokens(
    uint256 amountIn,
    uint256 amountOutMin,
    address[] calldata path,
    address to,
    uint256 deadline
  ) external returns (uint256[] memory amounts) {
    require(deadline >= block.timestamp, "expired");
    require(path.length >= 2, "bad path");
    address tokenIn = path[0];
    address tokenOut = path[path.length - 1];

    // Pull input from caller.
    IERC20(tokenIn).safeTransferFrom(msg.sender, address(this), amountIn);

    // Constant-price conversion across the (possibly multi-hop) path; we compose
    // per-hop prices so multi-hop paths still resolve deterministically.
    uint256 amt = amountIn;
    amounts = new uint256[](path.length);
    amounts[0] = amountIn;
    for (uint256 i = 0; i + 1 < path.length; i++) {
      uint256 p = price[path[i]][path[i + 1]];
      require(p > 0, "no price");
      amt = (amt * p) / 1e18;
      amounts[i + 1] = amt;
    }

    require(amt >= amountOutMin, "insufficient output");
    IERC20(tokenOut).safeTransfer(to, amt);
    return amounts;
  }
}
