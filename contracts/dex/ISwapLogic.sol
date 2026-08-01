// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/**
 * @title ISwapLogic
 * @notice Interface implemented by the UUPS-upgradable SwapLogic contract and
 *         consumed by the immutable SherwoodVault. SwapLogic is a pure ROUTE
 *         BUILDER: given a version + routeData it returns the concrete router
 *         target, the exact calldata, and the msg.value the vault must forward.
 *
 *         SwapLogic NEVER touches funds. The vault:
 *           (a) pulls exactly amountIn from its own custody,
 *           (b) asks SwapLogic to build the route,
 *           (c) re-checks the returned `router` against the vault-held allowlist,
 *           (d) performs the external call itself and measures the balance delta.
 *
 *         Because the allowlist check happens IN THE VAULT after SwapLogic runs,
 *         no SwapLogic upgrade can introduce a call target the vault hasn't
 *         allowlisted, nor can it redirect idle TVL — it only shapes the call for
 *         the in-flight amountIn.
 */
interface ISwapLogic {
  enum Version {
    V2,
    V3,
    V4
  }

  struct SwapRequest {
    Version version;
    bytes routeData;
    address tokenIn; // address(0) == native ETH
    address tokenOut; // address(0) == native ETH
    address weth; // canonical WETH the vault uses for ETH legs
    address router; // vault-allowlisted canonical router for `version`; vault re-checks it
    uint256 amountIn;
    uint256 minOut;
    uint256 deadline;
    address recipient; // where the router should deliver tokenOut (always the vault)
  }

  struct RouteInstruction {
    address router; // MUST be on the vault allowlist for `version`
    address approveToken; // token the vault must approve `router` to pull (address(0) = none)
    uint256 approveAmount;
    uint256 callValue; // ETH the vault forwards with the call
    bytes callData; // exact calldata for the router
  }

  /// @notice Build the concrete router instruction for a swap. Pure/view: no state, no funds.
  function buildRoute(SwapRequest calldata req) external view returns (RouteInstruction memory ins);

  /// @notice Version identifier of the logic implementation (bumped on upgrades).
  function logicVersion() external view returns (uint256);
}
