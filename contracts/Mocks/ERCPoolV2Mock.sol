// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "../ERCPool.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract ERCPoolV2Mock is ERCPool {
  uint256 public newVariable;

  /// @custom:oz-upgrades-unsafe-allow constructor
  constructor(
    Verifier2 _verifier2,
    uint32 _levels,
    address _hasher,
    IERC20 _token
  ) ERCPool(_verifier2, _levels, _hasher, _token) {}

  /// @custom:oz-upgrades-validate-as-initializer
  function initializeV2(uint256 _newVariable) external reinitializer(2) {
    newVariable = _newVariable;
  }

  function version() external pure returns (uint256) {
    return 2;
  }
}
