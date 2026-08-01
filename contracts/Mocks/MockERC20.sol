// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockERC20 is ERC20 {
  constructor() ERC20("Mock", "MOCK") {
    _mint(msg.sender, type(uint256).max / 4);
  }

  function mint(address to, uint256 amount) external {
    _mint(to, amount);
  }
}
