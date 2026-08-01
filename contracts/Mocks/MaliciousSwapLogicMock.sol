// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "../dex/ISwapLogic.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

/**
 * @title MaliciousSwapLogicMock
 * @notice A HOSTILE SwapLogic upgrade used only in tests. It tries every trick a
 *         rug-pull upgrade could attempt, to prove the immutable vault defeats them:
 *
 *           - `buildRoute` tries to redirect the swap to an ATTACKER-controlled
 *             router and to over-approve the vault's tokens to the attacker.
 *
 *         All of these are rejected by the vault because:
 *           (a) the vault re-checks `ins.router` against its OWN allowlist,
 *           (b) the vault overrides/validates the approval amount and token,
 *           (c) `buildRoute` is only STATICCALLED, so it can never move vault funds,
 *           (d) idle vault TVL is never referenced here — the vault holds it, not us.
 *
 *         Storage layout is compatible with SwapLogic (admin, pendingAdmin,
 *         _logicVersion) so it can be installed as a UUPS upgrade over it.
 */
contract MaliciousSwapLogicMock is ISwapLogic, Initializable, UUPSUpgradeable {
  address public admin;
  address public pendingAdmin;
  uint256 internal _logicVersion;

  // Attacker-controlled destination the malicious logic wants funds to flow to.
  address public attacker;

  modifier onlyAdmin() {
    require(msg.sender == admin, "only admin");
    _;
  }

  /// @custom:oz-upgrades-unsafe-allow constructor
  constructor() {
    _disableInitializers();
  }

  function setAttacker(address _attacker) external onlyAdmin {
    attacker = _attacker;
  }

  function logicVersion() external view override returns (uint256) {
    return _logicVersion + 666; // signal a "new" (malicious) version
  }

  /// @notice Hostile route builder: point the vault at the attacker and try to
  ///         over-approve the attacker for the input token. The vault rejects it.
  function buildRoute(SwapRequest calldata req) external view override returns (RouteInstruction memory ins) {
    address dest = attacker == address(0) ? msg.sender : attacker;
    ins.router = dest; // attacker "router" — vault's allowlist re-check will reject
    ins.approveToken = req.tokenIn == address(0) ? req.weth : req.tokenIn;
    ins.approveAmount = type(uint256).max; // try to drain via unlimited approval
    ins.callValue = req.amountIn; // try to siphon native ETH too
    ins.callData = abi.encodeWithSignature("pull()");
  }

  function _authorizeUpgrade(address) internal override onlyAdmin {}

  uint256[46] private __gap;
}
