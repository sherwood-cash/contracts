// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

/**
 * @title WZEC — Sherwood Wrapped Zcash
 * @notice One wZEC is one share of the bridge keeper's ZEC-PERP long on Lighter (the perp
 *         DEX on Robinhood Chain). The keeper sells the incoming ZEC for USDG, posts that
 *         USDG as collateral, buys the same size of ZEC-PERP at 1x, and mints EXACTLY the
 *         filled size here. Redemption runs the steps backwards: burn, close that size, and
 *         pay the holder their share of the account (size / position x equity), so funding
 *         the long has paid is carried by every wZEC pro rata and the account stays solvent.
 *
 *         So the supply of this token is, by construction, the size of the keeper's long.
 *         Anyone can check: `totalSupply()` against the position of the keeper's Lighter
 *         account (the backend exposes both at GET /zcash/wzec).
 *
 *         Deliberately a plain ERC-20 in behaviour. No pause, no blocklist, no
 *         fee-on-transfer, no rebasing — the vault holds it as a quote asset and swaps it
 *         like any other token, and every one of those features is a way to break that.
 *
 *         ON BEING UPGRADEABLE. Behind a UUPS proxy at the owner's request, the same shape as
 *         the stealth contracts. The owner can therefore change what this token does, which
 *         a holder is trusting not to happen to their balance; `renounceUpgradeability`
 *         makes it permanently immutable once the shape has settled. Storage order below is
 *         frozen: append, never reorder.
 *
 *         Trust model: the minter is the keeper's hot key. It can mint, which is the same
 *         power the bridge already has over bridged funds (it holds them for the seconds
 *         between arrival and deposit). A compromised minter can inflate the supply; it
 *         cannot take anyone's balance. Rotating the minter is one owner call.
 */
contract WZEC is Initializable, ERC20Upgradeable, Ownable2StepUpgradeable, UUPSUpgradeable {
  // Storage order is frozen: this sits behind a proxy.
  address public minter;
  /// @notice Once true, no further upgrade can ever be authorised. One-way.
  bool public upgradesFrozen;

  event MinterChanged(address indexed previous, address indexed current);
  event UpgradesFrozen();

  error NotMinter();
  error ZeroAddress();
  error UpgradesAreFrozen();

  /// @custom:oz-upgrades-unsafe-allow constructor
  constructor() {
    _disableInitializers();
  }

  function initialize(address _owner, address _minter) external initializer {
    if (_owner == address(0) || _minter == address(0)) revert ZeroAddress();
    __ERC20_init("Sherwood Wrapped Zcash", "wZEC");
    __Ownable_init(_owner);
    __Ownable2Step_init();
    minter = _minter;
    emit MinterChanged(address(0), _minter);
  }

  modifier onlyMinter() {
    if (msg.sender != minter) revert NotMinter();
    _;
  }

  /// @notice Rotate the keeper key. Owner only, immediate: the old key stops minting now.
  function setMinter(address _minter) external onlyOwner {
    if (_minter == address(0)) revert ZeroAddress();
    emit MinterChanged(minter, _minter);
    minter = _minter;
  }

  /// @notice Mint the size the keeper just bought on Lighter, to the bridge order's
  ///         one-time address. 18 decimals; Lighter sizes ZEC to 4, the keeper scales.
  function mint(address to, uint256 amount) external onlyMinter {
    _mint(to, amount);
  }

  /// @notice Burn from the caller's own balance. Anyone: the redemption path has the
  ///         order's one-time address burn what it received, and the keeper closes the
  ///         matching size. Burning without a redemption order only shrinks your balance
  ///         and leaves the long slightly over-collateralised — harmless to everyone else.
  function burn(uint256 amount) external {
    _burn(msg.sender, amount);
  }

  /// @notice Give up the ability to upgrade this contract, forever. Irreversible on
  ///         purpose — an "unfreeze" would make the freeze meaningless.
  function renounceUpgradeability() external onlyOwner {
    upgradesFrozen = true;
    emit UpgradesFrozen();
  }

  function _authorizeUpgrade(address) internal override onlyOwner {
    if (upgradesFrozen) revert UpgradesAreFrozen();
  }

  uint256[48] private __gap;
}
