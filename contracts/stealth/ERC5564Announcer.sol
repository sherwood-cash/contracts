// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

/**
 * @notice ERC-5564: the singleton every stealth payment is announced through.
 *
 * The contract holds nothing, guards nothing and trusts nothing. Its only job is to put one
 * log on chain per stealth payment so the recipient — who is the only party that can
 * recognise it — has somewhere to look. Anyone may call it about any address, including
 * addresses that were never paid, so a consumer MUST verify an announcement against its own
 * viewing key rather than believing what it says.
 *
 * The `announce` surface is deliberately unmodified from the standard, so a payment
 * announced here is discoverable by any ERC-5564 wallet, not only ours.
 *
 * ON BEING UPGRADEABLE. This is a proxy at the owner's explicit request, and it is worth
 * naming what that costs. The reference announcer is immutable, and immutability is part of
 * what an integrator is trusting: a third-party wallet indexing this address is relying on
 * `Announcement` continuing to mean what it means today. An upgrade cannot rewrite logs
 * already emitted — those are history — but it can change what future ones contain, so the
 * admin key is a live dependency for anyone building on this. Two mitigations are in place:
 * upgrades are admin-only through a two-step admin handover, and `renounceUpgradeability`
 * below lets the owner make this contract permanently immutable once the shape has settled,
 * which is the state an announcer should end its life in.
 */
contract ERC5564Announcer is Initializable, UUPSUpgradeable {
    // Storage order is frozen: this sits behind a proxy.
    address public admin;
    address public pendingAdmin;

    /// @notice Once true, no further upgrade can ever be authorised. One-way.
    bool public upgradesFrozen;

    event AdminChanged(address indexed oldAdmin, address indexed newAdmin);
    event UpgradesFrozen();

    modifier onlyAdmin() {
        require(msg.sender == admin, "only admin");
        _;
    }

    /**
     * @param schemeId         the stealth-address scheme. 1 = SECP256k1, per the ERC.
     * @param stealthAddress   the address the funds were sent to.
     * @param caller           whoever announced it. Indexed so a consumer can filter to
     *                         announcers it trusts, but it proves nothing on its own.
     * @param ephemeralPubKey  the sender's ephemeral public key, compressed (33 bytes for
     *                         scheme 1). The recipient needs it to recompute the shared
     *                         secret.
     * @param metadata         scheme-defined. For scheme 1 byte 0 is the VIEW TAG: one byte
     *                         of the shared-secret hash, which lets a scanner reject
     *                         ~255/256 of the announcements it will never own after a single
     *                         elliptic-curve multiplication instead of two.
     */
    event Announcement(
        uint256 indexed schemeId,
        address indexed stealthAddress,
        address indexed caller,
        bytes ephemeralPubKey,
        bytes metadata
    );

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address _admin) external initializer {
        require(_admin != address(0), "admin is zero address");
        admin = _admin;
    }

    /// @notice Announce a stealth payment. Permissionless and stateless by design.
    function announce(
        uint256 schemeId,
        address stealthAddress,
        bytes calldata ephemeralPubKey,
        bytes calldata metadata
    ) external {
        emit Announcement(schemeId, stealthAddress, msg.sender, ephemeralPubKey, metadata);
    }

    /**
     * @notice Give up the ability to upgrade this contract, forever.
     *
     * The exit from the tradeoff described at the top: it turns this proxy into something an
     * integrator can trust the way they trust the reference announcer. Irreversible on
     * purpose — an "unfreeze" would make the freeze meaningless.
     */
    function renounceUpgradeability() external onlyAdmin {
        upgradesFrozen = true;
        emit UpgradesFrozen();
    }

    function transferAdmin(address _newAdmin) external onlyAdmin {
        require(_newAdmin != address(0), "new admin is zero address");
        pendingAdmin = _newAdmin;
    }

    function claimAdmin() external {
        require(msg.sender == pendingAdmin, "only pending admin");
        emit AdminChanged(admin, pendingAdmin);
        admin = pendingAdmin;
        pendingAdmin = address(0);
    }

    function _authorizeUpgrade(address) internal override onlyAdmin {
        require(!upgradesFrozen, "upgrades frozen");
    }

    uint256[46] private __gap;
}
