// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

interface ISherwoodVault {
    struct Proof {
        uint256[2] pA;
        uint256[2][2] pB;
        uint256[2] pC;
        bytes32 root;
        bytes32[2] inputNullifiers;
        bytes32[2] outputCommitments;
        uint256 publicAmount;
        bytes32 extDataHash;
    }

    struct ExtData {
        address recipient;
        int256 extAmount;
        address feeRecipient;
        uint256 fee;
        bytes encryptedOutput1;
        bytes encryptedOutput2;
        bytes32 swapParamsHash;
    }

    function transact(uint256 assetId, uint32 inEpoch, Proof memory args, ExtData memory extData) external payable;

    function assetToken(uint256 assetId) external view returns (address);
}

/// @dev EIP-3009. `receiveWithAuthorization` is the front-running-safe half of the standard:
///      the token itself requires `to == msg.sender`, so an authorisation lifted from the
///      mempool cannot be replayed by anyone but its intended recipient.
interface IERC3009 {
    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;
}

/// @dev EIP-2612, the fallback for a token that has permit but not 3009.
interface IERC2612 {
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;
}

/**
 * @notice Deposits an ERC-20 into the Sherwood vault on behalf of an address that holds no
 *         gas — which is every stealth address that has only ever been paid in USDG.
 *
 * THE PROBLEM. A stealth address is generated, paid, and then sits there. If it was paid in
 * ETH it can pay for its own deposit; if it was paid only in USDG it holds no gas at all,
 * and the vault's only entrypoint pulls the deposit principal from `msg.sender`. So the
 * money is visible, spendable in principle, and stuck in practice. The obvious fix — send
 * the stealth address a little ETH for gas — is the one thing that must never happen: the
 * funding transaction publicly links the payer's wallet to the stealth address and undoes
 * the entire point of having generated one.
 *
 * THE FIX. The stealth key SIGNS rather than SPENDS. It signs an EIP-3009 authorisation (or
 * an EIP-2612 permit) moving its tokens to this contract; a relayer submits it and pays the
 * gas; this contract deposits the proceeds into the vault and is repaid out of the deposit
 * itself, through the vault's own `ExtData.fee`. No ETH ever has to reach the stealth
 * address, so nothing ever has to be sent to it, so nothing links it to anyone.
 *
 * WHY THE FEE RIDES ON ExtData.fee RATHER THAN A TRANSFER HERE. The vault already pays
 * `ExtData.fee` to `ExtData.feeRecipient` out of a deposit, in the deposited token. Routing
 * the relayer's payment through it means the note is minted for `extAmount - fee` in the
 * same transaction that pays for its own submission, and this contract never has to hold a
 * balance or be trusted to hand one back.
 *
 * CUSTODY. None. Every function pulls, approves, deposits and settles inside a single call,
 * and `_sweep` returns any dust the vault did not take to the address that authorised the
 * transfer — never to the caller. A relayer that tries to keep more than the fee the
 * signature commits to fails the `extAmount`/`fee` reconciliation below.
 */
contract StealthDepositForwarder is Initializable, UUPSUpgradeable {
    using SafeERC20 for IERC20;

    // Storage order is frozen from here down: this sits behind a proxy, and moving a slot
    // reinterprets what is already written rather than migrating it.
    address public admin;
    address public pendingAdmin;

    /**
     * @notice The vault deposits are routed into.
     *
     * Storage, not immutable. An immutable lives in the implementation's bytecode, so an
     * upgrade would silently reset it to whatever the NEW implementation was constructed
     * with — and a forwarder pointing at the wrong vault approves and deposits real money
     * into it.
     */
    ISherwoodVault public vault;

    event AdminChanged(address indexed oldAdmin, address indexed newAdmin);
    event VaultChanged(address indexed oldVault, address indexed newVault);

    modifier onlyAdmin() {
        require(msg.sender == admin, "only admin");
        _;
    }

    error AmountMismatch(int256 extAmount, uint256 authorised);
    error FeeExceedsPrincipal(uint256 fee, uint256 value);
    error WrongFeeRecipient(address expected, address actual);
    error WrongAsset(address expected, address actual);
    error NotADeposit(int256 extAmount);

    event StealthDeposit(
        address indexed from,
        uint256 indexed assetId,
        uint256 value,
        uint256 fee,
        address indexed relayer
    );

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address _admin, ISherwoodVault _vault) external initializer {
        require(_admin != address(0), "admin is zero address");
        require(address(_vault) != address(0), "vault is zero address");
        admin = _admin;
        vault = _vault;
    }

    /// @notice Repoint at a new vault. Holds nothing between calls, so this strands no funds.
    function setVault(ISherwoodVault _vault) external onlyAdmin {
        require(address(_vault) != address(0), "vault is zero address");
        emit VaultChanged(address(vault), address(_vault));
        vault = _vault;
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

    /**
     * @notice Deposit `value` of an EIP-3009 token from `from`, authorised by `from`'s own
     *         signature, paying the caller `extData.fee` out of the deposit.
     *
     * The preferred path. `receiveWithAuthorization` names this contract as the recipient
     * inside the signed payload, so the authorisation is worthless to anyone else even if
     * it is seen in the mempool — unlike a permit, which grants an allowance any observer
     * can race to spend.
     *
     * @param assetId   the vault's asset id for this token.
     * @param from      the stealth address being swept. Never `msg.sender`.
     * @param value     the total pulled from `from`. Must equal `extData.extAmount`, so the
     *                  proof the user built and the tokens actually moved cannot disagree.
     * @param auth      (validAfter, validBefore, nonce) of the EIP-3009 authorisation.
     */
    function depositWithAuthorization(
        uint256 assetId,
        address from,
        uint256 value,
        uint256[3] calldata auth,
        uint8 v,
        bytes32 r,
        bytes32 s,
        uint32 inEpoch,
        ISherwoodVault.Proof calldata proof,
        ISherwoodVault.ExtData calldata extData
    ) external {
        address token = _check(assetId, value, extData);

        // Pulls exactly `value` to this contract. Reverts if the signature does not cover
        // (from, this, value, window, nonce), if it is outside its window, or if the nonce
        // was already used — so this call is not replayable.
        IERC3009(token).receiveWithAuthorization(
            from,
            address(this),
            value,
            auth[0],
            auth[1],
            bytes32(auth[2]),
            v,
            r,
            s
        );

        _deposit(assetId, token, from, value, inEpoch, proof, extData);
    }

    /**
     * @notice The same, for a token that implements EIP-2612 `permit` but not EIP-3009.
     *
     * Kept as a fallback rather than the default because a permit is front-runnable: the
     * allowance it grants is to this contract, so an observer who replays it early can only
     * grant that same allowance — annoying (the user's permit is then spent and must be
     * re-signed) but not a theft. `receiveWithAuthorization` has neither problem, so use it
     * when the token has it.
     */
    function depositWithPermit(
        uint256 assetId,
        address from,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s,
        uint32 inEpoch,
        ISherwoodVault.Proof calldata proof,
        ISherwoodVault.ExtData calldata extData
    ) external {
        address token = _check(assetId, value, extData);

        // Tolerated rather than required: if the permit was already submitted (front-run,
        // or retried after a dropped transaction) the allowance is already there and the
        // deposit should still go through. The transferFrom below is what actually has to
        // succeed, and it is not fooled by a failed permit.
        try IERC2612(token).permit(from, address(this), value, deadline, v, r, s) {} catch {}

        IERC20(token).safeTransferFrom(from, address(this), value);

        _deposit(assetId, token, from, value, inEpoch, proof, extData);
    }

    // ---------------------------------------------------------------------------- internals

    /// @dev Everything that must hold before a single token moves.
    function _check(
        uint256 assetId,
        uint256 value,
        ISherwoodVault.ExtData calldata extData
    ) internal view returns (address token) {
        if (extData.extAmount <= 0) revert NotADeposit(extData.extAmount);
        // The proof commits to extAmount. Pulling a different number would either strand
        // tokens here or mint a note the deposit does not back, so they must be equal.
        if (uint256(extData.extAmount) != value) revert AmountMismatch(extData.extAmount, value);
        if (extData.fee > value) revert FeeExceedsPrincipal(extData.fee, value);

        token = vault.assetToken(assetId);
        if (token == address(0)) revert WrongAsset(address(0), token);
    }

    function _deposit(
        uint256 assetId,
        address token,
        address from,
        uint256 value,
        uint32 inEpoch,
        ISherwoodVault.Proof calldata proof,
        ISherwoodVault.ExtData calldata extData
    ) internal {
        // forceApprove, not approve: USDT-style tokens revert on a non-zero-to-non-zero
        // allowance change, and a leftover allowance from a reverted call would brick
        // every later deposit of that token.
        IERC20(token).forceApprove(address(vault), value);

        vault.transact(assetId, inEpoch, _toMemory(proof), _toMemory(extData));

        // The vault pulls `value` and pays `fee` from its own balance, so nothing should be
        // left — but an allowance that outlives the call is a standing grant, and a token
        // that did not take everything must not silently become this contract's property.
        IERC20(token).forceApprove(address(vault), 0);
        _sweep(token, from);

        emit StealthDeposit(from, assetId, value, extData.fee, msg.sender);
    }

    /// @dev Anything the vault left goes back to the address that authorised it, not the caller.
    function _sweep(address token, address to) internal {
        uint256 dust = IERC20(token).balanceOf(address(this));
        if (dust > 0) IERC20(token).safeTransfer(to, dust);
    }

    function _toMemory(ISherwoodVault.Proof calldata p) internal pure returns (ISherwoodVault.Proof memory) {
        return p;
    }

    function _toMemory(ISherwoodVault.ExtData calldata e) internal pure returns (ISherwoodVault.ExtData memory) {
        return e;
    }

    function _authorizeUpgrade(address) internal override onlyAdmin {}

    uint256[46] private __gap;
}
