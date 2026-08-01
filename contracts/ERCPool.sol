// SPDX-License-Identifier: MIT

pragma solidity 0.8.24;

import "./Verifier2.sol";
import "./MerkleTreeWithHistory.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

// Pool for a single ERC-20 asset (one deployment per token).
contract ERCPool is MerkleTreeWithHistory, UUPSUpgradeable, ReentrancyGuard, PausableUpgradeable {
  using SafeERC20 for IERC20;

  int256 public constant MAX_EXT_AMOUNT = 2**248;
  uint256 public constant MAX_FEE = 2**248;
  uint256 public constant MAX_ENCRYPTED_OUTPUT_SIZE = 256;

  Verifier2 public immutable verifier2;
  IERC20 public immutable token;
  address public admin;
  address public pendingAdmin;

  uint256 public maximumDepositAmount;
  uint256 public minimumAmount;
  mapping(bytes32 => bool) public nullifierHashes;

  // no need to put tokenAddress here, since it's one contract per token
  struct ExtData {
    address recipient;
    int256 extAmount;
    address feeRecipient;
    uint256 fee;
    bytes encryptedOutput1;
    bytes encryptedOutput2;
  }

  struct Proof {
    uint[2] pA;
    uint[2][2] pB;
    uint[2] pC;
    bytes32 root;
    bytes32[2] inputNullifiers;
    bytes32[2] outputCommitments;
    uint256 publicAmount;
    bytes32 extDataHash;
  }

  event NewCommitment(bytes32 commitment, uint256 index, bytes encryptedOutput);
  event NewNullifier(bytes32 nullifier);
  event MaximumDepositAmountConfigured(uint256 maximumDepositAmount);
  event MinimumAmountConfigured(uint256 minimumAmount);
  event AdminChanged(address indexed oldAdmin, address indexed newAdmin);

  modifier onlyAdmin() {
    require(msg.sender == admin, "only admin");
    _;
  }

  /// @custom:oz-upgrades-unsafe-allow constructor
  constructor(
    Verifier2 _verifier2,
    uint32 _levels,
    address _hasher,
    IERC20 _token
  )
    MerkleTreeWithHistory(_levels, _hasher)
  {
    require(address(_token) != address(0), "token is zero address");
    verifier2 = _verifier2;
    token = _token;
    _disableInitializers();
  }

  function initialize(uint256 _maximumDepositAmount, uint256 _minimumAmount, address _admin) external initializer {
    require(_admin != address(0), "admin is zero address");
    admin = _admin;
    __Pausable_init();
    _configureMaximumDepositAmount(_maximumDepositAmount);
    _configureMinimumAmount(_minimumAmount);
    super._initialize();
  }

  function transact(Proof memory _args, ExtData memory _extData) public nonReentrant whenNotPaused {
    require(
      _extData.encryptedOutput1.length <= MAX_ENCRYPTED_OUTPUT_SIZE &&
      _extData.encryptedOutput2.length <= MAX_ENCRYPTED_OUTPUT_SIZE,
      "Encrypted output too large"
    );
    if (_extData.extAmount > 0) {
      require(uint256(_extData.extAmount) >= minimumAmount, "Amount too small");
    } else if (_extData.extAmount < 0) {
      require(uint256(-_extData.extAmount) + _extData.fee >= minimumAmount, "Amount too small");
    }
    require(isKnownRoot(_args.root), "Invalid merkle root");
    require(!isSpent(_args.inputNullifiers[0]) && !isSpent(_args.inputNullifiers[1]), "Input is already spent");
    require(uint256(_args.extDataHash) == uint256(keccak256(abi.encode(_extData))) % FIELD_SIZE, "Incorrect external data hash");
    require(_args.publicAmount == calculatePublicAmount(_extData.extAmount, _extData.fee), "Invalid public amount");
    require(verifyProof(_args), "Invalid transaction proof");

    nullifierHashes[_args.inputNullifiers[0]] = true;
    nullifierHashes[_args.inputNullifiers[1]] = true;

    // internal transfers are not allowed. if _extData.extAmount == 0, it will fail at calculatePublicAmount() above.
    if (_extData.extAmount > 0) {
      require(uint256(_extData.extAmount) <= maximumDepositAmount, "amount is larger than maximumDepositAmount");
      token.safeTransferFrom(msg.sender, address(this), uint256(_extData.extAmount));
    } else if (_extData.extAmount < 0) {
      require(_extData.recipient != address(0), "Can't withdraw to zero address");
      token.safeTransfer(_extData.recipient, uint256(-_extData.extAmount));
    }

    // fees and feeRecipient are intentionally not checked at protocol level, as a tip to the relayer
    if (_extData.fee > 0) {
      token.safeTransfer(_extData.feeRecipient, _extData.fee);
    }

    _insert(_args.outputCommitments[0], _args.outputCommitments[1]);
    emit NewCommitment(_args.outputCommitments[0], nextIndex - 2, _extData.encryptedOutput1);
    emit NewCommitment(_args.outputCommitments[1], nextIndex - 1, _extData.encryptedOutput2);
    emit NewNullifier(_args.inputNullifiers[0]);
    emit NewNullifier(_args.inputNullifiers[1]);
  }

  function transferAdmin(address _newAdmin) public onlyAdmin {
    require(_newAdmin != address(0), "new admin is zero address");
    pendingAdmin = _newAdmin;
  }

  function claimAdmin() public {
    require(msg.sender == pendingAdmin, "not pending admin");
    emit AdminChanged(admin, pendingAdmin);
    admin = pendingAdmin;
    pendingAdmin = address(0);
  }

  function pause() public onlyAdmin {
    _pause();
  }

  function unpause() public onlyAdmin {
    _unpause();
  }

  function configureMaximumDepositAmount(uint256 _maximumDepositAmount) public onlyAdmin {
    _configureMaximumDepositAmount(_maximumDepositAmount);
  }

  function configureMinimumAmount(uint256 _minimumAmount) public onlyAdmin {
    _configureMinimumAmount(_minimumAmount);
  }

  function calculatePublicAmount(int256 _extAmount, uint256 _fee) public pure returns (uint256) {
    require(_fee < MAX_FEE, "Invalid fee");
    require(_extAmount > -MAX_EXT_AMOUNT && _extAmount < MAX_EXT_AMOUNT, "Invalid ext amount");
    require((_extAmount > 0 && uint256(_extAmount) > _fee) || (_extAmount < 0 && uint256(-_extAmount) > _fee), "ext amount must exceed fee for deposits");
    int256 publicAmount = _extAmount - int256(_fee);
    return (publicAmount >= 0) ? uint256(publicAmount) : FIELD_SIZE - uint256(-publicAmount);
  }

  function isSpent(bytes32 _nullifierHash) public view returns (bool) {
    return nullifierHashes[_nullifierHash];
  }

  function isSpentArray(bytes32[] calldata _nullifierHashes) external view returns (bool[] memory spent) {
    spent = new bool[](_nullifierHashes.length);
    for (uint256 i = 0; i < _nullifierHashes.length; i++) {
      spent[i] = nullifierHashes[_nullifierHashes[i]];
    }
  }

  function verifyProof(Proof memory _args) public view returns (bool) {
    return
      verifier2.verifyProof(
        _args.pA,
        _args.pB,
        _args.pC,
        [
          uint256(_args.root),
          _args.publicAmount,
          uint256(_args.extDataHash),
          uint256(_args.inputNullifiers[0]),
          uint256(_args.inputNullifiers[1]),
          uint256(_args.outputCommitments[0]),
          uint256(_args.outputCommitments[1])
        ]
      );
  }

  function _configureMaximumDepositAmount(uint256 _maximumDepositAmount) internal {
    require(minimumAmount <= _maximumDepositAmount, "min exceeds max");
    maximumDepositAmount = _maximumDepositAmount;
    emit MaximumDepositAmountConfigured(_maximumDepositAmount);
  }

  function _configureMinimumAmount(uint256 _minimumAmount) internal {
    require(_minimumAmount <= maximumDepositAmount, "min exceeds max");
    minimumAmount = _minimumAmount;
    emit MinimumAmountConfigured(_minimumAmount);
  }

  function _authorizeUpgrade(address) internal override onlyAdmin {}
}
