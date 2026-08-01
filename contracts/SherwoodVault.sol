// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "./Verifier2.sol";
import "./MultiAssetMerkleTree.sol";
import "./dex/ISwapLogic.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

interface IHasher4 {
  function poseidon(bytes32[4] calldata inputs) external pure returns (bytes32);
}

interface IWETH is IERC20 {
  function deposit() external payable;
  function withdraw(uint256) external;
}

/**
 * @title SherwoodVault
 * @notice IMMUTABLE, NON-UPGRADABLE sole custodian of all funds (ETH + ERC20) for
 *         the Robinhood privacy mixer + private DEX. There is NO proxy and NO UUPS
 *         here: this contract's code can never change, so deposited TVL can only ever
 *         move via a valid user withdrawal ZK proof.
 *
 *         Responsibilities held IMMUTABLY in this layer:
 *           - the per-asset Merkle trees, nullifiers, Verifier2 and Poseidon-4 hasher;
 *           - deposit/withdraw via ZK proof (`transact`);
 *           - `executeSwap`: the ONLY swap fund path. The vault verifies the input-note
 *             withdrawal proof, pulls EXACTLY the authorized amountIn, asks the
 *             (upgradable) SwapLogic to BUILD the router calldata, re-checks the router
 *             against the VAULT-HELD allowlist, performs the external call itself, and
 *             mints the output note from the REAL measured balance delta;
 *           - the router allowlist (2-step timelocked), so a malicious SwapLogic upgrade
 *             cannot redirect amountIn to an attacker router;
 *           - the SwapLogic address pointer (2-step timelocked).
 *
 *         The vault NEVER delegatecalls SwapLogic — only external calls / staticcalls —
 *         so no upgradable code ever gains write access to vault storage or funds.
 *
 *         INVARIANT (proved in tests): funds at rest can NEVER be moved by a SwapLogic
 *         upgrade. Worst case for a malicious upgrade is bounded to in-flight-swap
 *         slippage on the single authorized amountIn, and even that reverts via minOut.
 */
contract SherwoodVault is MultiAssetMerkleTree, ReentrancyGuard {
  using SafeERC20 for IERC20;

  int256 public constant MAX_EXT_AMOUNT = 2**248;
  uint256 public constant MAX_FEE = 2**248;
  uint256 public constant MAX_ENCRYPTED_OUTPUT_SIZE = 256;

  // Native ETH sentinel: assetId = 1, token address = address(0).
  uint256 public constant NATIVE_ASSET_ID = 1;

  // Delay (in seconds) between proposing and enabling a router / SwapLogic change.
  // Set to 0: config is still 2-step (a proposal must exist before it can be
  // enabled), but takes effect immediately with no waiting period.
  uint256 public constant CONFIG_TIMELOCK = 0;

  // ---- Protocol fee ----
  // Fee is a fixed rate in basis points, set by the admin and changeable at any time,
  // but HARD-CAPPED so a fee change can never become a rug vector (anti-FUD).
  uint256 public constant BPS_DENOMINATOR = 10_000;
  uint256 public constant MAX_PROTOCOL_FEE_BPS = 1_000; // 10% ceiling, immutable
  uint256 public protocolFeeBps; // current fee rate (<= MAX_PROTOCOL_FEE_BPS)
  address public protocolFeeRecipient; // where protocol fees accrue

  // "Base"/fee assets: the currencies the protocol fee is denominated in. Native ETH
  // (address(0)) is always a base asset; the admin enables others (e.g. USDG) by address.
  // On a swap the fee is taken on whichever side is a base asset (input first).
  mapping(address => bool) public feeAsset;

  Verifier2 public immutable verifier2;
  IHasher4 public immutable hasher4;
  IWETH public immutable weth;

  address public admin;
  address public pendingAdmin;

  // The UUPS proxy address of SwapLogic. Stable across logic upgrades. 2-step + timelock.
  address public swapLogic;
  address public pendingSwapLogic;
  uint256 public swapLogicETA;

  // assetId => token address (address(0) for native ETH)
  mapping(uint256 => address) public assetToken;
  mapping(uint256 => bool) public assetRegistered;

  mapping(bytes32 => bool) public nullifierHashes;

  // ---- Router allowlist, held IMMUTABLY IN THE VAULT (source of truth) ----
  // version => router => allowed
  mapping(ISwapLogic.Version => mapping(address => bool)) public routerAllowed;
  // version => canonical router used for execution (last one enabled)
  mapping(ISwapLogic.Version => address) public canonicalRouter;
  // proposal key (version, router) => ETA at which it may be enabled
  mapping(bytes32 => uint256) public routerProposalETA;

  struct ExtData {
    address recipient;
    int256 extAmount;
    address feeRecipient;
    uint256 fee;
    bytes encryptedOutput1;
    bytes encryptedOutput2;
    // keccak256(abi.encode(SwapParams)) for `executeSwap`, or bytes32(0) for `transact`.
    // ExtData is what `extDataHash` (a proof public input) commits to, so putting the
    // swap params' digest here is what makes the SWAP DESTINATION part of the signed
    // statement. Without it the proof authorizes "withdraw amountIn to the vault" and
    // says nothing about who receives the proceeds, letting anyone replay the proof
    // with their own outPubkey / minOut / routeData. See _requireSwapParams.
    bytes32 swapParamsHash;
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

  // Swap parameters: the input note is spent via `proof`/`extData` (recipient = this),
  // and only the OUTPUT note's ownership fields (pubkey P, blinding r) are supplied.
  struct SwapParams {
    uint256 assetIn; // asset being spent (must match extData/proof tree)
    address tokenOut; // ERC20 out, or address(0) for native ETH
    ISwapLogic.Version version;
    bytes routeData;
    uint256 minOut; // slippage floor; tx reverts if Y < minOut
    uint256 deadline;
    bytes32 outPubkey; // P: one-time stealth key of the output note
    bytes32 outBlinding; // r: blinding of the output note
    bytes encryptedOutput; // encrypted output note for wallet recovery
  }

  event NewCommitment(uint256 indexed assetId, bytes32 commitment, uint256 index, bytes encryptedOutput);
  event NewNullifier(bytes32 nullifier);
  event TokenRegistered(uint256 indexed assetId, address indexed token);
  event AdminChanged(address indexed oldAdmin, address indexed newAdmin);
  event Swap(uint256 indexed assetIn, uint256 indexed assetOut, uint256 amountIn, uint256 amountOut, bytes32 commitment);

  event RouterProposed(ISwapLogic.Version indexed version, address indexed router, uint256 eta);
  event RouterConfigured(ISwapLogic.Version indexed version, address indexed router, bool allowed);
  event SwapLogicProposed(address indexed newLogic, uint256 eta);
  event SwapLogicSet(address indexed oldLogic, address indexed newLogic);
  event ProtocolFeeSet(uint256 bps);
  event ProtocolFeeRecipientSet(address indexed recipient);
  event ProtocolFeeCharged(uint256 indexed assetId, address token, uint256 amount);
  event FeeAssetSet(address indexed token, bool enabled);

  modifier onlyAdmin() {
    require(msg.sender == admin, "only admin");
    _;
  }

  constructor(
    Verifier2 _verifier2,
    uint32 _levels,
    address _hasher,
    address _hasher4,
    address _weth,
    address _admin
  ) MultiAssetMerkleTree(_levels, _hasher) {
    require(_admin != address(0), "admin is zero address");
    require(_hasher4 != address(0), "hasher4 is zero address");
    require(_weth != address(0), "weth is zero address");
    verifier2 = _verifier2;
    hasher4 = IHasher4(_hasher4);
    weth = IWETH(_weth);
    admin = _admin;

    // Native ETH tree is always available.
    _registerAsset(NATIVE_ASSET_ID, address(0));
  }

  // ------------------------------------------------------------- registration

  /// @notice Register an ERC20 token, initializing its Merkle tree. assetId = uint160(token).
  function registerToken(address token) external onlyAdmin returns (uint256 assetId) {
    require(token != address(0), "token is zero address");
    assetId = uint256(uint160(token));
    require(assetId != NATIVE_ASSET_ID, "reserved asset id");
    _registerAsset(assetId, token);
  }

  function _registerAsset(uint256 assetId, address token) internal {
    require(!assetRegistered[assetId], "already registered");
    assetRegistered[assetId] = true;
    assetToken[assetId] = token;
    _initTree(assetId);
    emit TokenRegistered(assetId, token);
  }

  function assetIdOf(address token) public pure returns (uint256) {
    return token == address(0) ? NATIVE_ASSET_ID : uint256(uint160(token));
  }

  // ------------------------------------------------------------- config (2-step + timelock)

  /// @notice Step 1: propose enabling a router for `version`. Starts the timelock.
  function proposeRouter(ISwapLogic.Version version, address router) external onlyAdmin {
    require(router != address(0), "router is zero address");
    uint256 eta = block.timestamp + CONFIG_TIMELOCK;
    routerProposalETA[_routerKey(version, router)] = eta;
    emit RouterProposed(version, router, eta);
  }

  /// @notice Step 2: enable a router after its timelock elapses.
  function enableRouter(ISwapLogic.Version version, address router) external onlyAdmin {
    require(router != address(0), "router is zero address");
    bytes32 key = _routerKey(version, router);
    uint256 eta = routerProposalETA[key];
    require(eta != 0 && block.timestamp >= eta, "router timelock");
    routerProposalETA[key] = 0;
    routerAllowed[version][router] = true;
    canonicalRouter[version] = router;
    emit RouterConfigured(version, router, true);
  }

  /// @notice Disabling a router is immediate (safety action, never adds trust).
  function disableRouter(ISwapLogic.Version version, address router) external onlyAdmin {
    require(router != address(0), "router is zero address");
    routerAllowed[version][router] = false;
    if (canonicalRouter[version] == router) {
      canonicalRouter[version] = address(0);
    }
    emit RouterConfigured(version, router, false);
  }

  function isRouterAllowed(ISwapLogic.Version version, address router) external view returns (bool) {
    return routerAllowed[version][router];
  }

  /// @notice Step 1: propose a new SwapLogic proxy address. Starts the timelock.
  function proposeSwapLogic(address newLogic) external onlyAdmin {
    require(newLogic != address(0), "logic is zero address");
    pendingSwapLogic = newLogic;
    swapLogicETA = block.timestamp + CONFIG_TIMELOCK;
    emit SwapLogicProposed(newLogic, swapLogicETA);
  }

  /// @notice Step 2: adopt the proposed SwapLogic after its timelock elapses.
  function setSwapLogic() external onlyAdmin {
    require(pendingSwapLogic != address(0), "no pending logic");
    require(swapLogicETA != 0 && block.timestamp >= swapLogicETA, "logic timelock");
    emit SwapLogicSet(swapLogic, pendingSwapLogic);
    swapLogic = pendingSwapLogic;
    pendingSwapLogic = address(0);
    swapLogicETA = 0;
  }

  function transferAdmin(address _newAdmin) external onlyAdmin {
    require(_newAdmin != address(0), "new admin is zero address");
    pendingAdmin = _newAdmin;
  }

  function claimAdmin() external {
    require(msg.sender == pendingAdmin, "not pending admin");
    emit AdminChanged(admin, pendingAdmin);
    admin = pendingAdmin;
    pendingAdmin = address(0);
  }

  function _routerKey(ISwapLogic.Version version, address router) internal pure returns (bytes32) {
    return keccak256(abi.encode(version, router));
  }

  // ------------------------------------------------------------- protocol fee (admin)

  /// @notice Set the protocol fee rate in bps. Changeable at any time by the admin,
  ///         but bounded by MAX_PROTOCOL_FEE_BPS so it can never be weaponised.
  function setProtocolFee(uint256 bps) external onlyAdmin {
    require(bps <= MAX_PROTOCOL_FEE_BPS, "fee too high");
    require(bps == 0 || protocolFeeRecipient != address(0), "recipient unset");
    protocolFeeBps = bps;
    emit ProtocolFeeSet(bps);
  }

  /// @notice Set where protocol fees accrue.
  function setProtocolFeeRecipient(address recipient) external onlyAdmin {
    require(recipient != address(0), "recipient is zero address");
    protocolFeeRecipient = recipient;
    emit ProtocolFeeRecipientSet(recipient);
  }

  /// @notice Enable/disable a token as a base (fee) asset, e.g. USDG. Native ETH is
  ///         always a base asset and does not need to be set here.
  function setFeeAsset(address token, bool enabled) external onlyAdmin {
    require(token != address(0), "native always base");
    feeAsset[token] = enabled;
    emit FeeAssetSet(token, enabled);
  }

  /// @dev Whether `token` is a base/fee asset (native ETH always is).
  function _isFeeAsset(address token) internal view returns (bool) {
    return token == address(0) || feeAsset[token];
  }

  /// @dev The protocol fee owed on `amount` (0 if fee disabled or no recipient set).
  function _protocolFee(uint256 amount) internal view returns (uint256) {
    if (protocolFeeBps == 0 || protocolFeeRecipient == address(0)) return 0;
    return (amount * protocolFeeBps) / BPS_DENOMINATOR;
  }

  /// @dev Pay `fee` of `token` (address(0)=native ETH) to the protocol fee recipient.
  function _payProtocolFee(uint256 assetId, address token, uint256 fee) internal {
    if (fee == 0) return;
    if (token == address(0)) {
      (bool ok, ) = protocolFeeRecipient.call{value: fee}("");
      require(ok, "fee transfer failed");
    } else {
      IERC20(token).safeTransfer(protocolFeeRecipient, fee);
    }
    emit ProtocolFeeCharged(assetId, token, fee);
  }

  // ------------------------------------------------------------- transact

  /// @notice Deposit/withdraw of a single asset. Binds the transferred asset to its
  ///         tree via isKnownRoot(assetId, root): a proof only releases the asset
  ///         whose tree it proves membership in. Fund release is ONLY against a valid proof.
  function transact(uint256 assetId, Proof memory _args, ExtData memory _extData) public payable nonReentrant {
    // Domain separation: a `transact` proof must never be replayable as a swap. Pinning
    // the field to zero here means the two paths can never produce the same extDataHash
    // for the same funds movement.
    require(_extData.swapParamsHash == bytes32(0), "swapParamsHash must be zero");
    _verifyAndConsume(assetId, _args, _extData);

    address token = assetToken[assetId];
    bool isNative = token == address(0);

    if (_extData.extAmount > 0) {
      uint256 amt = uint256(_extData.extAmount);
      if (isNative) {
        require(msg.value == amt, "Incorrect ETH value");
      } else {
        require(msg.value == 0, "Unexpected ETH value");
        IERC20(token).safeTransferFrom(msg.sender, address(this), amt);
      }
    } else if (_extData.extAmount < 0) {
      require(_extData.recipient != address(0), "Can't withdraw to zero address");
      uint256 amt = uint256(-_extData.extAmount);
      // Protocol fee is charged on withdrawals, in the withdrawn asset.
      uint256 pFee = _protocolFee(amt);
      uint256 net = amt - pFee;
      if (isNative) {
        require(msg.value == 0, "Cannot send ETH during withdrawal");
        (bool ok, ) = _extData.recipient.call{value: net}("");
        require(ok, "ETH transfer failed");
      } else {
        require(msg.value == 0, "Unexpected ETH value");
        IERC20(token).safeTransfer(_extData.recipient, net);
      }
      _payProtocolFee(assetId, token, pFee);
    }

    if (_extData.fee > 0) {
      if (isNative) {
        (bool ok, ) = _extData.feeRecipient.call{value: _extData.fee}("");
        require(ok, "Fee transfer failed");
      } else {
        IERC20(token).safeTransfer(_extData.feeRecipient, _extData.fee);
      }
    }

    _insert(assetId, _args.outputCommitments[0], _args.outputCommitments[1]);
    uint32 idx = nextIndex(assetId);
    emit NewCommitment(assetId, _args.outputCommitments[0], idx - 2, _extData.encryptedOutput1);
    emit NewCommitment(assetId, _args.outputCommitments[1], idx - 1, _extData.encryptedOutput2);
    emit NewNullifier(_args.inputNullifiers[0]);
    emit NewNullifier(_args.inputNullifiers[1]);
  }

  /// @dev Shared proof verification + nullifier consumption for transact and executeSwap.
  function _verifyAndConsume(uint256 assetId, Proof memory _args, ExtData memory _extData) internal {
    require(assetRegistered[assetId], "asset not registered");
    require(
      _extData.encryptedOutput1.length <= MAX_ENCRYPTED_OUTPUT_SIZE &&
        _extData.encryptedOutput2.length <= MAX_ENCRYPTED_OUTPUT_SIZE,
      "Encrypted output too large"
    );
    require(isKnownRoot(assetId, _args.root), "Invalid merkle root");
    require(!isSpent(_args.inputNullifiers[0]) && !isSpent(_args.inputNullifiers[1]), "Input is already spent");
    require(
      uint256(_args.extDataHash) == uint256(keccak256(abi.encode(_extData))) % FIELD_SIZE,
      "Incorrect external data hash"
    );
    require(_args.publicAmount == calculatePublicAmount(_extData.extAmount, _extData.fee), "Invalid public amount");
    require(verifyProof(_args), "Invalid transaction proof");

    nullifierHashes[_args.inputNullifiers[0]] = true;
    nullifierHashes[_args.inputNullifiers[1]] = true;
  }

  /// @dev Enforce that the supplied SwapParams are exactly the ones the prover committed
  ///      to. `_extData.swapParamsHash` is inside ExtData, ExtData is keccak'd into
  ///      `_args.extDataHash` (checked in _verifyAndConsume), and extDataHash is a public
  ///      input of the SNARK — so a tampered p makes the whole tx unprovable, not just
  ///      mismatched. The full struct is hashed, encryptedOutput included, so a relayer
  ///      cannot even garble the recovery blob into an unspendable note.
  function _requireSwapParams(ExtData memory _extData, SwapParams memory p) internal pure {
    require(_extData.swapParamsHash == keccak256(abi.encode(p)), "swap params tampered");
  }

  // ------------------------------------------------------------- executeSwap

  /**
   * @notice The ONLY swap fund path. Spends an input-asset note (withdrawal proof,
   *         recipient = this vault), routes the withdrawn amountIn through a
   *         VAULT-ALLOWLISTED router (calldata built by SwapLogic), and mints the
   *         output note from the REAL measured balance delta of tokenOut.
   *
   * @dev Fund safety comes from THIS contract (immutable):
   *      - amountIn is exactly the user-authorized withdrawn amount (from the proof);
   *      - the SwapParams (destination pubkey, route, minOut, deadline) are committed to
   *        by that same proof via extData.swapParamsHash, so the submitter — relayer or
   *        front-running searcher — cannot redirect the proceeds to a note they own;
   *      - the router is re-checked against the vault-held allowlist AFTER SwapLogic
   *        builds the route, so no logic upgrade can redirect to an attacker router;
   *      - SwapLogic is only STATICCALLED (buildRoute is view) — never delegatecalled —
   *        so it can never touch vault storage or idle TVL;
   *      - the external swap call is performed BY THE VAULT; output is measured here;
   *      - if measured Y < minOut the whole tx reverts atomically (input note unspent).
   */
  function executeSwap(Proof memory _args, ExtData memory _extData, SwapParams memory p)
    external
    nonReentrant
    returns (uint256 amountOut)
  {
    require(swapLogic != address(0), "swapLogic unset");
    // Bind p to the proof BEFORE anything is derived from it (assetIdOf/_registerAsset
    // below already read p.tokenOut). Past this line every field of p is covered by
    // extDataHash, hence by the ZK proof: tokenOut, routeData, minOut, deadline and —
    // critically — outPubkey/outBlinding, which decide who owns the swap proceeds.
    _requireSwapParams(_extData, p);
    uint256 assetOut = assetIdOf(p.tokenOut);
    // Lazily register the output asset's tree on first use, so a swap can target
    // ANY token without a prior admin `registerToken`. Registration only inits an
    // empty, per-asset Merkle namespace (+ records tokenOut for later withdraw)
    // and emits TokenRegistered; it grants no funds and, on a revert later in this
    // call, rolls back atomically. Native ETH (assetOut == NATIVE_ASSET_ID) is
    // registered in the constructor, so this branch only ever hits real ERC20s.
    if (!assetRegistered[assetOut]) {
      _registerAsset(assetOut, p.tokenOut);
    }
    require(_extData.recipient == address(this), "recipient must be vault");
    require(_extData.extAmount < 0, "must be a withdrawal");
    require(p.encryptedOutput.length <= MAX_ENCRYPTED_OUTPUT_SIZE, "Encrypted output too large");

    // ---- verify + consume the input note (identical checks to transact) ----
    _verifyAndConsume(p.assetIn, _args, _extData);

    uint256 amountIn = uint256(-_extData.extAmount);
    address tokenIn = assetToken[p.assetIn];

    // Mint the change note back into the INPUT asset's tree (2-in/2-out invariant).
    _insert(p.assetIn, _args.outputCommitments[0], _args.outputCommitments[1]);
    {
      uint32 idx = nextIndex(p.assetIn);
      emit NewCommitment(p.assetIn, _args.outputCommitments[0], idx - 2, _extData.encryptedOutput1);
      emit NewCommitment(p.assetIn, _args.outputCommitments[1], idx - 1, _extData.encryptedOutput2);
    }
    emit NewNullifier(_args.inputNullifiers[0]);
    emit NewNullifier(_args.inputNullifiers[1]);

    // Optional relayer fee is paid out of the withdrawn amount before swapping.
    if (_extData.fee > 0) {
      if (tokenIn == address(0)) {
        (bool ok, ) = _extData.feeRecipient.call{value: _extData.fee}("");
        require(ok, "Fee transfer failed");
      } else {
        IERC20(tokenIn).safeTransfer(_extData.feeRecipient, _extData.fee);
      }
    }

    // ---- protocol fee ----
    // The fee is denominated in a base asset (ETH or e.g. USDG) and taken on whichever
    // side is a base asset: on the INPUT before swapping when tokenIn is a base asset
    // (buying with ETH/USDG), otherwise on the swap PROCEEDS before minting the output
    // note (selling a token to ETH/USDG, or a token->token fallback in tokenOut).
    bool inIsBase = _isFeeAsset(tokenIn);
    uint256 swapAmountIn = amountIn;
    if (inIsBase) {
      uint256 feeIn = _protocolFee(amountIn);
      if (feeIn > 0) {
        swapAmountIn = amountIn - feeIn;
        _payProtocolFee(p.assetIn, tokenIn, feeIn);
      }
    }

    // ---- route + execute the swap, measuring the REAL balance delta ----
    amountOut = _routeAndSwap(p, tokenIn, swapAmountIn);

    if (!inIsBase) {
      uint256 feeOut = _protocolFee(amountOut);
      if (feeOut > 0) {
        amountOut -= feeOut;
        _payProtocolFee(assetOut, p.tokenOut, feeOut);
      }
    }

    require(amountOut >= p.minOut, "insufficient output");
    require(amountOut > 0, "zero output");

    // ---- mint the output note: C_out = Poseidon4(Y, P, r, assetId(tokenOut)) ----
    bytes32 commitment = _poseidon4(bytes32(amountOut), p.outPubkey, p.outBlinding, bytes32(assetOut));
    bytes32 emptyLeaf = _poseidon4(bytes32(0), p.outPubkey, bytes32(0), bytes32(assetOut));
    _insert(assetOut, commitment, emptyLeaf);
    {
      uint32 idx = nextIndex(assetOut);
      emit NewCommitment(assetOut, commitment, idx - 2, p.encryptedOutput);
      emit NewCommitment(assetOut, emptyLeaf, idx - 1, "");
    }

    emit Swap(p.assetIn, assetOut, amountIn, amountOut, commitment);
  }

  /**
   * @dev The vault operates in pure ERC20 terms with routers: it wraps native ETH to
   *      WETH before the call and unwraps WETH after. It asks SwapLogic to BUILD the
   *      router calldata, RE-CHECKS the router against its own allowlist, performs the
   *      call itself, and measures the tokenOut balance delta.
   */
  function _routeAndSwap(SwapParams memory p, address tokenIn, uint256 amountIn) internal returns (uint256) {
    address canonical = canonicalRouter[p.version];
    require(canonical != address(0) && routerAllowed[p.version][canonical], "router not whitelisted");

    address effectiveIn = tokenIn == address(0) ? address(weth) : tokenIn;
    address effectiveOut = p.tokenOut == address(0) ? address(weth) : p.tokenOut;

    // Wrap native ETH input to WETH so the vault deals only in ERC20 with the router.
    if (tokenIn == address(0)) {
      weth.deposit{value: amountIn}();
    }

    // Build the route via the upgradable logic (STATICCALL — buildRoute is view).
    ISwapLogic.SwapRequest memory req = ISwapLogic.SwapRequest({
      version: p.version,
      routeData: p.routeData,
      tokenIn: tokenIn,
      tokenOut: p.tokenOut,
      weth: address(weth),
      router: canonical,
      amountIn: amountIn,
      minOut: p.minOut,
      deadline: p.deadline,
      recipient: address(this)
    });
    ISwapLogic.RouteInstruction memory ins = ISwapLogic(swapLogic).buildRoute(req);

    // CRITICAL: re-validate the router the logic returned against the VAULT allowlist.
    // This is what makes a malicious logic upgrade unable to redirect amountIn.
    require(ins.router == canonical, "router mismatch");
    require(routerAllowed[p.version][ins.router], "router not whitelisted");
    // The vault never forwards raw ETH to routers; it always uses WETH via approval.
    require(ins.callValue == 0, "no eth to router");
    require(ins.approveToken == effectiveIn, "bad approve token");
    require(ins.approveAmount == amountIn, "bad approve amount");

    uint256 balBefore = IERC20(effectiveOut).balanceOf(address(this));

    // Approve exactly amountIn, perform the swap, then reset approval.
    IERC20(effectiveIn).forceApprove(ins.router, amountIn);
    (bool ok, bytes memory ret) = ins.router.call(ins.callData);
    if (!ok) {
      // bubble up the revert reason
      if (ret.length > 0) {
        assembly {
          revert(add(ret, 0x20), mload(ret))
        }
      }
      revert("router call failed");
    }
    IERC20(effectiveIn).forceApprove(ins.router, 0);

    uint256 balAfter = IERC20(effectiveOut).balanceOf(address(this));
    uint256 measured = balAfter - balBefore;

    // Unwrap WETH back to native ETH if the user wanted ETH out.
    if (p.tokenOut == address(0) && measured > 0) {
      weth.withdraw(measured);
    }
    return measured;
  }

  function _poseidon4(bytes32 a, bytes32 b, bytes32 c, bytes32 d) internal view returns (bytes32) {
    bytes32[4] memory inp;
    inp[0] = a;
    inp[1] = b;
    inp[2] = c;
    inp[3] = d;
    return hasher4.poseidon(inp);
  }

  /// @notice Exposed for tests: on-chain Poseidon-4 over [amount, pubkey, blinding, mintAddress].
  function poseidon4(bytes32 a, bytes32 b, bytes32 c, bytes32 d) external view returns (bytes32) {
    return _poseidon4(a, b, c, d);
  }

  // ------------------------------------------------------------- views / helpers

  function calculatePublicAmount(int256 _extAmount, uint256 _fee) public pure returns (uint256) {
    require(_fee < MAX_FEE, "Invalid fee");
    require(_extAmount > -MAX_EXT_AMOUNT && _extAmount < MAX_EXT_AMOUNT, "Invalid ext amount");
    require(
      (_extAmount > 0 && uint256(_extAmount) > _fee) || (_extAmount < 0 && uint256(-_extAmount) > _fee),
      "ext amount must exceed fee for deposits"
    );
    int256 publicAmount = _extAmount - int256(_fee);
    return (publicAmount >= 0) ? uint256(publicAmount) : FIELD_SIZE - uint256(-publicAmount);
  }

  function isSpent(bytes32 _nullifierHash) public view returns (bool) {
    return nullifierHashes[_nullifierHash];
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

  receive() external payable {}
}
