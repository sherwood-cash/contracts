// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

/**
 * @notice ERC-6538, plus the one thing it is missing: a name.
 *
 * The standard registry maps an ADDRESS to a stealth meta-address. That is enough for a
 * wallet that already knows who it is paying and useless for the thing people actually
 * want to do, which is hand someone a short string. Paying an ERC-6538 registrant means
 * already holding their address — and if you hold their address you did not need stealth
 * addresses to find them, you needed them so the PAYMENT would not be linkable. The
 * lookup key was the last unsolved half.
 *
 * So this contract is the standard registry with a username layer bolted on top:
 *
 *   canonical ERC-6538, unchanged in behaviour and storage layout
 *     stealthMetaAddressOf(registrant, schemeId) -> bytes
 *     registerKeys / registerKeysOnBehalf / nonceOf / incrementNonce
 *
 *   the Sherwood extension
 *     registerUsername("alice")     claims a name for msg.sender
 *     resolve("alice", schemeId)    -> (registrant, stealthMetaAddress)
 *
 * The extension is additive: an ERC-6538 client that has never heard of usernames reads
 * this contract correctly, and a name is only ever a second index onto a registration the
 * standard already describes. Nothing here can change the keys a name points at without
 * the key owner's own transaction.
 *
 * WHAT A NAME IS AND IS NOT. A username is first-come, first-served and proves nothing
 * about who holds it. It is a lookup key, not an identity claim — "alice" is whoever
 * registered "alice", and a consumer showing one to a human should show the address too.
 * Impersonation is a squatting problem, which is a policy question this contract does not
 * try to answer on chain.
 */
contract SherwoodStealthRegistry is Initializable, UUPSUpgradeable {
    // Admin first, and never reordered: everything below it is live storage behind a proxy,
    // and moving a slot rewrites what the existing entries mean rather than migrating them.
    address public admin;
    address public pendingAdmin;

    event AdminChanged(address indexed oldAdmin, address indexed newAdmin);

    modifier onlyAdmin() {
        require(msg.sender == admin, "only admin");
        _;
    }

    // ---------------------------------------------------------------- ERC-6538 (canonical)

    /**
     * @notice The registrant's stealth meta-address for a scheme, exactly as they wrote it.
     *
     * For scheme 1 (SECP256k1) this is 66 bytes: the compressed spending public key (33)
     * followed by the compressed viewing public key (33). The contract does NOT parse it —
     * the standard treats it as opaque so a future scheme needs no new registry — but
     * `registerKeys` does enforce that length for scheme 1, because the single most
     * expensive failure here is a meta-address that is silently the wrong shape and only
     * discovered when a payment to it is unrecoverable.
     */
    mapping(address registrant => mapping(uint256 schemeId => bytes)) public stealthMetaAddressOf;

    /**
     * @notice EIP-712 domain separator, bound to this chain and this proxy.
     *
     * Computed on read, NOT stored in an immutable. An immutable is baked into the
     * implementation's bytecode at ITS construction, so behind a proxy `address(this)`
     * would be the implementation rather than the proxy every wallet actually signs for,
     * and `registerKeysOnBehalf` would reject every signature ever produced. Reading
     * block.chainid live also means a chain fork does not silently make old signatures
     * replayable on the new chain.
     */
    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return _domainSeparator();
    }

    /// @dev keccak256("ERC6538Registry(address registrant,uint256 schemeId,bytes stealthMetaAddress,uint256 nonce)")
    bytes32 public constant ERC6538REGISTRY_ENTRY_TYPE_HASH =
        keccak256("ERC6538Registry(address registrant,uint256 schemeId,bytes stealthMetaAddress,uint256 nonce)");

    /**
     * @notice Signature nonce, so a `registerKeysOnBehalf` signature is single-use.
     *
     * Also bumpable by the registrant on demand (`incrementNonce`), which is the only way
     * to revoke a signature that has been handed out but not yet submitted.
     */
    mapping(address registrant => uint256) public nonceOf;

    event StealthMetaAddressSet(address indexed registrant, uint256 indexed schemeId, bytes stealthMetaAddress);
    event NonceIncremented(address indexed registrant, uint256 newNonce);

    error ERC6538Registry__InvalidSignature();

    // ------------------------------------------------------------- the username extension

    /**
     * @notice usernameHash -> the address that holds it. usernameHash is
     *         keccak256(bytes(username)) over the ALREADY-LOWERCASE name.
     *
     * Hashed rather than stored as a string key because a mapping cannot be keyed by one,
     * and lowercase is enforced at registration rather than folded here: case folding a
     * name on lookup would make "Alice" and "alice" the same entry, which is right, but
     * doing it on chain costs gas on every read. Rejecting the uppercase spelling at
     * registration gets the same guarantee for free — there is only ever one spelling of a
     * registered name, so there is only ever one hash.
     */
    mapping(bytes32 usernameHash => address registrant) public registrantOfUsernameHash;

    /// @notice The name an address holds, or "" — the reverse record, for showing it back.
    mapping(address registrant => string username) public usernameOf;

    event UsernameSet(bytes32 indexed usernameHash, address indexed registrant, string username);
    event UsernameReleased(bytes32 indexed usernameHash, address indexed registrant, string username);

    error Registry__UsernameTaken(string username);
    error Registry__UsernameInvalid(string username);
    error Registry__AlreadyNamed(string username);
    error Registry__NoUsername();
    error Registry__NoKeysRegistered();
    error Registry__BadMetaAddressLength(uint256 length);

    /// @notice ERC-5564 scheme 1: SECP256k1 with view tags. The only scheme Sherwood speaks.
    uint256 public constant SECP256K1_SCHEME_ID = 1;

    /// @dev Compressed spending key (33) + compressed viewing key (33).
    uint256 private constant SECP256K1_META_ADDRESS_LENGTH = 66;

    uint256 private constant USERNAME_MIN_LENGTH = 3;
    uint256 private constant USERNAME_MAX_LENGTH = 32;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address _admin) external initializer {
        require(_admin != address(0), "admin is zero address");
        admin = _admin;
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

    // ------------------------------------------------------------------------ registration

    /// @notice Register (or replace) the caller's stealth meta-address for a scheme.
    function registerKeys(uint256 schemeId, bytes calldata stealthMetaAddress) external {
        _setKeys(msg.sender, schemeId, stealthMetaAddress);
    }

    /**
     * @notice Claim a username for the caller, pointing at the keys they have registered.
     *
     * Requires scheme-1 keys to already be on record. A name that resolves to nothing is
     * worse than no name: a payer who looks it up gets an empty answer at exactly the
     * moment they are about to send money, and cannot tell "not registered" from "this
     * person has no keys yet".
     */
    function registerUsername(string calldata username) external {
        if (stealthMetaAddressOf[msg.sender][SECP256K1_SCHEME_ID].length == 0) {
            revert Registry__NoKeysRegistered();
        }
        _setUsername(msg.sender, username);
    }

    /// @notice Register keys and claim a name in one transaction — the first-run path.
    function registerKeysWithUsername(
        uint256 schemeId,
        bytes calldata stealthMetaAddress,
        string calldata username
    ) external {
        _setKeys(msg.sender, schemeId, stealthMetaAddress);
        _setUsername(msg.sender, username);
    }

    /**
     * @notice Give up the caller's username, freeing it for anyone else.
     *
     * Their keys stay registered — releasing a name is not deregistering, and someone who
     * wants to be paid by address but not by name should not have to break every wallet
     * that already holds their meta-address to say so.
     */
    function releaseUsername() external {
        string memory current = usernameOf[msg.sender];
        if (bytes(current).length == 0) revert Registry__NoUsername();
        bytes32 hash = keccak256(bytes(current));
        delete registrantOfUsernameHash[hash];
        delete usernameOf[msg.sender];
        emit UsernameReleased(hash, msg.sender, current);
    }

    /**
     * @notice Register keys for `registrant` against their EIP-712 signature.
     *
     * The standard's sponsored path: it lets a third party pay the gas, and it is what a
     * smart-contract account uses (via EIP-1271) since it cannot be `msg.sender` of a
     * signature. Consumes one nonce, so a signature cannot be replayed onto a later
     * registration.
     */
    function registerKeysOnBehalf(
        address registrant,
        uint256 schemeId,
        bytes calldata signature,
        bytes calldata stealthMetaAddress
    ) external {
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                _domainSeparator(),
                keccak256(
                    abi.encode(
                        ERC6538REGISTRY_ENTRY_TYPE_HASH,
                        registrant,
                        schemeId,
                        keccak256(stealthMetaAddress),
                        nonceOf[registrant]
                    )
                )
            )
        );

        if (!_isValidSignature(registrant, digest, signature)) revert ERC6538Registry__InvalidSignature();

        unchecked {
            nonceOf[registrant]++;
        }
        _setKeys(registrant, schemeId, stealthMetaAddress);
    }

    /// @notice Invalidate every outstanding `registerKeysOnBehalf` signature of the caller.
    function incrementNonce() external {
        unchecked {
            nonceOf[msg.sender]++;
        }
        emit NonceIncremented(msg.sender, nonceOf[msg.sender]);
    }

    // ----------------------------------------------------------------------------- reading

    /**
     * @notice Look a name up. Returns the zero address and empty bytes when the name is
     *         unregistered, rather than reverting — a payer's "does this name exist?" is a
     *         normal question with a normal negative answer, and a revert would force every
     *         caller to wrap the lookup in a try/catch to ask it.
     */
    function resolve(string calldata username, uint256 schemeId)
        external
        view
        returns (address registrant, bytes memory stealthMetaAddress)
    {
        registrant = registrantOfUsernameHash[keccak256(bytes(username))];
        if (registrant == address(0)) return (address(0), "");
        stealthMetaAddress = stealthMetaAddressOf[registrant][schemeId];
    }

    /// @notice `resolve` for the only scheme Sherwood uses, split into its two public keys.
    function resolveSecp256k1(string calldata username)
        external
        view
        returns (address registrant, bytes memory spendingPubKey, bytes memory viewingPubKey)
    {
        registrant = registrantOfUsernameHash[keccak256(bytes(username))];
        if (registrant == address(0)) return (address(0), "", "");
        bytes memory meta = stealthMetaAddressOf[registrant][SECP256K1_SCHEME_ID];
        if (meta.length != SECP256K1_META_ADDRESS_LENGTH) return (registrant, "", "");
        spendingPubKey = new bytes(33);
        viewingPubKey = new bytes(33);
        for (uint256 i = 0; i < 33; i++) {
            spendingPubKey[i] = meta[i];
            viewingPubKey[i] = meta[i + 33];
        }
    }

    /// @notice Whether a name is free AND well-formed — what a UI greys the button on.
    function usernameAvailable(string calldata username) external view returns (bool) {
        if (!_validUsername(username)) return false;
        return registrantOfUsernameHash[keccak256(bytes(username))] == address(0);
    }

    // ---------------------------------------------------------------------------- internals

    function _setKeys(address registrant, uint256 schemeId, bytes calldata stealthMetaAddress) internal {
        // Only scheme 1 is length-checked. An unknown scheme is passed through opaquely,
        // which is what keeps this registry usable by a scheme that does not exist yet.
        if (schemeId == SECP256K1_SCHEME_ID && stealthMetaAddress.length != SECP256K1_META_ADDRESS_LENGTH) {
            revert Registry__BadMetaAddressLength(stealthMetaAddress.length);
        }
        stealthMetaAddressOf[registrant][schemeId] = stealthMetaAddress;
        emit StealthMetaAddressSet(registrant, schemeId, stealthMetaAddress);
    }

    function _setUsername(address registrant, string calldata username) internal {
        if (!_validUsername(username)) revert Registry__UsernameInvalid(username);

        bytes32 hash = keccak256(bytes(username));
        address holder = registrantOfUsernameHash[hash];
        // Re-registering your own name is a no-op rather than an error: a UI that retries a
        // dropped transaction should not fail on the second attempt.
        if (holder == registrant) return;
        if (holder != address(0)) revert Registry__UsernameTaken(username);

        // One name per address. Changing it means releasing the old one first — an address
        // holding two names would make the reverse record (usernameOf) ambiguous, and the
        // reverse record is what every "you are @alice" line in a UI reads from.
        string memory existing = usernameOf[registrant];
        if (bytes(existing).length != 0) revert Registry__AlreadyNamed(existing);

        registrantOfUsernameHash[hash] = registrant;
        usernameOf[registrant] = username;
        emit UsernameSet(hash, registrant, username);
    }

    /**
     * @dev 3–32 characters of [a-z0-9_], lowercase only.
     *
     * Uppercase is REJECTED rather than folded. Accepting "Alice" as a distinct entry from
     * "alice" is how a name becomes an impersonation vector, and folding it on write would
     * leave `usernameOf` disagreeing with what the user typed. Rejecting is the only option
     * that leaves exactly one spelling of every registered name, and a client can lowercase
     * before it calls.
     *
     * No leading underscore, so a name can never be visually confused with a UI's own
     * reserved-looking tokens, and no all-underscore names.
     */
    function _validUsername(string calldata username) internal pure returns (bool) {
        bytes calldata b = bytes(username);
        if (b.length < USERNAME_MIN_LENGTH || b.length > USERNAME_MAX_LENGTH) return false;
        if (b[0] == 0x5f) return false; // '_'

        for (uint256 i = 0; i < b.length; i++) {
            bytes1 c = b[i];
            bool isLower = c >= 0x61 && c <= 0x7a; // a-z
            bool isDigit = c >= 0x30 && c <= 0x39; // 0-9
            bool isUnderscore = c == 0x5f;
            if (!isLower && !isDigit && !isUnderscore) return false;
        }
        return true;
    }

    /// @dev EOA (ecrecover) first, then EIP-1271 so a smart account can register too.
    function _isValidSignature(address signer, bytes32 digest, bytes calldata signature)
        internal
        view
        returns (bool)
    {
        if (signature.length == 65) {
            bytes32 r;
            bytes32 s;
            uint8 v;
            assembly {
                r := calldataload(signature.offset)
                s := calldataload(add(signature.offset, 32))
                v := byte(0, calldataload(add(signature.offset, 64)))
            }
            // Reject the upper half of the s-range: an ECDSA signature is malleable into a
            // second valid form, and accepting both would let one authorisation be spent
            // twice under two different signature bytes.
            if (uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
                address recovered = ecrecover(digest, v, r, s);
                if (recovered != address(0) && recovered == signer) return true;
            }
        }

        // EIP-1271. `staticcall` so a contract wallet cannot reenter, and the magic value
        // is checked exactly rather than "call succeeded".
        (bool ok, bytes memory ret) = signer.staticcall(
            abi.encodeWithSelector(bytes4(0x1626ba7e), digest, signature)
        );
        return ok && ret.length == 32 && abi.decode(ret, (bytes4)) == bytes4(0x1626ba7e);
    }

    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("ERC6538Registry"),
                keccak256("1.0"),
                block.chainid,
                address(this)
            )
        );
    }

    function _authorizeUpgrade(address) internal override onlyAdmin {}

    // Room to add storage without disturbing anything already written. Shrink this by
    // exactly as many slots as you add.
    uint256[45] private __gap;
}
