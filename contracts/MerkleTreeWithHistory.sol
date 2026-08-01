// SPDX-License-Identifier: MIT

pragma solidity 0.8.24;

import "@openzeppelin/contracts/proxy/utils/Initializable.sol";

interface IHasher {
  function poseidon(bytes32[2] calldata inputs) external pure returns (bytes32);
}

contract MerkleTreeWithHistory is Initializable {
  uint256 public constant FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

  IHasher public immutable hasher;
  uint32 public immutable levels;

  // the following variables are made public for easier testing and debugging and
  // are not supposed to be accessed in regular code

  // filledSubtrees and roots could be bytes32[size], but using mappings makes it cheaper because
  // it removes index range check on every interaction
  mapping(uint256 => bytes32) public filledSubtrees;
  mapping(uint256 => bytes32) public roots;
  uint32 public constant ROOT_HISTORY_SIZE = 100;
  uint32 public currentRootIndex;
  uint32 public nextIndex;

  constructor(uint32 _levels, address _hasher) {
    require(_levels > 0, "_levels should be greater than zero");
    require(_levels < 32, "_levels should be less than 32");
    levels = _levels;
    hasher = IHasher(_hasher);
  }

  function _initialize() internal onlyInitializing {
    for (uint32 i = 0; i < levels; i++) {
      filledSubtrees[i] = zeros(i);
    }

    roots[0] = zeros(levels);
  }

  /**
    @dev Hash 2 tree leaves, returns Poseidon(_left, _right)
  */
  function hashLeftRight(bytes32 _left, bytes32 _right) public view returns (bytes32) {
    require(uint256(_left) < FIELD_SIZE, "_left should be inside the field");
    require(uint256(_right) < FIELD_SIZE, "_right should be inside the field");
    bytes32[2] memory input;
    input[0] = _left;
    input[1] = _right;
    return hasher.poseidon(input);
  }

  // Modified to insert pairs of leaves for better efficiency
  function _insert(bytes32 _leaf1, bytes32 _leaf2) internal returns (uint32 index) {
    uint32 _nextIndex = nextIndex;
    require(_nextIndex != uint32(2)**levels, "Merkle tree is full. No more leaves can be added");
    uint32 currentIndex = _nextIndex / 2;
    bytes32 currentLevelHash = hashLeftRight(_leaf1, _leaf2);
    bytes32 left;
    bytes32 right;

    for (uint32 i = 1; i < levels; i++) {
      if (currentIndex % 2 == 0) {
        left = currentLevelHash;
        right = zeros(i);
        filledSubtrees[i] = currentLevelHash;
      } else {
        left = filledSubtrees[i];
        right = currentLevelHash;
      }
      currentLevelHash = hashLeftRight(left, right);
      currentIndex /= 2;
    }

    uint32 newRootIndex = (currentRootIndex + 1) % ROOT_HISTORY_SIZE;
    currentRootIndex = newRootIndex;
    roots[newRootIndex] = currentLevelHash;
    nextIndex = _nextIndex + 2;
    return _nextIndex;
  }

  /**
    @dev Whether the root is present in the root history
  */
  function isKnownRoot(bytes32 _root) public view returns (bool) {
    if (_root == 0) {
      return false;
    }
    uint32 _currentRootIndex = currentRootIndex;
    uint32 i = _currentRootIndex;
    do {
      if (_root == roots[i]) {
        return true;
      }
      if (i == 0) {
        i = ROOT_HISTORY_SIZE;
      }
      i--;
    } while (i != _currentRootIndex);
    return false;
  }

  /**
    @dev Returns the last root
  */
  function getLastRoot() public view returns (bytes32) {
    return roots[currentRootIndex];
  }

  /// @dev provides Zero (Empty) elements for a Poseidon MerkleTree. Up to 31 levels
  function zeros(uint256 i) public pure returns (bytes32) {
    if (i == 0) return bytes32(0x062e4bce6065dea73d3010d1bb9bf83bd767b11f178cd2349116e0649be4ce0e);
    else if (i == 1) return bytes32(0x203c69291329a6b2dbaa3d99dac0f6dae70c1f2cf9771d964cc65774d0058868);
    else if (i == 2) return bytes32(0x259cd78d5647044523f7c12c83147bd35f887e708ebb65f72fe6156b6c4902cc);
    else if (i == 3) return bytes32(0x1718f4188f4814f56cf61bbe7cf24c7fac739f6ae9fdb8df37058fc8beb4da89);
    else if (i == 4) return bytes32(0x01ec4b26d068e323245587e0c7f142673691f56e5ee694e41fe13bbadd41ac59);
    else if (i == 5) return bytes32(0x1edb8987fccedd7398b3ac8542e361ec620283f1253ce350c1bec43ec5ba7b6d);
    else if (i == 6) return bytes32(0x1c3f61dd6b884ad15ec9526fa711fe1c4786de4d9f28b0fd7256a48817a5b1b3);
    else if (i == 7) return bytes32(0x1c6b10c894f5812b68f64910feb2385d9e2c0f8a0dfaedf912610425281a531a);
    else if (i == 8) return bytes32(0x12f9328216cdfa9581d589cfd5f59cdd6016bde77eb5af0dc48b288801c0f2ce);
    else if (i == 9) return bytes32(0x120a354c93a0940e92b6b151c95d8493f3657e2045c4d0b05324e2239432e96c);
    else if (i == 10) return bytes32(0x2427c1c222e69feaa3e50feef380e35e3011f636fba6a11181bb2a84022ba1a9);
    else if (i == 11) return bytes32(0x1ab7ed21c816b177cf72e0dc23637ac62ea0426ef38165af0f328f8eed0b90e7);
    else if (i == 12) return bytes32(0x1c676721bc6b7bcbc1f490742a340b34e6013e0a6c56f63e9b58cabe4605fc0e);
    else if (i == 13) return bytes32(0x19a6d02dc5961cf0670adedc62dc285255d36a502e14ab04984ef10de60f8bdb);
    else if (i == 14) return bytes32(0x0d6af647f9d8225ceb81686c714259ffde53f8a98b7a5588e9d950817358dc8b);
    else if (i == 15) return bytes32(0x03f62803dbfc8c348fca5737fc1a0b6bcfa478cfaba472f725762beaef19d6a3);
    else if (i == 16) return bytes32(0x081eda91f7fc1086ba5832841bf2ef528588d8a60416bee51a8d34421715d480);
    else if (i == 17) return bytes32(0x281e9d093c6f91387751478f100fd4420c099c09ca76ffdc48ff5ef88341f6f3);
    else if (i == 18) return bytes32(0x14012c3083720a5f4f91bb9470faa5559d062be44381e6f83512a3d23f49d9ed);
    else if (i == 19) return bytes32(0x1c543bc94c9536cc7f8a56cb3d68f2912f52aed28e910e018cd0b87259090369);
    else if (i == 20) return bytes32(0x0f1d1fc7250f8743348448e2b1cdfe838db1ca08200c25910028d5ab8fbc01a7);
    else if (i == 21) return bytes32(0x013aa4202eff20265f11c8594a79cbb182fbd9286fa1a215d36b7b001df27a42);
    else if (i == 22) return bytes32(0x20689b6f816111ff95e49acc7b2a5b7148a71e9bbf87a09b3168c4561239d26c);
    else if (i == 23) return bytes32(0x2857d81bf26d7a781139f5864c8da5a0d62dc3e13438cd0daeab367a0b2077e5);
    else if (i == 24) return bytes32(0x2d97a4b5c4b0c5ac03d03feefd3dec41ea08604b6b7f372cf980858bd6c2f150);
    else if (i == 25) return bytes32(0x231596c080bb1330c9bb77a6d2f57d1a7f9d1f2a3b569939c5041bac13f136a7);
    else if (i == 26) return bytes32(0x24c71211a61aa30fa3d898f4f4b7a6902cdaf09ecbc01549cab492329abacdb6);
    else if (i == 27) return bytes32(0x2e1d1cc2ce8daf9e5fb96fa878c04b8d7453068de6142988211db585ce80ba6f);
    else if (i == 28) return bytes32(0x0e90363081625685565d467c06ddcb89b43cb0679c5975c6ec1dcef9c9dc746c);
    else if (i == 29) return bytes32(0x18b42deaf69b75bf86bbae45a180117e1aff79b8aff5079ec7da18967bda2104);
    else if (i == 30) return bytes32(0x066aeacdb326f7a2033d53ffb94190030b9ca342a51557b37e1f2e5aa0c5b347);
    else if (i == 31) return bytes32(0x0e9e856377479d26ed15142f8647ee99818ed602a95ab45244cb692b990e09cc);
    else revert("Index out of bounds");
  }

  uint256[47] private __gap;
}
