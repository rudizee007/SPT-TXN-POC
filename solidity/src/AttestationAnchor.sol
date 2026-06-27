// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title SPT-Txn Attestation Anchor (Ethereum / EVM)
/// @notice Anchors SPT-Txn attestation roots (32-byte SHA-256 values) on-chain
///         so any party can verify, after the fact, that a given root was
///         anchored, by whom, and when. Mirrors the off-chain
///         `internal/ledger/ethereum.go` adapter and the Starknet (Cairo) /
///         Aptos (Move) anchor contracts — here as a first-class Solidity
///         contract that deploys identically on Ethereum L1 and every
///         EVM-equivalent L2 (Arbitrum, Optimism, Base, Scroll, Linea, …).
///
/// @dev A root is the off-chain SPT-Txn `ContextHash` (or any attestation root),
///      a 32-byte value held as `bytes32` — a clean fit, unlike chains where a
///      256-bit value must be split. Anchoring is open (append-only public log):
///      anyone may anchor; the submitter is recorded from msg.sender. No token,
///      no owner, no upgradeability — a minimal public good.
contract AttestationAnchor {
    struct Anchor {
        bytes32 root;
        address submitter;
        uint64 timestamp;
    }

    /// @dev Append-only log of anchored roots.
    Anchor[] private _anchors;

    /// @notice Emitted on every successful anchor.
    event Anchored(
        uint256 indexed index,
        address indexed submitter,
        bytes32 root,
        uint64 timestamp
    );

    error ZeroRoot();
    error IndexOutOfRange();

    /// @notice Anchor a 32-byte attestation root. Anyone may call.
    /// @param root The SPT-Txn ContextHash / attestation root (must be non-zero).
    /// @return index The position of the new anchor in the log.
    function anchor(bytes32 root) external returns (uint256 index) {
        if (root == bytes32(0)) revert ZeroRoot();
        index = _anchors.length;
        uint64 ts = uint64(block.timestamp);
        _anchors.push(Anchor({root: root, submitter: msg.sender, timestamp: ts}));
        emit Anchored(index, msg.sender, root, ts);
    }

    /// @notice Total number of anchors recorded.
    function getCount() external view returns (uint256) {
        return _anchors.length;
    }

    /// @notice Read a previously anchored record by index.
    function getAnchor(uint256 index) external view returns (Anchor memory) {
        if (index >= _anchors.length) revert IndexOutOfRange();
        return _anchors[index];
    }
}
