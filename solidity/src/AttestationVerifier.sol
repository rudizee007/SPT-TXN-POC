// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title SPT-Txn Attestation Verifier (on-chain ZK)
/// @notice Wraps the gnark-generated Groth16 verifier: it verifies an SPT-Txn
///         selective-disclosure proof ON-CHAIN and records the attestation root
///         only if the proof is valid. This is the "verify a predicate without
///         revealing the data" property, enforced on Ethereum / EVM L2s.
///
/// @dev Threshold circuit (amount >= threshold, amount hidden). Public inputs,
///      in declaration order from internal/zkproof/circuits.go:
///        input[0] = commitment   (Poseidon2 of amount, blinding)
///        input[1] = threshold
///      The proof is gnark's EIP-197 byte layout (256 bytes: points A, B, C).
///      The generated verifier REVERTS on an invalid proof rather than returning
///      a bool. Encode the proof bytes + inputs with `cmd/zk-solcalldata`.
interface IGroth16Verifier {
    function verifyProof(bytes calldata proof, uint256[2] calldata input) external view;
}

contract AttestationVerifier {
    IGroth16Verifier public immutable verifier;

    struct Anchor {
        bytes32 root;
        address submitter;
        uint64 timestamp;
        uint256 threshold;
    }

    Anchor[] private _anchors;

    event VerifiedAnchored(
        uint256 indexed index,
        address indexed submitter,
        bytes32 root,
        uint256 threshold
    );

    error ZeroRoot();
    error IndexOutOfRange();

    constructor(address verifierAddr) {
        verifier = IGroth16Verifier(verifierAddr);
    }

    /// @notice Verify a threshold proof; only if it checks out, record `root`.
    /// @param proof Groth16 proof points (from the off-chain encoder).
    /// @param input Public inputs: [commitment, threshold].
    /// @param root  The SPT-Txn attestation root to anchor on success.
    function anchorVerified(
        bytes calldata proof,
        uint256[2] calldata input,
        bytes32 root
    ) external returns (uint256 index) {
        if (root == bytes32(0)) revert ZeroRoot();
        verifier.verifyProof(proof, input); // reverts if the proof is invalid
        index = _anchors.length;
        _anchors.push(
            Anchor({
                root: root,
                submitter: msg.sender,
                timestamp: uint64(block.timestamp),
                threshold: input[1]
            })
        );
        emit VerifiedAnchored(index, msg.sender, root, input[1]);
    }

    function getCount() external view returns (uint256) {
        return _anchors.length;
    }

    function getAnchor(uint256 i) external view returns (Anchor memory) {
        if (i >= _anchors.length) revert IndexOutOfRange();
        return _anchors[i];
    }
}
