// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title Sphinx Verifier Interface
/// @author Lurk & Succinct Labs
/// @notice This contract is the interface for the Sphinx Verifier.
interface ISphinxVerifier {
    /// @notice Returns the version of Sphinx this verifier corresponds to.
    function VERSION() external pure returns (string memory);

    /// @notice Returns the hash of the verification key.
    function VERIFIER_HASH() external pure returns (bytes32);

    /// @notice Verifies a proof with given public values and vkey.
    /// @param vkey The verification key for the RISC-V program.
    /// @param publicValues The public values encoded as bytes.
    /// @param proofBytes The proof of the program execution the Sphinx zkVM encoded as bytes.
    function verifyProof(bytes32 vkey, bytes calldata publicValues, bytes calldata proofBytes) external view;
}

interface ISphinxVerifierWithHash is ISphinxVerifier {
    /// @notice Returns the SHA-256 hash of the verifier.
    /// @dev This is automatically generated by taking hash of the VKey file.
    function VERIFIER_HASH() external pure returns (bytes32);
}
