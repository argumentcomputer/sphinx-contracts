// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title Sphinx Verifier Interface
/// @notice This contract is the interface for the Sphinx Verifier.
interface ISphinxVerifier {
    /// @notice Returns the version of the Sphinx Verifier.
    function VERSION() external pure returns (string memory);

    /// @notice Verifies a proof with given public values and vkey.
    /// @param vkey The verification key for the RISC-V program.
    /// @param publicValues The public values encoded as bytes.
    /// @param proofBytes The proof of the program execution the SP1 zkVM encoded as bytes.
    function verifyProof(bytes32 vkey, bytes memory publicValues, bytes memory proofBytes) external view;
}