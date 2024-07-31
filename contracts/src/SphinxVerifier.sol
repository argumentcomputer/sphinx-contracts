// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {ISphinxVerifier} from "./ISphinxVerifier.sol";
import {PlonkVerifier} from "./PlonkVerifier.sol";

/// @title Sphinx Verifier
/// @author Lurk & Succinct Labs
/// @notice This contracts implements a solidity verifier for Sphinx.
contract SphinxVerifier is PlonkVerifier {
    error WrongVersionProof();

    function VERSION() external pure returns (string memory) {
        return "v1.0.7-testnet";
    }

    function VKEY_HASH() public pure returns (bytes32) {
        return 0x8c1fe03fbb392f2ca95a30373d77da38f72f88fd65570909f9fa31917391a1fd;
    }

    /// @notice Hashes the public values to a field elements inside Bn254.
    /// @param publicValues The public values.
    function hashPublicValues(
        bytes calldata publicValues
    ) public pure returns (bytes32) {
        return sha256(publicValues) & bytes32(uint256((1 << 253) - 1));
    }

    /// @notice Verifies a proof with given public values and vkey.
    /// @param vkey The verification key for the RISC-V program.
    /// @param publicValues The public values encoded as bytes.
    /// @param proofBytes The proof of the program execution the Sphinx zkVM encoded as bytes.
    function verifyProof(
        bytes32 vkey,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) public view {
        // To ensure the proof corresponds to this verifier, we check that the first 4 bytes of
        // proofBytes match the first 4 bytes of VKEY_HASH.
        bytes4 proofBytesPrefix = bytes4(proofBytes[:4]);
        if (proofBytesPrefix != bytes4(VKEY_HASH())) {
            revert WrongVersionProof();
        }

        bytes32 publicValuesDigest = hashPublicValues(publicValues);
        uint256[] memory inputs = new uint256[](2);
        inputs[0] = uint256(vkey);
        inputs[1] = uint256(publicValuesDigest);
        bool success = this.Verify(proofBytes[4:], inputs);
        if (!success) {
            revert InvalidProof();
        }
    }
}
