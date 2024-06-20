// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {SphinxVerifier} from "../src/SphinxVerifier.sol";

contract SphinxVerifierTest is Test {
    SphinxVerifier public verifier;

    function setUp() public {
        verifier = new SphinxVerifier();
    }
}
