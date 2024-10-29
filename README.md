# Smart contracts for Sphinx

This repository contains smart contracts required for on-chain verification of [Sphinx](https://github.com/lurk-lab/sphinx) proofs.

To install Solidity contracts in your Foundry project:

```
forge install argumentcomputer/sphinx-contracts@main --no-commit
```

To install Move contracts, add following dependency to your Move.toml file:

```
plonk-core = { git = "https://github.com/argumentcomputer/sphinx-contracts.git", rev = "main", subdir = "move" }
```

and also use `plonk_verifier_addr`

# Updating the contracts

To update the Solidity contracts, just download Sphinx artifacts using specific version and copy *.sol files into `contracts/src`:
```
wget https://sphinx-plonk-params.s3.amazonaws.com/<VERSION>.tar.gz
cp ~/.sp1/circuits/plonk_bn254/<VERSION>/*.sol contracts/src/
```

The Move contracts need to be updated manually, by looking at actual Solidity diff.
Usually contracts update is actually a changing of the constants' values.

In order to test the new version of contracts, copy the newly compiled ELF file from [fibonacci integration](https://github.com/argumentcomputer/sphinx/tree/dev/tests/fibonacci/elf)
test to the `sphinx-proof/fibonacci-elf` path of this repository and generate proof using new correspondent sphinx version:

```
RUST_LOG=info cargo run --package sphinx-proof --release
```

then copy-paste output to the relevant places in Move / Solidity tests.

You also need to update manually the version tag in `VERSION()` function and the value of the hash in the `VERIFIER_HASH()` function
from `solidity/src/SphinxVerifier.sol`. In Move contracts the verifier hash is stored in `VERSION_1082_TESTNET` constant from `move/sources/utilities.move` source file.

The first value can be taken directly from [Sphinx](https://github.com/argumentcomputer/sphinx/blob/dev/core/src/lib.rs#L33),
while the second is printed while running `sphinx-proof` program.

Finally, to test updated Solidity contracts:

```
cd solidity
forge test
```

and Move contracts:

```
aptos move compile --named-addresses plonk_verifier_addr=testnet
aptos move test --named-addresses plonk_verifier_addr=testnet
```

Additionally, it is necessary to publish (deploy) Move contract in order to re-use it as a dependency in higher-level project (in Aptos testnet):

```
aptos move publish --named-addresses plonk_verifier_addr=testnet --profile testnet --assume-yes
```

