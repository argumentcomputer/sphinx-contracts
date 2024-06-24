# Solidity contracts for Sphinx

This repository contains Solidity contracts required for on-chain verification of [Sphinx](https://github.com/lurk-lab/sphinx) proofs.

To install these contracts in your Foundry project:

```
forge install lurk-lab/sphinx-contracts --no-commit
```

### Updating the contracts

This section outlines the steps required to update the Sphinx contracts repository with a new Sphinx version.
Follow these instructions to ensure the Sphinx contracts are correctly updated and aligned with the latest version.

1. Change the branch in `Cargo.toml` to the target `sphinx` branch.

```toml
[dependencies]
sphinx-sdk = { git = "ssh://git@github.com/lurk-lab/sphinx", branch = "<BRANCH>" }
```

2. Update `artifacts` program with the new verifier contracts.

```bash
cargo update

cargo run --bin artifacts --release
```

3. Open a PR to commit the changes to `main`.
