# Smart contracts for Sphinx

This repository contains smart contracts required for on-chain verification of [Sphinx](https://github.com/lurk-lab/sphinx) proofs.

To install these contracts in your Foundry project:

```
forge install argumentcomputer/sphinx-contracts --no-commit
```

# Updating the contracts

To update the contracts, just download Sphinx artifacts using specific version and copy *.sol files into `contracts/src`:
```
wget https://sphinx-plonk-params.s3.amazonaws.com/<VERSION>.tar.gz
cp ~/.sp1/circuits/plonk_bn254/<VERSION>/*.sol contracts/src/
```
