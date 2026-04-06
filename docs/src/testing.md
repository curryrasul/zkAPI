# Testing and Verification

## Rust

The Rust workspace now covers:

- core hash/Merkle/nullifier helpers
- Pedersen algebra
- WOTS+ and XMSS signing/verification
- proof-envelope roundtrips for request and withdrawal
- client persistence and escape-hatch proof construction
- server nullifier storage and challenge planning

Run:

```bash
cd rust
cargo test
cargo clippy --workspace --all-targets -- -D warnings
```

## Cairo

The Cairo package now has actual unit tests instead of compiling with `0 tests`.

Current coverage includes:

- Pedersen commitment vector parity with Rust
- Merkle path verification
- genesis request program execution
- genesis escape-withdrawal program execution

Run:

```bash
cd cairo
scarb lint
scarb test
```

Note: `scarb test` still prints the upstream deprecation warning recommending `snforge`, but the test suite itself passes.

## Solidity

The Foundry suite now validates:

- deposit/update/remove tree behavior
- mutual close
- escape hatch initiation/challenge/finalization
- epoch management
- proof-adapter statement routing
- root mismatch behavior
- Poseidon sanity vectors

Run:

```bash
cd contracts
forge fmt --check
forge test --offline
forge build --sizes --offline
```

## Deployment Size

Current Foundry size report:

- `ZkApiVault` runtime size: `21,614` bytes
- runtime margin to EIP-170 limit: `2,962` bytes
- initcode size: `34,044` bytes
- initcode margin to EIP-3860 limit: `15,108` bytes

So the vault is deployable directly, but it is no longer especially roomy. Additional major features in the vault itself should be considered against that remaining runtime margin.
