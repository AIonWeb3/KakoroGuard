# KakoroGuard — Stellar Testnet deployment

Do not paste private keys into this file or into git. Use a named Stellar CLI identity.

## Prerequisites

- [Stellar CLI](https://developers.stellar.org/docs/tools/developer-tools/cli/install-cli)
- Rust target `wasm32v1-none`: `rustup target add wasm32v1-none`
- A Testnet-funded identity:

```bash
stellar keys generate kakoroguard-deployer --network testnet --fund
```

Fund the printed address from the [Stellar Laboratory friendbot](https://laboratory.stellar.org/#account-creator?network=testnet).

Copy `.env.example` to `.env` and set `STELLAR_IDENTITY=kakoroguard-deployer`.

## Build optimized WASM

```bash
./scripts/build-wasm.sh
```

Output: `target/wasm32v1-none/release/kakoro_guard.wasm`

## Deploy

```bash
./scripts/deploy-testnet.sh
```

The script prints the contract ID. Save it as `KAKOROGUARD_CONTRACT_ID` in `.env`. It also writes `scripts/.deployed-contract-id` (gitignored) if the deploy succeeds.

If credentials are missing, the script exits with the exact remaining manual command.

## Initialize

```bash
stellar contract invoke \
  --id "$KAKOROGUARD_CONTRACT_ID" \
  --source-account "$STELLAR_IDENTITY" \
  --network testnet \
  -- \
  initialize \
  --admin "$(stellar keys address "$STELLAR_IDENTITY")"
```

## Demo invoke flow

```bash
./scripts/invoke-demo.sh
```

Requires `KAKOROGUARD_CONTRACT_ID` and `STELLAR_IDENTITY`. The script registers, queries, suspends, reactivates, revokes, then shows that a second reactivate fails.

## Manual invoke examples

Replace `$OWNER` / `$AGENT` with G... addresses. Metadata is a Soroban map matching `AgentMetadata`.

```bash
stellar contract invoke --id "$KAKOROGUARD_CONTRACT_ID" --source-account "$STELLAR_IDENTITY" --network testnet -- \
  get_owner_agents --owner "$OWNER"
```

## Contract ID

No Testnet contract ID is recorded in this repository. This environment has no Stellar CLI identity and no `.env`. Remaining manual steps:

1. Install the Stellar CLI.
2. `stellar keys generate kakoroguard-deployer --network testnet --fund` and fund it.
3. Copy `.env.example` to `.env` and set `STELLAR_IDENTITY`.
4. `./scripts/build-wasm.sh && ./scripts/deploy-testnet.sh`
5. `initialize` then `./scripts/invoke-demo.sh`

Local verification already performed: `cargo test --lib` (43 passed) and `cargo build --target wasm32v1-none --release -p kakoro-guard` succeeded. WASM path: `target/wasm32v1-none/release/kakoro_guard.wasm`.
