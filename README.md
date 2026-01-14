# Passkey Smart Wallet

**A hyper-optimized, seedless Smart Contract Wallet protocol built for Ethereum L1.**

This repository contains the smart contracts for a Passkey-powered wallet system designed for extreme gas efficiency. By utilizing the **Proxy Factory pattern**, the protocol achieves deployment costs on Ethereum Mainnet that are comparable to Layer 2 solutions.

---

## Protocol Breakdown

The entire system was deployed and verified on Ethereum Mainnet for under a dollar, proving that building on L1 is still viable with the right architecture.

| Component          | Description                       | Cost (USD) | Transaction Hash (Mainnet) |
| ------------------ | --------------------------------- | ---------- | -------------------------- |
| **Implementation** | Core logic & Passkey verification |            |                            |
| **Factory**        | Deployer for user-owned proxies   |            |                            |
| **User Wallet**    | Individual cloned proxy wallet    |            |                            |

## ✨ Key Features

- **Passkey Authentication:** Uses WebAuthn (P256) signatures. No seed phrases, no private key management for the user—just biometrics or hardware keys.
- **Minimal Proxy Architecture:** Leverages ERC-1167 to keep individual wallet deployment costs at roughly cheaper on L1.
- **Modular Foundry Setup:** Built with **Rust-based Foundry** for blazing-fast testing and gas-optimized compilation.

---

## 🛠 Tech Stack

- **Solidity**: Ethereum smart contract development language.
- **Forge**: Ethereum testing framework (like Truffle, Hardhat and DappTools).
- **Cast**: Swiss army knife for interacting with EVM smart contracts and sending transactions.

---

## 🚀 Getting Started

### Installation

Ensure you have [Foundry installed](https://book.getfoundry.sh/getting-started/installation).

```shell
git clone <your-repo-url>
cd l1-passkey-wallet
forge install

```

### Build

Compile the contracts and generate ABIs:

```shell
forge build

```

### Test

Run the test suite (includes gas reports for Passkey verification):

```shell
forge test --gas-report

```

### Deploy

1. **Deploy Implementation & Factory:**

```shell
forge script script/DeployAll.s.sol:DeployScript --rpc-url <your_rpc_url> --private-key <your_private_key> --broadcast

```

2. **Clone a Wallet (Via Cast):**

```shell
cast send <FACTORY_ADDRESS> "createWallet(bytes32)" <PASSKEY_ID> --rpc-url <your_rpc_url> --private-key <your_private_key>

```

---

## 📊 Gas Snapshots

To keep the protocol lean, we monitor gas usage for every opcode. Generate a new snapshot with:

```shell
forge snapshot

```
