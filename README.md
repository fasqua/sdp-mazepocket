<div align="center">

# SDP Maze Pocket

### Privacy-Enhanced Wallet Funding on Solana

[![Solana](https://img.shields.io/badge/Solana-Mainnet-9945FF?style=for-the-badge&logo=solana)](https://solana.com)
[![Rust](https://img.shields.io/badge/Rust-1.75+-orange?style=for-the-badge&logo=rust)](https://rust-lang.org)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue?style=for-the-badge)](LICENSE)
[![KausaLayer](https://img.shields.io/badge/KausaLayer-Protocol-green?style=for-the-badge)](https://kausalayer.com)
[![Twitter](https://img.shields.io/badge/Twitter-@kausalayer-1DA1F2?style=for-the-badge&logo=twitter)](https://x.com/kausalayer)

**Fund wallets privately through maze-based transaction routing**

[Try It](https://kausalayer.com/pocket) · [Documentation](#how-it-works) · [Getting Started](#quick-start)

</div>

---
## What is Maze Pocket?

Maze Pocket is a privacy-preserving wallet funding system that routes your SOL through a dynamically generated maze of intermediate wallets before reaching your destination. Unlike traditional transfers that create a direct link between source and destination, Maze Pocket obscures the transaction trail through mathematical patterns inspired by the golden ratio and Fibonacci sequences.

**Create a stealth wallet, fund it privately, use it anywhere.**

```
Your Wallet                                              Stealth Pocket
    │                                                          ▲
    │   ┌─────────────────── MAZE ──────────────────────┐     │
    └──►│  Split → Route → Merge → Split → Route → Merge │────►│
        │  ████████████████████████████████████████████  │     │
        │  Using Fibonacci patterns & golden ratio splits │     │
        └────────────────────────────────────────────────┘     │
                                                               │
                                                    Import to Phantom
                                                    Use anywhere: DEXs, NFTs, etc.
```

---

## Key Features

### Military-Grade Encryption
- **Argon2id** key derivation (memory-hard, GPU/ASIC resistant)
- **AES-256-GCM** authenticated encryption for all keypairs
- **Zeroize** memory after use — no traces left in RAM

### Intelligent Maze Generation
- **5-10 hop depth** with configurable complexity
- **Golden ratio splits** (φ = 1.618) for natural-looking amounts
- **Fibonacci-based timing** to avoid pattern detection
- **Multiple merge strategies**: Early, Late, Middle, Random, Fibonacci

### Privacy Features
- Stealth wallet generation with encrypted private keys
- Amount obfuscation with configurable noise (±0.5%)
- Variable delays between transactions
- No direct link between source and destination

### Performance & Reliability
- Real-time progress tracking during routing
- Automatic recovery for stuck transactions
- Background maze execution with status polling
- Efficient SQLite storage with encrypted keypairs

---

## Quick Start

### Prerequisites

- Rust 1.75+
- Solana CLI tools
- SQLite3

### Installation

```bash
# Clone the repository
git clone https://github.com/kausalayer/sdp-mazepocket.git
cd sdp-mazepocket

# Build
cargo build --release

# Configure environment
cp .env.example .env
# Edit .env with your settings:
#   SOLANA_RPC_URL=https://your-rpc-endpoint
#   MASTER_KEY=your-secure-master-key
#   POCKET_PORT=3033

# Run
./target/release/pocket-relay
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SOLANA_RPC_URL` | Solana RPC endpoint | `https://api.mainnet-beta.solana.com` |
| `MASTER_KEY` | Encryption master key (required) | - |
| `POCKET_DB_PATH` | SQLite database path | `pocket.db` |
| `POCKET_PORT` | Server port | `3033` |

---

## Usage

### Create a Pocket
```
create 0.5 SOL
```
Generates a new stealth wallet and deposit address. Fund the deposit address to initiate maze routing.

### View Your Pockets
```
list
```
Shows all your pockets with balances and status.

### Export Private Key
```
export pocket_abc123
```
Retrieves the private key to import into Phantom, Solflare, or any Solana wallet.

### Sweep Funds Out
```
sweep pocket_abc123 to <destination_address>
```
Routes funds from your pocket through a new maze to your destination.

### Manage Destination Wallets
```
wallets                        # List saved wallets
wallet add 1 <address>         # Save to slot 1-5
wallet delete 1                # Remove from slot
sweep pocket_abc123 1          # Sweep to slot 1
```

### Recovery Commands
```
recover funding pocket_abc123  # Recover stuck funding
recover sweep pocket_abc123    # Recover stuck sweep
```

---

## How It Works

### 1. Pocket Creation

When you create a pocket, the system:
1. Generates a new Solana keypair (your stealth wallet)
2. Creates a maze topology with 20-30 intermediate nodes
3. Encrypts all keypairs with AES-256-GCM
4. Returns a deposit address (first maze node)

### 2. Maze Topology

The maze uses a parameterized graph structure:

```
Level 0    Level 1      Level 2      Level 3    Level 4    Level 5
(Entry)    (Split)      (Route)      (Merge)    (Split)    (Exit)
           
  [D] ────► [1] ──┬───► [4] ────┬──► [7] ──┬──► [9] ────► [Pocket]
            │     │      │      │          │
           [2] ──┼───► [5] ────┤          [10]───►
            │    │       │      │
           [3] ─┴────► [6] ────┘
```

Each level applies one of these strategies:
- **Split**: Divide funds across 2-4 nodes
- **Route**: 1-to-1 transfer with timing variance
- **Merge**: Combine multiple inputs into fewer outputs

### 3. Amount Obfuscation

Amounts are split using golden ratio variations:
```
Input: 1.0 SOL
Split ratio: φ ≈ 1.618

Output 1: 0.618 SOL
Output 2: 0.382 SOL
+ random noise (±0.5%)
```

### 4. Timing Patterns

Five delay patterns prevent timing analysis:
- **None**: Immediate execution
- **Linear**: Fixed delay per hop
- **Exponential**: 2^n delay growth
- **Fibonacci**: fib(n) × base delay
- **Random**: Randomized within range

### 5. Sweep Process

Sweeping reverses the process:
1. Generates new maze from pocket to destination
2. Routes funds through intermediate nodes
3. Final node transfers to your destination
4. Pocket marked as swept

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                      Frontend (React)                     │
│                   AgentPocket.tsx UI                      │
└─────────────────────────┬────────────────────────────────┘
                          │ HTTP/JSON
┌─────────────────────────▼────────────────────────────────┐
│                    Relay Server (Axum)                    │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐   │
│  │ API Handlers│  │Maze Executor│  │ Deposit Monitor │   │
│  └──────┬──────┘  └──────┬──────┘  └────────┬────────┘   │
│         │                │                   │            │
│  ┌──────▼────────────────▼───────────────────▼────────┐  │
│  │              Database Layer (SQLite)                │  │
│  │  ┌──────────────────┐  ┌─────────────────────────┐  │  │
│  │  │ Argon2id KDF     │  │ AES-256-GCM Encryption  │  │  │
│  │  └──────────────────┘  └─────────────────────────┘  │  │
│  └─────────────────────────────────────────────────────┘  │
└─────────────────────────┬────────────────────────────────┘
                          │ RPC
┌─────────────────────────▼────────────────────────────────┐
│                    Solana Blockchain                      │
│              System Program Transfers                     │
└──────────────────────────────────────────────────────────┘
```

---

## Security Model

### Threat Mitigations

| Threat | Mitigation |
|--------|------------|
| Key extraction | Argon2id (64MB memory cost) + AES-256-GCM |
| Memory forensics | Zeroize all sensitive data after use |
| Transaction analysis | Multi-hop routing with amount noise |
| Timing analysis | Variable delays (Linear/Exp/Fib/Random) |
| Database theft | All keypairs encrypted at rest |

---

## Parameters

### Maze Configuration

| Parameter | Range | Default | Description |
|-----------|-------|---------|-------------|
| `hop_count` | 5-10 | 7 | Number of maze levels |
| `split_ratio` | 1.1-3.0 | 1.618 (φ) | Golden ratio for splits |
| `merge_strategy` | enum | Random | When to merge paths |
| `delay_pattern` | enum | Random | Timing between hops |
| `delay_ms` | 0-5000 | 500 | Base delay in ms |
| `amount_noise` | 0.01-1% | 0.5% | Amount obfuscation |

### System Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `FEE_PERCENT` | 0.5% | Protocol fee |
| `TX_FEE_LAMPORTS` | 5000 | Solana TX fee buffer |
| `MIN_AMOUNT_SOL` | 0.01 | Minimum transfer |
| `EXPIRY_SECONDS` | 1800 | Request timeout (30 min) |

---

## Testing

```bash
# Run unit tests
cargo test

# Run with logging
RUST_LOG=debug cargo test

# Test specific module
cargo test maze::tests
cargo test database::tests
```

---

## Contributing

We welcome contributions! Please:

1. Fork the repository
2. Create a feature branch
3. Write tests for new functionality
4. Ensure `cargo test` passes
5. Submit a pull request

---

## License

Apache 2.0 License - see [LICENSE](LICENSE) for details.
