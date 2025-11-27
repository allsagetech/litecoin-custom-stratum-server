# Drivechain Stratum Server

*A minimal Stratum v1 server for Litecoin + BIP300/301 (Drivechain),
compatible with Antminer L3 and other Stratum miners.*

This project provides a lightweight Python Stratum server for **solo
mining** against a **Drivechain-enabled Litecoin node**.\
It automatically constructs coinbase transactions that contain the **BMM
Accept (BIP301) OP_RETURN**, enabling Blind-Merged-Mining for Drivechain
sidechains.

The server supports **Antminer ASICs (e.g., L3/L3+)** and **any other
miner that speaks Stratum V1**.

------------------------------------------------------------------------

## Features

-   Simple, self-contained Stratum V1 server\
-   Fully compatible with **Antminer L3/L3+**\
-   Automatically inserts **BMM OP_RETURN** into coinbase\
-   Submits full reconstructed blocks to a Drivechain-enabled Litecoin
    node\
-   Optional sidechain RPC (`ENABLE_SIDECHAIN=1`)\
-   Share counters + approximate hashrate estimation\
-   Fully configurable via `.env`\
-   Designed for **home miners**, **developers**, and **Drivechain
    testers**

------------------------------------------------------------------------

## Requirements

-   Python 3.8+\
-   Litecoin Core patched with BIP300/301\
-   Optional sidechain node (Thunder / custom chain)\
-   Antminer L3/L3+ or any Stratum V1 compatible miner

------------------------------------------------------------------------

## 🚀 Installation

Run the server:

``` bash
python litecoin_drivechain_stratum_server.py
```

The server listens on:

    0.0.0.0:3333

so ASICs on your LAN can connect.

------------------------------------------------------------------------

## Configuration (`.env`)

All configuration is set through a `.env` file:

``` ini
NETWORK=regtest
RPC_HOST=127.0.0.1
RPC_PORT=19443
RPC_USER=rpcuser
RPC_PASSWORD=rpcpassword

SC_RPC_HOST=127.0.0.1
SC_RPC_PORT=18554
SC_RPC_USER=scrpcuser
SC_RPC_PASSWORD=scrpcpassword
ENABLE_SIDECHAIN=1

STRATUM_HOST=0.0.0.0
STRATUM_PORT=3333
JOB_REFRESH_INTERVAL=10
POOL_DIFFICULTY=0.1

BMM_HEADER_HEX=D1617368
SIDECHAIN_NUMBER=0

# Payout pubkey-hash (20 bytes)
MINER_PKH_HEX=1d0f172a0ecb48aee1be1f2687d2963ae33f71a1
```

**Important:**\
Use `getaddressinfo "<your_LTC_address>"` to obtain your correct
`pubkeyhash`.

------------------------------------------------------------------------

## Using an Antminer L3/L3+

On the Antminer's Pool Configuration page:

**Pool URL:**

    stratum+tcp://<server_ip>:3333

**Worker:**\
Any non-empty string (example: `l3.worker1`)

**Password:**\
`x` (ignored)

Once saved, the L3 will connect and begin submitting shares.

------------------------------------------------------------------------

## Statistics

Every accepted share is logged with:

-   Accepted shares\
-   Total shares\
-   Elapsed mining time\
-   Estimated hashrate (MH/s)

This helps monitor whether the miner is performing as expected.

------------------------------------------------------------------------

## Notes

-   The server **does not** validate Litecoin PoW --- the Litecoin node
    does (scrypt).\
-   All valid share submissions are accepted for stats purposes.\
-   Includes stub support for Antminer's `mining.configure` request.\
-   Perfect for **solo testing**, **Drivechain R&D**, or **sidechain
    integration**.

------------------------------------------------------------------------

## Disclaimer

This Stratum server is **experimental** and intended for
development/testing only.\
Do **not** use on real mainnet Litecoin without fully understanding the
implications.
