# Drivechain Stratum Server
*A minimal Stratum v1 server for BIP300/301 (Drivechain) mining using USB/ASIC miners.*

This project provides a simple Python-based Stratum server designed for **home miners**, **experimentation**, and **sidechain developers** running a Drivechain-patched litecoin node (BIP300/301).
It enables **mining with real USB or ASIC devices** while automatically inserting **BMM Accept OP_RETURN outputs** into the coinbase transaction.

## Features
- Self-contained Stratum server.
- BMM OP_RETURN insertion.
- Works with cgminer/bfgminer + USB miners.
- Reconstructs full blocks from shares.
- Fully configurable via `.env`.

## Installation
```
python drivechain_stratum_server.py
```

## Configure
Edit the `.env` file with your node RPC settings and payout pubkey hash.

## Run Miner
Example:
```
cgminer -o stratum+tcp://<ip>:3333 -u worker -p x
```

## Disclaimer
Experimental software for Drivechain testing—not production-grade.
