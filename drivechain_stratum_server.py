#!/usr/bin/env python3
"""litecoin_drivechain_stratum_server.py

Minimal Stratum server skeleton for Drivechain / BMM experimentation **on Litecoin**.

Target: cgminer/bfgminer + USB miner, on a local Litecoin node
(patched for BIP301 / Drivechain) and a single Drivechain sidechain
(Thunder / cusf_sidechain / etc.).

*** IMPORTANT ***
- This is a reference / experimental implementation, NOT production-ready.
- You will almost certainly need to tweak it for your exact node/sidechain versions.
"""

import socket
import threading
import json
import time
import logging
import hashlib
from base64 import b64encode
from http.client import HTTPConnection
import os

# ----------------------------
# Simple .env loader (no python-dotenv dependency)
# ----------------------------

def load_simple_env(path: str = ".env") -> None:
    """
    Minimal .env loader:
    - Lines starting with '#' are ignored
    - Blank lines are ignored
    - KEY=VALUE pairs are loaded into os.environ (if not already set)
    - Surrounding single/double quotes around VALUE are stripped
    """
    if not os.path.exists(path):
        return

    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                # Do not override already-set environment variables
                os.environ.setdefault(key, value)
    except OSError as e:
        logging.warning(f"Failed to read .env file '{path}': {e}")

# Load .env before reading config
load_simple_env()

# ----------------------------
# Config (from environment / .env)
# ----------------------------

# Mainchain RPC (Litecoin with BIP301 / Drivechain patch)
RPC_HOST = os.getenv("RPC_HOST", "127.0.0.1")
# Default to Litecoin mainnet RPC port; override in .env if needed
RPC_PORT = int(os.getenv("RPC_PORT", "9332"))
RPC_USER = os.getenv("RPC_USER", "rpcuser")
RPC_PASSWORD = os.getenv("RPC_PASSWORD", "rpcpassword")

# Sidechain RPC (Thunder / cusf_sidechain / etc.)
SC_RPC_HOST = os.getenv("SC_RPC_HOST", "127.0.0.1")
SC_RPC_PORT = int(os.getenv("SC_RPC_PORT", "18554"))
SC_RPC_USER = os.getenv("SC_RPC_USER", "scrpcuser")
SC_RPC_PASSWORD = os.getenv("SC_RPC_PASSWORD", "scrpcpassword")

# Sidechain enable/disable flag
# Set ENABLE_SIDECHAIN=0 to disable sidechain RPC and BMM output
ENABLE_SIDECHAIN = os.getenv("ENABLE_SIDECHAIN", "1") == "1"

# Stratum server bind
STRATUM_HOST = os.getenv("STRATUM_HOST", "0.0.0.0")
STRATUM_PORT = int(os.getenv("STRATUM_PORT", "3333"))
POOL_DIFFICULTY = float(os.getenv("POOL_DIFFICULTY", "1.0"))

# Seconds between new jobs sent to miners
JOB_REFRESH_INTERVAL = int(os.getenv("JOB_REFRESH_INTERVAL", "10"))

# BMM / Drivechain
# BIP301 4-byte header (unchanged for Litecoin’s BIP301 implementation)
BMM_HEADER_HEX = os.getenv("BMM_HEADER_HEX", "D1617368")
SIDECHAIN_NUMBER = int(os.getenv("SIDECHAIN_NUMBER", "0"))  # set this to your sidechain's ID (0-255)

# Miner payout (P2PKH)
# 20-byte pubkey hash (NOT the whole address).
# Example from `getaddressinfo "addr"` -> "pubkeyhash"
# For Litecoin, this is still a 20-byte hash; address version bytes differ at the node/wallet level.
MINER_PKH_HEX = os.getenv("MINER_PKH_HEX", "")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


# ----------------------------
# Generic helpers
# ----------------------------

def sha256d(b: bytes) -> bytes:
    """Double SHA256."""
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def varint(n: int) -> bytes:
    """Encode an integer as Bitcoin/Litecoin-style varint."""
    if n < 0xfd:
        return n.to_bytes(1, "little")
    elif n <= 0xffff:
        return b"\xfd" + n.to_bytes(2, "little")
    elif n <= 0xffffffff:
        return b"\xfe" + n.to_bytes(4, "little")
    else:
        return b"\xff" + n.to_bytes(8, "little")


def hex_le(x: str) -> str:
    """Convert big-endian hex to little-endian hex."""
    b = bytes.fromhex(x)
    return b[::-1].hex()


def nbits_to_target(nbits_hex: str) -> int:
    """Convert compact nBits (hex string) to full target integer."""
    nbits = int(nbits_hex, 16)
    exponent = nbits >> 24
    mantissa = nbits & 0x007fffff
    if exponent <= 3:
        target = mantissa >> (8 * (3 - exponent))
    else:
        target = mantissa << (8 * (exponent - 3))
    return target


def encode_scriptnum(value: int) -> bytes:
    """Encode an integer as minimally-encoded CScriptNum (BIP34-style)."""
    if value == 0:
        return b""  # empty vector is 0

    neg = value < 0
    if neg:
        value = -value

    result = b""
    while value:
        result += bytes([value & 0xff])
        value >>= 8

    # If the highest bit is set, append a new byte to avoid sign confusion.
    if result and (result[-1] & 0x80):
        result += bytes([0x80 if neg else 0x00])
    elif neg and result:
        result = result[:-1] + bytes([result[-1] | 0x80])

    return result


# ----------------------------
# BMM / payout helpers
# ----------------------------

def build_bmm_accept_script(sidechain_number: int, h_star_hex: str) -> bytes:
    """Build the scriptPubKey for a BMM Accept OP_RETURN output (BIP301)."""
    header = bytes.fromhex(BMM_HEADER_HEX)
    side = sidechain_number.to_bytes(1, "big")
    h_star = bytes.fromhex(h_star_hex)  # must be 32-byte hash

    payload = header + side + h_star  # 4 + 1 + 32 = 37 bytes
    if len(payload) != 37:
        raise ValueError(f"BMM payload must be 37 bytes, got {len(payload)}")

    push_len = len(payload).to_bytes(1, "little")  # single-byte push (OK for <75)
    script = b"\x6a" + push_len + payload  # OP_RETURN
    return script


def build_p2pkh_script(pkh_hex: str) -> bytes:
    """Build a standard P2PKH script, or OP_TRUE if MINER_PKH_HEX is empty.

    Works for Litecoin exactly as for Bitcoin, since the address version
    bytes are handled at the wallet layer; the script itself is standard.
    """
    if not pkh_hex:
        # Fallback: OP_TRUE (anyone-can-spend) for testing
        return bytes.fromhex("51")

    pkh = bytes.fromhex(pkh_hex)
    if len(pkh) != 20:
        raise ValueError("MINER_PKH_HEX must be 20 bytes (40 hex chars)")

    return (
        b"\x76"              # OP_DUP
        + b"\xa9"            # OP_HASH160
        + b"\x14"            # push 20 bytes
        + pkh
        + b"\x88"            # OP_EQUALVERIFY
        + b"\xac"            # OP_CHECKSIG
    )


# ----------------------------
# JSON-RPC client
# ----------------------------

class JsonRPC:
    def __init__(self, host, port, user, password):
        self.host = host
        self.port = port
        self.auth = b"Basic " + b64encode(f"{user}:{password}".encode())

    def _call(self, method, params=None):
        if params is None:
            params = []
        conn = HTTPConnection(self.host, self.port, timeout=10)
        payload = json.dumps({
            "jsonrpc": "1.0",
            "id": "stratum",
            "method": method,
            "params": params
        })
        headers = {
            "Content-Type": "application/json",
            "Authorization": self.auth.decode()
        }
        conn.request("POST", "/", body=payload, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        if resp.status != 200:
            raise RuntimeError(f"RPC {method} HTTP error {resp.status}: {data}")
        obj = json.loads(data)
        if obj.get("error"):
            raise RuntimeError(f"RPC {method} error: {obj['error']}")
        return obj["result"]

    # Convenience helpers for Litecoin mainchain node (Bitcoin-like RPC)
    def getblocktemplate(self):
        # Litecoin Core also supports segwit and GBT with similar rules
        return self._call("getblocktemplate", [{"rules": ["segwit"]}])

    def submitblock(self, block_hex: str):
        return self._call("submitblock", [block_hex])


# ----------------------------
# Sidechain RPC wrapper
# ----------------------------

class SidechainRPC:
    """Wrapper around a JsonRPC client talking to your sidechain daemon."""

    def __init__(self, rpc_client: JsonRPC):
        self.rpc = rpc_client

    def get_bmm_hash(self) -> str:
        """Return 32-byte hex string h* for the sidechain block to BMM-accept."""
        h_star = self.rpc._call("getbestblockhash")
        if not isinstance(h_star, str) or len(h_star) != 64:
            raise RuntimeError(f"Sidechain getbestblockhash returned weird value: {h_star}")
        return h_star


# ----------------------------
# Template builder (Drivechain hooks)
# ----------------------------

class TemplateBuilder:
    """Fetch templates, insert BMM, and build Stratum jobs."""

    def __init__(self, rpc: JsonRPC, sidechain_rpc, enable_sidechain: bool = True):
        self.rpc = rpc
        self.sidechain_rpc = sidechain_rpc
        self.enable_sidechain = enable_sidechain

        self.current_job_id = 0
        self.current_template = None
        self.extranonce1 = "00000001"   # fixed extranonce1 for simple setups
        self.extranonce2_size = 4       # bytes

        # job_id -> job data
        self.jobs = {}

    def _build_coinbase(self, template, extranonce1_hex: str, extranonce2_hex: str) -> bytes:
        """Build coinbase tx with BIP34 height, extranonces, P2PKH, and optional BMM OP_RETURN."""
        coinbase_value = template["coinbasevalue"]  # in litoshis (same structure as satoshis)
        height = template["height"]

        # scriptSig: <PUSHDATA(height)> <ex1> <ex2>
        height_bytes = encode_scriptnum(height)
        height_push = len(height_bytes).to_bytes(1, "little") + height_bytes

        ex1 = bytes.fromhex(extranonce1_hex)
        ex2 = bytes.fromhex(extranonce2_hex)

        script_sig_data = height_push + ex1 + ex2
        script_sig = varint(len(script_sig_data)) + script_sig_data

        # Outputs list: (value_bytes, script_bytes)
        outputs = []

        # 1) Miner payout
        miner_pk_script = build_p2pkh_script(MINER_PKH_HEX)
        miner_value = coinbase_value.to_bytes(8, "little")
        outputs.append((miner_value, miner_pk_script))

        # 2) Optional BMM Accept OP_RETURN when sidechain is enabled
        if self.enable_sidechain and self.sidechain_rpc is not None:
            try:
                h_star_hex = self.sidechain_rpc.get_bmm_hash()
            except Exception as e:
                logging.warning(f"SidechainRPC get_bmm_hash failed: {e}, using zeros")
                h_star_hex = "00" * 32

            bmm_script = build_bmm_accept_script(SIDECHAIN_NUMBER, h_star_hex)
            bmm_value = (0).to_bytes(8, "little")
            outputs.append((bmm_value, bmm_script))

        # Assemble tx
        tx_version = (1).to_bytes(4, "little")
        tx_locktime = (0).to_bytes(4, "little")

        input_count = varint(1)
        prevout_hash = b"\x00" * 32
        prevout_n = (0xffffffff).to_bytes(4, "little")
        sequence = (0xffffffff).to_bytes(4, "little")

        output_count = varint(len(outputs))

        tx = (
            tx_version +
            input_count +
            prevout_hash +
            prevout_n +
            script_sig +
            sequence +
            output_count
        )

        for value_bytes, script_bytes in outputs:
            tx += value_bytes + varint(len(script_bytes)) + script_bytes

        tx += tx_locktime

        return tx

    def _split_coinbase_for_stratum(self, coinbase_tx: bytes):
        """Split coinbase into coinb1 + extranonce2 + coinb2 for Stratum."""
        # tx layout:
        # 4  version
        # 1  vin_count
        # 32 prevout hash
        # 4  prevout idx
        # 1  script_len (varint, assume <0xfd for coinbase)
        # N  scriptSig_data

        height = self.current_template["height"]
        height_bytes = encode_scriptnum(height)
        height_push = len(height_bytes).to_bytes(1, "little") + height_bytes

        # parse tx
        _version = coinbase_tx[0:4]
        _vin_count = coinbase_tx[4:5]
        _prevout = coinbase_tx[5:5+32+4]

        script_len_pos = 5+32+4
        script_len = coinbase_tx[script_len_pos]
        script_start = script_len_pos + 1
        script_end = script_start + script_len

        _script_data = coinbase_tx[script_start:script_end]

        # script_data = height_push + ex1 + ex2
        ex1 = bytes.fromhex(self.extranonce1)
        ex2_len = self.extranonce2_size

        height_len = len(height_push)
        ex1_len = len(ex1)

        ex2_start_offset = height_len + ex1_len
        ex2_end_offset = ex2_start_offset + ex2_len

        ex2_start = script_start + ex2_start_offset
        ex2_end = script_start + ex2_end_offset

        coinb1 = coinbase_tx[:ex2_start]
        coinb2 = coinbase_tx[ex2_end:]

        return coinb1.hex(), coinb2.hex()

    def build_stratum_job(self):
        """Fetch a new template, construct coinbase, and return Stratum job pieces."""
        tpl = self.rpc.getblocktemplate()
        self.current_template = tpl
        self.current_job_id += 1
        job_id = str(self.current_job_id)

        # Placeholder extranonce2 (zeros), real one comes from miner
        placeholder_ex2 = "00" * self.extranonce2_size

        coinbase_tx = self._build_coinbase(
            tpl,
            self.extranonce1,
            placeholder_ex2,
        )

        prevhash_be = tpl["previousblockhash"]
        prevhash_le = hex_le(prevhash_be)

        coinb1, coinb2 = self._split_coinbase_for_stratum(coinbase_tx)

        # Stratum merkle branch: tx hashes excluding coinbase
        merkle_branch = [tx["hash"] for tx in tpl["transactions"]]

        version = "{:08x}".format(tpl["version"])
        nbits = tpl["bits"]
        ntime = "{:08x}".format(tpl["curtime"])

        clean_jobs = True  # always clean on refresh (simple setup)

        # Store job
        self.jobs[job_id] = {
            "template": tpl,
            "coinb1": coinb1,
            "coinb2": coinb2,
            "merkle_branch": merkle_branch,
            "version": version,
            "nbits": nbits,
            "ntime": ntime,
            "prevhash_le": prevhash_le,
        }

        return {
            "job_id": job_id,
            "prevhash": prevhash_le,
            "coinb1": coinb1,
            "coinb2": coinb2,
            "merkle_branch": merkle_branch,
            "version": version,
            "nbits": nbits,
            "ntime": ntime,
            "clean_jobs": clean_jobs,
        }

    def build_full_block(self, job_id: str, extranonce2_hex: str, ntime_hex: str, nonce_hex: str) -> bytes:
        """Rebuild the full block hex from a share submission."""
        if job_id not in self.jobs:
            raise ValueError("Unknown job_id")

        job = self.jobs[job_id]
        tpl = job["template"]

        # Rebuild coinbase with the actual extranonce2 from the miner
        coinbase_tx = self._build_coinbase(
            tpl,
            self.extranonce1,
            extranonce2_hex,
        )

        # Rebuild full transaction list
        txs = [coinbase_tx] + [bytes.fromhex(tx["data"]) for tx in tpl["transactions"]]

        # Compute merkle root
        tx_hashes = [sha256d(tx) for tx in txs]
        layer = tx_hashes
        while len(layer) > 1:
            if len(layer) % 2 == 1:
                layer.append(layer[-1])
            new_layer = []
            for i in range(0, len(layer), 2):
                new_layer.append(sha256d(layer[i] + layer[i+1]))
            layer = new_layer
        merkle_root = layer[0]

        version_i = int(job["version"], 16).to_bytes(4, "little")
        prevhash_be = tpl["previousblockhash"]
        prevhash = bytes.fromhex(prevhash_be)[::-1]
        merkle_root_be = merkle_root[::-1]
        ntime = int(ntime_hex, 16).to_bytes(4, "little")
        nbits = int(job["nbits"], 16).to_bytes(4, "little")
        nonce = int(nonce_hex, 16).to_bytes(4, "little")

        header = version_i + prevhash + merkle_root_be + ntime + nbits + nonce

        # Build full block: header + varint(txcount) + all txs
        block = header + varint(len(txs)) + b"".join(txs)
        return block


# ----------------------------
# Stratum connection handler
# ----------------------------

class StratumConnection(threading.Thread):
    def __init__(self, conn, addr, tmpl_builder: TemplateBuilder, rpc: JsonRPC):
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr
        self.tmpl_builder = tmpl_builder
        self.rpc = rpc

        self.alive = True
        self.subscribed = False
        self.authorized = False
        self.worker_name = None

        self.id_counter = 0
        self.conn_lock = threading.Lock()

    def send_json(self, obj):
        line = json.dumps(obj) + "\n"
        with self.conn_lock:
            self.conn.sendall(line.encode())

    def next_id(self):
        self.id_counter += 1
        return self.id_counter

    def handle_subscribe(self, msg):
        """Respond to mining.subscribe."""
        self.subscribed = True
        result = [
            [
                ["mining.notify", "subid-notify"],
                ["mining.set_difficulty", "subid-diff"],
            ],
            self.tmpl_builder.extranonce1,
            self.tmpl_builder.extranonce2_size,
        ]
        resp = {
            "id": msg["id"],
            "result": result,
            "error": None,
        }
        self.send_json(resp)

        # Immediately send difficulty and a job
        self.send_difficulty(POOL_DIFFICULTY)
        self.send_job()

    def handle_authorize(self, msg):
        """Respond to mining.authorize."""
        params = msg.get("params", [])
        if len(params) >= 1:
            self.worker_name = params[0]
        self.authorized = True
        resp = {
            "id": msg["id"],
            "result": True,
            "error": None,
        }
        self.send_json(resp)

    def send_difficulty(self, diff: float):
        msg = {
            "id": None,
            "method": "mining.set_difficulty",
            "params": [diff],
        }
        self.send_json(msg)

    def send_job(self):
        job = self.tmpl_builder.build_stratum_job()
        params = [
            job["job_id"],
            job["prevhash"],
            job["coinb1"],
            job["coinb2"],
            job["merkle_branch"],
            job["version"],
            job["nbits"],
            job["ntime"],
            job["clean_jobs"],
        ]
        msg = {
            "id": None,
            "method": "mining.notify",
            "params": params,
        }
        self.send_json(msg)

    def handle_submit(self, msg):
        """Handle mining.submit: [worker_name, job_id, extranonce2, ntime, nonce]."""
        params = msg.get("params", [])
        if len(params) != 5:
            resp = {"id": msg["id"], "result": None, "error": "Invalid params"}
            self.send_json(resp)
            return

        _worker, job_id, extranonce2, ntime, nonce = params

        try:
            block = self.tmpl_builder.build_full_block(job_id, extranonce2, ntime, nonce)
            block_hash = sha256d(block[:80])[::-1].hex()
            logging.info(f"Share from {self.addr}: job={job_id} hash={block_hash}")

            # Look up job & compute network (full) target
            job = self.tmpl_builder.jobs[job_id]
            network_target = nbits_to_target(job["nbits"])
            hash_int = int(block_hash, 16)

            if hash_int > network_target:
                # Regular share (above network target but valid) – accept it.
                logging.info("Accepted share (above network target, regular share)")
                resp = {"id": msg["id"], "result": True, "error": None}
                self.send_json(resp)
                return

            # Hash <= network target: this is a block candidate!
            logging.info("Share meets network target – submitting block to node")
            block_hex = block.hex()
            try:
                submit_result = self.rpc.submitblock(block_hex)
                if submit_result is None:
                    logging.info("Block accepted by Litecoin node")
                else:
                    logging.warning(f"submitblock returned error: {submit_result}")
            except Exception:
                logging.exception("submitblock RPC raised an exception")

            # Either way, count it as an accepted share for the miner
            resp = {"id": msg["id"], "result": True, "error": None}
            self.send_json(resp)

        except Exception as e:
            logging.exception("Error handling share")
            resp = {"id": msg["id"], "result": None, "error": str(e)}
            self.send_json(resp)

    def run(self):
        logging.info(f"New miner connected from {self.addr}")
        buff = b""
        self.conn.settimeout(1.0)

        last_job_time = 0

        while self.alive:
            # Periodically refresh jobs
            now = time.time()
            if self.subscribed and (now - last_job_time) > JOB_REFRESH_INTERVAL:
                try:
                    self.send_job()
                    last_job_time = now
                except Exception:
                    logging.exception("Error sending periodic job")

            try:
                data = self.conn.recv(4096)
                if not data:
                    break
                buff += data
                while b"\n" in buff:
                    line, buff = buff.split(b"\n", 1)
                    if not line.strip():
                        continue
                    try:
                        msg = json.loads(line.decode())
                        self.handle_message(msg)
                    except Exception:
                        logging.exception("Failed to parse / handle message")
            except socket.timeout:
                continue
            except (ConnectionResetError, OSError):
                break
            except Exception:
                logging.exception("Unexpected connection error")
                break

        logging.info(f"Miner disconnected: {self.addr}")
        self.conn.close()

    def handle_message(self, msg):
        method = msg.get("method")
        if method == "mining.subscribe":
            self.handle_subscribe(msg)
        elif method == "mining.authorize":
            self.handle_authorize(msg)
        elif method == "mining.submit":
            self.handle_submit(msg)
        else:
            # Respond with null for unknown methods
            if msg.get("id") is not None:
                resp = {"id": msg.get("id"), "result": None, "error": f"Unknown method {method}"}
                self.send_json(resp)


# ----------------------------
# Stratum Server
# ----------------------------

class StratumServer:
    def __init__(self, host, port, rpc: JsonRPC, sidechain_rpc, enable_sidechain: bool):
        self.host = host
        self.port = port
        self.rpc = rpc
        self.tmpl_builder = TemplateBuilder(rpc, sidechain_rpc, enable_sidechain)

    def start(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))
        s.listen(5)
        logging.info(f"Stratum server listening on {self.host}:{self.port}")

        try:
            while True:
                conn, addr = s.accept()
                handler = StratumConnection(conn, addr, self.tmpl_builder, self.rpc)
                handler.start()
        finally:
            s.close()


# ----------------------------
# Main
# ----------------------------

def main():
    rpc = JsonRPC(RPC_HOST, RPC_PORT, RPC_USER, RPC_PASSWORD)

    sidechain_rpc = None
    if ENABLE_SIDECHAIN:
        logging.info("Sidechain support ENABLED (ENABLE_SIDECHAIN=1)")
        sc_rpc = JsonRPC(SC_RPC_HOST, SC_RPC_PORT, SC_RPC_USER, SC_RPC_PASSWORD)
        sidechain_rpc = SidechainRPC(sc_rpc)
    else:
        logging.info("Sidechain support DISABLED (ENABLE_SIDECHAIN=0)")

    server = StratumServer(STRATUM_HOST, STRATUM_PORT, rpc, sidechain_rpc, ENABLE_SIDECHAIN)
    server.start()


if __name__ == "__main__":
    main()
