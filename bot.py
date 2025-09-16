

from __future__ import annotations

import asyncio
import json
import os
import re
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Optional, Tuple, List

import base58
import requests
from dotenv import load_dotenv

from telegram import Update
from telegram.ext import (
    ApplicationBuilder, CommandHandler, ContextTypes,
    MessageHandler, filters
)

# -------- Chain libs --------
# Solana
from solana.rpc.api import Client as SolClient
from solders.keypair import Keypair
from solders.pubkey import PublicKey
from solders.transaction import Transaction
from solders.system_program import TransferParams, transfer

# EVM
from web3 import Web3
from web3.types import TxParams

# ------------- ENV -------------
load_dotenv()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TWITTER_BEARER     = os.getenv("TWITTER_BEARER", "").strip()

SOLANA_RPC_URL     = os.getenv("SOLANA_RPC_URL", "https://api.mainnet-beta.solana.com").strip()
SOLANA_SECRET      = os.getenv("SOLANA_SECRET", "").strip()

ETH_RPC_URL        = os.getenv("ETH_RPC_URL", "https://ethereum.publicnode.com").strip()
BASE_RPC_URL       = os.getenv("BASE_RPC_URL", "https://mainnet.base.org").strip()
PRIVATE_KEY        = os.getenv("PRIVATE_KEY", "").strip()

# Optional preconfigured Base router/WETH (can be set later via commands)
ENV_BASE_ROUTER    = os.getenv("BASE_ROUTER", "").strip()
ENV_BASE_WETH      = os.getenv("BASE_WETH", "").strip()

if not TELEGRAM_BOT_TOKEN:
    raise SystemExit("Missing TELEGRAM_BOT_TOKEN in .env")

# ------------- Storage -------------
USERS_FILE = Path("users.json")
USERS_FILE.touch(exist_ok=True)
try:
    USERS_DB: Dict[str, Dict] = json.loads(USERS_FILE.read_text("utf-8") or "{}")
except Exception:
    USERS_DB = {}

def save_users():
    USERS_FILE.write_text(json.dumps(USERS_DB, ensure_ascii=False, indent=2), "utf-8")

@dataclass
class UserCfg:
    chain: str = "solana"          # solana | ethereum | base
    amount: float = 0.01           # SOL or ETH
    # EVM router/WETH overrides per user (for base or custom forks)
    evm_router: Dict[str, str] = None
    evm_weth: Dict[str, str] = None

    @classmethod
    def load(cls, uid: int) -> "UserCfg":
        row = USERS_DB.get(str(uid), {})
        return cls(
            chain=row.get("chain", "solana"),
            amount=float(row.get("amount", 0.01)),
            evm_router=row.get("evm_router", {}),
            evm_weth=row.get("evm_weth", {}),
        )

    def save(self, uid: int):
        USERS_DB[str(uid)] = asdict(self)
        save_users()

# ------------- Monitors -------------
# per-user monitoring task state
MONITORS: Dict[int, Dict] = {}  # uid -> {"task": asyncio.Task, "handle": str, "mode": "A"/"B", "last_id": str}

POLL_SECONDS = 15  # keep lightweight but responsive

# ------------- Regex & Helpers -------------
EVM_ADDR_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
SOL_BASE58_RE = re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b")
SOL_TOKEN_LINK_RE = re.compile(r"solscan\.io/token/([1-9A-HJ-NP-Za-km-z]{32,44})", re.IGNORECASE)

TOKEN_PROGRAM_ID = PublicKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
JUP_QUOTE = "https://quote.jup.ag/v6/quote"
JUP_SWAP  = "https://quote.jup.ag/v6/swap"

ETHERSCAN_TX   = "https://etherscan.io/tx/"
BASESCAN_TX    = "https://basescan.org/tx/"
SOLSCAN_TX     = "https://solscan.io/tx/"

# Uniswap V2 Router ABI pieces
ROUTER_ABI = [
    {
        "name": "getAmountsOut",
        "outputs": [{"name": "amounts", "type": "uint256[]"}],
        "inputs": [{"name": "amountIn", "type": "uint256"}, {"name": "path", "type": "address[]"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "name": "swapExactETHForTokens",
        "outputs": [{"name": "amounts", "type": "uint256[]"}],
        "inputs": [
            {"name": "amountOutMin", "type": "uint256"},
            {"name": "path", "type": "address[]"},
            {"name": "to", "type": "address"},
            {"name": "deadline", "type": "uint256"},
        ],
        "stateMutability": "payable",
        "type": "function",
    },
]

# Defaults for EVM routers/WETH
EVM_DEFAULTS = {
    "ethereum": {
        "rpc": ETH_RPC_URL,
        "chain_id": 1,
        "router": "0x7a250d5630B4cf539739dF2C5dAcb4c659F2488D",     # UniswapV2 Router02
        "weth":   "0xC02aaA39b223FE8D0A0E5C4F27eAD9083C756Cc2",     # WETH
        "explorer": ETHERSCAN_TX
    },
    "base": {
        "rpc": BASE_RPC_URL,
        "chain_id": 8453,
        "router": ENV_BASE_ROUTER or "",  # you can set later via /setrouter base 0x...
        "weth":   ENV_BASE_WETH   or "",  # you can set later via /setweth base 0x...
        "explorer": BASESCAN_TX
    }
}

# ---------- Twitter helpers ----------
def twitter_user_id(handle: str) -> Optional[str]:
    if not TWITTER_BEARER:
        return None
    url = f"https://api.twitter.com/2/users/by/username/{handle}"
    headers = {"Authorization": f"Bearer {TWITTER_BEARER}"}
    r = requests.get(url, headers=headers, timeout=20)
    if r.ok:
        return r.json().get("data", {}).get("id")
    return None

def twitter_latest_tweets(user_id: str, since_id: Optional[str]) -> List[Dict]:
    if not TWITTER_BEARER:
        return []
    url = f"https://api.twitter.com/2/users/{user_id}/tweets"
    headers = {"Authorization": f"Bearer {TWITTER_BEARER}"}
    params = {
        "max_results": 5,
        "tweet.fields": "created_at",
        "exclude": "replies"
    }
    if since_id:
        params["since_id"] = since_id
    r = requests.get(url, headers=headers, params=params, timeout=20)
    if not r.ok:
        return []
    data = r.json().get("data", [])
    # return newest first
    return sorted(data, key=lambda x: int(x["id"]), reverse=False)

# ---------- Address detection & verification ----------
def is_valid_solana_pubkey(s: str) -> bool:
    try:
        _ = PublicKey(s)
        return True
    except Exception:
        return False

def parse_candidates(text: str, chain: str) -> List[str]:
    cands = []
    if chain in ("ethereum", "base"):
        cands += EVM_ADDR_RE.findall(text)
    if chain == "solana":
        # token link first
        m = SOL_TOKEN_LINK_RE.search(text)
        if m and is_valid_solana_pubkey(m.group(1)):
            cands.append(m.group(1))
        # any base58 strings
        for x in SOL_BASE58_RE.findall(text):
            if is_valid_solana_pubkey(x):
                cands.append(x)
    # dedupe keep order
    seen = set()
    out = []
    for a in cands:
        if a not in seen:
            out.append(a)
            seen.add(a)
    return out

# --- Solana verification ---
def sol_is_mint(client: SolClient, key: str) -> bool:
    try:
        acc = client.get_account_info(key)
        info = acc.get("result", {}).get("value")
        if not info:
            return False
        owner = info.get("owner")
        return owner == str(TOKEN_PROGRAM_ID)
    except Exception:
        return False

def sol_wallet_exists(client: SolClient, key: str) -> bool:
    try:
        _ = client.get_balance(key)
        return True
    except Exception:
        return False

# --- EVM verification ---
def evm_get_web3(chain: str) -> Web3:
    conf = EVM_DEFAULTS[chain]
    w3 = Web3(Web3.HTTPProvider(conf["rpc"], request_kwargs={"timeout": 30}))
    if not w3.is_connected():
        raise RuntimeError(f"RPC not reachable for {chain}")
    return w3

def evm_is_contract(chain: str, addr: str) -> bool:
    try:
        w3 = evm_get_web3(chain)
        code = w3.eth.get_code(Web3.to_checksum_address(addr)).hex()
        return code != "0x"
    except Exception:
        return False

def evm_wallet_exists(chain: str, addr: str) -> bool:
    try:
        w3 = evm_get_web3(chain)
        _ = w3.eth.get_balance(Web3.to_checksum_address(addr))
        return True
    except Exception:
        return False

# ---------- Transactions ----------
# Solana keypair loader (Base58 or JSON[64])
def load_solana_keypair() -> Keypair:
    if not SOLANA_SECRET:
        raise RuntimeError("SOLANA_SECRET not set")
    if SOLANA_SECRET.strip().startswith("["):
        arr = json.loads(SOLANA_SECRET)
        return Keypair.from_bytes(bytes(arr))
    raw = base58.b58decode(SOLANA_SECRET)
    if len(raw) == 64:
        return Keypair.from_bytes(raw)
    elif len(raw) == 32:
        # derive 64 from seed
        from nacl import signing
        sk = signing.SigningKey(raw)
        return Keypair.from_secret_key(bytes(sk._seed) + bytes(sk.verify_key))
    raise RuntimeError("SOLANA_SECRET format invalid (expect Base58 32/64 or JSON[64])")

def sol_send_sol(to_pubkey: str, amount_sol: float) -> str:
    client = SolClient(SOLANA_RPC_URL)
    kp = load_solana_keypair()
    lamports = int(amount_sol * 1_000_000_000)
    tx = Transaction().add(transfer(TransferParams(
        from_pubkey=kp.public_key,
        to_pubkey=PublicKey(to_pubkey),
        lamports=lamports
    )))
    resp = client.send_transaction(tx, kp)
    sig = resp["result"]
    return SOLSCAN_TX + sig

def sol_buy_via_jupiter(mint_out: str, amount_sol: float, slippage_bps: int = 800) -> str:
    client = SolClient(SOLANA_RPC_URL)
    kp = load_solana_keypair()
    user_pubkey = str(kp.public_key)
    amount_lamports = int(amount_sol * 1_000_000_000)
    input_mint = "So11111111111111111111111111111111111111112"
    # quote
    q = requests.get(JUP_QUOTE, params={
        "inputMint": input_mint,
        "outputMint": mint_out,
        "amount": amount_lamports,
        "slippageBps": slippage_bps
    }, timeout=25)
    q.raise_for_status()
    quote = q.json()
    # legacy swap
    s = requests.post(JUP_SWAP, json={
        "quoteResponse": quote,
        "userPublicKey": user_pubkey,
        "wrapAndUnwrapSol": True,
        "asLegacyTransaction": True
    }, timeout=25)
    s.raise_for_status()
    swap_tx_b64 = s.json().get("swapTransaction")
    if not swap_tx_b64:
        raise RuntimeError("Jupiter did not return transaction")
    from base64 import b64decode
    tx_bytes = b64decode(swap_tx_b64)
    tx = Transaction.deserialize(tx_bytes)
    tx.sign(kp)
    resp = client.send_raw_transaction(tx.serialize())
    sig = resp["result"]
    return SOLSCAN_TX + sig

def evm_native_send(chain: str, to_addr: str, amount_eth: float) -> str:
    if not PRIVATE_KEY:
        raise RuntimeError("PRIVATE_KEY not set for EVM")
    conf = EVM_DEFAULTS[chain]
    w3 = evm_get_web3(chain)
    acct = w3.eth.account.from_key(PRIVATE_KEY)
    nonce = w3.eth.get_transaction_count(acct.address)
    tx: TxParams = {
        "to": Web3.to_checksum_address(to_addr),
        "value": w3.to_wei(amount_eth, "ether"),
        "nonce": nonce,
        "gasPrice": w3.eth.gas_price,
        "chainId": conf["chain_id"],
    }
    tx["gas"] = w3.eth.estimate_gas({"from": acct.address, "to": tx["to"], "value": tx["value"]})
    signed = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction).hex()
    return conf["explorer"] + tx_hash

def evm_swap_exact_eth_for_tokens(chain: str, token_addr: str, amount_eth: float, slippage_bps: int = 800) -> str:
    if not PRIVATE_KEY:
        raise RuntimeError("PRIVATE_KEY not set for EVM")
    conf = EVM_DEFAULTS[chain]
    if not conf.get("router") or not conf.get("weth"):
        raise RuntimeError(f"{chain}: Router/WETH not set. Use /setrouter and /setweth (or .env) first.")
    w3 = evm_get_web3(chain)
    acct = w3.eth.account.from_key(PRIVATE_KEY)
    router = w3.eth.contract(address=Web3.to_checksum_address(conf["router"]), abi=ROUTER_ABI)

    path = [Web3.to_checksum_address(conf["weth"]), Web3.to_checksum_address(token_addr)]
    value = w3.to_wei(amount_eth, "ether")
    amounts_out = router.functions.getAmountsOut(value, path).call()
    expected_out = amounts_out[-1]
    min_out = expected_out * (10_000 - slippage_bps) // 10_000

    deadline = int(time.time()) + 60 * 5
    nonce = w3.eth.get_transaction_count(acct.address)
    tx = router.functions.swapExactETHForTokens(
        min_out, path, acct.address, deadline
    ).build_transaction({
        "from": acct.address,
        "value": value,
        "nonce": nonce,
        "gasPrice": w3.eth.gas_price,
        "chainId": conf["chain_id"],
    })
    tx["gas"] = w3.eth.estimate_gas(tx)
    signed = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction).hex()
    return conf["explorer"] + tx_hash

# ---------- Telegram Commands ----------
HELP = (
    "X Watcher Bot (SOL + ETH + BASE)\n\n"
    "Config:\n"
    "  /setchain <solana|ethereum|base>\n"
    "  /setamount <float>\n"
    "  /config\n"
    "  /setrouter <ethereum|base> <router_addr>   (EVM buy)\n"
    "  /setweth   <ethereum|base> <weth_addr>     (EVM buy)\n\n"
    "Monitor:\n"
    "  /monitor <x_handle> <A|B>\n"
    "    A = Buy from CA  |  B = Send to wallet\n"
    "  /stopmonitor\n"
)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    cfg = UserCfg.load(uid)
    # seed defaults for base from env if provided
    if ENV_BASE_ROUTER and (cfg.evm_router or {}) .get("base") in (None, "",):
        cfg.evm_router["base"] = ENV_BASE_ROUTER
    if ENV_BASE_WETH and (cfg.evm_weth or {}).get("base") in (None, "",):
        cfg.evm_weth["base"] = ENV_BASE_WETH
    if cfg.evm_router is None: cfg.evm_router = {}
    if cfg.evm_weth   is None: cfg.evm_weth   = {}
    cfg.save(uid)
    await update.message.reply_text("Welcome 👋\n\n" + HELP)

async def config_show(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    cfg = UserCfg.load(uid)
    er = cfg.evm_router or {}
    ew = cfg.evm_weth or {}
    txt = [
        f"chain = {cfg.chain}",
        f"amount = {cfg.amount}",
        f"evm_router.ethereum = {er.get('ethereum','') or EVM_DEFAULTS['ethereum']['router']}",
        f"evm_weth.ethereum   = {ew.get('ethereum','')   or EVM_DEFAULTS['ethereum']['weth']}",
        f"evm_router.base     = {er.get('base','') or EVM_DEFAULTS['base']['router']}",
        f"evm_weth.base       = {ew.get('base','') or EVM_DEFAULTS['base']['weth']}",
    ]
    await update.message.reply_text("Your config:\n" + "\n".join(txt))

async def setchain(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if not context.args:
        await update.message.reply_text("Usage: /setchain <solana|ethereum|base>")
        return
    chain = context.args[0].strip().lower()
    if chain not in ("solana", "ethereum", "base"):
        await update.message.reply_text("Choose: solana | ethereum | base")
        return
    cfg = UserCfg.load(uid); cfg.chain = chain; cfg.save(uid)
    await update.message.reply_text(f"✅ chain set to {chain}")

async def setamount(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if not context.args:
        await update.message.reply_text("Usage: /setamount <float>")
        return
    try:
        amt = float(context.args[0])
        if amt <= 0: raise ValueError
    except Exception:
        await update.message.reply_text("Provide a positive number, e.g., /setamount 0.05")
        return
    cfg = UserCfg.load(uid); cfg.amount = amt; cfg.save(uid)
    await update.message.reply_text(f"✅ amount set to {amt}")

async def setrouter(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if len(context.args) != 2:
        await update.message.reply_text("Usage: /setrouter <ethereum|base> <router_addr>")
        return
    net = context.args[0].lower()
    addr = context.args[1]
    if net not in ("ethereum", "base"):
        await update.message.reply_text("Network must be ethereum or base")
        return
    if not EVM_ADDR_RE.fullmatch(addr):
        await update.message.reply_text("Router must be a valid 0x... address")
        return
    cfg = UserCfg.load(uid)
    if not cfg.evm_router: cfg.evm_router = {}
    cfg.evm_router[net] = addr
    cfg.save(uid)
    if net == "base":
        EVM_DEFAULTS["base"]["router"] = addr
    else:
        EVM_DEFAULTS["ethereum"]["router"] = addr
    await update.message.reply_text(f"✅ {net} router set to {addr}")

async def setweth(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if len(context.args) != 2:
        await update.message.reply_text("Usage: /setweth <ethereum|base> <weth_addr>")
        return
    net = context.args[0].lower()
    addr = context.args[1]
    if net not in ("ethereum", "base"):
        await update.message.reply_text("Network must be ethereum or base")
        return
    if not EVM_ADDR_RE.fullmatch(addr):
        await update.message.reply_text("WETH must be a valid 0x... address")
        return
    cfg = UserCfg.load(uid)
    if not cfg.evm_weth: cfg.evm_weth = {}
    cfg.evm_weth[net] = addr
    cfg.save(uid)
    if net == "base":
        EVM_DEFAULTS["base"]["weth"] = addr
    else:
        EVM_DEFAULTS["ethereum"]["weth"] = addr
    await update.message.reply_text(f"✅ {net} WETH set to {addr}")

async def stopmonitor(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    st = MONITORS.get(uid)
    if st and st.get("task"):
        st["task"].cancel()
        MONITORS.pop(uid, None)
        await update.message.reply_text("🛑 Monitor stopped.")
    else:
        await update.message.reply_text("No active monitor.")

# ------------- Monitor loop -------------
async def monitor_loop(app_ctx: ContextTypes.DEFAULT_TYPE, uid: int, handle: str, mode: str):
    await app_ctx.bot.send_message(chat_id=uid, text=f"👀 Monitoring @{handle} for mode {mode}…")
    tw_uid = twitter_user_id(handle)
    if not tw_uid:
        await app_ctx.bot.send_message(chat_id=uid, text="Couldn't resolve Twitter handle (set TWITTER_BEARER in .env).")
        return
    last_id = MONITORS[uid].get("last_id")
    cfg = UserCfg.load(uid)
    while True:
        try:
            tweets = twitter_latest_tweets(tw_uid, since_id=last_id)
            for t in tweets:
                last_id = t["id"]
                MONITORS[uid]["last_id"] = last_id
                text = t.get("text", "")
                # parse candidates by current cfg.chain
                cands = parse_candidates(text, cfg.chain)
                if not cands:
                    continue

                # verify and execute first valid by mode
                if mode == "A":
                    # BUY from CA
                    tx_link = await asyncio.get_event_loop().run_in_executor(None, buy_from_candidates, cfg, cands)
                else:
                    # SEND to wallet
                    tx_link = await asyncio.get_event_loop().run_in_executor(None, send_to_candidates, cfg, cands)

                if tx_link:
                    await app_ctx.bot.send_message(chat_id=uid, text=f"✅ Executed.\n{tx_link}")
                else:
                    await app_ctx.bot.send_message(chat_id=uid, text="No valid address passed verification in that tweet.")
            await asyncio.sleep(POLL_SECONDS)
            # reload cfg to allow on-the-fly changes
            cfg = UserCfg.load(uid)
        except asyncio.CancelledError:
            break
        except Exception as e:
            await app_ctx.bot.send_message(chat_id=uid, text=f"Monitor error: {e}")
            await asyncio.sleep(POLL_SECONDS)

def buy_from_candidates(cfg: UserCfg, cands: List[str]) -> Optional[str]:
    try:
        if cfg.chain == "solana":
            client = SolClient(SOLANA_RPC_URL)
            for a in cands:
                if sol_is_mint(client, a):
                    return sol_buy_via_jupiter(a, cfg.amount, slippage_bps=800)
            return None
        elif cfg.chain in ("ethereum", "base"):
            for a in cands:
                if evm_is_contract(cfg.chain, a):
                    # use per-user overrides if present
                    if cfg.evm_router and cfg.chain in cfg.evm_router and cfg.evm_router[cfg.chain]:
                        EVM_DEFAULTS[cfg.chain]["router"] = cfg.evm_router[cfg.chain]
                    if cfg.evm_weth and cfg.chain in cfg.evm_weth and cfg.evm_weth[cfg.chain]:
                        EVM_DEFAULTS[cfg.chain]["weth"] = cfg.evm_weth[cfg.chain]
                    return evm_swap_exact_eth_for_tokens(cfg.chain, a, cfg.amount, slippage_bps=800)
            return None
        else:
            return None
    except Exception as e:
        # surface error up
        return f"Buy failed: {e}"

def send_to_candidates(cfg: UserCfg, cands: List[str]) -> Optional[str]:
    try:
        if cfg.chain == "solana":
            client = SolClient(SOLANA_RPC_URL)
            for a in cands:
                if sol_wallet_exists(client, a):
                    return sol_send_sol(a, cfg.amount)
            return None
        elif cfg.chain in ("ethereum", "base"):
            for a in cands:
                if evm_wallet_exists(cfg.chain, a) and not evm_is_contract(cfg.chain, a):
                    return evm_native_send(cfg.chain, a, cfg.amount)
            return None
        else:
            return None
    except Exception as e:
        return f"Send failed: {e}"

# ------------- Command: /monitor -------------
async def monitor_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if len(context.args) != 2:
        await update.message.reply_text("Usage: /monitor <x_handle> <A|B>")
        return
    handle = context.args[0].lstrip("@")
    mode = context.args[1].upper()
    if mode not in ("A", "B"):
        await update.message.reply_text("Mode must be A (buy) or B (send)")
        return
    # cancel old
    old = MONITORS.get(uid)
    if old and old.get("task"):
        old["task"].cancel()
    MONITORS[uid] = {"task": None, "handle": handle, "mode": mode, "last_id": None}
    task = asyncio.create_task(monitor_loop(context, uid, handle, mode))
    MONITORS[uid]["task"] = task
    await update.message.reply_text(f"Started monitoring @{handle} for mode {mode}.")

async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(HELP)

# ------------- Main -------------
def main():
    app = ApplicationBuilder().token(TELEGRAM_BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(CommandHandler("config", config_show))
    app.add_handler(CommandHandler("setchain", setchain))
    app.add_handler(CommandHandler("setamount", setamount))
    app.add_handler(CommandHandler("setrouter", setrouter))
    app.add_handler(CommandHandler("setweth", setweth))
    app.add_handler(CommandHandler("monitor", monitor_cmd))
    app.add_handler(CommandHandler("stopmonitor", stopmonitor))
    app.add_handler(MessageHandler(filters.COMMAND, help_cmd))
    print("Bot running. Ctrl+C to stop.")
    app.run_polling(close_loop=False)

if __name__ == "__main__":
    main()
