import os
import asyncio
import datetime
import sqlite3
import logging
import re
import base58
import json

from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

from solana.rpc.async_api import AsyncClient
from solana.transaction import Transaction
from solana.keypair import Keypair as SolanaKeypair
from solana.publickey import PublicKey
from solana.rpc.types import TxOpts
from spl.token.instructions import TransferCheckedParams, transfer_checked, get_associated_token_address, create_associated_token_account
from spl.token.constants import TOKEN_PROGRAM_ID

import httpx

# Logger setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
PRIVATE_KEY = os.getenv("FOGO_BOT_PRIVATE_KEY")
FOGO_TOKEN_MINT = PublicKey("So11111111111111111111111111111111111111112")
RPC_ENDPOINT = "https://testnet.fogo.io"

if PRIVATE_KEY is None:
    logger.critical("FOGO_BOT_PRIVATE_KEY environment variable is not set.")
    raise EnvironmentError("FOGO_BOT_PRIVATE_KEY is missing.")

AMOUNT_TO_SEND_FOGO = 500_000_000  # SPL token
DECIMALS = 9
DB_PATH = "fogo_requests.db"

# Database functions
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS requests (
            user_id INTEGER PRIMARY KEY,
            last_request TIMESTAMP,
            wallet TEXT,
            tx_hash TEXT
        )
    """)
    conn.commit()
    conn.close()

def get_last_request_time(user_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT last_request FROM requests WHERE user_id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return datetime.datetime.fromisoformat(row[0])
    return None

def update_last_request_time(user_id, request_time, wallet, tx_hash):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("REPLACE INTO requests (user_id, last_request, wallet, tx_hash) VALUES (?, ?, ?, ?)",
              (user_id, request_time.isoformat(), wallet, tx_hash))
    conn.commit()
    conn.close()

# Handlers
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    name = update.effective_user.first_name or "there"
    await update.message.reply_text(
        f"Hi {name}! I’m a FOGO Testnet faucet bot.\n"
        "Use the /send command to receive 0.5 testnet FOGO (once every 24 hours).\n"
        "Use /send_fee for a small amount of native FOGO if your wallet is low."
    )

async def send_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    now = datetime.datetime.now()
    last = get_last_request_time(user_id)

    if last and now - last < datetime.timedelta(hours=24):
        remaining = datetime.timedelta(hours=24) - (now - last)
        h, m = divmod(int(remaining.total_seconds()), 3600)
        m, s = divmod(m, 60)
        await update.message.reply_text(
            f"You've already received tokens within the last 24 hours.\n"
            f"Please try again in {h} hour(s), {m} minute(s), and {s} second(s)."
        )
        return

    context.user_data['waiting_for_address'] = True
    await update.message.reply_text("Please send your FOGO wallet address (Solana format):")

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if context.user_data.get("waiting_for_address"):
        address = update.message.text.strip()
        user_id = update.effective_user.id
        context.user_data["waiting_for_address"] = False

        if not re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{32,44}", address):
            await update.message.reply_text("Invalid wallet address. Please try again.")
            return

        await update.message.reply_text(f"Sending {AMOUNT_TO_SEND_FOGO / 1_000_000_000} FOGO to {address}...")
        tx_hash = await send_fogo_spl_token(address, AMOUNT_TO_SEND_FOGO)

        if tx_hash:
            update_last_request_time(user_id, datetime.datetime.now(), address, tx_hash)
            await update.message.reply_text(
                f"✅ Tokens sent!\n[View transaction](https://fogoscan.com/tx/{tx_hash}?cluster=testnet)",
                parse_mode="Markdown"
            )
        else:
            await update.message.reply_text("❌ Failed to send tokens. Please try again later.")
    else:
        await update.message.reply_text("Use /start or /send to request tokens.")

# SPL sending logic
async def send_fogo_spl_token(to_address: str, amount: int):
    try:
        decoded_key = base58.b58decode(PRIVATE_KEY)
        sender = SolanaKeypair.from_secret_key(decoded_key)
        sender_pubkey = sender.public_key
        receiver_pubkey = PublicKey(to_address)

        sender_token_account = get_associated_token_address(sender_pubkey, FOGO_TOKEN_MINT)
        receiver_token_account = get_associated_token_address(receiver_pubkey, FOGO_TOKEN_MINT)

        async with AsyncClient(RPC_ENDPOINT) as client:
            resp = await client.get_account_info(receiver_token_account)
            account_exists = resp.get("result", {}).get("value") is not None

        async with httpx.AsyncClient(timeout=20.0) as http_client:
            blockhash_req = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getLatestBlockhash",
                "params": []
            }
            resp = await http_client.post(RPC_ENDPOINT, json=blockhash_req)
            bh = resp.json()
            blockhash = bh.get("result", {}).get("value", {}).get("blockhash")

        if not blockhash:
            return None

        tx = Transaction()
        tx.fee_payer = sender_pubkey
        tx.recent_blockhash = blockhash

        if not account_exists:
            tx.add(create_associated_token_account(sender_pubkey, receiver_pubkey, FOGO_TOKEN_MINT))

        tx.add(transfer_checked(
            TransferCheckedParams(
                program_id=TOKEN_PROGRAM_ID,
                source=sender_token_account,
                mint=FOGO_TOKEN_MINT,
                dest=receiver_token_account,
                owner=sender_pubkey,
                amount=amount,
                decimals=DECIMALS,
                signers=[]
            )
        ))

        tx.sign(sender)
        raw_tx = tx.serialize()

        async with AsyncClient(RPC_ENDPOINT) as client:
            send_resp = await client.send_raw_transaction(raw_tx, opts=TxOpts(skip_confirmation=False))

        return send_resp.get("result")
    except Exception as e:
        logger.error(f"Send SPL error: {e}", exc_info=True)
        return None

# Native FOGO (SOL-like) faucet logic
async def send_fee_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Please send your wallet address to receive native FOGO.")
    context.user_data['waiting_for_native'] = True

async def handle_native_request(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if context.user_data.get("waiting_for_native"):
        context.user_data['waiting_for_native'] = False
        wallet = update.message.text.strip()
        if not re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{32,44}", wallet):
            await update.message.reply_text("Invalid wallet address.")
            return

        balance = await get_native_balance(wallet)
        if balance is None:
            await update.message.reply_text("❌ Failed to check balance.")
            return

        if balance > 0.01:
            await update.message.reply_text("❌ Wallet already has enough FOGO native balance.")
            return

        tx = await send_native_fogo(wallet, 100_000)  # 0.0001 FOGO
        if tx:
            await update.message.reply_text(f"✅ Sent native FOGO! [View](https://fogoscan.com/tx/{tx}?cluster=testnet)", parse_mode="Markdown")
        else:
            await update.message.reply_text("❌ Failed to send native FOGO.")

async def get_native_balance(address: str) -> float:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(RPC_ENDPOINT, json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getBalance",
                "params": [address]
            })
            lamports = resp.json().get("result", {}).get("value", 0)
            return lamports / 1_000_000_000
    except Exception as e:
        logger.error(f"Balance check error: {e}", exc_info=True)
        return None

async def send_native_fogo(to_address: str, lamports: int):
    try:
        decoded_key = base58.b58decode(PRIVATE_KEY)
        sender = SolanaKeypair.from_secret_key(decoded_key)
        sender_pubkey = sender.public_key
        receiver = PublicKey(to_address)

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(RPC_ENDPOINT, json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getLatestBlockhash",
                "params": []
            })
            blockhash = resp.json().get("result", {}).get("value", {}).get("blockhash")

        if not blockhash:
            return None

        tx = Transaction(recent_blockhash=blockhash, fee_payer=sender_pubkey)
        tx.add({
            "programId": "11111111111111111111111111111111",
            "keys": [
                {"pubkey": str(sender_pubkey), "isSigner": True, "isWritable": True},
                {"pubkey": str(receiver), "isSigner": False, "isWritable": True}
            ],
            "data": base58.b58encode(lamports.to_bytes(8, "little")).decode()
        })
        tx.sign(sender)
        raw_tx = tx.serialize()

        async with AsyncClient(RPC_ENDPOINT) as client:
            send_resp = await client.send_raw_transaction(raw_tx, opts=TxOpts(skip_confirmation=False))
        return send_resp.get("result")
    except Exception as e:
        logger.error(f"Native send error: {e}", exc_info=True)
        return None

# Error
async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.error(f"Unexpected error: {context.error}", exc_info=True)
    if update and update.message:
        await update.message.reply_text("An error occurred. Please try again later.")

# Main app
if __name__ == "__main__":
    init_db()
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("send", send_command))
    app.add_handler(CommandHandler("send_fee", send_fee_command))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_native_request))
    app.add_error_handler(error_handler)
    app.run_polling()
