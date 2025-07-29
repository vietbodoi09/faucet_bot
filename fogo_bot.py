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

if PRIVATE_KEY is None:
    logger.critical("FOGO_BOT_PRIVATE_KEY environment variable is not set.")
    raise EnvironmentError("FOGO_BOT_PRIVATE_KEY is missing.")

AMOUNT_TO_SEND_FOGO = 500_000_000  # 0.5 FOGO = 500_000_000 base units
DECIMALS = 9
DB_PATH = "fogo_requests.db"

# Initialize DB
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

    c.execute("""
        CREATE TABLE IF NOT EXISTS fee_requests (
            user_id INTEGER PRIMARY KEY,
            last_request TIMESTAMP
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

def get_last_fee_request_time(user_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT last_request FROM fee_requests WHERE user_id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return datetime.datetime.fromisoformat(row[0])
    return None

def update_last_fee_request_time(user_id, request_time):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("REPLACE INTO fee_requests (user_id, last_request) VALUES (?, ?)",
              (user_id, request_time.isoformat()))
    conn.commit()
    conn.close()

async def send_fee_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    now = datetime.datetime.now()
    last = get_last_fee_request_time(user_id)

    if last and now - last < datetime.timedelta(hours=24):
        remaining = datetime.timedelta(hours=24) - (now - last)
        h, m = divmod(int(remaining.total_seconds()), 3600)
        m, s = divmod(m, 60)
        await update.message.reply_text(
            f"You've already used /send_fee in the last 24 hours.\n"
            f"Try again in {h} hour(s), {m} minute(s), {s} second(s)."
        )
        return

    if len(context.args) != 1:
        await update.message.reply_text("Usage: /send_fee <your_wallet_address>")
        return

    address = context.args[0].strip()
    if not re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{32,44}", address):
        await update.message.reply_text("Invalid wallet address format.")
        return

    await update.message.reply_text(f"Checking balance and sending fee if needed to {address}...")
    success = await send_native_fogo_fee(address)
    if success:
        update_last_fee_request_time(user_id, now)
        await update.message.reply_text("✅ Native FOGO fee sent successfully.")
    else:
        await update.message.reply_text("❌ Failed or wallet already has enough FOGO.")

async def send_native_fogo_fee(wallet_address: str) -> bool:
    try:
        async with AsyncClient("https://testnet.fogo.io") as client:
            balance_resp = await client.get_balance(PublicKey(wallet_address))
            lamports = balance_resp['result']['value'] if isinstance(balance_resp, dict) else balance_resp.value
            if lamports > 10_000_000:
                return False

        decoded_key = base58.b58decode(PRIVATE_KEY)
        sender = SolanaKeypair.from_secret_key(decoded_key)

        async with httpx.AsyncClient(timeout=20.0) as http_client:
            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getLatestBlockhash",
                "params": []
            }
            rpc_response = await http_client.post("https://testnet.fogo.io", json=payload)
            latest_blockhash = rpc_response.json().get("result", {}).get("value", {}).get("blockhash")

        if not latest_blockhash:
            return False

        tx = Transaction()
        tx.recent_blockhash = latest_blockhash
        tx.fee_payer = sender.public_key
        tx.add(
            transfer(
                from_pubkey=sender.public_key,
                to_pubkey=PublicKey(wallet_address),
                lamports=20_000_000
            )
        )

        tx.sign(sender)
        async with AsyncClient("https://testnet.fogo.io") as client:
            result = await client.send_transaction(tx, sender)
            return 'result' in result
    except Exception as e:
        logger.error(f"Failed to send native FOGO: {e}", exc_info=True)
        return False

async def send_fogo_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    now = datetime.datetime.now()
    last = get_last_request_time(user_id)

    if last and now - last < datetime.timedelta(hours=24):
        remaining = datetime.timedelta(hours=24) - (now - last)
        h, m = divmod(int(remaining.total_seconds()), 3600)
        m, s = divmod(m, 60)
        await update.message.reply_text(
            f"You've already used /send_fogo in the last 24 hours.\n"
            f"Try again in {h} hour(s), {m} minute(s), {s} second(s)."
        )
        return

    if len(context.args) != 1:
        await update.message.reply_text("Usage: /send_fogo <your_wallet_address>")
        return

    wallet = context.args[0].strip()
    if not re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{32,44}", wallet):
        await update.message.reply_text("Invalid wallet address format.")
        return

    await update.message.reply_text(f"Sending 0.5 SPL FOGO to {wallet}...")
    tx = await send_fogo_spl_token(wallet, AMOUNT_TO_SEND_FOGO)
    if tx:
        update_last_request_time(user_id, now, wallet, tx)
        await update.message.reply_text(f"✅ 0.5 SPL FOGO sent successfully.\nTransaction: {tx}")
    else:
        await update.message.reply_text("❌ Failed to send SPL FOGO.")

async def send_fogo_spl_token(to_address: str, amount: int) -> str:
    try:
        decoded_key = base58.b58decode(PRIVATE_KEY)
        sender = SolanaKeypair.from_secret_key(decoded_key)
        async with AsyncClient("https://testnet.fogo.io") as client:
            ata = get_associated_token_address(PublicKey(to_address), FOGO_TOKEN_MINT)
            info = await client.get_account_info(ata)
            if info['result']['value'] is None:
                tx = Transaction()
                tx.add(
                    create_associated_token_account(
                        payer=sender.public_key,
                        owner=PublicKey(to_address),
                        mint=FOGO_TOKEN_MINT
                    )
                )
                await client.send_transaction(tx, sender, opts=TxOpts(skip_confirmation=False))

            tx = Transaction()
            tx.add(
                transfer_checked(
                    TransferCheckedParams(
                        program_id=TOKEN_PROGRAM_ID,
                        source=get_associated_token_address(sender.public_key, FOGO_TOKEN_MINT),
                        mint=FOGO_TOKEN_MINT,
                        dest=get_associated_token_address(PublicKey(to_address), FOGO_TOKEN_MINT),
                        owner=sender.public_key,
                        amount=amount,
                        decimals=DECIMALS
                    )
                )
            )
            resp = await client.send_transaction(tx, sender, opts=TxOpts(skip_confirmation=False))
            return resp['result'] if 'result' in resp else None
    except Exception as e:
        logger.error(f"Error sending token: {e}", exc_info=True)
        return None

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    name = update.effective_user.first_name or "there"
    await update.message.reply_text(
        f"Hi {name}! I’m a FOGO Testnet faucet bot.\n"
        "Use the /send_fogo command to receive 0.5 SPL testnet FOGO (once every 24 hours).\n"
        "Use /send_fee <wallet> to request native FOGO if your wallet has ≤ 0.01."
    )

if __name__ == "__main__":
    init_db()
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("send_fee", send_fee_command))
    app.add_handler(CommandHandler("send_fogo", send_fogo_command))
    app.run_polling()
