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
from solana import system_program

from spl.token.instructions import (
    TransferCheckedParams, transfer_checked,
    get_associated_token_address, create_associated_token_account
)
from spl.token.constants import TOKEN_PROGRAM_ID

import httpx

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
PRIVATE_KEY = os.getenv("FOGO_BOT_PRIVATE_KEY")
FOGO_TOKEN_MINT = PublicKey("So11111111111111111111111111111111111111112")

AMOUNT_TO_SEND_FOGO = 500_000_000
AMOUNT_TO_SEND_NATIVE = 500_000_000
MIN_BALANCE_THRESHOLD = 10_000_000

DB_PATH = "fogo_requests.db"

if PRIVATE_KEY is None:
    logger.critical("FOGO_BOT_PRIVATE_KEY environment variable is not set.")
    raise EnvironmentError("FOGO_BOT_PRIVATE_KEY is missing.")

# --- Database ---
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS requests (
            user_id INTEGER,
            request_type TEXT,
            last_request TIMESTAMP,
            wallet TEXT,
            tx_hash TEXT,
            PRIMARY KEY (user_id, request_type)
        )
    """)
    conn.commit()
    conn.close()

def get_last_request_time(user_id, request_type):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT last_request FROM requests WHERE user_id = ? AND request_type = ?", (user_id, request_type))
    row = c.fetchone()
    conn.close()
    if row:
        return datetime.datetime.fromisoformat(row[0])
    return None

def update_last_request_time(user_id, request_type, request_time, wallet, tx_hash):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        REPLACE INTO requests (user_id, request_type, last_request, wallet, tx_hash)
        VALUES (?, ?, ?, ?, ?)
    """, (user_id, request_type, request_time.isoformat(), wallet, tx_hash))
    conn.commit()
    conn.close()

# --- Bot Commands ---
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    name = update.effective_user.first_name or "there"
    await update.message.reply_text(
        f"Hi {name}! I’m a FOGO Testnet faucet bot.\n"
        "Use /send_fogo to get 0.5 testnet SPL FOGO.\n"
        "Use /send_fee to get 0.5 native FOGO if your wallet has ≤ 0.01 FOGO."
    )

async def send_fogo_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    now = datetime.datetime.now()
    last = get_last_request_time(user_id, "spl")

    if last and now - last < datetime.timedelta(hours=24):
        remaining = datetime.timedelta(hours=24) - (now - last)
        h, m = divmod(int(remaining.total_seconds()), 3600)
        m, s = divmod(m, 60)
        await update.message.reply_text(
            f"You've already received SPL tokens in the last 24 hours.\nTry again in {h}h {m}m {s}s."
        )
        return

    context.user_data['waiting_for_address'] = True
    await update.message.reply_text("Send your SPL wallet address (Solana format):")

async def send_fee_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    context.user_data['waiting_for_fee_address'] = True
    await update.message.reply_text("Send your Solana wallet address to receive native FOGO:")

# --- Message Handling ---
async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()
    user_id = update.effective_user.id

    if context.user_data.get("waiting_for_address"):
        context.user_data["waiting_for_address"] = False
        await handle_token_request(update, context, text, user_id)

    elif context.user_data.get("waiting_for_fee_address"):
        context.user_data["waiting_for_fee_address"] = False
        await handle_native_fee_request(update, context, text, user_id)

    else:
        await update.message.reply_text("Use /start, /send_fogo, or /send_fee.")

# --- Logic: SPL ---
async def handle_token_request(update, context, address, user_id):
    if not re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{32,44}", address):
        await update.message.reply_text("Invalid wallet address.")
        return

    await update.message.reply_text(f"Sending {AMOUNT_TO_SEND_FOGO / 1_000_000_000} FOGO SPL to {address}...")

    tx_hash = await send_fogo_spl_token(address, AMOUNT_TO_SEND_FOGO)
    if tx_hash:
        update_last_request_time(user_id, "spl", datetime.datetime.now(), address, tx_hash)
        await update.message.reply_text(
            f"✅ SPL token sent!\n[View transaction](https://fogoscan.com/tx/{tx_hash}?cluster=testnet)",
            parse_mode="Markdown"
        )
    else:
        await update.message.reply_text("❌ Failed to send SPL token.")

# --- Logic: Native ---
async def handle_native_fee_request(update, context, address, user_id):
    if not re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{32,44}", address):
        await update.message.reply_text("Invalid wallet address.")
        return

    try:
        pubkey = PublicKey(address)
    except Exception:
        await update.message.reply_text("Invalid public key format.")
        return

    # ✅ Check cooldown by Telegram user ID only
    now = datetime.datetime.now()
    last = get_last_request_time(user_id, "native")
    if last and now - last < datetime.timedelta(hours=24):
        remaining = datetime.timedelta(hours=24) - (now - last)
        h, m = divmod(int(remaining.total_seconds()), 3600)
        m, s = divmod(m, 60)
        await update.message.reply_text(
            f"You've already received native FOGO in the last 24 hours.\nTry again in {h}h {m}m {s}s."
        )
        return

    await update.message.reply_text("Checking wallet balance...")

    async with AsyncClient("https://testnet.fogo.io") as client:
        balance_resp = await client.get_balance(pubkey)
        balance = balance_resp.value if balance_resp and hasattr(balance_resp, 'value') else 0

    if balance > MIN_BALANCE_THRESHOLD:
        await update.message.reply_text(
            f"Wallet has {balance / 1_000_000_000:.9f} FOGO, more than 0.01 threshold.\n❌ Not eligible."
        )
        return

    await update.message.reply_text(f"Sending 0.5 native FOGO to {address}...")

    tx_hash = await send_native_fogo(pubkey, AMOUNT_TO_SEND_NATIVE)
    if tx_hash:
        update_last_request_time(user_id, "native", datetime.datetime.now(), address, tx_hash)
        await update.message.reply_text(
            f"✅ Native FOGO sent!\n[View transaction](https://fogoscan.com/tx/{tx_hash}?cluster=testnet)",
            parse_mode="Markdown"
        )
    else:
        await update.message.reply_text("❌ Failed to send native FOGO.")

# --- Blockchain Senders ---
async def send_fogo_spl_token(to_address: str, amount: int):
    try:
        decoded_key = base58.b58decode(PRIVATE_KEY)
        sender = SolanaKeypair.from_secret_key(decoded_key)
        sender_pubkey = sender.public_key
        receiver_pubkey = PublicKey(to_address)

        sender_token_account = get_associated_token_address(sender_pubkey, FOGO_TOKEN_MINT)
        receiver_token_account = get_associated_token_address(receiver_pubkey, FOGO_TOKEN_MINT)

        async with AsyncClient("https://testnet.fogo.io") as client:
            resp = await client.get_account_info(receiver_token_account)
            account_exists = resp.get("result", {}).get("value") is not None

        async with httpx.AsyncClient(timeout=20.0) as http_client:
            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getLatestBlockhash",
                "params": []
            }
            rpc_response = await http_client.post("https://testnet.fogo.io", json=payload)
            blockhash = rpc_response.json().get("result", {}).get("value", {}).get("blockhash")

        if not blockhash:
            return None

        tx = Transaction(recent_blockhash=blockhash, fee_payer=sender_pubkey)

        if not account_exists:
            tx.add(create_associated_token_account(
                payer=sender_pubkey,
                owner=receiver_pubkey,
                mint=FOGO_TOKEN_MINT
            ))

        tx.add(transfer_checked(TransferCheckedParams(
            program_id=TOKEN_PROGRAM_ID,
            source=sender_token_account,
            mint=FOGO_TOKEN_MINT,
            dest=receiver_token_account,
            owner=sender.public_key,
            amount=amount,
            decimals=9,
            signers=[]
        )))

        tx.sign(sender)
        async with AsyncClient("https://testnet.fogo.io") as client:
            send_resp = await client.send_transaction(tx, sender, opts=TxOpts(skip_confirmation=False))

        return send_resp.get('result') if send_resp and isinstance(send_resp, dict) else None

    except Exception as e:
        logger.error(f"SPL send error: {e}", exc_info=True)
        return None

async def send_native_fogo(to_pubkey: PublicKey, amount: int):
    try:
        decoded_key = base58.b58decode(PRIVATE_KEY)
        sender = SolanaKeypair.from_secret_key(decoded_key)

        async with AsyncClient("https://testnet.fogo.io") as client:
            blockhash_resp = await client.get_latest_blockhash()
            blockhash = blockhash_resp.value.blockhash

            tx = Transaction(recent_blockhash=blockhash, fee_payer=sender.public_key)
            tx.add(system_program.transfer(system_program.TransferParams(
                from_pubkey=sender.public_key,
                to_pubkey=to_pubkey,
                lamports=amount
            )))
            tx.sign(sender)

            resp = await client.send_transaction(tx, sender, opts=TxOpts(skip_confirmation=False))
            return resp.get('result') if resp else None

    except Exception as e:
        logger.error(f"Native send error: {e}", exc_info=True)
        return None

# --- Error Handler ---
async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.error(f"Unexpected error: {context.error}", exc_info=True)
    if update and update.message:
        await update.message.reply_text("An error occurred. Please try again later.")

# --- Main ---
if __name__ == "__main__":
    init_db()
    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("send_fogo", send_fogo_command))
    app.add_handler(CommandHandler("send_fee", send_fee_command))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    app.add_error_handler(error_handler)

    app.run_polling()
