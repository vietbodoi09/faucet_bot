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

from solana.rpc.api import Client
from solana.transaction import Transaction
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solana.rpc.types import TxOpts
from spl.token.instructions import TransferCheckedParams, transfer_checked, get_associated_token_address, create_associated_token_account
from spl.token.constants import TOKEN_PROGRAM_ID

import httpx

from dotenv import load_dotenv

load_dotenv()
# Logger setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants
BOT_TOKEN = os.getenv("BOT_TOKEN")
PRIVATE_KEY = os.getenv("PRIVATE_KEY")
FOGO_TOKEN_MINT = Pubkey.from_string("So11111111111111111111111111111111111111112")

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

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    name = update.effective_user.first_name or "there"
    await update.message.reply_text(
        f"Hi {name}! I’m a FOGO Testnet faucet bot.\n"
        "Use the /send command to receive 0.5 testnet FOGO (once every 24 hours)."
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
                f"\u2705 Tokens sent successfully!\n"
                f"[View transaction](https://fogoscan.com/tx/{tx_hash}?cluster=testnet)",
                parse_mode="Markdown"
            )
        else:
            await update.message.reply_text("\u274C Failed to send tokens. Please try again later.")
    else:
        await update.message.reply_text("Use /start or /send to request tokens.")

async def send_fogo_spl_token(to_address: str, amount: int):
    try:
        logger.info(f"Sending {amount / 1_000_000_000} FOGO to {to_address}")

        decoded_key = base58.b58decode(PRIVATE_KEY)
        sender = Keypair.from_bytes(decoded_key[:64])
        sender_pubkey = sender.pubkey()
        receiver_pubkey = Pubkey.from_string(to_address)

        sender_token_account = get_associated_token_address(sender_pubkey, FOGO_TOKEN_MINT)
        receiver_token_account = get_associated_token_address(receiver_pubkey, FOGO_TOKEN_MINT)

        client = Client("https://testnet.fogo.io")
        resp = client.get_account_info(receiver_token_account)
        account_exists = resp.get("result", {}).get("value") is not None

        http_client = httpx.Client(timeout=20.0)
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getLatestBlockhash",
            "params": []
        }
        rpc_response = http_client.post("https://testnet.fogo.io", json=payload)
        rpc_json = rpc_response.json()
        latest_blockhash = rpc_json.get("result", {}).get("value", {}).get("blockhash")

        if not latest_blockhash:
            logger.error(f"Invalid blockhash response: {rpc_json}")
            return None

        tx = Transaction()
        tx.fee_payer = sender_pubkey
        tx.recent_blockhash = latest_blockhash

        if not account_exists:
            create_ata_ix = create_associated_token_account(
                payer=sender_pubkey,
                owner=receiver_pubkey,
                mint=FOGO_TOKEN_MINT
            )
            tx.add(create_ata_ix)

        transfer_ix = transfer_checked(
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
        )
        tx.add(transfer_ix)
        tx.sign([sender])
        raw_tx = tx.serialize()

        send_resp = client.send_raw_transaction(raw_tx, opts=TxOpts(skip_confirmation=False))
        if send_resp and isinstance(send_resp, dict) and 'result' in send_resp:
            return send_resp['result']
        else:
            logger.error(f"Failed to send transaction: {send_resp}")
            return None

    except Exception as e:
        logger.error(f"Critical error while sending token: {e}", exc_info=True)
        return None

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.error(f"Unexpected error: {context.error}", exc_info=True)
    if update and update.message:
        await update.message.reply_text("An error occurred. Please try again later.")

if __name__ == "__main__":
    init_db()
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("send", send_command))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    app.add_error_handler(error_handler)
    app.run_polling()
