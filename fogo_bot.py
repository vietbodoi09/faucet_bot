import os
import asyncio
import datetime
import sqlite3
import logging
import re
import base58
import json

import httpx

from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

from solana.rpc.async_api import AsyncClient
from solana.rpc.types import TxOpts
from solana.keypair import Keypair
from solana.publickey import PublicKey
from solana.transaction import Transaction
from solana.system_program import transfer, TransferParams
from solana.blockhash import Blockhash

from spl.token.instructions import get_associated_token_address, create_associated_token_account, transfer_checked

# Constants
DATABASE = "fogo_requests.db"
RPC_ENDPOINT = "https://testnet.fogo.io"
FAUCET_KEYPAIR_PATH = "faucet.json"
FOGO_TOKEN_MINT = PublicKey("So11111111111111111111111111111111111111112")
SEND_AMOUNT = 1_000_000  # Adjust as needed
FEE_AMOUNT = 100_000     # Native FOGO fee

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load faucet keypair
def load_faucet_keypair():
    with open(FAUCET_KEYPAIR_PATH, "r") as f:
        secret = json.load(f)
    return Keypair.from_secret_key(bytes(secret))

# Cooldown check
def is_on_cooldown(user_id: int, command: str) -> bool:
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS requests (
            user_id INTEGER,
            request_type TEXT,
            last_request TIMESTAMP
        )
    """)
    c.execute("SELECT last_request FROM requests WHERE user_id=? AND request_type=?", (user_id, command))
    row = c.fetchone()
    if row:
        last_request = datetime.datetime.fromisoformat(row[0])
        if datetime.datetime.now() - last_request < datetime.timedelta(hours=24):
            conn.close()
            return True
    conn.close()
    return False

def update_cooldown(user_id: int, command: str):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("REPLACE INTO requests (user_id, request_type, last_request) VALUES (?, ?, ?)",
              (user_id, command, datetime.datetime.now().isoformat()))
    conn.commit()
    conn.close()

# Validate wallet address
def is_valid_solana_address(address: str) -> bool:
    try:
        decoded = base58.b58decode(address)
        return len(decoded) == 32
    except Exception:
        return False

# Send native FOGO
async def send_native_fogo_fee(to_address: str, amount: int):
    sender = load_faucet_keypair()
    sender_pubkey = sender.public_key
    receiver_pubkey = PublicKey(to_address)

    tx = Transaction()
    tx.add(transfer(TransferParams(from_pubkey=sender_pubkey, to_pubkey=receiver_pubkey, lamports=amount)))

    # Fetch recent blockhash
    response = await httpx.post(RPC_ENDPOINT, json={
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getLatestBlockhash"
    })
    latest_blockhash = response.json()["result"]["value"]["blockhash"]
    tx.recent_blockhash = Blockhash(latest_blockhash)
    tx.fee_payer = sender_pubkey
    tx_signed = tx.sign([sender])

    async with AsyncClient(RPC_ENDPOINT) as client:
        await client.send_raw_transaction(tx_signed.serialize(), opts=TxOpts(skip_confirmation=False))

# Send SPL FOGO token
async def send_fogo_spl_token(to_address: str, amount: int):
    sender = load_faucet_keypair()
    sender_pubkey = sender.public_key
    receiver_pubkey = PublicKey(to_address)

    async with AsyncClient(RPC_ENDPOINT) as client:
        # Create ATA for receiver if it doesn't exist
        ata = get_associated_token_address(receiver_pubkey, FOGO_TOKEN_MINT)
        resp = await client.get_account_info(ata)
        tx = Transaction()

        if resp.value is None:
            tx.add(create_associated_token_account(sender_pubkey, receiver_pubkey, FOGO_TOKEN_MINT))

        tx.add(transfer_checked(
            source=get_associated_token_address(sender_pubkey, FOGO_TOKEN_MINT),
            dest=ata,
            owner=sender_pubkey,
            mint=FOGO_TOKEN_MINT,
            amount=amount,
            decimals=9
        ))

        # Fetch recent blockhash
        response = await httpx.post(RPC_ENDPOINT, json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getLatestBlockhash"
        })
        latest_blockhash = response.json()["result"]["value"]["blockhash"]
        tx.recent_blockhash = Blockhash(latest_blockhash)
        tx.fee_payer = sender_pubkey
        tx_signed = tx.sign([sender])

        await client.send_raw_transaction(tx_signed.serialize(), opts=TxOpts(skip_confirmation=False))

# Telegram handlers
async def send_fee(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if is_on_cooldown(user_id, "send_fee"):
        await update.message.reply_text("⏳ You can only request native FOGO once every 24 hours.")
        return

    args = context.args
    if not args or not is_valid_solana_address(args[0]):
        await update.message.reply_text("❌ Invalid Solana wallet address.")
        return

    try:
        await send_native_fogo_fee(args[0], FEE_AMOUNT)
        await update.message.reply_text(f"✅ Native FOGO sent to {args[0]}")
        update_cooldown(user_id, "send_fee")
    except Exception as e:
        logger.error(f"Failed to send native FOGO: {e}")
        await update.message.reply_text("❌ Error sending native FOGO.")

async def send_fogo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if is_on_cooldown(user_id, "send_fogo"):
        await update.message.reply_text("⏳ You can only request SPL FOGO once every 24 hours.")
        return

    args = context.args
    if not args or not is_valid_solana_address(args[0]):
        await update.message.reply_text("❌ Invalid Solana wallet address.")
        return

    try:
        await send_fogo_spl_token(args[0], SEND_AMOUNT)
        await update.message.reply_text(f"✅ SPL FOGO sent to {args[0]}")
        update_cooldown(user_id, "send_fogo")
    except Exception as e:
        logger.error(f"Error sending token: {e}")
        await update.message.reply_text("❌ Error sending SPL FOGO.")

# Main
async def main():
    app = Application.builder().token(os.environ["BOT_TOKEN"]).build()

    app.add_handler(CommandHandler("send_fee", send_fee))
    app.add_handler(CommandHandler("send_fogo", send_fogo))

    await app.run_polling()

if __name__ == "__main__":
    asyncio.run(main())
