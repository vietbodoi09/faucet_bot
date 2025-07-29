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
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters

from solana.rpc.async_api import AsyncClient
from solana.rpc.types import TxOpts
from solana.transaction import Transaction
from solana.system_program import transfer, TransferParams
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from spl.token.async_client import AsyncToken
from spl.token.constants import TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID
from spl.token.instructions import get_associated_token_address, create_associated_token_account

DB_PATH = "fogo_requests.db"
LAMPORTS_PER_SOL = 1000000000
FOGO_MINT = Pubkey.from_string("8j8V2VRSrZBJzKpR2n3oRZGfNn2SM8HKka9R6qFwbxMn")
PRIVATE_KEY = os.getenv("FOGO_BOT_PRIVATE_KEY")
SENDER_KEYPAIR = Keypair.from_base58_string(PRIVATE_KEY)
SOLANA_RPC = "https://testnet.fogo.io"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS requests (
                user_id INTEGER,
                last_request TIMESTAMP,
                wallet TEXT,
                tx TEXT,
                request_type TEXT
            )
        ''')
        conn.commit()

init_db()

def get_last_request_time(user_id: int, request_type: str):
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT last_request FROM requests WHERE user_id = ? AND request_type = ?", (user_id, request_type))
        row = c.fetchone()
        return datetime.datetime.fromisoformat(row[0]) if row else None

def update_request_time(user_id: int, wallet: str, tx: str, request_type: str):
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        now = datetime.datetime.utcnow().isoformat()
        c.execute("REPLACE INTO requests (user_id, last_request, wallet, tx, request_type) VALUES (?, ?, ?, ?, ?)", (user_id, now, wallet, tx, request_type))
        conn.commit()

def is_valid_address(address: str):
    try:
        decoded = base58.b58decode(address)
        return len(decoded) == 32
    except Exception:
        return False

async def get_latest_blockhash():
    async with httpx.AsyncClient() as client:
        resp = await client.post(SOLANA_RPC, json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getLatestBlockhash"
        })
        return resp.json()["result"]["value"]["blockhash"]

async def send_fogo_spl_token(to_address: str, amount: int) -> str:
    async with AsyncClient(SOLANA_RPC) as client:
        token = AsyncToken(client, FOGO_MINT, TOKEN_PROGRAM_ID, SENDER_KEYPAIR)
        ata = get_associated_token_address(Pubkey.from_string(to_address), FOGO_MINT)

        info = await client.get_account_info(ata)
        account_info = info.get("result", {}).get("value")  # Sửa truy cập dict đúng
        tx = Transaction()
        if account_info is None:
            tx.add(
                create_associated_token_account(
                    payer=SENDER_KEYPAIR.pubkey(),
                    owner=Pubkey.from_string(to_address),
                    mint=FOGO_MINT
                )
            )
        tx.add(
            await token.transfer_checked(
                source=await token.get_associated_token_address(SENDER_KEYPAIR.pubkey()),
                dest=ata,
                owner=SENDER_KEYPAIR.pubkey(),
                amount=amount,
                decimals=9
            )
        )
        recent_blockhash = await get_latest_blockhash()
        tx.recent_blockhash = recent_blockhash
        tx.fee_payer = SENDER_KEYPAIR.pubkey()

        result = await client.send_transaction(tx, SENDER_KEYPAIR, opts=TxOpts(skip_confirmation=False))
        return result["result"]

async def send_native_fogo(to_address: str, amount_sol: float) -> str:
    async with AsyncClient(SOLANA_RPC) as client:
        recent_blockhash_resp = await httpx.AsyncClient().post(SOLANA_RPC, json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getLatestBlockhash"
        })
        blockhash = recent_blockhash_resp.json()["result"]["value"]["blockhash"]
        tx = Transaction(recent_blockhash=blockhash)
        tx.add(
            transfer(
                TransferParams(
                    from_pubkey=SENDER_KEYPAIR.pubkey(),
                    to_pubkey=Pubkey.from_string(to_address),
                    lamports=int(amount_sol * LAMPORTS_PER_SOL),
                )
            )
        )
        tx.fee_payer = SENDER_KEYPAIR.pubkey()
        result = await client.send_transaction(tx, SENDER_KEYPAIR, opts=TxOpts(skip_confirmation=False))
        return result["result"]

async def handle_request(update: Update, context: ContextTypes.DEFAULT_TYPE, request_type: str, amount):
    user_id = update.effective_user.id
    args = context.args
    if len(args) != 1 or not is_valid_address(args[0]):
        await update.message.reply_text("⚠️ Please provide a valid Solana wallet address. Example: /send_fogo YOUR_WALLET_ADDRESS")
        return
    wallet = args[0]
    last = get_last_request_time(user_id, request_type)
    if last and (datetime.datetime.utcnow() - last).total_seconds() < 86400:
        await update.message.reply_text("⏳ You can only request once every 24 hours.")
        return
    try:
        if request_type == "spl":
            tx = await send_fogo_spl_token(wallet, amount)
        else:
            async with AsyncClient(SOLANA_RPC) as client:
                balance_resp = await client.get_balance(Pubkey.from_string(wallet))
                balance_lamports = balance_resp['result']['value']
                balance_sol = balance_lamports / LAMPORTS_PER_SOL

                if balance_sol > 0.01:
                    await update.message.reply_text("⚠️ This wallet already has enough native FOGO (> 0.01 SOL). No need to send more.")
                    return

            tx = await send_native_fogo(wallet, amount)

        update_request_time(user_id, wallet, tx, request_type)
        await update.message.reply_text(
            f"✅ Tokens sent successfully!\n"
            f"[View transaction](https://fogoscan.com/tx/{tx}?cluster=testnet)",
            parse_mode="Markdown"
        )
    except Exception as e:
        logger.exception("Error sending token: %s", e)
        await update.message.reply_text("🚫 An error occurred while sending the token.")

async def send_fogo_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # Gửi 1 FOGO token (1_000_000_000 là số lượng tối thiểu cho 9 decimals)
    await handle_request(update, context, "spl", amount=1_000_000_000)

async def send_fee_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # Gửi 0.01 SOL native FOGO
    await handle_request(update, context, "native", amount=0.01)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Welcome to FOGO Faucet Bot! Use /send_fogo or /send_fee to receive tokens.")

if __name__ == "__main__":
    app = Application.builder().token(os.getenv("TELEGRAM_BOT_TOKEN")).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("send_fogo", send_fogo_command))
    app.add_handler(CommandHandler("send_fee", send_fee_command))
    app.run_polling()
