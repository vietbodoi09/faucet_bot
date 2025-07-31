import os
import asyncio
import datetime
import sqlite3
import logging
import re
import base58
import json
import io
import random
import string

from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

from solana.rpc.async_api import AsyncClient
from solana.transaction import Transaction
from solana.keypair import Keypair as SolanaKeypair
from solana.publickey import PublicKey
from solana.rpc.types import TxOpts
from solana.system_program import transfer, TransferParams
from spl.token.instructions import TransferCheckedParams, transfer_checked, get_associated_token_address, create_associated_token_account
from spl.token.constants import TOKEN_PROGRAM_ID

import httpx
from PIL import Image, ImageDraw, ImageFont # Add Pillow library
from captcha.image import ImageCaptcha # Add captcha library

# Logger setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants and environment variables
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
PRIVATE_KEY = os.getenv("FOGO_BOT_PRIVATE_KEY")
FOGO_TOKEN_MINT = PublicKey("So11111111111111111111111111111111111111112")

if PRIVATE_KEY is None:
    logger.critical("FOGO_BOT_PRIVATE_KEY environment variable is not set.")
    raise EnvironmentError("FOGO_BOT_PRIVATE_KEY is missing.")

AMOUNT_TO_SEND_FOGO = 500_000_000  # 0.5 SPL FOGO (in base units, decimals=9)
FEE_AMOUNT = 100_000_000           # 0.0001 native FOGO (lamports)
DECIMALS = 9
DB_PATH = "fogo_requests.db"

# Load blacklist
def load_blacklist(path="blacklist.txt") -> set:
    try:
        with open(path, "r") as f:
            return set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        logger.warning("⚠️ blacklist.txt not found, no wallet is blacklisted.")
        return set()

# Load banned users
def load_banned_users(path="banned_users.txt") -> set:
    try:
        with open(path, "r") as f:
            return set(int(line.strip()) for line in f if line.strip())
    except FileNotFoundError:
        logger.warning("⚠️ banned_users.txt not found, no user is banned.")
        return set()

def ban_user(user_id: int, path="banned_users.txt"):
    with open(path, "a") as f:
        f.write(f"{user_id}\n")
    BANNED_USERS.add(user_id)

BLACKLISTED_WALLETS = load_blacklist()
BANNED_USERS = load_banned_users()

# Database init & helpers
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
    # Table to store active CAPTCHA challenges
    c.execute("""
        CREATE TABLE IF NOT EXISTS captcha_challenges (
            user_id INTEGER PRIMARY KEY,
            challenge_text TEXT,
            timestamp TIMESTAMP
        )
    """)
    # New table to store the user's last CAPTCHA solve time (for daily logic)
    c.execute("""
        CREATE TABLE IF NOT EXISTS user_captcha_status (
            user_id INTEGER PRIMARY KEY,
            last_solve_time TIMESTAMP
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
    c.execute("REPLACE INTO requests (user_id, request_type, last_request, wallet, tx_hash) VALUES (?, ?, ?, ?, ?)",
              (user_id, request_type, request_time.isoformat(), wallet, tx_hash))
    conn.commit()
    conn.close()

# Validate Solana address
def is_valid_solana_address(address: str) -> bool:
    try:
        decoded = base58.b58decode(address)
        return len(decoded) == 32
    except Exception:
        return False

# Get native FOGO balance
async def get_native_balance(pubkey_str: str) -> int:
    async with AsyncClient("https://testnet.fogo.io") as client:
        resp = await client.get_balance(PublicKey(pubkey_str))
        logger.info(f"get_native_balance response: {resp}")
        value = resp.get("result", {}).get("value", None)
        if value is None:
            logger.error(f"get_balance RPC returned no value: {resp}")
            return 0
        return value

# Send native FOGO
async def send_native_fogo(to_address: str, amount: int):
    decoded_key = base58.b58decode(PRIVATE_KEY)
    sender = SolanaKeypair.from_secret_key(decoded_key)
    sender_pubkey = sender.public_key
    receiver_pubkey = PublicKey(to_address)

    tx = Transaction()
    tx.add(transfer(
        TransferParams(
            from_pubkey=sender_pubkey,
            to_pubkey=receiver_pubkey,
            lamports=amount
        )
    ))

    async with httpx.AsyncClient() as http_client:
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getLatestBlockhash",
            "params": [{"commitment": "finalized"}]
        }
        rpc_response = await http_client.post("https://testnet.fogo.io", json=payload)
        rpc_json = rpc_response.json()
        latest_blockhash = rpc_json.get("result", {}).get("value", {}).get("blockhash")

    if not latest_blockhash:
        logger.error(f"Invalid blockhash response: {rpc_json}")
        return None

    tx.recent_blockhash = latest_blockhash
    tx.fee_payer = sender_pubkey
    tx.sign(sender)

    async with AsyncClient("https://testnet.fogo.io") as client:
        resp = await client.send_raw_transaction(tx.serialize(), opts=TxOpts(skip_confirmation=False))

    if resp and 'result' in resp:
        return resp['result']
    else:
        logger.error(f"Failed to send native FOGO tx: {resp}")
        return None

# Send SPL FOGO
async def send_fogo_spl_token(to_address: str, amount: int):
    try:
        logger.info(f"Sending {amount / 1_000_000_000} SPL FOGO to {to_address}")

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
                owner=sender.public_key,
                amount=amount,
                decimals=DECIMALS,
                signers=[]
            )
        )
        tx.add(transfer_ix)
        tx.sign(sender)
        raw_tx = tx.serialize()

        async with AsyncClient("https://testnet.fogo.io") as client:
            send_resp = await client.send_raw_transaction(raw_tx, opts=TxOpts(skip_confirmation=False))

        if send_resp and isinstance(send_resp, dict) and 'result' in send_resp:
            return send_resp['result']
        else:
            logger.error(f"Failed to send SPL transaction: {send_resp}")
            return None

    except Exception as e:
        logger.error(f"Critical error while sending SPL token: {e}", exc_info=True)
        return None

# --- CAPTCHA Functions ---
def generate_captcha():
    """
    Generates a CAPTCHA image and its corresponding text.
    Uses the 'captcha' library for better quality CAPTCHAs.
    Note: To use 'arial.ttf' font, ensure this font file is available
    in the same directory as the script or provide its full path.
    Otherwise, you can omit the 'fonts' parameter to use the default font.
    """
    generator = ImageCaptcha(width=200, height=60, fonts=['./arial.ttf'])
    characters = string.ascii_uppercase + string.digits
    captcha_text = ''.join(random.choice(characters) for i in range(5)) # 5 random characters

    # Generate CAPTCHA image
    image_data = generator.generate(captcha_text)

    # Save image to memory
    img_byte_arr = io.BytesIO(image_data.read())
    img_byte_arr.seek(0)
    return captcha_text, img_byte_arr

def save_captcha_challenge(user_id: int, challenge_text: str):
    """
    Saves the active CAPTCHA challenge to the database.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("REPLACE INTO captcha_challenges (user_id, challenge_text, timestamp) VALUES (?, ?, ?)",
              (user_id, challenge_text, datetime.datetime.now().isoformat()))
    conn.commit()
    conn.close()

def get_captcha_challenge(user_id: int):
    """
    Retrieves the active CAPTCHA challenge from the database.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT challenge_text, timestamp FROM captcha_challenges WHERE user_id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return row[0], datetime.datetime.fromisoformat(row[1])
    return None, None

def delete_captcha_challenge(user_id: int):
    """
    Deletes the active CAPTCHA challenge from the database.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM captcha_challenges WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()

def update_user_captcha_solve_time(user_id: int, solve_time: datetime.datetime):
    """
    Updates the user's last CAPTCHA solve time in the user_captcha_status table.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("REPLACE INTO user_captcha_status (user_id, last_solve_time) VALUES (?, ?)",
              (user_id, solve_time.isoformat()))
    conn.commit()
    conn.close()

def get_user_captcha_solve_time(user_id: int):
    """
    Retrieves the user's last CAPTCHA solve time from the user_captcha_status table.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT last_solve_time FROM user_captcha_status WHERE user_id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return datetime.datetime.fromisoformat(row[0])
    return None
# --- End CAPTCHA Functions ---


# Telegram handlers
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id in BANNED_USERS:
        return
    name = update.effective_user.first_name or "there"
    await update.message.reply_text(
        f"Hi {name}! I’m a FOGO Testnet faucet bot.\n"
        "Use /send to get 0.5 SPL FOGO tokens once every 24 hours.\n"
        "Use /send_fee to get a small amount of native FOGO once every 24 hours.\n"
        "You will need to solve an image CAPTCHA daily before requesting tokens."
    )

async def send_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id in BANNED_USERS:
        return

    now = datetime.datetime.now()
    last_captcha_solve_time = get_user_captcha_solve_time(user_id)
    
    # Check if a daily CAPTCHA re-solve is required
    daily_captcha_required = True
    if last_captcha_solve_time:
        time_since_last_solve = now - last_captcha_solve_time
        if time_since_last_solve < datetime.timedelta(hours=24):
            daily_captcha_required = False # CAPTCHA re-solve not required today

    # If daily CAPTCHA is required OR the current session CAPTCHA hasn't been solved
    if daily_captcha_required or not context.user_data.get('captcha_passed', False):
        # Reset session flag if daily CAPTCHA is required
        if daily_captcha_required:
            context.user_data['captcha_passed'] = False
        
        # If current session CAPTCHA is not solved (due to daily reset or never solved)
        if not context.user_data.get('captcha_passed', False):
            captcha_text, captcha_image = generate_captcha()
            save_captcha_challenge(user_id, captcha_text)
            context.user_data['awaiting_captcha_answer'] = True # Set flag to await CAPTCHA answer
            await update.message.reply_photo(
                photo=captcha_image,
                caption="Please enter the characters you see in the image to proceed (this CAPTCHA will require re-solving after 24 hours):"
            )
            return

    # Proceed with the original flow if CAPTCHA has been passed (both session and daily)
    last_faucet_request = get_last_request_time(user_id, "send_fogo")

    if last_faucet_request and now - last_faucet_request < datetime.timedelta(hours=24):
        remaining = datetime.timedelta(hours=24) - (now - last_faucet_request)
        h, rem = divmod(int(remaining.total_seconds()), 3600)
        m, s = divmod(rem, 60)
        await update.message.reply_text(
            f"You've already requested SPL FOGO within the last 24 hours.\n"
            f"Try again in {h} hour(s), {m} minute(s), and {s} second(s)."
        )
        return

    context.user_data['waiting_for_spl_address'] = True
    await update.message.reply_text("Please send your FOGO wallet address for SPL FOGO:")

async def send_fee_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id in BANNED_USERS:
        return

    now = datetime.datetime.now()
    last_captcha_solve_time = get_user_captcha_solve_time(user_id)
    
    # Check if a daily CAPTCHA re-solve is required
    daily_captcha_required = True
    if last_captcha_solve_time:
        time_since_last_solve = now - last_captcha_solve_time
        if time_since_last_solve < datetime.timedelta(hours=24):
            daily_captcha_required = False # CAPTCHA re-solve not required today

    # If daily CAPTCHA is required OR the current session CAPTCHA hasn't been solved
    if daily_captcha_required or not context.user_data.get('captcha_passed', False):
        # Reset session flag if daily CAPTCHA is required
        if daily_captcha_required:
            context.user_data['captcha_passed'] = False
        
        # If current session CAPTCHA is not solved (due to daily reset or never solved)
        if not context.user_data.get('captcha_passed', False):
            captcha_text, captcha_image = generate_captcha()
            save_captcha_challenge(user_id, captcha_text)
            context.user_data['awaiting_captcha_answer'] = True
            await update.message.reply_photo(
                photo=captcha_image,
                caption="Please enter the characters you see in the image to proceed (this CAPTCHA will require re-solving after 24 hours):"
            )
            return

    # Proceed with the original flow if CAPTCHA has been passed (both session and daily)
    last_faucet_request = get_last_request_time(user_id, "send_fee")

    if last_faucet_request and now - last_faucet_request < datetime.timedelta(hours=24):
        remaining = datetime.timedelta(hours=24) - (now - last_faucet_request)
        h, rem = divmod(int(remaining.total_seconds()), 3600)
        m, s = divmod(rem, 60)
        await update.message.reply_text(
            f"You can only request native FOGO once every 24 hours.\n"
            f"Try again in {h} hour(s), {m} minute(s), and {s} second(s)."
        )
        return

    context.user_data['waiting_for_fee_address'] = True
    await update.message.reply_text("Please send your FOGO wallet address to receive native FOGO:")

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id

    if user_id in BANNED_USERS:
        return

    # --- Handle CAPTCHA first ---
    if context.user_data.get('awaiting_captcha_answer', False):
        user_answer = update.message.text.strip().upper() # Convert to uppercase for comparison

        stored_challenge, _ = get_captcha_challenge(user_id)

        if stored_challenge and user_answer == stored_challenge.upper(): # Case-insensitive comparison
            context.user_data['captcha_passed'] = True # Set CAPTCHA passed flag for current session
            context.user_data['awaiting_captcha_answer'] = False # Turn off awaiting answer flag
            delete_captcha_challenge(user_id) # Delete active challenge from DB
            update_user_captcha_solve_time(user_id, datetime.datetime.now()) # Update daily CAPTCHA solve time
            await update.message.reply_text("✅ CAPTCHA solved successfully! You can now use /send or /send_fee commands again.")
            return
        else:
            await update.message.reply_text("❌ Incorrect CAPTCHA answer. Please try again. You need to re-type /send or /send_fee to get a new CAPTCHA.")
            context.user_data['awaiting_captcha_answer'] = False # Turn off awaiting answer flag
            delete_captcha_challenge(user_id) # Delete old CAPTCHA to force new one on retry
            context.user_data['captcha_passed'] = False # Reset current session CAPTCHA status
            return

    # --- Rest of handle_message (wallet address processing) ---
    if context.user_data.get("waiting_for_spl_address"):
        address = update.message.text.strip()
        context.user_data["waiting_for_spl_address"] = False

        if not is_valid_solana_address(address):
            await update.message.reply_text("Invalid wallet address. Please try again.")
            return

        if address in BLACKLISTED_WALLETS:
            await update.message.reply_text("🚫 This wallet is blacklisted. You are now banned from using the bot.")
            ban_user(user_id)
            return

        await update.message.reply_text(f"Sending {AMOUNT_TO_SEND_FOGO / 1_000_000_000} SPL FOGO to {address}...")

        tx_hash = await send_fogo_spl_token(address, AMOUNT_TO_SEND_FOGO)

        if tx_hash:
            update_last_request_time(user_id, "send_fogo", datetime.datetime.now(), address, tx_hash)
            # captcha_passed is not reset here, as it's managed by the 24-hour logic
            await update.message.reply_text(
                f"✅ SPL FOGO sent successfully!\n"
                f"[View transaction](https://fogoscan.com/tx/{tx_hash}?cluster=testnet)",
                parse_mode="Markdown"
            )
        else:
            await update.message.reply_text("❌ Failed to send SPL FOGO. Please try again later.")
        return

    if context.user_data.get("waiting_for_fee_address"):
        address = update.message.text.strip()
        context.user_data["waiting_for_fee_address"] = False

        if not is_valid_solana_address(address):
            await update.message.reply_text("Invalid wallet address. Please try again.")
            return

        if address in BLACKLISTED_WALLETS:
            await update.message.reply_text("🚫 This wallet is blacklisted. You are now banned from using the bot.")
            ban_user(user_id)
            return

        balance = await get_native_balance(address)
        if balance > 10_000_000:
            await update.message.reply_text("Your wallet balance is above 0.01 native FOGO, not eligible for fee airdrop.")
            return

        await update.message.reply_text(f"Sending {FEE_AMOUNT / 1_000_000_000} native FOGO to {address}...")

        tx_hash = await send_native_fogo(address, FEE_AMOUNT)

        if tx_hash:
            update_last_request_time(user_id, "send_fee", datetime.datetime.now(), address, tx_hash)
            # captcha_passed is not reset here, as it's managed by the 24-hour logic
            await update.message.reply_text(
                f"✅ Native FOGO sent successfully!\n"
                f"[View transaction](https://fogoscan.com/tx/{tx_hash}?cluster=testnet)",
                parse_mode="Markdown"
            )
        else:
            await update.message.reply_text("❌ Failed to send native FOGO. Please try again later.")
        return

    await update.message.reply_text("Use /start, /send or /send_fee commands to request tokens.")

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.error(f"Unexpected error: {context.error}", exc_info=True)
    if update and update.message:
        await update.message.reply_text("An error occurred. Please try again later.")

# Add /unban command handler for admins
async def unban_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    admin_ids = os.getenv("ADMIN_IDS", "").split(",")
    if str(user_id) not in admin_ids:
        await update.message.reply_text("❌ You are not authorized to use this command.")
        return

    if not context.args:
        await update.message.reply_text("Usage: /unban <user_id>")
        return

    try:
        target_id = int(context.args[0])
    except ValueError:
        await update.message.reply_text("Invalid user ID.")
        return

    if target_id not in BANNED_USERS:
        await update.message.reply_text("User is not banned.")
        return

    BANNED_USERS.remove(target_id)

    try:
        with open("banned_users.txt", "r") as f:
            lines = f.readlines()
        with open("banned_users.txt", "w") as f:
            for line in lines:
                if line.strip() != str(target_id):
                    f.write(line)
    except Exception as e:
        logger.error(f"Failed to update banned_users.txt: {e}")

    await update.message.reply_text(f"✅ Unbanned user {target_id}.")

# Add /ban command to block a wallet address (admin only)
async def ban_wallet_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    admin_ids = os.getenv("ADMIN_IDS", "").split(",")
    if str(user_id) not in admin_ids:
        await update.message.reply_text("❌ You are not authorized to use this command.")
        return

    if not context.args:
        await update.message.reply_text("Usage: /ban <wallet_address>")
        return

    wallet = context.args[0].strip()
    if wallet in BLACKLISTED_WALLETS:
        await update.message.reply_text("This wallet is already blacklisted.")
        return

    BLACKLISTED_WALLETS.add(wallet)
    try:
        with open("blacklist.txt", "a") as f:
            f.write(wallet + "\n")
    except Exception as e:
        logger.error(f"Failed to write to blacklist.txt: {e}")

    await update.message.reply_text(f"✅ Wallet {wallet} has been blacklisted.")

# Add /banstats command to show number of blacklisted wallets and banned users
async def banstats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    admin_ids = os.getenv("ADMIN_IDS", "").split(",")
    if str(user_id) not in admin_ids:
        await update.message.reply_text("❌ You are not authorized to use this command.")
        return

    wallet_count = 0
    user_count = 0

    try:
        with open("blacklist.txt", "r") as f:
            wallet_count = len(set(line.strip() for line in f if line.strip()))
    except:
        pass

    try:
        with open("banned_users.txt", "r") as f:
            user_count = len(set(line.strip() for line in f if line.strip()))
    except:
        pass

    await update.message.reply_text(f"🔒 Blacklisted wallets: {wallet_count}\n👤 Banned users: {user_count}")

# Register handlers
if __name__ == "__main__":
    init_db()
    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("send", send_command))
    app.add_handler(CommandHandler("send_fee", send_fee_command))
    app.add_handler(CommandHandler("unban", unban_command))
    app.add_handler(CommandHandler("ban", ban_wallet_command))
    app.add_handler(CommandHandler("banstats", banstats_command))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    app.add_error_handler(error_handler)

    app.run_polling()
