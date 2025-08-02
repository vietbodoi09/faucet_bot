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
from PIL import Image, ImageDraw, ImageFont
from captcha.image import ImageCaptcha

# Import new libraries for X (Twitter) integration
import tweepy
from tweepy.errors import TweepyException

# Logger setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants and environment variables
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
PRIVATE_KEY = os.getenv("FOGO_BOT_PRIVATE_KEY")
FOGO_TOKEN_MINT = PublicKey("So11111111111111111111111111111111111111112")

# Updated list of target X (Twitter) accounts to be followed
TARGET_X_USERNAMES_STR = os.getenv(
    "TARGET_X_USERNAMES",
    "FogoChain,ambient_finance,ValiantTrade,RobertSagurton,catcake0907,thebookofjoey,Pyronfi"
)
TARGET_X_USERNAMES = [name.strip() for name in TARGET_X_USERNAMES_STR.split(',') if name.strip()]

# New constant for the specific X post ID that needs to be retweeted
TARGET_X_POST_ID = "1951268728555053106"
TARGET_X_POST_URL = "https://x.com/FogoChain/status/1951268728555053106"

# Khóa API X (Twitter) đã được thêm
X_API_KEY = "fg5Sb5BQdqpMA6av9yIMdcxkA"
X_API_SECRET = "sF2Orm9hw1UIWhEOMDoC3sHkoQDYNW1Zs7I9XC0Bo247YVFt9k"
X_ACCESS_TOKEN = "1392057369769627651-NSFPv7VqLOyA6sXwOtu3PJB2UxkryG"
X_ACCESS_TOKEN_SECRET = "6ghQP5tDb08k6pCsFq4H0l8ykZO6sMSdLC2eUUl1b3hKQ"

if PRIVATE_KEY is None:
    logger.critical("FOGO_BOT_PRIVATE_KEY environment variable is not set.")
    raise EnvironmentError("FOGO_BOT_PRIVATE_KEY is missing.")

# Check for X API credentials
if any(key is None for key in [X_API_KEY, X_API_SECRET, X_ACCESS_TOKEN, X_ACCESS_TOKEN_SECRET]):
    logger.warning("X (Twitter) API credentials are not fully set. The bot will not be able to check for X follows and retweets.")
    X_API_ENABLED = False
else:
    X_API_ENABLED = True
    try:
        auth = tweepy.OAuth1UserHandler(X_API_KEY, X_API_SECRET, X_ACCESS_TOKEN, X_ACCESS_TOKEN_SECRET)
        x_api_v1 = tweepy.API(auth)
    except TweepyException as e:
        logger.error(f"Failed to authenticate with X API: {e}")
        X_API_ENABLED = False

AMOUNT_TO_SEND_FOGO = 100_000_000  # 0.1 SPL FOGO (in base units, decimals=9)
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
    c.execute("""
        CREATE TABLE IF NOT EXISTS captcha_challenges (
            user_id INTEGER PRIMARY KEY,
            challenge_text TEXT,
            timestamp TIMESTAMP
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS user_captcha_status (
            user_id INTEGER PRIMARY KEY,
            last_solve_time TIMESTAMP
        )
    """)
    # New table to store user's X (Twitter) username and OAuth tokens
    # Added UNIQUE constraint on x_username to prevent multiple Telegram users from linking the same X account
    c.execute("""
        CREATE TABLE IF NOT EXISTS user_x_accounts (
            user_id INTEGER PRIMARY KEY,
            x_username TEXT UNIQUE,
            x_access_token TEXT,
            x_access_token_secret TEXT,
            is_verified INTEGER DEFAULT 0
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

def get_user_x_account_info(user_id: int):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT x_username, is_verified, x_access_token, x_access_token_secret FROM user_x_accounts WHERE user_id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return row[0], bool(row[1]), row[2], row[3]
    return None, False, None, None

def get_telegram_user_id_by_x_username(x_username: str):
    """Retrieves the Telegram user_id associated with a given X username."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT user_id FROM user_x_accounts WHERE x_username = ?", (x_username,))
    row = c.fetchone()
    conn.close()
    if row:
        return row[0]
    return None

def save_user_x_account_info(user_id: int, x_username: str, x_access_token: str, x_access_token_secret: str):
    """
    Saves the user's X account info.
    Returns True on success, False if the X account is already linked to another Telegram ID.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("REPLACE INTO user_x_accounts (user_id, x_username, x_access_token, x_access_token_secret, is_verified) VALUES (?, ?, ?, ?, ?)",
                  (user_id, x_username, x_access_token, x_access_token_secret, 1))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError as e:
        logger.error(f"IntegrityError: {e}")
        conn.close()
        return False

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
    """Generates a CAPTCHA image and its corresponding text."""
    generator = ImageCaptcha(width=200, height=80)
    characters = string.ascii_uppercase + string.digits
    captcha_text = ''.join(random.choice(characters) for i in range(5))

    image_data = generator.generate(captcha_text)
    img_byte_arr = io.BytesIO(image_data.read())
    img_byte_arr.seek(0)
    return captcha_text, img_byte_arr

def save_captcha_challenge(user_id: int, challenge_text: str):
    """Saves the active CAPTCHA challenge to the database."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("REPLACE INTO captcha_challenges (user_id, challenge_text, timestamp) VALUES (?, ?, ?)",
              (user_id, challenge_text, datetime.datetime.now().isoformat()))
    conn.commit()
    conn.close()

def get_captcha_challenge(user_id: int):
    """Retrieves the active CAPTCHA challenge from the database."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT challenge_text, timestamp FROM captcha_challenges WHERE user_id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return row[0], datetime.datetime.fromisoformat(row[1])
    return None, None

def delete_captcha_challenge(user_id: int):
    """Deletes the active CAPTCHA challenge from the database."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM captcha_challenges WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()

def update_user_captcha_solve_time(user_id: int, solve_time: datetime.datetime):
    """Updates the user's last CAPTCHA solve time in the user_captcha_status table."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("REPLACE INTO user_captcha_status (user_id, last_solve_time) VALUES (?, ?)",
              (user_id, solve_time.isoformat()))
    conn.commit()
    conn.close()

def get_user_captcha_solve_time(user_id: int):
    """Retrieves the user's last CAPTCHA solve time from the user_captcha_status table."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT last_solve_time FROM user_captcha_status WHERE user_id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return datetime.datetime.fromisoformat(row[0])
    return None
# --- End CAPTCHA Functions ---

# --- X (Twitter) Follower and Retweet Check Functions ---
def are_all_x_accounts_followed(user_x_username):
    """
    Checks if a given X username is following all TARGET_X_USERNAMES.
    Returns True if following all, False otherwise.
    """
    if not X_API_ENABLED:
        logger.warning("X API is not enabled. Skipping follow check.")
        return True, None

    try:
        # Get the IDs of the users that user_x_username is following
        following_ids = x_api_v1.get_friend_ids(screen_name=user_x_username)
        
        # Get the IDs of all target accounts once for efficiency
        target_ids = {}
        for target_username in TARGET_X_USERNAMES:
            try:
                target_user = x_api_v1.get_user(screen_name=target_username)
                target_ids[target_username] = target_user.id
            except TweepyException as e:
                logger.error(f"Error checking for target X account '{target_username}': {e}")
                return False, target_username

        # Check if they are following all target accounts
        for target_username, target_id in target_ids.items():
            if target_id not in following_ids:
                return False, target_username # Return False and the missing account
        return True, None # Return True and None if all are followed
    except TweepyException as e:
        logger.error(f"Error checking X follow status for {user_x_username}: {e}")
        return False, None
    except Exception as e:
        logger.error(f"An unexpected error occurred during X follow check: {e}")
        return False, None

def has_retweeted_post(user_x_username, post_id):
    """
    Checks if a user has retweeted a specific post.
    Note: The current Tweepy version (v1.x) does not provide a simple way to check for likes.
    """
    if not X_API_ENABLED:
        logger.warning("X API is not enabled. Skipping retweet check.")
        return True

    try:
        retweeters = x_api_v1.get_retweeters(id=post_id)
        user_id = x_api_v1.get_user(screen_name=user_x_username).id
        return user_id in retweeters
    except TweepyException as e:
        logger.error(f"Error checking retweet status for user {user_x_username} on post {post_id}: {e}")
        return False
    except Exception as e:
        logger.error(f"An unexpected error occurred during X retweet check: {e}")
        return False

# Telegram handlers
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id in BANNED_USERS:
        return
    name = update.effective_user.first_name or "there"
    
    x_accounts_list = "\n".join([f"- @{x}" for x in TARGET_X_USERNAMES])
    
    await update.message.reply_text(
        f"Hello {name}! I am the FOGO Testnet faucet bot.\n"
        "Use /send to get 0.1 SPL FOGO tokens every 24 hours.\n"
        "Use /send_fee to get a small amount of native FOGO tokens every 24 hours.\n"
        "You will need to solve a daily CAPTCHA and complete the following steps to claim tokens:\n"
        f"1. Follow these X (Twitter) accounts:\n{x_accounts_list}\n"
        f"2. Retweet this post: {TARGET_X_POST_URL}"
    )

async def send_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id in BANNED_USERS:
        return

    now = datetime.datetime.now()
    last_faucet_request = get_last_request_time(user_id, "send_fogo")

    if last_faucet_request and now - last_faucet_request < datetime.timedelta(hours=24):
        remaining = datetime.timedelta(hours=24) - (now - last_faucet_request)
        h, rem = divmod(int(remaining.total_seconds()), 3600)
        m, s = divmod(rem, 60)
        await update.message.reply_text(
            f"You have requested SPL FOGO within the last 24 hours.\n"
            f"Please try again in {h} hours, {m} minutes, and {s} seconds."
        )
        return

    # Check for X account verification
    if X_API_ENABLED:
        user_x_username, is_verified, _, _ = get_user_x_account_info(user_id)
        if not is_verified:
            try:
                auth = tweepy.OAuth1UserHandler(X_API_KEY, X_API_SECRET)
                # Removed 'signin_with_x=True' as it is not a valid argument in some tweepy versions
                auth_url = auth.get_authorization_url()
                context.user_data['oauth_request_token'] = auth.request_token['oauth_token']
                context.user_data['oauth_request_token_secret'] = auth.request_token['oauth_token_secret']
                context.user_data['awaiting_x_verifier_for_send'] = True
                
                await update.message.reply_text(
                    f"Please connect your X account to proceed. Click the link below, "
                    f"authorize the bot, and then paste the provided PIN here:\n\n"
                    f"{auth_url}"
                )
                return
            except TweepyException as e:
                logger.error(f"Failed to get X OAuth authorization URL: {e}")
                await update.message.reply_text("An error occurred while trying to connect to X. Please try again later.")
                return

        # If verified, proceed with follow check
        is_followed, missing_account = are_all_x_accounts_followed(user_x_username)
        if not is_followed:
            await update.message.reply_text(
                f"You are not following the account @{missing_account}. "
                "Please follow all required accounts to receive tokens."
            )
            return

        # Check for retweet
        if not has_retweeted_post(user_x_username, TARGET_X_POST_ID):
            await update.message.reply_text(
                f"You have not retweeted this post: {TARGET_X_POST_URL}\n"
                "Please retweet the post to continue."
            )
            return

    # Existing CAPTCHA logic
    last_captcha_solve_time = get_user_captcha_solve_time(user_id)
    daily_captcha_required = True
    if last_captcha_solve_time:
        time_since_last_solve = now - last_captcha_solve_time
        if time_since_last_solve < datetime.timedelta(hours=24):
            daily_captcha_required = False

    if daily_captcha_required or not context.user_data.get('captcha_passed', False):
        if daily_captcha_required:
            context.user_data['captcha_passed'] = False
        
        if not context.user_data.get('captcha_passed', False):
            captcha_text, captcha_image = generate_captcha()
            save_captcha_challenge(user_id, captcha_text)
            context.user_data['awaiting_captcha_answer'] = True
            context.user_data['next_action'] = 'send_spl'
            await update.message.reply_photo(
                photo=captcha_image,
                caption="Please enter the characters from the image to continue (you will need to solve the CAPTCHA again after 24 hours):"
            )
            return

    # Proceed with wallet address request if all checks pass
    context.user_data['waiting_for_spl_address'] = True
    await update.message.reply_text("Please send your FOGO wallet address to receive SPL FOGO:")

async def send_fee_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id in BANNED_USERS:
        return

    now = datetime.datetime.now()
    last_faucet_request = get_last_request_time(user_id, "send_fee")

    if last_faucet_request and now - last_faucet_request < datetime.timedelta(hours=24):
        remaining = datetime.timedelta(hours=24) - (now - last_faucet_request)
        h, rem = divmod(int(remaining.total_seconds()), 3600)
        m, s = divmod(rem, 60)
        await update.message.reply_text(
            f"You can only request native FOGO tokens once every 24 hours.\n"
            f"Please try again in {h} hours, {m} minutes, and {s} seconds."
        )
        return

    # Check for X account verification
    if X_API_ENABLED:
        user_x_username, is_verified, _, _ = get_user_x_account_info(user_id)
        if not is_verified:
            try:
                auth = tweepy.OAuth1UserHandler(X_API_KEY, X_API_SECRET)
                # Removed 'signin_with_x=True' as it is not a valid argument in some tweepy versions
                auth_url = auth.get_authorization_url()
                context.user_data['oauth_request_token'] = auth.request_token['oauth_token']
                context.user_data['oauth_request_token_secret'] = auth.request_token['oauth_token_secret']
                context.user_data['awaiting_x_verifier_for_send_fee'] = True
                
                await update.message.reply_text(
                    f"Please connect your X account to proceed. Click the link below, "
                    f"authorize the bot, and then paste the provided PIN here:\n\n"
                    f"{auth_url}"
                )
                return
            except TweepyException as e:
                logger.error(f"Failed to get X OAuth authorization URL: {e}")
                await update.message.reply_text("An error occurred while trying to connect to X. Please try again later.")
                return

        # If verified, proceed with follow check
        is_followed, missing_account = are_all_x_accounts_followed(user_x_username)
        if not is_followed:
            await update.message.reply_text(
                f"You are not following the account @{missing_account}. "
                "Please follow all required accounts to receive tokens."
            )
            return
        
        # Check for retweet
        if not has_retweeted_post(user_x_username, TARGET_X_POST_ID):
            await update.message.reply_text(
                f"You have not retweeted this post: {TARGET_X_POST_URL}\n"
                "Please retweet the post to continue."
            )
            return

    # Existing CAPTCHA logic
    last_captcha_solve_time = get_user_captcha_solve_time(user_id)
    daily_captcha_required = True
    if last_captcha_solve_time:
        time_since_last_solve = now - last_captcha_solve_time
        if time_since_last_solve < datetime.timedelta(hours=24):
            daily_captcha_required = False

    if daily_captcha_required or not context.user_data.get('captcha_passed', False):
        if daily_captcha_required:
            context.user_data['captcha_passed'] = False
        
        if not context.user_data.get('captcha_passed', False):
            captcha_text, captcha_image = generate_captcha()
            save_captcha_challenge(user_id, captcha_text)
            context.user_data['awaiting_captcha_answer'] = True
            context.user_data['next_action'] = 'send_fee'
            await update.message.reply_photo(
                photo=captcha_image,
                caption="Please enter the characters from the image to continue (you will need to solve the CAPTCHA again after 24 hours):"
            )
            return

    # Proceed with wallet address request if all checks pass
    context.user_data['waiting_for_fee_address'] = True
    await update.message.reply_text("Please send your FOGO wallet address to receive native FOGO tokens:")

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id in BANNED_USERS:
        return

    # --- New logic to handle X verifier code from OAuth ---
    if context.user_data.get('awaiting_x_verifier_for_send') or context.user_data.get('awaiting_x_verifier_for_send_fee'):
        verifier = update.message.text.strip()
        request_token = context.user_data.get('oauth_request_token')
        request_token_secret = context.user_data.get('oauth_request_token_secret')

        if not request_token or not request_token_secret:
            await update.message.reply_text("Authorization token not found. Please try the /send or /send_fee command again.")
            context.user_data.pop('awaiting_x_verifier_for_send', None)
            context.user_data.pop('awaiting_x_verifier_for_send_fee', None)
            return

        try:
            auth = tweepy.OAuth1UserHandler(X_API_KEY, X_API_SECRET)
            auth.request_token = {'oauth_token': request_token, 'oauth_token_secret': request_token_secret}
            access_token, access_token_secret = auth.get_access_token(verifier)
            
            # Use the access token to get user info
            auth_v1 = tweepy.OAuth1UserHandler(X_API_KEY, X_API_SECRET, access_token, access_token_secret)
            api = tweepy.API(auth_v1)
            user_data = api.verify_credentials()
            x_username = user_data.screen_name

            # Check if this X account is already linked to another Telegram ID
            if not save_user_x_account_info(user_id, x_username, access_token, access_token_secret):
                linked_user_id = get_telegram_user_id_by_x_username(x_username)
                await update.message.reply_text(
                    f"❌ This X account (@{x_username}) is already linked to another Telegram account (ID: {linked_user_id}).\n"
                    "Please use a different X account or contact an administrator."
                )
                context.user_data.pop('awaiting_x_verifier_for_send', None)
                context.user_data.pop('awaiting_x_verifier_for_send_fee', None)
                context.user_data.pop('oauth_request_token', None)
                context.user_data.pop('oauth_request_token_secret', None)
                return

            await update.message.reply_text(f"✅ X account @{x_username} successfully verified! Checking status...")

            # Clear the waiting state flags and continue
            action_type = None
            if context.user_data.get('awaiting_x_verifier_for_send'):
                context.user_data.pop('awaiting_x_verifier_for_send', None)
                action_type = 'send'
            elif context.user_data.get('awaiting_x_verifier_for_send_fee'):
                context.user_data.pop('awaiting_x_verifier_for_send_fee', None)
                action_type = 'send_fee'

            context.user_data.pop('oauth_request_token', None)
            context.user_data.pop('oauth_request_token_secret', None)
            
            # Now, re-call the appropriate command handler to continue the flow
            if action_type == 'send':
                await send_command(update, context)
            elif action_type == 'send_fee':
                await send_fee_command(update, context)
        
        except TweepyException as e:
            logger.error(f"X OAuth verification failed: {e}")
            await update.message.reply_text("❌ X verification failed. Please make sure you pasted the correct PIN. Try again.")
            context.user_data.pop('awaiting_x_verifier_for_send', None)
            context.user_data.pop('awaiting_x_verifier_for_send_fee', None)
        return

    # --- Handle CAPTCHA first ---
    if context.user_data.get('awaiting_captcha_answer', False):
        user_answer = update.message.text.strip().upper()

        stored_challenge, _ = get_captcha_challenge(user_id)

        if stored_challenge and user_answer == stored_challenge.upper():
            context.user_data['captcha_passed'] = True
            context.user_data['awaiting_captcha_answer'] = False
            delete_captcha_challenge(user_id)
            update_user_captcha_solve_time(user_id, datetime.datetime.now())
            await update.message.reply_text("✅ CAPTCHA solved successfully! You can now proceed.")
            
            # Continue the original flow based on stored 'next_action'
            next_action = context.user_data.pop('next_action', None)
            if next_action == 'send_spl':
                context.user_data['waiting_for_spl_address'] = True
                await update.message.reply_text("Please send your FOGO wallet address to receive SPL FOGO:")
            elif next_action == 'send_fee':
                context.user_data['waiting_for_fee_address'] = True
                await update.message.reply_text("Please send your FOGO wallet address to receive native FOGO tokens:")
            return
        else:
            await update.message.reply_text("❌ Incorrect CAPTCHA. Please try again. "
                                           "You will need to re-type the /send or /send_fee command to get a new CAPTCHA.")
            context.user_data['awaiting_captcha_answer'] = False
            delete_captcha_challenge(user_id)
            context.user_data['captcha_passed'] = False
            context.user_data.pop('next_action', None)
            return

    # --- Rest of handle_message (wallet address processing) ---
    if context.user_data.get("waiting_for_spl_address"):
        address = update.message.text.strip()
        context.user_data["waiting_for_spl_address"] = False

        if not is_valid_solana_address(address):
            await update.message.reply_text("Invalid wallet address. Please try again.")
            return

        if address in BLACKLISTED_WALLETS:
            await update.message.reply_text("🚫 This wallet is blacklisted. You have been banned from using the bot.")
            ban_user(user_id)
            return

        await update.message.reply_text(f"Sending {AMOUNT_TO_SEND_FOGO / 1_000_000_000} SPL FOGO to {address}...")

        tx_hash = await send_fogo_spl_token(address, AMOUNT_TO_SEND_FOGO)

        if tx_hash:
            update_last_request_time(user_id, "send_fogo", datetime.datetime.now(), address, tx_hash)
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
            await update.message.reply_text("🚫 This wallet is blacklisted. You have been banned from using the bot.")
            ban_user(user_id)
            return

        balance = await get_native_balance(address)
        if balance > 10_000_000:
            await update.message.reply_text("Your wallet balance exceeds 0.01 FOGO native tokens, you are not eligible for a fee airdrop.")
            return

        await update.message.reply_text(f"Sending {FEE_AMOUNT / 1_000_000_000} FOGO native token to {address}...")

        tx_hash = await send_native_fogo(address, FEE_AMOUNT)

        if tx_hash:
            update_last_request_time(user_id, "send_fee", datetime.datetime.now(), address, tx_hash)
            await update.message.reply_text(
                f"✅ FOGO native token sent successfully!\n"
                f"[View transaction](https://fogoscan.com/tx/{tx_hash}?cluster=testnet)",
                parse_mode="Markdown"
            )
        else:
            await update.message.reply_text("❌ Failed to send FOGO native token. Please try again later.")
        return

    await update.message.reply_text("Use /start, /send, or /send_fee to request tokens.")

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.error(f"An unexpected error occurred: {context.error}", exc_info=True)
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
        await update.message.reply_text("This user is not banned.")
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

    await update.message.reply_text(f"✅ User {target_id} has been unbanned.")

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
