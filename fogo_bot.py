# faucet_bot.py
import os
import io
import datetime
import sqlite3
import logging
import base58
import random
import string
import subprocess
from typing import Optional

import httpx
from captcha.image import ImageCaptcha
import tweepy
from tweepy.errors import TweepyException

from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

from solana.rpc.async_api import AsyncClient
from solana.transaction import Transaction
from solana.keypair import Keypair as SolanaKeypair
from solana.publickey import PublicKey
from solana.rpc.types import TxOpts
from solana.system_program import transfer, TransferParams

from spl.token.instructions import (
    TransferCheckedParams,
    transfer_checked,
    get_associated_token_address,
    create_associated_token_account,
)
from spl.token.constants import TOKEN_PROGRAM_ID

# optional snscrape fallback
try:
    import snscrape.modules.twitter as sntwitter
    SNSCRAPE_ENABLED = True
except Exception:
    SNSCRAPE_ENABLED = False

# -----------------------
# Logger
# -----------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("faucet_bot")

# -----------------------
# Config (env)
# -----------------------
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
PRIVATE_KEY = os.getenv("FOGO_BOT_PRIVATE_KEY")  # base58 secret key bytes
FOGO_TOKEN_MINT = PublicKey(os.getenv("FOGO_TOKEN_MINT", "So11111111111111111111111111111111111111112"))

TARGET_X_USERNAMES_STR = os.getenv(
    "TARGET_X_USERNAMES",
    "FogoChain,ambient_finance,ValiantTrade,RobertSagurton,catcake0907,thebookofjoey,Pyronfi"
)
TARGET_X_USERNAMES = [n.strip() for n in TARGET_X_USERNAMES_STR.split(",") if n.strip()]

X_API_KEY = os.getenv("X_API_KEY")
X_API_SECRET = os.getenv("X_API_SECRET")

# cookie-based single-account web-check (optional, recommended)
X_COOKIE_AUTH_TOKEN = os.getenv("X_COOKIE_AUTH_TOKEN")  # auth_token cookie from faucet account
X_COOKIE_CT0 = os.getenv("X_COOKIE_CT0")                # ct0 cookie (x-csrf-token)
X_USER_AGENT = os.getenv("X_USER_AGENT",
                         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                         "Chrome/127.0.0.0 Safari/537.36")

if PRIVATE_KEY is None:
    logger.critical("FOGO_BOT_PRIVATE_KEY is not set.")
    raise EnvironmentError("FOGO_BOT_PRIVATE_KEY is missing.")

X_API_ENABLED = not any(k in (None, "") for k in [X_API_KEY, X_API_SECRET])

AMOUNT_TO_SEND_FOGO = int(os.getenv("AMOUNT_TO_SEND_FOGO", 800_000_000))  # 0.8 SPL (decimals=9)
FEE_AMOUNT = int(os.getenv("FEE_AMOUNT", 10_000_000))  # 0.01 native (lamports)
DECIMALS = int(os.getenv("DECIMALS", 9))
DB_PATH = os.getenv("DB_PATH", "fogo_requests.db")

# -----------------------
# Blacklist / banned
# -----------------------
def load_blacklist(path="blacklist.txt") -> set:
    try:
        with open(path, "r") as f:
            return set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        logger.info("blacklist.txt not found — starting empty")
        return set()

def load_banned_users(path="banned_users.txt") -> set:
    try:
        with open(path, "r") as f:
            return set(int(line.strip()) for line in f if line.strip())
    except FileNotFoundError:
        logger.info("banned_users.txt not found — starting empty")
        return set()

def ban_user(user_id: int, path="banned_users.txt"):
    try:
        with open(path, "a") as f:
            f.write(f"{user_id}\n")
    except Exception as e:
        logger.error("Error appending banned user: %s", e)
    BANNED_USERS.add(user_id)

BLACKLISTED_WALLETS = load_blacklist()
BANNED_USERS = load_banned_users()

# -----------------------
# DB helpers
# -----------------------
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
            user_id INTEGER,
            request_type TEXT,
            last_solve_time TIMESTAMP,
            PRIMARY KEY (user_id, request_type)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS user_x_accounts (
            user_id INTEGER PRIMARY KEY,
            x_username TEXT UNIQUE,
            x_access_token TEXT,
            x_access_token_secret TEXT,
            last_verification_time TIMESTAMP
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
    if row and row[0]:
        try:
            return datetime.datetime.fromisoformat(row[0])
        except Exception:
            return None
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
    c.execute("SELECT x_username, last_verification_time, x_access_token, x_access_token_secret FROM user_x_accounts WHERE user_id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    if row:
        last_verification_time = datetime.datetime.fromisoformat(row[1]) if row[1] else None
        return row[0], last_verification_time, row[2], row[3]
    return None, None, None, None

def get_telegram_user_id_by_x_username(x_username: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT user_id FROM user_x_accounts WHERE x_username = ?", (x_username,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None

def save_user_x_account_info(user_id: int, x_username: str, x_access_token: str, x_access_token_secret: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("SELECT user_id FROM user_x_accounts WHERE x_username = ? AND user_id != ?", (x_username, user_id))
        existing = c.fetchone()
        if existing:
            logger.warning("X account @%s already linked to Telegram user %s", x_username, existing[0])
            conn.close()
            return False
        c.execute("""
            REPLACE INTO user_x_accounts (user_id, x_username, x_access_token, x_access_token_secret, last_verification_time)
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, x_username, x_access_token, x_access_token_secret, datetime.datetime.now().isoformat()))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError as e:
        logger.error("IntegrityError saving user_x_accounts: %s", e)
        conn.close()
        return False

# -----------------------
# Chain utils
# -----------------------
def is_valid_solana_address(address: str) -> bool:
    try:
        decoded = base58.b58decode(address)
        return len(decoded) == 32
    except Exception:
        return False

async def get_native_balance(pubkey_str: str) -> int:
    async with AsyncClient("https://testnet.fogo.io") as client:
        resp = await client.get_balance(PublicKey(pubkey_str))
        logger.info("get_native_balance: %s", resp)
        value = resp.get("result", {}).get("value", None)
        if value is None:
            return 0
        return value

async def send_native_fogo(to_address: str, amount: int):
    decoded_key = base58.b58decode(PRIVATE_KEY)
    sender = SolanaKeypair.from_secret_key(decoded_key)
    sender_pubkey = sender.public_key
    receiver_pubkey = PublicKey(to_address)

    tx = Transaction()
    tx.add(transfer(TransferParams(from_pubkey=sender_pubkey, to_pubkey=receiver_pubkey, lamports=amount)))

    async with httpx.AsyncClient(timeout=15.0) as http_client:
        payload = {"jsonrpc": "2.0", "id": 1, "method": "getLatestBlockhash", "params": [{"commitment": "finalized"}]}
        rpc_response = await http_client.post("https://testnet.fogo.io", json=payload)
        rpc_json = rpc_response.json()
        latest_blockhash = rpc_json.get("result", {}).get("value", {}).get("blockhash")

    if not latest_blockhash:
        logger.error("Invalid blockhash response")
        return None

    tx.recent_blockhash = latest_blockhash
    tx.fee_payer = sender_pubkey
    tx.sign(sender)

    async with AsyncClient("https://testnet.fogo.io") as client:
        resp = await client.send_raw_transaction(tx.serialize(), opts=TxOpts(skip_confirmation=False))

    if resp and isinstance(resp, dict) and 'result' in resp:
        return resp['result']
    else:
        logger.error("Failed to send native FOGO tx: %s", resp)
        return None

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

        async with httpx.AsyncClient(timeout=15.0) as http_client:
            payload = {"jsonrpc": "2.0", "id": 1, "method": "getLatestBlockhash", "params": []}
            rpc_response = await http_client.post("https://testnet.fogo.io", json=payload)
            rpc_json = rpc_response.json()
            latest_blockhash = rpc_json.get("result", {}).get("value", {}).get("blockhash")

        if not latest_blockhash:
            logger.error("Invalid blockhash response")
            return None

        tx = Transaction()
        tx.fee_payer = sender_pubkey
        tx.recent_blockhash = latest_blockhash

        if not account_exists:
            create_ata_ix = create_associated_token_account(payer=sender_pubkey, owner=receiver_pubkey, mint=FOGO_TOKEN_MINT)
            tx.add(create_ata_ix)

        transfer_ix = transfer_checked(TransferCheckedParams(
            program_id=TOKEN_PROGRAM_ID,
            source=sender_token_account,
            mint=FOGO_TOKEN_MINT,
            dest=receiver_token_account,
            owner=sender.public_key,
            amount=amount,
            decimals=DECIMALS,
            signers=[]
        ))
        tx.add(transfer_ix)
        tx.sign(sender)

        raw_tx = tx.serialize()
        async with AsyncClient("https://testnet.fogo.io") as client:
            send_resp = await client.send_raw_transaction(raw_tx, opts=TxOpts(skip_confirmation=False))

        if send_resp and isinstance(send_resp, dict) and 'result' in send_resp:
            return send_resp['result']
        else:
            logger.error("Failed to send SPL tx: %s", send_resp)
            return None
    except Exception as e:
        logger.exception("Critical error while sending SPL token")
        return None

# -----------------------
# CAPTCHA
# -----------------------
def generate_captcha():
    generator = ImageCaptcha(width=200, height=80)
    characters = string.ascii_uppercase + string.digits
    captcha_text = ''.join(random.choice(characters) for _ in range(5))
    img = generator.generate(captcha_text)
    img_bytes = io.BytesIO(img.read())
    img_bytes.seek(0)
    return captcha_text, img_bytes

def save_captcha_challenge(user_id: int, challenge_text: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("REPLACE INTO captcha_challenges (user_id, challenge_text, timestamp) VALUES (?, ?, ?)",
              (user_id, challenge_text, datetime.datetime.now().isoformat()))
    conn.commit()
    conn.close()

def get_captcha_challenge(user_id: int):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT challenge_text, timestamp FROM captcha_challenges WHERE user_id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return row[0], datetime.datetime.fromisoformat(row[1])
    return None, None

def delete_captcha_challenge(user_id: int):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM captcha_challenges WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()

def update_user_captcha_solve_time(user_id: int, request_type: str, solve_time: datetime.datetime):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("REPLACE INTO user_captcha_status (user_id, request_type, last_solve_time) VALUES (?, ?, ?)",
              (user_id, request_type, solve_time.isoformat()))
    conn.commit()
    conn.close()

def get_user_captcha_solve_time(user_id: int, request_type: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT last_solve_time FROM user_captcha_status WHERE user_id = ? AND request_type = ?", (user_id, request_type))
    row = c.fetchone()
    conn.close()
    if row and row[0]:
        return datetime.datetime.fromisoformat(row[0])
    return None

# -----------------------
# X check: cookie-based web API (single account) + snscrape fallback
# -----------------------
X_TASK_KEYWORD = "$FURBO"

def _snscrape_check(username: str) -> bool:
    if not SNSCRAPE_ENABLED:
        return False
    try:
        for i, t in enumerate(sntwitter.TwitterUserScraper(username).get_items()):
            if i >= 20:
                break
            text = getattr(t, "rawContent", "") or getattr(t, "content", "") or ""
            if X_TASK_KEYWORD.lower() in text.lower():
                return True
    except Exception as e:
        logger.warning("snscrape python error: %s", e)
    # fallback to CLI
    try:
        res = subprocess.run(["snscrape", "--max-results", "20", f"twitter-user:{username}"], capture_output=True, text=True, check=True)
        for line in res.stdout.splitlines():
            if X_TASK_KEYWORD.lower() in line.lower():
                return True
    except Exception as e:
        logger.debug("snscrape CLI error: %s", e)
    return False

async def _cookie_check(username: str) -> Optional[bool]:
    if not X_COOKIE_AUTH_TOKEN or not X_COOKIE_CT0:
        logger.info("X cookie not configured; skipping cookie check")
        return None
    cookies = {"auth_token": X_COOKIE_AUTH_TOKEN, "ct0": X_COOKIE_CT0}
    headers = {"User-Agent": X_USER_AGENT, "x-csrf-token": X_COOKIE_CT0, "Accept": "application/json, text/plain, */*"}
    params = {"q": f"from:{username} {X_TASK_KEYWORD}", "count": "20", "query_source": "typed_query", "tweet_search_mode": "live"}
    url = "https://twitter.com/i/api/2/search/adaptive.json"
    try:
        async with httpx.AsyncClient(timeout=15.0, headers=headers, cookies=cookies, follow_redirects=True) as client:
            r = await client.get(url, params=params)
            if r.status_code != 200:
                logger.warning("X web API returned %s: %.200s", r.status_code, r.text)
                return None
            data = r.json()
            tweets = (data.get("globalObjects") or {}).get("tweets") or {}
            for t in tweets.values():
                text = t.get("full_text") or t.get("text") or ""
                if X_TASK_KEYWORD.lower() in text.lower():
                    return True
            return False
    except Exception as e:
        logger.warning("Cookie-based X web API error: %s", e)
        return None

async def user_has_task_tweet(username: str) -> bool:
    cookie_res = await _cookie_check(username)
    if cookie_res is not None:
        return cookie_res
    # fallback to snscrape if available
    return _snscrape_check(username)

# -----------------------
# Telegram handlers
# -----------------------
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id in BANNED_USERS:
        return
    name = update.effective_user.first_name or "there"
    x_list = "\n".join([f"- @{x}" for x in TARGET_X_USERNAMES])
    await update.message.reply_text(
        f"Hello {name}! FOGO testnet faucet.\n\n"
        f"Follow these X accounts:\n{x_list}\n\n"
        f"Tweet the keyword: `{X_TASK_KEYWORD}`\n\n"
        "Commands:\n• /send — claim 0.8 SPL FOGO every 24h\n• /send_fee — claim 0.01 native FOGO every 24h",
        disable_web_page_preview=True
    )

async def send_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id in BANNED_USERS:
        return
    now = datetime.datetime.now()
    last = get_last_request_time(user_id, "send_fogo")
    if last and now - last < datetime.timedelta(hours=24):
        rem = datetime.timedelta(hours=24) - (now - last)
        h, rem2 = divmod(int(rem.total_seconds()), 3600)
        m, s = divmod(rem2, 60)
        await update.message.reply_text(f"Already claimed in last 24h. Try again in {h}h {m}m.")
        return

    x_username, last_ver, _, _ = get_user_x_account_info(user_id)
    # Require OAuth connect at least every 24h
    if (last_ver is None) or ((now - last_ver) > datetime.timedelta(hours=24)) or (not x_username):
        if X_API_ENABLED:
            try:
                auth = tweepy.OAuth1UserHandler(X_API_KEY, X_API_SECRET, callback="oob")
                auth_url = auth.get_authorization_url(signin_with_twitter=False)
                context.user_data['oauth_request_token'] = auth.request_token.get('oauth_token')
                context.user_data['oauth_request_token_secret'] = auth.request_token.get('oauth_token_secret')
                context.user_data['awaiting_x_verifier_for_send'] = True
                await update.message.reply_text("Please connect your X account and paste the PIN here:\n\n" + auth_url, disable_web_page_preview=True)
                return
            except Exception as e:
                logger.error("OAuth URL error: %s", e)
                await update.message.reply_text("Error starting X OAuth. Try later.")
                return
        else:
            await update.message.reply_text("X OAuth disabled — admin must configure X_API_KEY/X_API_SECRET.")
            return

    if not x_username:
        await update.message.reply_text("No X account linked. Use /send to connect.")
        return

    ok = await user_has_task_tweet(x_username)
    if not ok:
        if not X_COOKIE_AUTH_TOKEN or not X_COOKIE_CT0:
            await update.message.reply_text("Verification error: faucet's X session is not configured. Please try again later.")
            return
        await update.message.reply_text(f"We couldn't find a recent tweet containing `{X_TASK_KEYWORD}` from @{x_username}. Please tweet and run /send again.")
        return

    # CAPTCHA daily
    last_captcha = get_user_captcha_solve_time(user_id, "send_fogo")
    needs_captcha = True
    if last_captcha and (now - last_captcha) < datetime.timedelta(hours=24):
        needs_captcha = False
    if needs_captcha or not context.user_data.get('captcha_passed_send', False):
        context.user_data['captcha_passed_send'] = False
        captcha_text, captcha_image = generate_captcha()
        save_captcha_challenge(user_id, captcha_text)
        context.user_data['awaiting_captcha_answer'] = True
        context.user_data['next_action'] = 'send_spl'
        await update.message.reply_photo(photo=captcha_image, caption="Enter the characters from the image to proceed (CAPTCHA resets every 24 hours).")
        return

    # ask for wallet
    context.user_data['waiting_for_spl_address'] = True
    await update.message.reply_text("Please provide your FOGO wallet address to receive 0.8 SPL FOGO:")

async def send_fee_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id in BANNED_USERS:
        return
    now = datetime.datetime.now()
    last = get_last_request_time(user_id, "send_fee")
    if last and now - last < datetime.timedelta(hours=24):
        rem = datetime.timedelta(hours=24) - (now - last)
        h, rem2 = divmod(int(rem.total_seconds()), 3600)
        m, s = divmod(rem2, 60)
        await update.message.reply_text(f"Already claimed fee in last 24h. Try again in {h}h {m}m.")
        return

    x_username, last_ver, _, _ = get_user_x_account_info(user_id)
    if (last_ver is None) or ((now - last_ver) > datetime.timedelta(hours=24)) or (not x_username):
        if X_API_ENABLED:
            try:
                auth = tweepy.OAuth1UserHandler(X_API_KEY, X_API_SECRET, callback="oob")
                auth_url = auth.get_authorization_url(signin_with_twitter=False)
                context.user_data['oauth_request_token'] = auth.request_token.get('oauth_token')
                context.user_data['oauth_request_token_secret'] = auth.request_token.get('oauth_token_secret')
                context.user_data['awaiting_x_verifier_for_send_fee'] = True
                await update.message.reply_text("Please connect your X account and paste the PIN here:\n\n" + auth_url, disable_web_page_preview=True)
                return
            except Exception as e:
                logger.error("OAuth URL error: %s", e)
                await update.message.reply_text("Error starting X OAuth. Try later.")
                return
        else:
            await update.message.reply_text("X OAuth disabled — admin must configure X_API_KEY/X_API_SECRET.")
            return

    # CAPTCHA daily
    last_captcha = get_user_captcha_solve_time(user_id, "send_fee")
    needs_captcha = True
    if last_captcha and (now - last_captcha) < datetime.timedelta(hours=24):
        needs_captcha = False
    if needs_captcha or not context.user_data.get('captcha_passed_fee', False):
        context.user_data['captcha_passed_fee'] = False
        captcha_text, captcha_image = generate_captcha()
        save_captcha_challenge(user_id, captcha_text)
        context.user_data['awaiting_captcha_answer'] = True
        context.user_data['next_action'] = 'send_fee'
        await update.message.reply_photo(photo=captcha_image, caption="Enter the characters from the image to proceed (CAPTCHA resets every 24 hours).")
        return

    context.user_data['waiting_for_fee_address'] = True
    await update.message.reply_text("Please provide your FOGO wallet address to receive 0.01 native FOGO:")

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id in BANNED_USERS:
        return
    text = (update.message.text or "").strip()

    # OAuth PIN handling
    if context.user_data.get('awaiting_x_verifier_for_send') or context.user_data.get('awaiting_x_verifier_for_send_fee'):
        verifier = text
        request_token = context.user_data.get('oauth_request_token')
        request_token_secret = context.user_data.get('oauth_request_token_secret')
        if not request_token or not request_token_secret:
            await update.message.reply_text("Authorization token not found. Please run /send or /send_fee again.")
            context.user_data.pop('awaiting_x_verifier_for_send', None)
            context.user_data.pop('awaiting_x_verifier_for_send_fee', None)
            return
        try:
            auth = tweepy.OAuth1UserHandler(X_API_KEY, X_API_SECRET, callback="oob")
            auth.request_token = {'oauth_token': request_token, 'oauth_token_secret': request_token_secret}
            access_token, access_token_secret = auth.get_access_token(verifier)
            auth_v1 = tweepy.OAuth1UserHandler(X_API_KEY, X_API_SECRET, access_token, access_token_secret)
            api = tweepy.API(auth_v1)
            user_data = api.verify_credentials()
            x_username = getattr(user_data, "screen_name", None)
            if not x_username:
                await update.message.reply_text("Failed to verify X credentials. Try again.")
                return
            if not save_user_x_account_info(user_id, x_username, access_token, access_token_secret):
                linked = get_telegram_user_id_by_x_username(x_username)
                await update.message.reply_text(f"This X account (@{x_username}) is already linked to another Telegram ID: {linked}.")
                context.user_data.pop('awaiting_x_verifier_for_send', None)
                context.user_data.pop('awaiting_x_verifier_for_send_fee', None)
                context.user_data.pop('oauth_request_token', None)
                context.user_data.pop('oauth_request_token_secret', None)
                return
            await update.message.reply_text(f"X account @{x_username} connected successfully!")
            action = None
            if context.user_data.get('awaiting_x_verifier_for_send'):
                context.user_data.pop('awaiting_x_verifier_for_send', None)
                action = 'send'
            elif context.user_data.get('awaiting_x_verifier_for_send_fee'):
                context.user_data.pop('awaiting_x_verifier_for_send_fee', None)
                action = 'send_fee'
            context.user_data.pop('oauth_request_token', None)
            context.user_data.pop('oauth_request_token_secret', None)
            if action == 'send':
                await send_command(update, context)
            elif action == 'send_fee':
                await send_fee_command(update, context)
        except TweepyException as e:
            logger.error("OAuth verification failed: %s", e)
            await update.message.reply_text("X verification failed. Make sure you pasted the correct PIN and try again.")
            context.user_data.pop('awaiting_x_verifier_for_send', None)
            context.user_data.pop('awaiting_x_verifier_for_send_fee', None)
        except Exception as e:
            logger.exception("Unexpected error during OAuth PIN handling")
            await update.message.reply_text("X verification failed due to an unexpected error. Please try again.")
            context.user_data.pop('awaiting_x_verifier_for_send', None)
            context.user_data.pop('awaiting_x_verifier_for_send_fee', None)
        return

    # CAPTCHA handling
    if context.user_data.get('awaiting_captcha_answer', False):
        ans = text.upper()
        stored, _ = get_captcha_challenge(user_id)
        if stored and ans == stored.upper():
            context.user_data['awaiting_captcha_answer'] = False
            delete_captcha_challenge(user_id)
            next_action = context.user_data.pop('next_action', None)
            if next_action == 'send_spl':
                update_user_captcha_solve_time(user_id, "send_fogo", datetime.datetime.now())
                context.user_data['captcha_passed_send'] = True
                await update.message.reply_text("CAPTCHA solved! Proceeding.")
                context.user_data['waiting_for_spl_address'] = True
                await update.message.reply_text("Please provide your FOGO wallet address to receive 0.8 SPL FOGO:")
            elif next_action == 'send_fee':
                update_user_captcha_solve_time(user_id, "send_fee", datetime.datetime.now())
                context.user_data['captcha_passed_fee'] = True
                await update.message.reply_text("CAPTCHA solved! Proceeding.")
                context.user_data['waiting_for_fee_address'] = True
                await update.message.reply_text("Please provide your FOGO wallet address to receive 0.01 native FOGO:")
            return
        else:
            await update.message.reply_text("Incorrect CAPTCHA. Please run /send or /send_fee again to get a new CAPTCHA.")
            context.user_data['awaiting_captcha_answer'] = False
            delete_captcha_challenge(user_id)
            context.user_data['captcha_passed_send'] = False
            context.user_data['captcha_passed_fee'] = False
            context.user_data.pop('next_action', None)
            return

    # Wallet handling
    if context.user_data.get('waiting_for_spl_address'):
        address = text
        context.user_data['waiting_for_spl_address'] = False
        if not is_valid_solana_address(address):
            await update.message.reply_text("Invalid wallet address. Please try again.")
            return
        if address in BLACKLISTED_WALLETS:
            await update.message.reply_text("This wallet is blacklisted. You are banned.")
            ban_user(user_id)
            return
        await update.message.reply_text(f"Sending 0.8 SPL FOGO to {address}...")
        tx = await send_fogo_spl_token(address, AMOUNT_TO_SEND_FOGO)
        if tx:
            update_last_request_time(user_id, "send_fogo", datetime.datetime.now(), address, tx)
            await update.message.reply_text(f"SPL sent! https://fogoscan.com/tx/{tx}?cluster=testnet", disable_web_page_preview=True)
        else:
            await update.message.reply_text("Failed to send SPL. Try later.")
        return

    if context.user_data.get('waiting_for_fee_address'):
        address = text
        context.user_data['waiting_for_fee_address'] = False
        if not is_valid_solana_address(address):
            await update.message.reply_text("Invalid wallet address. Please try again.")
            return
        if address in BLACKLISTED_WALLETS:
            await update.message.reply_text("This wallet is blacklisted. You are banned.")
            ban_user(user_id)
            return
        bal = await get_native_balance(address)
        if bal > FEE_AMOUNT:
            await update.message.reply_text("Your wallet balance exceeds eligibility for fee airdrop.")
            return
        await update.message.reply_text(f"Sending 0.01 native FOGO to {address}...")
        tx = await send_native_fogo(address, FEE_AMOUNT)
        if tx:
            update_last_request_time(user_id, "send_fee", datetime.datetime.now(), address, tx)
            await update.message.reply_text(f"Native sent! https://fogoscan.com/tx/{tx}?cluster=testnet", disable_web_page_preview=True)
        else:
            await update.message.reply_text("Failed to send native token. Try later.")
        return

    # default
    await update.message.reply_text("Use /start, /send, or /send_fee to request tokens.")

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.error("Unexpected error: %s", context.error, exc_info=True)
    try:
        if update and update.message:
            await update.message.reply_text("An error occurred. Please try again later.")
    except Exception:
        pass

# -----------------------
# Admin commands (unban, ban wallet, delete wallet, banstats)
# -----------------------
async def unban_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    admin_ids = os.getenv("ADMIN_IDS", "").split(",")
    if str(user_id) not in admin_ids:
        await update.message.reply_text("Not authorized.")
        return
    if not context.args:
        await update.message.reply_text("Usage: /unban <user_id>")
        return
    try:
        target = int(context.args[0])
    except ValueError:
        await update.message.reply_text("Invalid user id.")
        return
    if target not in BANNED_USERS:
        await update.message.reply_text("User not banned.")
        return
    BANNED_USERS.remove(target)
    try:
        with open("banned_users.txt", "r") as f:
            lines = f.readlines()
        with open("banned_users.txt", "w") as f:
            for l in lines:
                if l.strip() != str(target):
                    f.write(l)
    except Exception as e:
        logger.error("Failed updating banned_users.txt: %s", e)
    await update.message.reply_text(f"User {target} unbanned.")

async def ban_wallet_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    admin_ids = os.getenv("ADMIN_IDS", "").split(",")
    if str(user_id) not in admin_ids:
        await update.message.reply_text("Not authorized.")
        return
    if not context.args:
        await update.message.reply_text("Usage: /ban <wallet>")
        return
    wallet = context.args[0].strip()
    if wallet in BLACKLISTED_WALLETS:
        await update.message.reply_text("Wallet already blacklisted.")
        return
    BLACKLISTED_WALLETS.add(wallet)
    try:
        with open("blacklist.txt", "a") as f:
            f.write(wallet + "\n")
    except Exception as e:
        logger.error("Failed writing blacklist.txt: %s", e)
    await update.message.reply_text(f"Wallet {wallet} blacklisted.")

async def delete_wallet_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    admin_ids = os.getenv("ADMIN_IDS", "").split(",")
    if str(user_id) not in admin_ids:
        await update.message.reply_text("Not authorized.")
        return
    if not context.args:
        await update.message.reply_text("Usage: /delete <wallet>")
        return
    wal = context.args[0].strip()
    if wal not in BLACKLISTED_WALLETS:
        await update.message.reply_text("Wallet not in blacklist.")
        return
    try:
        BLACKLISTED_WALLETS.remove(wal)
        with open("blacklist.txt", "r") as f:
            lines = f.readlines()
        with open("blacklist.txt", "w") as f:
            for l in lines:
                if l.strip() != wal:
                    f.write(l)
        await update.message.reply_text(f"Wallet {wal} removed from blacklist.")
    except Exception as e:
        logger.error("Failed deleting wallet: %s", e)
        await update.message.reply_text("Error updating blacklist.")

async def banstats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    admin_ids = os.getenv("ADMIN_IDS", "").split(",")
    if str(user_id) not in admin_ids:
        await update.message.reply_text("Not authorized.")
        return
    wcount = 0
    ucount = 0
    try:
        with open("blacklist.txt", "r") as f:
            wcount = len(set(line.strip() for line in f if line.strip()))
    except Exception:
        pass
    try:
        with open("banned_users.txt", "r") as f:
            ucount = len(set(line.strip() for line in f if line.strip()))
    except Exception:
        pass
    await update.message.reply_text(f"Blacklisted wallets: {wcount}\nBanned users: {ucount}")

# -----------------------
# Main
# -----------------------
def main():
    if not BOT_TOKEN:
        raise EnvironmentError("TELEGRAM_BOT_TOKEN is not set.")
    init_db()
    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("send", send_command))
    app.add_handler(CommandHandler("send_fee", send_fee_command))
    app.add_handler(CommandHandler("unban", unban_command))
    app.add_handler(CommandHandler("ban", ban_wallet_command))
    app.add_handler(CommandHandler("delete", delete_wallet_command))
    app.add_handler(CommandHandler("banstats", banstats_command))

    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    app.add_error_handler(error_handler)

    logger.info("Starting faucet bot...")
    app.run_polling()

if __name__ == "__main__":
    main()
