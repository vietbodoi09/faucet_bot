# faucet_bot.py
import os
import datetime
import sqlite3
import logging
import base58
import io
import random
import string
import subprocess
from typing import Optional

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

import httpx
from captcha.image import ImageCaptcha

# X (Twitter) OAuth (only for connect/verify user identity)
import tweepy
from tweepy.errors import TweepyException

# snscrape (fallback) — có thể không dùng nếu cookie hoạt động ổn
try:
    import snscrape.modules.twitter as sntwitter
    SNSCRAPE_ENABLED = True
except Exception:
    SNSCRAPE_ENABLED = False

# =========================
# Logger
# =========================
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("faucet_bot")

# =========================
# Config & constants
# =========================
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
PRIVATE_KEY = os.getenv("FOGO_BOT_PRIVATE_KEY")  # base58 secret key (64 bytes)
# THAY bằng mint SPL FOGO thật của bạn
FOGO_TOKEN_MINT = PublicKey("So11111111111111111111111111111111111111112")

TARGET_X_USERNAMES_STR = os.getenv(
    "TARGET_X_USERNAMES",
    "FogoChain,ambient_finance,ValiantTrade,RobertSagurton,catcake0907,thebookofjoey,Pyronfi,furbocoin",
)
TARGET_X_USERNAMES = [
    name.strip() for name in TARGET_X_USERNAMES_STR.split(",") if name.strip()
]

# Tham khảo (không dùng verify)
TARGET_X_POST_ID = "1951268728555053106"
TARGET_X_POST_URL = "https://x.com/FogoChain/status/1951268728555053106"

# X API keys (dùng cho OAuth connect)
X_API_KEY = os.getenv("X_API_KEY")
X_API_SECRET = os.getenv("X_API_SECRET")

# Single-account cookie (web API)
X_COOKIE_AUTH_TOKEN = os.getenv("X_COOKIE_AUTH_TOKEN")  # cookie auth_token
X_COOKIE_CT0 = os.getenv("X_COOKIE_CT0")                # cookie ct0 (cũng là x-csrf-token)
X_USER_AGENT = os.getenv(
    "X_USER_AGENT",
    # UA mặc định cho đỡ nghi ngờ
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/127.0.0.0 Safari/537.36"
)

if PRIVATE_KEY is None:
    logger.critical("FOGO_BOT_PRIVATE_KEY environment variable is not set.")
    raise EnvironmentError("FOGO_BOT_PRIVATE_KEY is missing.")

# OAuth enable?
if any(key in (None, "") for key in [X_API_KEY, X_API_SECRET]):
    logger.warning("X (Twitter) API credentials missing. OAuth connect DISABLED.")
    X_API_ENABLED = False
else:
    X_API_ENABLED = True

# Amounts
AMOUNT_TO_SEND_FOGO = 800_000_000  # 0.8 SPL (decimals=9)
FEE_AMOUNT = 10_000_000            # 0.01 native (lamports)
DECIMALS = 9
DB_PATH = "fogo_requests.db"

# =========================
# Blacklist/Ban
# =========================
def load_blacklist(path="blacklist.txt") -> set:
    try:
        with open(path, "r") as f:
            return set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        logger.warning("blacklist.txt not found, no wallet is blacklisted.")
        return set()

def load_banned_users(path="banned_users.txt") -> set:
    try:
        with open(path, "r") as f:
            return set(int(line.strip()) for line in f if line.strip())
    except FileNotFoundError:
        logger.warning("banned_users.txt not found, no user is banned.")
        return set()

def ban_user(user_id: int, path="banned_users.txt"):
    with open(path, "a") as f:
        f.write(f"{user_id}\n")
    BANNED_USERS.add(user_id)

BLACKLISTED_WALLETS = load_blacklist()
BANNED_USERS = load_banned_users()

# =========================
# DB init & helpers
# =========================
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS requests (
            user_id INTEGER,
            request_type TEXT,
            last_request TIMESTAMP,
            wallet TEXT,
            tx_hash TEXT,
            PRIMARY KEY (user_id, request_type)
        )
    """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS captcha_challenges (
            user_id INTEGER PRIMARY KEY,
            challenge_text TEXT,
            timestamp TIMESTAMP
        )
    """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS user_captcha_status (
            user_id INTEGER,
            request_type TEXT,
            last_solve_time TIMESTAMP,
            PRIMARY KEY (user_id, request_type)
        )
    """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS user_x_accounts (
            user_id INTEGER PRIMARY KEY,
            x_username TEXT UNIQUE,
            x_access_token TEXT,
            x_access_token_secret TEXT,
            last_verification_time TIMESTAMP
        )
    """
    )
    # Ensure column exists (idempotent)
    try:
        c.execute("ALTER TABLE user_x_accounts ADD COLUMN last_verification_time TIMESTAMP")
    except sqlite3.OperationalError as e:
        if "duplicate column name" not in str(e).lower():
            logger.error(f"Error adding column: {e}")

    # Ensure request_type exists in user_captcha_status
    c.execute("PRAGMA table_info(user_captcha_status)")
    columns = [col[1] for col in c.fetchall()]
    if "request_type" not in columns:
        c.execute("ALTER TABLE user_captcha_status ADD COLUMN request_type TEXT DEFAULT 'default_type'")

    conn.commit()
    conn.close()

def get_last_request_time(user_id, request_type):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "SELECT last_request FROM requests WHERE user_id = ? AND request_type = ?",
        (user_id, request_type),
    )
    row = c.fetchone()
    conn.close()
    if row and row[0]:
        return datetime.datetime.fromisoformat(row[0])
    return None

def update_last_request_time(user_id, request_type, request_time, wallet, tx_hash):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "REPLACE INTO requests (user_id, request_type, last_request, wallet, tx_hash) VALUES (?, ?, ?, ?, ?)",
        (user_id, request_type, request_time.isoformat(), wallet, tx_hash),
    )
    conn.commit()
    conn.close()

def get_user_x_account_info(user_id: int):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "SELECT x_username, last_verification_time, x_access_token, x_access_token_secret FROM user_x_accounts WHERE user_id = ?",
        (user_id,),
    )
    row = c.fetchone()
    conn.close()
    if row:
        last_verification_time = (
            datetime.datetime.fromisoformat(row[1]) if row[1] else None
        )
        return row[0], last_verification_time, row[2], row[3]
    return None, None, None, None

def get_telegram_user_id_by_x_username(x_username: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT user_id FROM user_x_accounts WHERE x_username = ?", (x_username,))
    row = c.fetchone()
    conn.close()
    if row:
        return row[0]
    return None

def save_user_x_account_info(
    user_id: int, x_username: str, x_access_token: str, x_access_token_secret: str
):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute(
            "SELECT user_id FROM user_x_accounts WHERE x_username = ? AND user_id != ?",
            (x_username, user_id),
        )
        existing_link = c.fetchone()
        if existing_link:
            logger.warning(
                f"X account @{x_username} is already linked to Telegram user ID {existing_link[0]}."
            )
            conn.close()
            return False

        c.execute(
            """
            REPLACE INTO user_x_accounts (user_id, x_username, x_access_token, x_access_token_secret, last_verification_time)
            VALUES (?, ?, ?, ?, ?)
        """,
            (
                user_id,
                x_username,
                x_access_token,
                x_access_token_secret,
                datetime.datetime.now().isoformat(),
            ),
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError as e:
        logger.error(f"IntegrityError: {e}")
        conn.close()
        return False

# =========================
# Chain utils
# =========================
def is_valid_solana_address(address: str) -> bool:
    try:
        decoded = base58.b58decode(address)
        return len(decoded) == 32
    except Exception:
        return False

async def get_native_balance(pubkey_str: str) -> int:
    async with AsyncClient("https://testnet.fogo.io") as client:
        resp = await client.get_balance(PublicKey(pubkey_str))
        logger.info(f"get_native_balance response: {resp}")
        value = resp.get("result", {}).get("value", None)
        if value is None:
            logger.error(f"get_balance RPC returned no value: {resp}")
            return 0
        return value

async def send_native_fogo(to_address: str, amount: int):
    decoded_key = base58.b58decode(PRIVATE_KEY)
    sender = SolanaKeypair.from_secret_key(decoded_key)
    sender_pubkey = sender.public_key
    receiver_pubkey = PublicKey(to_address)

    tx = Transaction()
    tx.add(
        transfer(
            TransferParams(
                from_pubkey=sender_pubkey, to_pubkey=receiver_pubkey, lamports=amount
            )
        )
    )

    async with httpx.AsyncClient(timeout=20.0) as http_client:
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getLatestBlockhash",
            "params": [{"commitment": "finalized"}],
        }
        rpc_response = await http_client.post("https://testnet.fogo.io", json=payload)
        rpc_json = rpc_response.json()
        latest_blockhash = (
            rpc_json.get("result", {}).get("value", {}).get("blockhash")
        )

    if not latest_blockhash:
        logger.error(f"Invalid blockhash response: {rpc_json}")
        return None

    tx.recent_blockhash = latest_blockhash
    tx.fee_payer = sender_pubkey
    tx.sign(sender)

    async with AsyncClient("https://testnet.fogo.io") as client:
        resp = await client.send_raw_transaction(
            tx.serialize(), opts=TxOpts(skip_confirmation=False)
        )

    if resp and isinstance(resp, dict) and "result" in resp:
        return resp["result"]
    else:
        logger.error(f"Failed to send native FOGO tx: {resp}")
        return None

async def send_fogo_spl_token(to_address: str, amount: int):
    try:
        logger.info(f"Sending {amount / 1_000_000_000} SPL FOGO to {to_address}")
        decoded_key = base58.b58decode(PRIVATE_KEY)
        sender = SolanaKeypair.from_secret_key(decoded_key)
        sender_pubkey = sender.public_key
        receiver_pubkey = PublicKey(to_address)

        sender_token_account = get_associated_token_address(
            sender_pubkey, FOGO_TOKEN_MINT
        )
        receiver_token_account = get_associated_token_address(
            receiver_pubkey, FOGO_TOKEN_MINT
        )

        async with AsyncClient("https://testnet.fogo.io") as client:
            resp = await client.get_account_info(receiver_token_account)
            account_exists = resp.get("result", {}).get("value") is not None

        async with httpx.AsyncClient(timeout=20.0) as http_client:
            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getLatestBlockhash",
                "params": [],
            }
            rpc_response = await http_client.post(
                "https://testnet.fogo.io", json=payload
            )
            rpc_json = rpc_response.json()
            latest_blockhash = (
                rpc_json.get("result", {}).get("value", {}).get("blockhash")
            )

        if not latest_blockhash:
            logger.error(f"Invalid blockhash response: {rpc_json}")
            return None

        tx = Transaction()
        tx.fee_payer = sender_pubkey
        tx.recent_blockhash = latest_blockhash

        if not account_exists:
            create_ata_ix = create_associated_token_account(
                payer=sender_pubkey, owner=receiver_pubkey, mint=FOGO_TOKEN_MINT
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
                signers=[],
            )
        )
        tx.add(transfer_ix)
        tx.sign(sender)
        raw_tx = tx.serialize()

        async with AsyncClient("https://testnet.fogo.io") as client:
            send_resp = await client.send_raw_transaction(
                raw_tx, opts=TxOpts(skip_confirmation=False)
            )

        if send_resp and isinstance(send_resp, dict) and "result" in send_resp:
            return send_resp["result"]
        else:
            logger.error(f"Failed to send SPL transaction: {send_resp}")
            return None
    except Exception as e:
        logger.error(f"Critical error while sending SPL token: {e}", exc_info=True)
        return None

# =========================
# CAPTCHA
# =========================
def generate_captcha():
    generator = ImageCaptcha(width=200, height=80)
    characters = string.ascii_uppercase + string.digits
    captcha_text = "".join(random.choice(characters) for _ in range(5))
    image_data = generator.generate(captcha_text)
    img_byte_arr = io.BytesIO(image_data.read())
    img_byte_arr.seek(0)
    return captcha_text, img_byte_arr

def save_captcha_challenge(user_id: int, challenge_text: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "REPLACE INTO captcha_challenges (user_id, challenge_text, timestamp) VALUES (?, ?, ?)",
        (user_id, challenge_text, datetime.datetime.now().isoformat()),
    )
    conn.commit()
    conn.close()

def get_captcha_challenge(user_id: int):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "SELECT challenge_text, timestamp FROM captcha_challenges WHERE user_id = ?",
        (user_id,),
    )
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

def update_user_captcha_solve_time(
    user_id: int, request_type: str, solve_time: datetime.datetime
):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "REPLACE INTO user_captcha_status (user_id, request_type, last_solve_time) VALUES (?, ?, ?)",
        (user_id, request_type, solve_time.isoformat()),
    )
    conn.commit()
    conn.close()

def get_user_captcha_solve_time(user_id: int, request_type: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "SELECT last_solve_time FROM user_captcha_status WHERE user_id = ? AND request_type = ?",
        (user_id, request_type),
    )
    row = c.fetchone()
    conn.close()
    if row and row[0]:
        return datetime.datetime.fromisoformat(row[0])
    return None

# =========================
# X helpers — COOKIE-BASED (single account) + fallback
# =========================
X_TASK_KEYWORD = "$FURBO"

def _has_furbo_tweet_python(username: str) -> bool:
    """Fallback: snscrape Python API."""
    try:
        for i, tweet in enumerate(sntwitter.TwitterUserScraper(username).get_items()):
            if i >= 20:
                break
            text = getattr(tweet, "rawContent", "") or ""
            if "$furbo" in text.lower():
                return True
        return False
    except Exception as e:
        logger.warning(f"snscrape python error: {e}")
        return False

def _has_furbo_tweet_cli(username: str) -> bool:
    """Fallback: snscrape CLI."""
    try:
        result = subprocess.run(
            ["snscrape", "--max-results", "20", f"twitter-user:{username}"],
            capture_output=True,
            text=True,
            check=True,
        )
        tweets = result.stdout.splitlines()
        for line in tweets:
            if "$furbo" in line.lower():
                return True
        return False
    except Exception as e:
        logger.warning(f"snscrape CLI error: {e}")
        return False

async def _has_furbo_tweet_cookie(username: str) -> Optional[bool]:
    """
    Trả về:
      True  -> có tweet chứa $FURBO
      False -> không có
      None  -> lỗi cookie / bị 403 / cấu hình sai
    """
    if not X_COOKIE_AUTH_TOKEN or not X_COOKIE_CT0:
        logger.warning("X cookie not configured (X_COOKIE_AUTH_TOKEN/X_COOKIE_CT0 missing).")
        return None

    cookies = {
        "auth_token": X_COOKIE_AUTH_TOKEN,
        "ct0": X_COOKIE_CT0,
    }

    headers = {
        "User-Agent": X_USER_AGENT,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": f"https://twitter.com/{username}",
        "x-csrf-token": X_COOKIE_CT0,
        "x-twitter-active-user": "yes",
        "x-twitter-client-language": "en",
    }

    # Cách ổn định: gọi web API adaptive search (cần cookie + csrf)
    # q = "from:<username> $FURBO"
    params = {
        "q": f"from:{username} {X_TASK_KEYWORD}",
        "count": "20",
        "query_source": "typed_query",
        "tweet_search_mode": "live",
    }

    url = "https://twitter.com/i/api/2/search/adaptive.json"
    try:
        async with httpx.AsyncClient(timeout=20.0, headers=headers, cookies=cookies, follow_redirects=True) as client:
            r = await client.get(url, params=params)
            if r.status_code != 200:
                logger.warning(f"X web API status {r.status_code}: {r.text[:200]}")
                return None

            data = r.json()
            tweets_obj = (data.get("globalObjects") or {}).get("tweets") or {}
            for t in tweets_obj.values():
                # text field có thể là 'full_text' hoặc 'text' tùy API
                text = t.get("full_text") or t.get("text") or ""
                if "$furbo" in text.lower():
                    return True
            return False
    except Exception as e:
        logger.warning(f"X web API error: {e}")
        return None

async def user_has_task_tweet(username: str) -> bool:
    """
    Ưu tiên cookie (1 account duy nhất). Nếu lỗi cookie (None) thì fallback sang snscrape (nếu có).
    """
    cookie_result = await _has_furbo_tweet_cookie(username)
    if cookie_result is not None:
        return cookie_result

    # Fallback
    if SNSCRAPE_ENABLED:
        ok = _has_furbo_tweet_python(username)
        if ok:
            return True
        return _has_furbo_tweet_cli(username)
    else:
        # Không có cookie hợp lệ và cũng không có snscrape
        return False

# =========================
# Telegram handlers
# =========================
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id in BANNED_USERS:
        return
    name = update.effective_user.first_name or "there"
    x_accounts_list = "\n".join([f"- @{x}" for x in TARGET_X_USERNAMES])

    await update.message.reply_text(
        f"Hello {name}! I am the FOGO Testnet faucet bot.\n\n"
        "To receive tokens, please do the following:\n"
        f"1) Follow these X (Twitter) accounts (no verification):\n{x_accounts_list}\n"
        f"2) Post a public tweet containing the keyword: `{X_TASK_KEYWORD}`\n\n"
        "After completing the tasks, use these commands:\n"
        "• /send — claim 0.8 SPL FOGO every 24h (requires tweet check)\n"
        "• /send_fee — claim 0.01 native FOGO every 24h",
        disable_web_page_preview=True,
    )

async def send_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    /send flow:
    1) 24h faucet cooldown check
    2) Nếu X chưa verify trong 24h -> hiện nhiệm vụ + OAuth PIN link
    3) Sau khi connect: check tweet $FURBO qua web API (cookie 1 account)
    4) CAPTCHA mỗi ngày
    5) Hỏi ví & gửi SPL
    """
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
            "You have already requested SPL FOGO within the last 24 hours.\n"
            f"Please try again in {h} hours, {m} minutes, and {s} seconds."
        )
        return

    x_accounts_list = "\n".join([f"- @{x}" for x in TARGET_X_USERNAMES])
    x_username, last_verification_time, _, _ = get_user_x_account_info(user_id)

    # Require OAuth connect ít nhất 24h/lần
    if (
        (last_verification_time is None)
        or ((now - last_verification_time) > datetime.timedelta(hours=24))
        or (not x_username)
    ):
        if X_API_ENABLED:
            try:
                # PIN-based OAuth flow
                auth = tweepy.OAuth1UserHandler(X_API_KEY, X_API_SECRET, callback="oob")
                auth_url = auth.get_authorization_url(signin_with_twitter=False)
                context.user_data["oauth_request_token"] = auth.request_token.get("oauth_token")
                context.user_data["oauth_request_token_secret"] = auth.request_token.get("oauth_token_secret")
                context.user_data["awaiting_x_verifier_for_send"] = True

                task_message = (
                    "To receive tokens, please do the following:\n\n"
                    "1) Follow these X (Twitter) accounts (no verification):\n"
                    f"{x_accounts_list}\n\n"
                    f"2) Post a public tweet containing the keyword: `{X_TASK_KEYWORD}`\n\n"
                    "3) Connect your X account to verify. Click the link below, authorize the bot, "
                    "then paste the provided PIN here:\n\n"
                    f"{auth_url}"
                )
                await update.message.reply_text(
                    task_message, disable_web_page_preview=True
                )
                return
            except TweepyException as e:
                logger.error(f"Failed to get X OAuth authorization URL: {e}")
                await update.message.reply_text(
                    "An error occurred while connecting to X. Please try again later."
                )
                return
            except Exception as e:
                logger.error(f"Unexpected OAuth error: {e}")
                await update.message.reply_text(
                    "X API (OAuth) is not enabled. Please try again later."
                )
                return
        else:
            await update.message.reply_text(
                "X API (OAuth) is not enabled. Please try again later."
            )
            return

    # Đã có X username -> check tweet $FURBO bằng cookie (1 account)
    if not x_username:
        await update.message.reply_text(
            "You must connect your X account first using /send to continue."
        )
        return

    ok = await user_has_task_tweet(x_username)
    if not ok:
        # Nếu cookie lỗi => gợi ý admin (log đã có chi tiết)
        if not X_COOKIE_AUTH_TOKEN or not X_COOKIE_CT0:
            await update.message.reply_text(
                "Verification error: faucet's X session is not configured. Please try again later."
            )
            return
        await update.message.reply_text(
            f"We couldn't find a recent tweet containing `{X_TASK_KEYWORD}` from @{x_username}.\n"
            f"Please post a tweet with `{X_TASK_KEYWORD}` and run /send again."
        )
        return

    # Daily CAPTCHA (per request_type=send_fogo)
    last_captcha_solve_time = get_user_captcha_solve_time(user_id, "send_fogo")
    daily_captcha_required = True
    if last_captcha_solve_time:
        time_since_last_solve = now - last_captcha_solve_time
        if time_since_last_solve < datetime.timedelta(hours=24):
            daily_captcha_required = False

    if daily_captcha_required or not context.user_data.get("captcha_passed_send", False):
        if daily_captcha_required:
            context.user_data["captcha_passed_send"] = False

        captcha_text, captcha_image = generate_captcha()
        save_captcha_challenge(user_id, captcha_text)
        context.user_data["awaiting_captcha_answer"] = True
        context.user_data["next_action"] = "send_spl"
        await update.message.reply_photo(
            photo=captcha_image,
            caption="Enter the characters from the image to proceed (CAPTCHA resets every 24 hours).",
        )
        return

    # Ask wallet
    context.user_data["waiting_for_spl_address"] = True
    await update.message.reply_text(
        "Please provide your FOGO wallet address to receive 0.8 SPL FOGO:"
    )

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
            "You can only request native FOGO once every 24 hours.\n"
            f"Please try again in {h} hours, {m} minutes, and {s} seconds."
        )
        return

    x_accounts_list = "\n".join([f"- @{x}" for x in TARGET_X_USERNAMES])
    _, last_verification_time, _, _ = get_user_x_account_info(user_id)

    if last_verification_time is None or (now - last_verification_time) > datetime.timedelta(hours=24):
        if X_API_ENABLED:
            try:
                auth = tweepy.OAuth1UserHandler(X_API_KEY, X_API_SECRET, callback="oob")
                auth_url = auth.get_authorization_url(signin_with_twitter=False)
                context.user_data["oauth_request_token"] = auth.request_token.get("oauth_token")
                context.user_data["oauth_request_token_secret"] = auth.request_token.get("oauth_token_secret")
                context.user_data["awaiting_x_verifier_for_send_fee"] = True

                task_message = (
                    "To claim the native fee, please connect your X account and solve a CAPTCHA:\n\n"
                    "1) Follow these X (Twitter) accounts (no verification):\n"
                    f"{x_accounts_list}\n\n"
                    f"2) (Optional for /send_fee) You may tweet `{X_TASK_KEYWORD}` — not required for native faucet.\n\n"
                    "3) Connect your X account to proceed. Click the link below, authorize the bot, "
                    "then paste the provided PIN here:\n\n"
                    f"{auth_url}"
                )
                await update.message.reply_text(
                    task_message, disable_web_page_preview=True
                )
                return
            except TweepyException as e:
                logger.error(f"Failed to get X OAuth authorization URL: {e}")
                await update.message.reply_text(
                    "An error occurred while connecting to X. Please try again later."
                )
                return
            except Exception as e:
                logger.error(f"Unexpected OAuth error: {e}")
                await update.message.reply_text("X API is not enabled. Please try again later.")
                return
        else:
            await update.message.reply_text("X API is not enabled. Please try again later.")
            return

    # Daily CAPTCHA (per request_type=send_fee)
    last_captcha_solve_time = get_user_captcha_solve_time(user_id, "send_fee")
    daily_captcha_required = True
    if last_captcha_solve_time:
        time_since_last_solve = now - last_captcha_solve_time
        if time_since_last_solve < datetime.timedelta(hours=24):
            daily_captcha_required = False

    if daily_captcha_required or not context.user_data.get("captcha_passed_fee", False):
        if daily_captcha_required:
            context.user_data["captcha_passed_fee"] = False

        captcha_text, captcha_image = generate_captcha()
        save_captcha_challenge(user_id, captcha_text)
        context.user_data["awaiting_captcha_answer"] = True
        context.user_data["next_action"] = "send_fee"
        await update.message.reply_photo(
            photo=captcha_image,
            caption="Enter the characters from the image to proceed (CAPTCHA resets every 24 hours).",
        )
        return

    context.user_data["waiting_for_fee_address"] = True
    await update.message.reply_text(
        "Please provide your FOGO wallet address to receive 0.01 native FOGO:"
    )

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Bắt mọi tin nhắn text: xử lý PIN OAuth, CAPTCHA, địa chỉ ví."""
    user_id = update.effective_user.id
    if user_id in BANNED_USERS:
        return

    text = (update.message.text or "").strip()

    # --- Handle X OAuth PIN ---
    if context.user_data.get("awaiting_x_verifier_for_send") or context.user_data.get(
        "awaiting_x_verifier_for_send_fee"
    ):
        verifier = text
        request_token = context.user_data.get("oauth_request_token")
        request_token_secret = context.user_data.get("oauth_request_token_secret")

        if not request_token or not request_token_secret:
            await update.message.reply_text(
                "Authorization token not found. Please run /send or /send_fee again."
            )
            context.user_data.pop("awaiting_x_verifier_for_send", None)
            context.user_data.pop("awaiting_x_verifier_for_send_fee", None)
            return

        try:
            auth = tweepy.OAuth1UserHandler(X_API_KEY, X_API_SECRET, callback="oob")
            auth.request_token = {
                "oauth_token": request_token,
                "oauth_token_secret": request_token_secret,
            }
            access_token, access_token_secret = auth.get_access_token(verifier)

            # Fetch user data with token
            auth_v1 = tweepy.OAuth1UserHandler(
                X_API_KEY, X_API_SECRET, access_token, access_token_secret
            )
            api = tweepy.API(auth_v1)
            user_data = api.verify_credentials()
            x_username = user_data.screen_name

            if not save_user_x_account_info(
                user_id, x_username, access_token, access_token_secret
            ):
                linked_user_id = get_telegram_user_id_by_x_username(x_username)
                await update.message.reply_text(
                    f"This X account (@{x_username}) is already linked to another Telegram account (ID: {linked_user_id}).\n"
                    "Each X account can be linked to only one Telegram account."
                )
                context.user_data.pop("awaiting_x_verifier_for_send", None)
                context.user_data.pop("awaiting_x_verifier_for_send_fee", None)
                context.user_data.pop("oauth_request_token", None)
                context.user_data.pop("oauth_request_token_secret", None)
                return

            await update.message.reply_text(
                f"X account @{x_username} connected successfully!"
            )

            action_type = None
            if context.user_data.get("awaiting_x_verifier_for_send"):
                context.user_data.pop("awaiting_x_verifier_for_send", None)
                action_type = "send"
            elif context.user_data.get("awaiting_x_verifier_for_send_fee"):
                context.user_data.pop("awaiting_x_verifier_for_send_fee", None)
                action_type = "send_fee"

            context.user_data.pop("oauth_request_token", None)
            context.user_data.pop("oauth_request_token_secret", None)

            if action_type == "send":
                await send_command(update, context)
            elif action_type == "send_fee":
                await send_fee_command(update, context)

        except TweepyException as e:
            logger.error(f"X OAuth verification failed: {e}")
            await update.message.reply_text(
                "X verification failed. Please make sure you pasted the correct PIN and try again."
            )
            context.user_data.pop("awaiting_x_verifier_for_send", None)
            context.user_data.pop("awaiting_x_verifier_for_send_fee", None)
        except Exception as e:
            logger.error(f"Unexpected error during OAuth PIN handling: {e}")
            await update.message.reply_text(
                "X verification failed due to an unexpected error. Please try again."
            )
            context.user_data.pop("awaiting_x_verifier_for_send", None)
            context.user_data.pop("awaiting_x_verifier_for_send_fee", None)
        return

    # --- CAPTCHA handling ---
    if context.user_data.get("awaiting_captcha_answer", False):
        user_answer = text.upper()
        stored_challenge, _ = get_captcha_challenge(user_id)

        if stored_challenge and user_answer == stored_challenge.upper():
            context.user_data["awaiting_captcha_answer"] = False
            delete_captcha_challenge(user_id)
            next_action = context.user_data.pop("next_action", None)

            if next_action == "send_spl":
                update_user_captcha_solve_time(
                    user_id, "send_fogo", datetime.datetime.now()
                )
                context.user_data["captcha_passed_send"] = True
                await update.message.reply_text("CAPTCHA solved! Proceeding.")
                context.user_data["waiting_for_spl_address"] = True
                await update.message.reply_text(
                    "Please provide your FOGO wallet address to receive 0.8 SPL FOGO:"
                )
            elif next_action == "send_fee":
                update_user_captcha_solve_time(
                    user_id, "send_fee", datetime.datetime.now()
                )
                context.user_data["captcha_passed_fee"] = True
                await update.message.reply_text("CAPTCHA solved! Proceeding.")
                context.user_data["waiting_for_fee_address"] = True
                await update.message.reply_text(
                    "Please provide your FOGO wallet address to receive 0.01 native FOGO:"
                )
            return
        else:
            await update.message.reply_text(
                "Incorrect CAPTCHA. Please re-run /send or /send_fee to get a new CAPTCHA."
            )
            context.user_data["awaiting_captcha_answer"] = False
            delete_captcha_challenge(user_id)
            context.user_data["captcha_passed_send"] = False
            context.user_data["captcha_passed_fee"] = False
            context.user_data.pop("next_action", None)
            return

    # --- Wallet handling ---
    if context.user_data.get("waiting_for_spl_address"):
        address = text
        context.user_data["waiting_for_spl_address"] = False

        if not is_valid_solana_address(address):
            await update.message.reply_text("Invalid wallet address. Please try again.")
            return

        if address in BLACKLISTED_WALLETS:
            await update.message.reply_text(
                "This wallet is blacklisted. You are banned from using this bot."
            )
            ban_user(user_id)
            return

        await update.message.reply_text(f"Sending 0.8 SPL FOGO to {address}...")

        tx_hash = await send_fogo_spl_token(address, AMOUNT_TO_SEND_FOGO)

        if tx_hash:
            update_last_request_time(
                user_id, "send_fogo", datetime.datetime.now(), address, tx_hash
            )
            await update.message.reply_text(
                f"SPL FOGO sent successfully!\n"
                f"[View transaction](https://fogoscan.com/tx/{tx_hash}?cluster=testnet)",
                parse_mode="Markdown",
                disable_web_page_preview=True,
            )
        else:
            await update.message.reply_text(
                "Failed to send SPL FOGO. Please try again later."
            )
        return

    if context.user_data.get("waiting_for_fee_address"):
        address = text
        context.user_data["waiting_for_fee_address"] = False

        if not is_valid_solana_address(address):
            await update.message.reply_text("Invalid wallet address. Please try again.")
            return

        if address in BLACKLISTED_WALLETS:
            await update.message.reply_text(
                "This wallet is blacklisted. You are banned from using this bot."
            )
            ban_user(user_id)
            return

        balance = await get_native_balance(address)
        if balance > 10_000_000:
            await update.message.reply_text(
                "Your wallet balance exceeds 0.01 native FOGO, so you are not eligible for the fee airdrop."
            )
            return

        await update.message.reply_text(f"Sending 0.01 native FOGO to {address}...")

        tx_hash = await send_native_fogo(address, FEE_AMOUNT)

        if tx_hash:
            update_last_request_time(
                user_id, "send_fee", datetime.datetime.now(), address, tx_hash
            )
            await update.message.reply_text(
                f"Native FOGO sent successfully!\n"
                f"[View transaction](https://fogoscan.com/tx/{tx_hash}?cluster=testnet)",
                parse_mode="Markdown",
                disable_web_page_preview=True,
            )
        else:
            await update.message.reply_text(
                "Failed to send native FOGO. Please try again later."
            )
        return

    # Mặc định
    await update.message.reply_text("Use /start, /send, or /send_fee to request tokens.")

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.error(f"An unexpected error occurred: {context.error}", exc_info=True)
    try:
        if update and update.message:
            await update.message.reply_text("An error occurred. Please try again later.")
    except Exception:
        pass

# =========================
# Admin commands
# =========================
async def unban_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    admin_ids = os.getenv("ADMIN_IDS", "").split(",")
    if str(user_id) not in admin_ids:
        await update.message.reply_text("You are not authorized to use this command.")
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

    await update.message.reply_text(f"User {target_id} has been unbanned.")

async def ban_wallet_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    admin_ids = os.getenv("ADMIN_IDS", "").split(",")
    if str(user_id) not in admin_ids:
        await update.message.reply_text("You are not authorized to use this command.")
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

    await update.message.reply_text(f"Wallet {wallet} has been blacklisted.")

async def delete_wallet_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    admin_ids = os.getenv("ADMIN_IDS", "").split(",")
    if str(user_id) not in admin_ids:
        await update.message.reply_text("You are not authorized to use this command.")
        return

    if not context.args:
        await update.message.reply_text("Usage: /delete <wallet_address>")
        return

    wallet_to_delete = context.args[0].strip()
    if wallet_to_delete not in BLACKLISTED_WALLETS:
        await update.message.reply_text(
            f"Wallet {wallet_to_delete} is not in the blacklist."
        )
        return

    try:
        BLACKLISTED_WALLETS.remove(wallet_to_delete)
        with open("blacklist.txt", "r") as f:
            lines = f.readlines()
        with open("blacklist.txt", "w") as f:
            for line in lines:
                if line.strip() != wallet_to_delete:
                    f.write(line)
        await update.message.reply_text(
            f"Wallet {wallet_to_delete} has been removed from the blacklist."
        )
    except Exception as e:
        logger.error(
            f"Failed to delete wallet {wallet_to_delete} from blacklist.txt: {e}"
        )
        await update.message.reply_text(
            "An error occurred while trying to update the blacklist."
        )

async def banstats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    admin_ids = os.getenv("ADMIN_IDS", "").split(",")
    if str(user_id) not in admin_ids:
        await update.message.reply_text("You are not authorized to use this command.")
        return

    wallet_count = 0
    user_count = 0
    try:
        with open("blacklist.txt", "r") as f:
            wallet_count = len(set(line.strip() for line in f if line.strip()))
    except Exception:
        pass
    try:
        with open("banned_users.txt", "r") as f:
            user_count = len(set(line.strip() for line in f if line.strip()))
    except Exception:
        pass

    await update.message.reply_text(
        f"Blacklisted wallets: {wallet_count}\nBanned users: {user_count}"
    )

# =========================
# Main
# =========================
if __name__ == "__main__":
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

    # Mọi text vào đây: PIN OAuth / CAPTCHA / ví
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    app.add_error_handler(error_handler)

    app.run_polling()
