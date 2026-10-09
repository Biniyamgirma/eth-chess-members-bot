#!/usr/bin/env python3
"""
Ethchess VENUE OWNER Telegram bot (Python port of the Node.js bot).

Run:
    pip install -r requirements.txt
    python ethchess_owner_bot.py

Environment (.env supported):
    TELEGRAM_BOT_TOKEN        required (the token of the venue-owner bot, NOT the member bot)
    TELEGRAM_BOT_API_SECRET   required (sent as x-ethchess-bot-secret)
    ETHCHESS_API_URL          optional, default http://localhost:4000
"""
from __future__ import annotations

import logging
import os
import re
import time
import unicodedata
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx
from dotenv import load_dotenv
from telegram import (
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    KeyboardButton,
    ReplyKeyboardMarkup,
    Update,
)
from telegram.constants import ChatType
from telegram.error import TelegramError
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
load_dotenv()

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(name)s: %(message)s", level=logging.INFO
)
# httpx logs full request URLs at INFO, and Telegram URLs contain the bot token.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logger = logging.getLogger("ethchess-owner-bot")


def require_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


TOKEN = require_env("TELEGRAM_BOT_TOKEN_FOR_VENUE_OWNERS")
BOT_API_SECRET = require_env("TELEGRAM_BOT_API_SECRET")
API_URL = (os.getenv("ETHCHESS_API_URL") or "http://localhost:4000").strip().rstrip("/")

_parsed_url = urlparse(API_URL)
if _parsed_url.scheme not in ("http", "https") or not _parsed_url.hostname:
    raise RuntimeError("ETHCHESS_API_URL must be a valid http(s) URL")
if _parsed_url.scheme == "http" and _parsed_url.hostname not in ("localhost", "127.0.0.1", "::1"):
    logger.warning(
        "ETHCHESS_API_URL uses plain http for a non-local host; "
        "passwords and the bot secret would travel unencrypted. Use https."
    )

SESSION_TTL_SECONDS = 10 * 60
MAX_LOGIN_ATTEMPTS = 5
MAX_INCOMING_TEXT = 512
MAX_PASSWORD_LENGTH = 128
MAX_TABLE_NAME_LENGTH = 40
MAX_LIST_ROWS = 40                 # cap rows in the "active matches" message
RATE_LIMIT_EVENTS = 12
RATE_LIMIT_WINDOW = 10.0
MAX_SESSIONS = 10_000

# --------------------------------------------------------------------------- #
# UI
# --------------------------------------------------------------------------- #
MENU_ACTIONS = {
    "Add venue table": "table",
    "Cancel a match": "cancel",
    "Start match": "start",
    "View active matches": "active",
}

MENU_KEYBOARD = ReplyKeyboardMarkup(
    [
        [KeyboardButton("Add venue table"), KeyboardButton("Cancel a match")],
        [KeyboardButton("Start match"), KeyboardButton("View active matches")],
    ],
    resize_keyboard=True,
    is_persistent=True,
)

LOGIN_KEYBOARD = InlineKeyboardMarkup([[InlineKeyboardButton("Login", callback_data="owner:login")]])

# --------------------------------------------------------------------------- #
# Input validation / sanitisation
# --------------------------------------------------------------------------- #
# Callback data is attacker-controllable, so every pattern is anchored with
# fullmatch, ASCII-only and length-bounded.
VENUE_RE = re.compile(r"owner:venue:(table|cancel|start|active):([0-9]{1,12})")
TABLE_RE = re.compile(r"owner:table:([0-9]{1,12}):([0-9]{1,12})")
CANCEL_RE = re.compile(r"owner:cancel:([0-9]{1,12})")
CANCEL_CONFIRM_RE = re.compile(r"owner:cancel-confirm:([0-9]{1,12})")

PHONE_RE = re.compile(r"09[0-9]{8}")                       # e.g. 0912345678
ETHCHESS_ID_RE = re.compile(r"(?:U|ETH)[A-Za-z0-9_-]{1,30}", re.IGNORECASE)
TELEGRAM_USERNAME_RE = re.compile(r"[A-Za-z0-9_]{4,32}")

TABLE_NAME_PUNCTUATION = set("-_.#&()'/")


def strip_unsafe(value: str) -> str:
    """Drop control, format (zero-width / bidi) and other non-printable chars."""
    return "".join(ch for ch in value if unicodedata.category(ch)[0] != "C")


def clean_display(value: Any, max_len: int, default: str = "") -> str:
    """Sanitise text coming from the backend before showing it to a user."""
    if not isinstance(value, str):
        return default
    value = " ".join(strip_unsafe(value).split())
    return value[:max_len] or default


def clean_identifier(value: str) -> str:
    value = unicodedata.normalize("NFKC", value)
    return " ".join(strip_unsafe(value).split())[:64]


def is_player_identifier(identifier: str) -> bool:
    return bool(PHONE_RE.fullmatch(identifier) or ETHCHESS_ID_RE.fullmatch(identifier))


def valid_password(password: str) -> bool:
    # Never altered (that would change the password); only reject empty,
    # oversized, or non-printable input.
    return 0 < len(password) <= MAX_PASSWORD_LENGTH and password.isprintable()


def clean_table_name(value: str) -> str | None:
    """Return a safe table name, or None when the input is not acceptable.

    Allows letters/numbers/marks in any script (e.g. Amharic), spaces and a
    small set of punctuation. Everything else (<, >, quotes, backticks,
    braces, ...) is rejected rather than silently altered.
    """
    name = " ".join(strip_unsafe(unicodedata.normalize("NFC", value)).split())
    if not name or len(name) > MAX_TABLE_NAME_LENGTH:
        return None
    for ch in name:
        if ch == " " or ch in TABLE_NAME_PUNCTUATION:
            continue
        if unicodedata.category(ch)[0] in ("L", "N", "M"):
            continue
        return None
    return name


def to_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str) and re.fullmatch(r"[0-9]{1,12}", value):
        return int(value)
    return None


def as_dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def as_dict_list(value: Any) -> list[dict]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


# --------------------------------------------------------------------------- #
# State: sessions + rate limiting
# --------------------------------------------------------------------------- #
@dataclass
class Session:
    step: str          # login_phone | login_password | table_name | player_one | player_two
    venue_id: int | None = None
    table_id: int | None = None
    phone: str | None = None
    player_one: str | None = None
    attempts: int = 0
    created: float = field(default_factory=time.monotonic)


SESSIONS: dict[str, Session] = {}


def get_session(chat_key: str) -> Session | None:
    session = SESSIONS.get(chat_key)
    if session and time.monotonic() - session.created > SESSION_TTL_SECONDS:
        SESSIONS.pop(chat_key, None)
        return None
    return session


def set_session(chat_key: str, session: Session) -> None:
    if len(SESSIONS) >= MAX_SESSIONS:
        now = time.monotonic()
        for key in [k for k, s in SESSIONS.items() if now - s.created > SESSION_TTL_SECONDS]:
            SESSIONS.pop(key, None)
        if len(SESSIONS) >= MAX_SESSIONS:
            return  # refuse new sessions rather than grow without bound
    SESSIONS[chat_key] = session


class RateLimiter:
    """Sliding-window limiter keyed by chat id."""

    def __init__(self, max_events: int, window: float) -> None:
        self.max_events = max_events
        self.window = window
        self.events: dict[int, deque[float]] = defaultdict(deque)

    def allow(self, key: int) -> bool:
        now = time.monotonic()
        if len(self.events) > 50_000:
            self.events.clear()
        bucket = self.events[key]
        while bucket and now - bucket[0] > self.window:
            bucket.popleft()
        if len(bucket) >= self.max_events:
            return False
        bucket.append(now)
        return True


limiter = RateLimiter(RATE_LIMIT_EVENTS, RATE_LIMIT_WINDOW)

# --------------------------------------------------------------------------- #
# Backend client
# --------------------------------------------------------------------------- #
class BackendError(Exception):
    """Error whose message is safe to show to the end user."""

    def __init__(self, user_message: str) -> None:
        super().__init__(user_message)
        self.user_message = user_message


DEFAULT_BACKEND_ERROR = "The ethchess service is unavailable."


def http_client(context: ContextTypes.DEFAULT_TYPE) -> httpx.AsyncClient:
    return context.application.bot_data["http"]


async def call_backend(
    context: ContextTypes.DEFAULT_TYPE,
    path: str,
    body: dict | None = None,
    chat_id: int | None = None,
) -> Any:
    """Call /api/venue-owner-bot{path}. GET when body is None, otherwise POST.

    For GET requests chat_id is sent as a query parameter (properly encoded
    by httpx), exactly like the original `?chat_id=...`.
    """
    url = f"{API_URL}/api/venue-owner-bot{path}"
    params = {"chat_id": str(chat_id)} if (body is None and chat_id is not None) else None
    try:
        response = await http_client(context).request(
            "POST" if body is not None else "GET",
            url,
            headers={"x-ethchess-bot-secret": BOT_API_SECRET},
            params=params,
            json=body,
        )
    except httpx.HTTPError as exc:
        logger.warning("Backend request failed: %s", type(exc).__name__)
        raise BackendError(DEFAULT_BACKEND_ERROR) from None

    try:
        payload = as_dict(response.json())
    except ValueError:
        payload = {}

    if not response.is_success or payload.get("success") is not True:
        raise BackendError(clean_display(payload.get("message"), 300, DEFAULT_BACKEND_ERROR))
    return payload.get("data")


async def link_vendor(
    context: ContextTypes.DEFAULT_TYPE,
    phone: str,
    password: str,
    chat_id: int,
    username: str | None,
) -> tuple[int, dict]:
    body: dict[str, Any] = {"phone": phone, "password": password, "chatId": str(chat_id)}
    if username and TELEGRAM_USERNAME_RE.fullmatch(username):
        body["telegramUsername"] = username
    try:
        response = await http_client(context).post(f"{API_URL}/api/auth/telegram/vendor-link", json=body)
    except httpx.HTTPError as exc:
        logger.warning("Vendor link request failed: %s", type(exc).__name__)
        raise BackendError("Could not reach ethchess. Please try again or use /cancel.") from None
    try:
        payload = as_dict(response.json())
    except ValueError:
        payload = {}
    ok = response.is_success and payload.get("success") is True
    return (200 if ok else (response.status_code if response.status_code >= 400 else 400)), payload


# --------------------------------------------------------------------------- #
# Telegram helpers
# --------------------------------------------------------------------------- #
async def send(context: ContextTypes.DEFAULT_TYPE, chat_id: int | str, text: str, markup=None) -> None:
    # No parse_mode anywhere: user/backend text can never be interpreted as markup.
    await context.bot.send_message(chat_id, text, reply_markup=markup)


async def show_menu(context: ContextTypes.DEFAULT_TYPE, chat_id: int, text: str = "Venue owner menu") -> None:
    await send(context, chat_id, text, MENU_KEYBOARD)


async def safe_answer(query, text: str | None = None, alert: bool = False) -> None:
    try:
        await query.answer(text=text, show_alert=alert)
    except TelegramError as exc:
        logger.debug("answer_callback_query failed: %s", exc)


async def delete_quietly(message) -> None:
    try:
        await message.delete()
    except TelegramError:
        pass


# --------------------------------------------------------------------------- #
# Venue owner workflows
# --------------------------------------------------------------------------- #
async def show_login(context: ContextTypes.DEFAULT_TYPE, chat_id: int) -> None:
    SESSIONS.pop(str(chat_id), None)
    await send(context, chat_id, "Login to your ethchess venue owner account.", LOGIN_KEYBOARD)


async def begin_venue_action(context: ContextTypes.DEFAULT_TYPE, chat_id: int, action: str) -> None:
    venues = []
    for venue in as_dict_list(await call_backend(context, "/venues", chat_id=chat_id)):
        venue_id = to_int(venue.get("id"))
        if venue_id is not None:
            venues.append((venue_id, clean_display(venue.get("name"), 40, f"Venue {venue_id}")))

    if not venues:
        await show_menu(context, chat_id, "No active venues are assigned to your account.")
        return

    if len(venues) == 1:
        await run_venue_action(context, chat_id, action, venues[0][0])
        return

    await send(
        context, chat_id, "Choose a venue:",
        InlineKeyboardMarkup(
            [[InlineKeyboardButton(name, callback_data=f"owner:venue:{action}:{venue_id}")]
             for venue_id, name in venues]
        ),
    )


async def run_venue_action(context: ContextTypes.DEFAULT_TYPE, chat_id: int, action: str, venue_id: int) -> None:
    if action == "table":
        set_session(str(chat_id), Session(step="table_name", venue_id=venue_id))
        await send(context, chat_id, "Send a name for the new table, or use /cancel.")
        return

    if action == "start":
        buttons = []
        for table in as_dict_list(await call_backend(context, f"/venues/{venue_id}/tables", chat_id=chat_id)):
            table_id = to_int(table.get("id"))
            if table_id is not None and table.get("is_available"):
                name = clean_display(table.get("name"), 40, f"Table {table_id}")
                buttons.append([InlineKeyboardButton(name, callback_data=f"owner:table:{venue_id}:{table_id}")])
        if not buttons:
            await send(context, chat_id, "There are no available active tables at this venue.")
            return
        await send(context, chat_id, "Choose a table for the match:", InlineKeyboardMarkup(buttons))
        return

    if action in ("active", "cancel"):
        matches = []
        for match in as_dict_list(await call_backend(context, f"/venues/{venue_id}/matches", chat_id=chat_id)):
            match_id = to_int(match.get("id"))
            if match_id is None:
                continue
            matches.append({
                "id": match_id,
                "white": clean_display(match.get("white_player_name"), 40, "?"),
                "black": clean_display(match.get("black_player_name"), 40, "?"),
                "table": clean_display(match.get("table_name"), 40, "?"),
                "pending": match.get("status") == "pending_start",
            })

        if not matches:
            await send(context, chat_id, "There are no active matches at this venue.")
            return

        if action == "active":
            rows = [
                f"{m['white']} VS {m['black']} : {m['table']}" + (" (waiting to start)" if m["pending"] else "")
                for m in matches[:MAX_LIST_ROWS]
            ]
            if len(matches) > MAX_LIST_ROWS:
                rows.append(f"...and {len(matches) - MAX_LIST_ROWS} more")
            await send(context, chat_id, "\n".join(rows), MENU_KEYBOARD)
            return

        await send(
            context, chat_id, "Choose the match to cancel:",
            InlineKeyboardMarkup(
                [[InlineKeyboardButton(
                    f"Cancel: {m['white']} VS {m['black']} : {m['table']}"[:60],
                    callback_data=f"owner:cancel:{m['id']}",
                )] for m in matches[:MAX_LIST_ROWS]]
            ),
        )


async def begin_manual_match(context: ContextTypes.DEFAULT_TYPE, chat_id: int, venue_id: int, table_id: int) -> None:
    set_session(str(chat_id), Session(step="player_one", venue_id=venue_id, table_id=table_id))
    await send(
        context, chat_id,
        "Enter player 1 phone number (starting with 09) or ethchess ID (starting with U or ETH). "
        "Use /cancel to stop.",
    )


async def create_manual_match(
    context: ContextTypes.DEFAULT_TYPE, chat_id: int, session: Session, player_two: str
) -> None:
    match = as_dict(await call_backend(
        context,
        f"/venues/{session.venue_id}/matches/manual",
        {
            "chat_id": str(chat_id),
            "table_id": session.table_id,
            "player_one": session.player_one,
            "player_two": player_two,
        },
    ))
    SESSIONS.pop(str(chat_id), None)
    white = clean_display(match.get("white_player_name"), 40, "?")
    black = clean_display(match.get("black_player_name"), 40, "?")
    table = clean_display(match.get("table_name"), 40, "?")
    await show_menu(context, chat_id, f"Match started: {white} VS {black} : {table}")


# --------------------------------------------------------------------------- #
# Handlers
# --------------------------------------------------------------------------- #
async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat = update.effective_chat
    if chat is None:
        return
    if chat.type != ChatType.PRIVATE:
        await send(context, chat.id, "Please message me in a private chat to log in.")
        return
    if not limiter.allow(chat.id):
        return
    await show_login(context, chat.id)


async def cmd_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat = update.effective_chat
    if chat is None or chat.type != ChatType.PRIVATE or not limiter.allow(chat.id):
        return
    SESSIONS.pop(str(chat.id), None)
    await show_menu(context, chat.id, "Action cancelled.")


async def on_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if query is None or not query.data or query.message is None:
        return
    chat = query.message.chat
    if chat.type != ChatType.PRIVATE:
        await safe_answer(query)
        return
    chat_id = chat.id

    if not limiter.allow(chat_id):
        await safe_answer(query, "You're going too fast. Please wait a moment.")
        return

    data = query.data
    if len(data) > 64:
        await safe_answer(query)
        return

    # --- cancellation confirm (answers the query itself after the backend call)
    if m := CANCEL_CONFIRM_RE.fullmatch(data):
        try:
            result = as_dict(await call_backend(
                context, f"/matches/{int(m.group(1))}/cancel", {"chat_id": str(chat_id)}
            ))
            await safe_answer(query, "Match cancelled.")
            cancelled_id = to_int(result.get("id"))
            await show_menu(
                context, chat_id,
                f"Match {cancelled_id if cancelled_id is not None else m.group(1)} was cancelled.",
            )
        except BackendError as exc:
            await safe_answer(query, exc.user_message, alert=True)
            await send(context, chat_id, exc.user_message)
        except Exception:
            logger.exception("Match cancellation failed")
            await safe_answer(query, "Unable to complete that action.", alert=True)
            await send(context, chat_id, "Unable to complete that action.")
        return

    # --- everything else ---------------------------------------------------
    await safe_answer(query)
    try:
        if data == "owner:login":
            set_session(str(chat_id), Session(step="login_phone"))
            await send(context, chat_id, "Enter the phone number on your venue owner account.")
        elif m := VENUE_RE.fullmatch(data):
            await run_venue_action(context, chat_id, m.group(1), int(m.group(2)))
        elif m := TABLE_RE.fullmatch(data):
            await begin_manual_match(context, chat_id, int(m.group(1)), int(m.group(2)))
        elif m := CANCEL_RE.fullmatch(data):
            await send(
                context, chat_id, "Cancel this match?",
                InlineKeyboardMarkup([[InlineKeyboardButton(
                    "Confirm cancellation", callback_data=f"owner:cancel-confirm:{int(m.group(1))}"
                )]]),
            )
        # anything else: silently ignored
    except BackendError as exc:
        await send(context, chat_id, exc.user_message)
    except TelegramError as exc:
        logger.warning("Telegram error during owner action: %s", exc)
    except Exception:
        logger.exception("Venue owner action failed")
        await send(context, chat_id, "Unable to complete that action.")


async def on_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.effective_message
    chat = update.effective_chat
    if message is None or chat is None or message.text is None:
        return
    if chat.type != ChatType.PRIVATE:
        return

    chat_id = chat.id
    chat_key = str(chat_id)
    if not limiter.allow(chat_id):
        return

    raw = message.text
    session = get_session(chat_key)

    # Oversized input is rejected before any processing; if it was a password
    # attempt it is also removed from the chat.
    if len(raw) > MAX_INCOMING_TEXT:
        if session and session.step == "login_password":
            await delete_quietly(message)
        await send(context, chat_id, "That message is too long.")
        return

    text = raw.strip()
    if not text or text.startswith("/"):
        return

    try:
        # A menu button always wins over a half-finished flow (except while a
        # password is expected), so "Start match" can never end up as a table name.
        if text in MENU_ACTIONS and not (session and session.step == "login_password"):
            SESSIONS.pop(chat_key, None)
            await begin_venue_action(context, chat_id, MENU_ACTIONS[text])
            return

        if session is None:
            return  # unrelated text outside a flow is ignored

        # --- login: phone -------------------------------------------------
        if session.step == "login_phone":
            phone = clean_identifier(text)
            if not PHONE_RE.fullmatch(phone):
                await send(context, chat_id, "Enter a valid phone number starting with 09.")
                return
            session.step = "login_password"
            session.phone = phone
            await send(context, chat_id, "Enter your venue owner password.")
            return

        # --- login: password ----------------------------------------------
        if session.step == "login_password" and session.phone:
            await delete_quietly(message)  # never leave the password in the chat
            if not valid_password(text):
                await send(context, chat_id, "That password isn't in a valid format. Enter it again, or use /cancel.")
                return

            username = message.from_user.username if message.from_user else None
            status, payload = await link_vendor(context, session.phone, text, chat_id, username)
            if status != 200:
                if 400 <= status < 500:
                    session.attempts += 1
                    if session.attempts >= MAX_LOGIN_ATTEMPTS:
                        SESSIONS.pop(chat_key, None)
                        await send(context, chat_id, "Too many failed attempts. Use /start to try again.")
                        return
                await send(
                    context, chat_id,
                    clean_display(payload.get("message"), 300, "Login failed. Enter your password again, or use /cancel."),
                )
                return

            SESSIONS.pop(chat_key, None)
            owner_name = clean_display(as_dict(as_dict(payload.get("data")).get("vendor")).get("name"), 60)
            suffix = f" ({owner_name})" if owner_name else ""
            await show_menu(context, chat_id, f"Venue owner account{suffix} connected.")
            return

        # --- add table: name ----------------------------------------------
        if session.step == "table_name":
            name = clean_table_name(text)
            if name is None:
                await send(
                    context, chat_id,
                    f"Table names can use letters, numbers, spaces and - _ . # & ( ) ' / "
                    f"(max {MAX_TABLE_NAME_LENGTH} characters). Try again, or use /cancel.",
                )
                return
            table = as_dict(await call_backend(
                context, f"/venues/{session.venue_id}/tables", {"chat_id": chat_key, "name": name}
            ))
            SESSIONS.pop(chat_key, None)
            table_id = to_int(table.get("id"))
            label = clean_display(table.get("name"), 40, f"Table {table_id}" if table_id is not None else name)
            await show_menu(context, chat_id, f"Added {label}.")
            return

        # --- manual match: players ----------------------------------------
        if session.step in ("player_one", "player_two"):
            player = clean_identifier(text)
            if not is_player_identifier(player):
                await send(
                    context, chat_id,
                    "Use a phone number starting with 09 or an ethchess ID starting with U or ETH.",
                )
                return
            if session.step == "player_one":
                session.player_one = player
                session.step = "player_two"
                await send(context, chat_id, "Enter player 2 phone number or ethchess ID.")
                return
            if session.player_one and player.casefold() == session.player_one.casefold():
                await send(context, chat_id, "Player 2 must be different from player 1.")
                return
            await create_manual_match(context, chat_id, session, player)
            return

    except BackendError as exc:
        await send(context, chat_id, exc.user_message)
    except TelegramError as exc:
        logger.warning("Telegram error in owner workflow: %s", exc)
    except Exception as exc:
        # Log only the type: the exception text could contain secrets.
        logger.error("Venue owner workflow failed: %s", type(exc).__name__)
        await send(context, chat_id, "Unable to complete that action.")


async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.error("Unhandled error: %s", type(context.error).__name__)


# --------------------------------------------------------------------------- #
# App wiring
# --------------------------------------------------------------------------- #
async def post_init(application: Application) -> None:
    application.bot_data["http"] = httpx.AsyncClient(
        timeout=httpx.Timeout(15.0, connect=5.0),
        follow_redirects=False,  # a redirect must never carry our secret header elsewhere
        limits=httpx.Limits(max_connections=50, max_keepalive_connections=10),
    )


async def post_shutdown(application: Application) -> None:
    client = application.bot_data.get("http")
    if client:
        await client.aclose()


def main() -> None:
    application = (
        Application.builder()
        .token(TOKEN)
        .post_init(post_init)
        .post_shutdown(post_shutdown)
        .concurrent_updates(32)
        .build()
    )
    application.add_handler(CommandHandler("start", cmd_start))
    application.add_handler(CommandHandler("cancel", cmd_cancel))
    application.add_handler(CallbackQueryHandler(on_callback))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))
    application.add_error_handler(on_error)

    logger.info("Ethchess venue owner bot starting (backend: %s)", API_URL)
    application.run_polling(allowed_updates=["message", "callback_query"])


if __name__ == "__main__":
    main()
