from __future__ import annotations

import asyncio
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
from telegram.error import Forbidden, NetworkError, TelegramError, TimedOut
from telegram.request import HTTPXRequest
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
logger = logging.getLogger("ethchess-bot")


def require_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is required")
    return value

print("Loading ethchess bot configuration...")

TOKEN = require_env("TELEGRAM_BOT_TOKEN")
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

# Security limits
SESSION_TTL_SECONDS = 10 * 60      # login flow expires after 10 minutes
MAX_LOGIN_ATTEMPTS = 5             # wrong passwords before the flow is reset
MAX_INCOMING_TEXT = 512            # reject anything longer than this outright
MAX_PASSWORD_LENGTH = 128
RATE_LIMIT_EVENTS = 12             # max events per chat ...
RATE_LIMIT_WINDOW = 10.0           # ... per this many seconds
MAX_SESSIONS = 10_000

# --------------------------------------------------------------------------- #
# UI
# --------------------------------------------------------------------------- #
MENU_PLAY = "Play physical match"
MENU_CURRENT_MATCHES = "Active matches"
MENU_FIND_TABLE = "Find a table"
MENU_LEAVE_TABLE = "Leave waiting table"
MENU_BACK = "Main menu"
MENU_ITEMS = (
    MENU_PLAY,
    "Get ethchess tournaments",
    "View profile details",
    "Analyze physical match history",
    "Brilliant move",
)
PHYSICAL_MATCH_ITEMS = (
    MENU_FIND_TABLE,
    MENU_CURRENT_MATCHES,
    MENU_LEAVE_TABLE,
    MENU_BACK,
)

MENU_KEYBOARD = ReplyKeyboardMarkup(
    [[KeyboardButton(item)] for item in MENU_ITEMS],
    resize_keyboard=True,
    is_persistent=True,
)

PHYSICAL_MATCH_KEYBOARD = ReplyKeyboardMarkup(
    [[KeyboardButton(item)] for item in PHYSICAL_MATCH_ITEMS],
    resize_keyboard=True,
    is_persistent=True,
)

LOGIN_KEYBOARD = InlineKeyboardMarkup(
    [
        [
            InlineKeyboardButton("Ethchess ID & Password", callback_data="member_login:id"),
            InlineKeyboardButton("Phone Number & Password", callback_data="member_login:phone"),
        ],
        [InlineKeyboardButton("Register to EthChess", callback_data="member_register:start")],
    ]
)


def start_match_keyboard(match_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [[InlineKeyboardButton("Start Match", callback_data=f"match:start:{match_id}")]]
    )


def end_match_keyboard(match_id: int, chat_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [[InlineKeyboardButton("End Match", callback_data=f"match:end:{match_id}:{chat_id}")]]
    )


def table_color_keyboard(table_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("White", callback_data=f"match:color:{table_id}:white"),
                InlineKeyboardButton("Black", callback_data=f"match:color:{table_id}:black"),
            ],
            [InlineKeyboardButton("Skip color preference", callback_data=f"match:color:{table_id}:skip")],
        ]
    )


def registration_district_keyboard(districts: list[dict]) -> InlineKeyboardMarkup:
    buttons = []
    for district in districts:
        district_id = to_int(district.get("id"))
        if district_id is None:
            continue
        name = clean_display(district.get("name"), 50, f"District {district_id}")
        buttons.append([
            InlineKeyboardButton(
                name,
                callback_data=f"member_register:district:{district_id}",
            )
        ])
    return InlineKeyboardMarkup(buttons)


# --------------------------------------------------------------------------- #
# Input validation / sanitisation
# --------------------------------------------------------------------------- #
# Callback data is attacker-controllable (clients can forge it), so every
# pattern is anchored with fullmatch, ASCII-only and length-bounded.
LOGIN_RE = re.compile(r"member_login:(id|phone)")
REGISTER_RE = re.compile(r"member_register:start")
REGISTER_DISTRICT_RE = re.compile(r"member_register:district:([0-9]{1,12})")
VENUE_RE = re.compile(r"match:venue:([0-9]{1,12})")
TABLE_RE = re.compile(r"match:table:([0-9]{1,12})")
OPEN_TABLE_RE = re.compile(r"match:table:open:([0-9]{1,12})")
TABLE_JOIN_RE = re.compile(r"match:table:join:([0-9]{1,12})")
TABLE_LEAVE_RE = re.compile(r"match:table:leave:([0-9]{1,12})")
COLOR_RE = re.compile(r"match:color:([0-9]{1,12}):(white|black|skip)")
START_RE = re.compile(r"match:start:([0-9]{1,12})")
END_RE = re.compile(r"match:end:([0-9]{1,12})(?::(-?[0-9]{1,20}))?")
LOSER_RE = re.compile(
    r"match:loser:(self|opponent):([0-9]{1,12})(?::(-?[0-9]{1,20}))?"
)
CONFIRM_RE = re.compile(r"match:loser:([0-9]{1,12}):([a-fA-F0-9-]{8,64})")

PHONE_RE = re.compile(r"09[0-9]{8}")                       # e.g. 0912345678
ETHCHESS_ID_RE = re.compile(r"(?:U|ETH)[A-Za-z0-9_-]{1,30}", re.IGNORECASE)
TELEGRAM_USERNAME_RE = re.compile(r"[A-Za-z0-9_]{4,32}")
CHAT_ID_RE = re.compile(r"-?[0-9]{1,20}")


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


def infer_identifier_type(identifier: str) -> str | None:
    if PHONE_RE.fullmatch(identifier):
        return "phone"
    if ETHCHESS_ID_RE.fullmatch(identifier):
        return "id"
    return None


def valid_password(password: str) -> bool:
    # Content is never altered (that would change the password); we only
    # reject empty, oversized, or non-printable input.
    return 0 < len(password) <= MAX_PASSWORD_LENGTH and password.isprintable()


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


def format_minutes(value: Any) -> str:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(int(value))
    return "unknown"


# --------------------------------------------------------------------------- #
# State: login sessions + rate limiting
# --------------------------------------------------------------------------- #
@dataclass
class LoginSession:
    step: str                       # "identifier" | "password"
    method: str                     # "id" | "phone"
    identifier: str | None = None
    identifier_type: str | None = None
    attempts: int = 0
    created: float = field(default_factory=time.monotonic)


@dataclass
class RegistrationSession:
    step: str
    first_name: str
    last_name: str
    telegram_username: str | None
    phone: str | None = None
    address: str | None = None
    district_id: int | None = None
    district_name: str | None = None
    created: float = field(default_factory=time.monotonic)


SESSIONS: dict[str, LoginSession | RegistrationSession] = {}


def get_session(chat_key: str) -> LoginSession | RegistrationSession | None:
    session = SESSIONS.get(chat_key)
    if session and time.monotonic() - session.created > SESSION_TTL_SECONDS:
        SESSIONS.pop(chat_key, None)
        return None
    return session


def set_session(chat_key: str, session: LoginSession | RegistrationSession) -> None:
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
        bucket = self.events[key]
        while bucket and now - bucket[0] > self.window:
            bucket.popleft()
        if not bucket:
            # keep the dict from growing forever with idle chats
            if len(self.events) > 50_000:
                self.events.clear()
                bucket = self.events[key]
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


def is_authentication_required(error: BackendError) -> bool:
    return error.user_message.strip().casefold() == "authentication required"


DEFAULT_BACKEND_ERROR = "The ethchess service is unavailable."


def http_client(context: ContextTypes.DEFAULT_TYPE) -> httpx.AsyncClient:
    return context.application.bot_data["http"]


async def call_backend(
    context: ContextTypes.DEFAULT_TYPE, path: str, body: dict | None = None
) -> Any:
    url = f"{API_URL}/api/matches/bot{path}"
    headers = {"x-ethchess-bot-secret": BOT_API_SECRET}
    try:
        response = await http_client(context).request(
            "POST" if body is not None else "GET",
            url,
            headers=headers,
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


# --------------------------------------------------------------------------- #
# Telegram helpers
# --------------------------------------------------------------------------- #
async def send(
    context: ContextTypes.DEFAULT_TYPE, chat_id: int | str, text: str, markup=None
) -> None:
    # No parse_mode anywhere: user/backend text can never be interpreted as markup.
    for attempt in range(3):
        try:
            await context.bot.send_message(chat_id, text, reply_markup=markup)
            return
        except Forbidden as exc:
            if "user is deactivated" not in str(exc).casefold():
                raise
            logger.info("Skipped Telegram message because the recipient is deactivated")
            return
        except (TimedOut, NetworkError):
            if attempt == 2:
                raise
            await asyncio.sleep(1.5 * (attempt + 1))


async def safe_answer(query, text: str | None = None, alert: bool = False) -> None:
    try:
        await query.answer(text=text, show_alert=alert)
    except TelegramError as exc:
        logger.debug("answer_callback_query failed: %s", exc)


# --------------------------------------------------------------------------- #
# Match flow
# --------------------------------------------------------------------------- #
async def show_login(context: ContextTypes.DEFAULT_TYPE, chat_id: int) -> None:
    SESSIONS.pop(str(chat_id), None)
    await send(context, chat_id, "Connect your ethchess account to the bot", LOGIN_KEYBOARD)


async def start_registration(context, chat_id: int, telegram_user) -> None:
    username = getattr(telegram_user, "username", None)
    if not isinstance(username, str) or not TELEGRAM_USERNAME_RE.fullmatch(username):
        username = None
    set_session(
        str(chat_id),
        RegistrationSession(
            step="first_name",
            first_name="",
            last_name="",
            telegram_username=username,
        ),
    )
    await send(
        context,
        chat_id,
        "Let's create your EthChess member account. Your Telegram username and chat ID "
        "will be linked automatically. Enter your first name.",
    )


async def list_registration_districts(context: ContextTypes.DEFAULT_TYPE) -> list[dict]:
    print(f'Requesting active district list from /api/lookups/district/active')
    try:
        print(f'Requesting active district list from {API_URL}/api/lookups/district/active')
        response = await http_client(context).get(
            f"{API_URL}/api/lookups/district/active",
        )
    except httpx.HTTPError as exc:
        logger.warning("District list request failed: %s", type(exc).__name__)
        raise BackendError(DEFAULT_BACKEND_ERROR) from None

    try:
        payload = as_dict(response.json())
    except ValueError:
        payload = {}
    if not response.is_success or payload.get("success") is not True:
        raise BackendError(clean_display(payload.get("message"), 300, DEFAULT_BACKEND_ERROR))
    return as_dict_list(payload.get("data"))


async def get_linked_account(context, chat_id) -> dict | None:
    try:
        result = as_dict(
            await call_backend(context, "/account", {"chat_id": str(chat_id)})
        )
    except BackendError as exc:
        if is_authentication_required(exc):
            return None
        raise
    if result.get("linked") is not True:
        return None
    return as_dict(result.get("member"))


async def show_home(context: ContextTypes.DEFAULT_TYPE, chat_id: int) -> None:
    account = await get_linked_account(context, chat_id)
    if account is None:
        await show_login(context, chat_id)
        return

    name = clean_display(account.get("name"), 60, "your account")
    await send(context, chat_id, f"Your ethchess account is connected as {name}.", MENU_KEYBOARD)


async def show_venues(context: ContextTypes.DEFAULT_TYPE, chat_id: int) -> None:
    venues = as_dict_list(
        await call_backend(context, "/venues", {"chat_id": str(chat_id)})
    )
    buttons = []
    for venue in venues:
        venue_id = to_int(venue.get("id"))
        if venue_id is None:
            continue
        name = clean_display(venue.get("name"), 40, f"Venue {venue_id}")
        buttons.append([InlineKeyboardButton(name, callback_data=f"match:venue:{venue_id}")])

    if not buttons:
        await send(
            context,
            chat_id,
            "There are no active venues available right now.",
            PHYSICAL_MATCH_KEYBOARD,
        )
        return
    await send(context, chat_id, "Choose a venue:", InlineKeyboardMarkup(buttons))


async def show_physical_match_menu(
    context: ContextTypes.DEFAULT_TYPE, chat_id: int
) -> None:
    await send(
        context,
        chat_id,
        "Physical match options:",
        PHYSICAL_MATCH_KEYBOARD,
    )


async def show_current_matches(
    context: ContextTypes.DEFAULT_TYPE,
    chat_id: int,
    matches: list[dict] | None = None,
    intro: str | None = None,
) -> None:
    if matches is None:
        matches = as_dict_list(
            await call_backend(context, "/matches", {"chat_id": str(chat_id)})
        )
    if not matches:
        await send(
            context,
            chat_id,
            "You have no current physical matches.",
            PHYSICAL_MATCH_KEYBOARD,
        )
        return

    match_lines = []
    buttons = []
    for match in matches:
        match_id = to_int(match.get("id"))
        white = as_dict(match.get("white_player"))
        black = as_dict(match.get("black_player"))
        if match_id is None or not white or not black:
            continue
        white_name = clean_display(white.get("name"), 80, "White player")
        black_name = clean_display(black.get("name"), 80, "Black player")
        match_lines.append(f"Match {match_id}: {white_name} vs {black_name}")
        if match.get("status") == "started":
            buttons.append([
                InlineKeyboardButton(
                    f"End match {match_id}",
                    callback_data=f"match:end:{match_id}:{chat_id}",
                )
            ])
        else:
            match_lines.append("Awaiting loser confirmation.")

    if not match_lines:
        await send(
            context,
            chat_id,
            "Unable to display your current matches. Please try again.",
            PHYSICAL_MATCH_KEYBOARD,
        )
        return
    lines = ([intro] if intro else []) + match_lines
    await send(
        context,
        chat_id,
        "\n".join(lines),
        InlineKeyboardMarkup(buttons) if buttons else PHYSICAL_MATCH_KEYBOARD,
    )


async def show_waiting_tables(
    context: ContextTypes.DEFAULT_TYPE, chat_id: int
) -> None:
    account = await get_linked_account(context, chat_id)
    if account is None:
        await show_login(context, chat_id)
        return

    member_id = str(account.get("id", ""))
    venues = as_dict_list(
        await call_backend(context, "/venues", {"chat_id": str(chat_id)})
    )
    buttons = []
    for venue in venues:
        venue_id = to_int(venue.get("id"))
        if venue_id is None:
            continue
        tables = as_dict_list(
            await call_backend(
                context,
                f"/venues/{venue_id}/tables",
                {"chat_id": str(chat_id)},
            )
        )
        for table in tables:
            table_id = to_int(table.get("id"))
            if (
                table_id is None
                or str(table.get("ideal_player")) != member_id
                or not table.get("is_available")
            ):
                continue
            table_name = clean_display(table.get("name"), 40, f"Table {table_id}")
            venue_name = clean_display(venue.get("name"), 40, f"Venue {venue_id}")
            buttons.append([
                InlineKeyboardButton(
                    f"Leave {table_name} ({venue_name})",
                    callback_data=f"match:table:leave:{table_id}",
                )
            ])

    if not buttons:
        await send(
            context,
            chat_id,
            "You are not waiting for an opponent at any table.",
            PHYSICAL_MATCH_KEYBOARD,
        )
        return

    await send(
        context,
        chat_id,
        "Choose the table you are waiting at:",
        InlineKeyboardMarkup(buttons),
    )


async def show_venue_tables(context: ContextTypes.DEFAULT_TYPE, chat_id: int, venue_id: int) -> None:
    account = await get_linked_account(context, chat_id)
    if account is None:
        await show_login(context, chat_id)
        return

    tables = as_dict_list(
        await call_backend(
            context,
            f"/venues/{venue_id}/tables",
            {"chat_id": str(chat_id)},
        )
    )

    if not tables:
        await send(context, chat_id, "This venue has no active tables. Choose another venue.")
        return

    lines = ["Choose a table:"]
    buttons = []
    own_member_id = str(account.get("id", ""))
    for table in tables:
        table_id = to_int(table.get("id"))
        if table_id is None:
            continue
        name = clean_display(table.get("name"), 40, f"Table {table_id}")
        if not table.get("is_available"):
            lines.append(f"{name}: Match in progress.")
            continue

        ideal_player_id = table.get("ideal_player")
        ideal_player_name = clean_display(table.get("ideal_player_name"), 80, "")
        if ideal_player_id is not None and str(ideal_player_id) == own_member_id:
            lines.append(f"{name}: You are waiting for an opponent.")
            buttons.append([
                InlineKeyboardButton(
                    f"Choose color preference for {name}",
                    callback_data=f"match:table:{table_id}",
                ),
                InlineKeyboardButton(
                    f"Leave {name}",
                    callback_data=f"match:table:leave:{table_id}",
                ),
            ])
        elif ideal_player_id is not None and ideal_player_name:
            buttons.append([
                InlineKeyboardButton(
                    f"Start match against {ideal_player_name} /n ({name})",
                    callback_data=f"match:table:join:{table_id}",
                )
            ])
        else:
            buttons.append([
                InlineKeyboardButton(
                    f"Join {name}",
                    callback_data=f"match:table:open:{table_id}",
                )
            ])

    await send(
        context,
        chat_id,
        "\n".join(lines),
        InlineKeyboardMarkup(buttons) if buttons else None,
    )


async def choose_table_color(
    context: ContextTypes.DEFAULT_TYPE, chat_id: int, table_id: int, color: str
) -> None:
    if color == "skip":
        await join_table(context, chat_id, table_id, color=None)
        return
    await join_table(context, chat_id, table_id, color=color)


async def leave_table(
    context: ContextTypes.DEFAULT_TYPE, chat_id: int, table_id: int
) -> None:
    matches = as_dict_list(
        await call_backend(context, "/matches", {"chat_id": str(chat_id)})
    )
    if matches:
        await show_current_matches(
            context,
            chat_id,
            matches,
            "End or complete your active matches before leaving this table. "
            "Afterward, choose Leave again.",
        )
        return

    result = as_dict(
        await call_backend(context, f"/tables/{table_id}/leave", {"chat_id": str(chat_id)})
    )
    message = clean_display(result.get("message"), 300, "You left the table.")
    await send(context, chat_id, message, PHYSICAL_MATCH_KEYBOARD)


async def join_table(
    context: ContextTypes.DEFAULT_TYPE,
    chat_id: int,
    table_id: int,
    color: str | None = None,
    ask_color_preference: bool = False,
) -> None:
    body: dict[str, Any] = {"chat_id": str(chat_id)}
    body["color"] = color
    result = as_dict(await call_backend(context, f"/tables/{table_id}/join", body))

    if result.get("state") == "waiting_for_opponent":
        message = clean_display(result.get("message"), 300, "Waiting for an opponent.")
        if ask_color_preference:
            await send(
                context,
                chat_id,
                f"{message} Choose your preferred color for when an opponent joins, "
                "or skip to leave it undecided:",
                table_color_keyboard(table_id),
            )
        else:
            await send(
                context,
                chat_id,
                f"{message} You can change your color preference from the table list.",
                PHYSICAL_MATCH_KEYBOARD,
            )
        return

    if result.get("state") != "match_started":
        raise BackendError("Received an unexpected response from ethchess.")

    match_id = to_int(as_dict(result.get("match")).get("id"))
    if match_id is None:
        raise BackendError("Received an unexpected response from ethchess.")

    opponent = clean_display(result.get("opponent_first_name"), 50, "your opponent")
    await send(
        context, chat_id,
        f"You Have Started a Match against {opponent}.",
        end_match_keyboard(match_id, chat_id),
    )

    notify_chat_id = result.get("notify_chat_id")
    if notify_chat_id is not None:
        notify_chat_id = str(notify_chat_id)
        if CHAT_ID_RE.fullmatch(notify_chat_id) and notify_chat_id != str(chat_id):
            joiner = clean_display(result.get("joining_player_first_name"), 50, "your opponent")
            try:
                await send(
                    context, notify_chat_id,
                    f"You Have Started a Match against {joiner}.",
                    end_match_keyboard(match_id, int(notify_chat_id)),
                )
            except TelegramError as exc:
                logger.warning("Could not notify opponent: %s", exc)


async def start_match(context: ContextTypes.DEFAULT_TYPE, chat_id: int, match_id: int) -> None:
    result = as_dict(await call_backend(context, f"/{match_id}/start", {"chat_id": str(chat_id)}))
    opponent = clean_display(result.get("opponent_first_name"), 50, "your opponent")
    await send(context, chat_id, f"You Have Started a Match against {opponent}.", end_match_keyboard(match_id, chat_id))


async def ask_who_lost(context: ContextTypes.DEFAULT_TYPE, chat_id: int, match_id: int) -> None:
    matches = as_dict_list(
        await call_backend(context, "/matches", {"chat_id": str(chat_id)})
    )
    match = next((item for item in matches if to_int(item.get("id")) == match_id), None)
    if match is None:
        await send(context, chat_id, "This is not one of your current matches.")
        return
    account = await get_linked_account(context, chat_id)
    if account is None:
        await send(context, chat_id, "Connect your ethchess account first.")
        return

    buttons = []
    for key in ("white_player", "black_player"):
        player = as_dict(match.get(key))
        player_id = player.get("id")
        if player_id is None:
            continue
        loser = "self" if str(player_id) == str(account.get("id")) else "opponent"
        label = clean_display(player.get("name"), 80, "Player")
        buttons.append(
            InlineKeyboardButton(
                label,
                callback_data=f"match:loser:{loser}:{match_id}:{chat_id}",
            )
        )
    if len(buttons) != 2:
        await send(context, chat_id, "Unable to load the players for this match.")
        return

    await send(
        context,
        chat_id,
        "Who lost this game?",
        InlineKeyboardMarkup([buttons]),
    )


async def select_loser(context: ContextTypes.DEFAULT_TYPE, chat_id: int, match_id: int, loser: str) -> None:
    result = as_dict(
        await call_backend(context, f"/{match_id}/end", {"chat_id": str(chat_id), "loser": loser})
    )
    if result.get("state") == "match_ended":
        await send(
            context, chat_id,
            f"Match ended. Total minutes played: {format_minutes(result.get('totalMinutes'))}.",
            PHYSICAL_MATCH_KEYBOARD,
        )
        return
    await send(context, chat_id, clean_display(result.get("message"), 300, "Your result was recorded."))


async def confirm_opponent_loss(
    context: ContextTypes.DEFAULT_TYPE, query, chat_id: int, match_id: int, token: str
) -> None:
    result = as_dict(
        await call_backend(context, f"/{match_id}/confirm-loser", {"chat_id": str(chat_id), "token": token})
    )
    await safe_answer(query, "Match result confirmed.")
    await send(
        context, chat_id,
        f"Thanks for confirming. The match is complete ({format_minutes(result.get('totalMinutes'))} minutes).",
        MENU_KEYBOARD,
    )
    try:
        await query.edit_message_reply_markup(InlineKeyboardMarkup([]))
    except TelegramError:
        pass


# --------------------------------------------------------------------------- #
# Account linking
# --------------------------------------------------------------------------- #
async def link_account(
    context: ContextTypes.DEFAULT_TYPE,
    identifier: str,
    identifier_type: str,
    password: str,
    chat_id: int,
    username: str | None,
) -> tuple[int, dict]:
    body: dict[str, Any] = {
        "phone" if identifier_type == "phone" else "identifier": identifier,
        "password": password,
        "chatId": str(chat_id),
    }
    if username and TELEGRAM_USERNAME_RE.fullmatch(username):
        body["telegramUsername"] = username
    try:
        response = await http_client(context).post(f"{API_URL}/api/auth/telegram/link", json=body)
    except httpx.HTTPError as exc:
        logger.warning("Account link request failed: %s", type(exc).__name__)
        raise BackendError("Could not reach ethchess. Please try again or use /cancel.") from None
    try:
        payload = as_dict(response.json())
    except ValueError:
        payload = {}
    if response.is_success and payload.get("success") is True:
        return response.status_code, payload
    return response.status_code, payload


async def register_telegram_account(
    context: ContextTypes.DEFAULT_TYPE,
    chat_id: int,
    session: RegistrationSession,
    password: str,
) -> dict:
    body: dict[str, Any] = {
        "chat_id": str(chat_id),
        "f_name": session.first_name,
        "phone": session.phone,
        "password": password,
        "address": session.address,
        "district": session.district_id,
    }
    if session.last_name:
        body["l_name"] = session.last_name
    if session.telegram_username:
        body["telegram_username"] = f"@{session.telegram_username}"
    try:
        response = await http_client(context).post(
            f"{API_URL}/api/members/bot/register",
            headers={"x-ethchess-bot-secret": BOT_API_SECRET},
            json=body,
        )
    except httpx.HTTPError as exc:
        logger.warning("Telegram registration request failed: %s", type(exc).__name__)
        raise BackendError(DEFAULT_BACKEND_ERROR) from None

    try:
        payload = as_dict(response.json())
    except ValueError:
        payload = {}
    if not response.is_success or payload.get("success") is not True:
        raise BackendError(clean_display(payload.get("message"), 300, DEFAULT_BACKEND_ERROR))
    return as_dict(payload.get("data"))


# --------------------------------------------------------------------------- #
# Handlers
# --------------------------------------------------------------------------- #
async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat = update.effective_chat
    if chat is None:
        return
    if chat.type != ChatType.PRIVATE:
        await send(context, chat.id, "Please message me in a private chat to connect your account.")
        return
    if not limiter.allow(chat.id):
        return
    try:
        await show_home(context, chat.id)
    except BackendError as exc:
        if is_authentication_required(exc):
            await show_login(context, chat.id)
            return
        await send(context, chat.id, exc.user_message)
    except Exception:
        logger.exception("Unable to check linked Telegram account")
        await send(context, chat.id, "Unable to reach ethchess right now. Please try again.")


async def cmd_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat = update.effective_chat
    if chat is None or chat.type != ChatType.PRIVATE or not limiter.allow(chat.id):
        return
    SESSIONS.pop(str(chat.id), None)
    await send(context, chat.id, "Registration or login cancelled. Use /start to try again.")


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

    # --- login method selection -------------------------------------------
    if m := LOGIN_RE.fullmatch(data):
        try:
            account = await get_linked_account(context, chat_id)
        except BackendError as exc:
            await safe_answer(query, exc.user_message, alert=True)
            return
        except Exception:
            logger.exception("Unable to verify linked Telegram account")
            await safe_answer(query, "Unable to reach ethchess right now.", alert=True)
            return
        if account is not None:
            name = clean_display(account.get("name"), 60, "your account")
            await safe_answer(query, "Your account is already connected.")
            await send(
                context,
                chat_id,
                f"Your ethchess account is connected as {name}.",
                MENU_KEYBOARD,
            )
            return

        method = m.group(1)
        set_session(str(chat_id), LoginSession(step="identifier", method=method))
        await safe_answer(query)
        await send(
            context, chat_id,
            "Enter the phone number on your ethchess account." if method == "phone"
            else "Enter your ethchess ID.",
        )
        return

    if REGISTER_RE.fullmatch(data):
        try:
            account = await get_linked_account(context, chat_id)
        except BackendError as exc:
            await safe_answer(query, exc.user_message, alert=True)
            return
        except Exception:
            logger.exception("Unable to check account before registration")
            await safe_answer(query, "Unable to reach ethchess right now.", alert=True)
            return
        if account is not None:
            name = clean_display(account.get("name"), 60, "your account")
            await safe_answer(query, "This Telegram account is already registered.")
            await send(
                context,
                chat_id,
                f"Your ethchess account is connected as {name}.",
                MENU_KEYBOARD,
            )
            return

        await safe_answer(query)
        await start_registration(context, chat_id, query.from_user)
        return

    if m := REGISTER_DISTRICT_RE.fullmatch(data):
        session = get_session(str(chat_id))
        if not isinstance(session, RegistrationSession) or session.step != "district":
            await safe_answer(query, "This registration step has expired. Start again.", alert=True)
            await send(context, chat_id, "Use /start and choose Register to EthChess to try again.")
            return
        try:
            district_id = int(m.group(1))
            print(f"User selected district {district_id} for registration")
            districts = await list_registration_districts(context)
        except BackendError as exc:
            await safe_answer(query, exc.user_message, alert=True)
            return
        district = next(
            (item for item in districts if to_int(item.get("id")) == district_id),
            None,
        )
        if district is None:
            await safe_answer(query, "That district is no longer available. Please choose again.", alert=True)
            await send(
                context,
                chat_id,
                "Choose an active district:",
                registration_district_keyboard(districts),
            )
            return

        session.district_id = district_id
        session.district_name = clean_display(
            district.get("name"),
            50,
            f"District {district_id}",
        )
        session.step = "password"
        await safe_answer(query)
        await send(
            context,
            chat_id,
            f"Selected {session.district_name}. Now create a password with at least 8 characters. "
            "Your password message will be deleted from this chat.",
        )
        return

    match_callback = any(
        pattern.fullmatch(data)
        for pattern in (
            CONFIRM_RE,
            VENUE_RE,
            TABLE_RE,
            OPEN_TABLE_RE,
            TABLE_JOIN_RE,
            TABLE_LEAVE_RE,
            COLOR_RE,
            START_RE,
            END_RE,
            LOSER_RE,
        )
    )
    if not match_callback:
        await safe_answer(query, "This button is no longer available.", alert=True)
        await send(context, chat_id, "That button is out of date. Please use /start and try again.")
        return

    if match_callback:
        try:
            if await get_linked_account(context, chat_id) is None:
                await safe_answer(query, "Connect your ethchess account first.", alert=True)
                await show_login(context, chat_id)
                return
        except BackendError as exc:
            if is_authentication_required(exc):
                await safe_answer(query, "Connect your ethchess account first.", alert=True)
                await show_login(context, chat_id)
                return
            await safe_answer(query, exc.user_message, alert=True)
            return
        except Exception:
            logger.exception("Unable to verify linked Telegram account")
            await safe_answer(query, "Unable to reach ethchess right now.", alert=True)
            return

    # --- opponent confirmation (answers the query itself) ------------------
    if m := CONFIRM_RE.fullmatch(data):
        try:
            await confirm_opponent_loss(context, query, chat_id, int(m.group(1)), m.group(2))
        except BackendError as exc:
            await safe_answer(query, exc.user_message, alert=True)
            await send(context, chat_id, exc.user_message)
        except Exception:
            logger.exception("Opponent confirmation failed")
            await safe_answer(query, "Unable to complete that action.", alert=True)
            await send(context, chat_id, "Unable to complete that action.")
        return

    if (m := END_RE.fullmatch(data)) and m.group(2) is not None and m.group(2) != str(chat_id):
        await safe_answer(query, "This match button belongs to another chat.", alert=True)
        return
    if (m := LOSER_RE.fullmatch(data)) and m.group(3) is not None and m.group(3) != str(chat_id):
        await safe_answer(query, "This match button belongs to another chat.", alert=True)
        return

    # --- everything else ---------------------------------------------------
    await safe_answer(query)
    try:
        if m := VENUE_RE.fullmatch(data):
            await show_venue_tables(context, chat_id, int(m.group(1)))
        elif m := TABLE_RE.fullmatch(data):
            table_id = int(m.group(1))
            await send(
                context,
                chat_id,
                "Choose your preferred color for when an opponent joins, or skip:",
                table_color_keyboard(table_id),
            )
        elif m := OPEN_TABLE_RE.fullmatch(data):
            await join_table(
                context,
                chat_id,
                int(m.group(1)),
                ask_color_preference=True,
            )
        elif m := TABLE_JOIN_RE.fullmatch(data):
            await join_table(context, chat_id, int(m.group(1)))
        elif m := TABLE_LEAVE_RE.fullmatch(data):
            await leave_table(context, chat_id, int(m.group(1)))
        elif m := COLOR_RE.fullmatch(data):
            await choose_table_color(context, chat_id, int(m.group(1)), m.group(2))
        elif m := START_RE.fullmatch(data):
            await start_match(context, chat_id, int(m.group(1)))
        elif m := END_RE.fullmatch(data):
            await ask_who_lost(context, chat_id, int(m.group(1)))
        elif m := LOSER_RE.fullmatch(data):
            await select_loser(context, chat_id, int(m.group(2)), m.group(1))
        # anything else: silently ignored
    except BackendError as exc:
        await send(context, chat_id, exc.user_message)
    except TelegramError as exc:
        logger.warning("Telegram error during match action: %s", exc)
    except Exception:
        logger.exception("Member match action failed")
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

    # Oversized input is rejected before any processing. If it was a password
    # attempt we still remove it from the chat.
    if len(raw) > MAX_INCOMING_TEXT:
        if session and session.step == "password":
            await _delete_quietly(message)
        await send(context, chat_id, "That message is too long.")
        return

    text = raw.strip()
    if not text or text.startswith("/"):
        return

    # --- no active login flow: main menu -----------------------------------
    if session is None:
        if text in (*MENU_ITEMS, *PHYSICAL_MATCH_ITEMS):
            try:
                account = await get_linked_account(context, chat_id)
                if account is None:
                    await show_login(context, chat_id)
                elif text == MENU_PLAY:
                    await show_physical_match_menu(context, chat_id)
                elif text == MENU_FIND_TABLE:
                    await show_venues(context, chat_id)
                elif text == MENU_CURRENT_MATCHES:
                    await show_current_matches(context, chat_id)
                elif text == MENU_LEAVE_TABLE:
                    await show_waiting_tables(context, chat_id)
                elif text == MENU_BACK:
                    await show_home(context, chat_id)
                else:
                    await send(
                        context,
                        chat_id,
                        "This option will be available in a later update.",
                        MENU_KEYBOARD,
                    )
            except BackendError as exc:
                if is_authentication_required(exc):
                    await show_login(context, chat_id)
                    return
                await send(context, chat_id, exc.user_message)
            except (TimedOut, NetworkError) as exc:
                logger.warning("Telegram network problem: %s", type(exc).__name__)
            except Exception:
                logger.exception("Menu action failed")
                await send(context, chat_id, "Something went wrong. Please try again.")
        return

    if isinstance(session, RegistrationSession):
        if session.step == "first_name":
            first_name = " ".join(strip_unsafe(text).split())
            if not first_name or len(first_name) > 80:
                await send(context, chat_id, "Enter a first name between 1 and 80 characters.")
                return
            session.first_name = first_name
            session.step = "last_name"
            await send(context, chat_id, "Enter your last name, or type Skip if you don't have one.")
            return

        if session.step == "last_name":
            last_name = "" if text.casefold() == "skip" else " ".join(strip_unsafe(text).split())
            if len(last_name) > 80:
                await send(context, chat_id, "Enter a last name up to 80 characters, or type Skip.")
                return
            session.last_name = last_name
            session.step = "phone"
            await send(
                context,
                chat_id,
                "Enter your phone number starting with 09 (for example, 0912345678).",
            )
            return

        if session.step == "phone":
            phone = clean_identifier(text)
            if not PHONE_RE.fullmatch(phone):
                await send(
                    context,
                    chat_id,
                    "Enter a valid phone number starting with 09, such as 0912345678.",
                )
                return
            session.phone = phone
            session.step = "address"
            await send(context, chat_id, "Enter your address (up to 200 characters).")
            return

        if session.step == "address":
            print(f'raw address: {text}')
            address = " ".join(strip_unsafe(text).split())
            if not address or len(address) > 200:
                await send(context, chat_id, "Enter an address between 1 and 200 characters.")
                return
            try:
                print(f'works here: {address}')
                districts = await list_registration_districts(context)
                print(f'districts :{districts}')
            except BackendError as exc:
                await send(context, chat_id, exc.user_message)
                return
            districts = [
                district for district in districts
                if to_int(district.get("id")) is not None
            ]
            if not districts:
                await send(
                    context,
                    chat_id,
                    "There are no active districts available right now. Please try registering later.",
                    LOGIN_KEYBOARD,
                )
                SESSIONS.pop(chat_key, None)
                return
            session.address = address
            session.step = "district"
            await send(
                context,
                chat_id,
                "Choose your district:",
                registration_district_keyboard(districts),
            )
            return

        if (
            session.step == "password"
            and session.phone
            and session.address
            and session.district_id is not None
        ):
            await _delete_quietly(message)
            if len(text) < 8 or not valid_password(text):
                await send(
                    context,
                    chat_id,
                    "Your password must be 8 to 128 printable characters. Enter it again, or use /cancel.",
                )
                return

            try:
                account = await register_telegram_account(context, chat_id, session, text)
            except BackendError as exc:
                message = exc.user_message.casefold()
                if "already exists" in message or "already linked" in message:
                    SESSIONS.pop(chat_key, None)
                    await send(context, chat_id, exc.user_message, LOGIN_KEYBOARD)
                    return
                await send(context, chat_id, exc.user_message)
                return
            except Exception:
                logger.exception("Telegram member registration failed")
                await send(context, chat_id, "Unable to complete registration. Please try again.")
                return

            SESSIONS.pop(chat_key, None)
            name = clean_display(account.get("name"), 60, session.first_name)
            member_id = clean_display(account.get("id"), 40)
            id_suffix = f" Your EthChess ID is {member_id}." if member_id else ""
            await send(
                context,
                chat_id,
                f"Welcome to EthChess, {name}! Your account is registered and linked to Telegram. "
                f"District: {session.district_name}.{id_suffix}",
                MENU_KEYBOARD,
            )
            return

    # --- login step 1: identifier ------------------------------------------
    if session.step == "identifier":
        identifier = clean_identifier(text)
        identifier_type = infer_identifier_type(identifier)
        if identifier_type is None or identifier_type != session.method:
            await send(
                context, chat_id,
                "Use a phone number starting with 09, or an ethchess ID starting with U or ETH.",
            )
            return
        session.step = "password"
        session.identifier = identifier
        session.identifier_type = identifier_type
        await send(context, chat_id, "Enter your ethchess password.")
        return

    # --- login step 2: password --------------------------------------------
    if session.step == "password" and session.identifier:
        await _delete_quietly(message)  # never leave the password in the chat

        if not valid_password(text):
            await send(context, chat_id, "That password isn't in a valid format. Enter it again, or use /cancel.")
            return

        username = message.from_user.username if message.from_user else None
        try:
            status, payload = await link_account(
                context,
                session.identifier,
                session.identifier_type or session.method,
                text,
                chat_id,
                username,
            )
        except BackendError as exc:
            await send(context, chat_id, exc.user_message)
            return
        except Exception as exc:  # never log the exception body: it may hold secrets
            logger.error("Member account linking failed: %s", type(exc).__name__)
            await send(context, chat_id, "Could not reach ethchess. Please try again or use /cancel.")
            return

        if status >= 400 or payload.get("success") is not True:
            if status == 401:
                session.attempts += 1
                if session.attempts >= MAX_LOGIN_ATTEMPTS:
                    SESSIONS.pop(chat_key, None)
                    await send(context, chat_id, "Too many failed attempts. Use /start to try again.")
                    return
                reply = "Those credentials were not accepted. Enter your password again, or use /cancel."
            else:
                reply = clean_display(
                    payload.get("message"), 300,
                    "Unable to connect your account right now. Please try again.",
                )
            await send(context, chat_id, reply)
            return

        SESSIONS.pop(chat_key, None)
        member_name = clean_display(as_dict(as_dict(payload.get("data")).get("member")).get("name"), 60)
        suffix = f" ({member_name})" if member_name else ""
        await send(context, chat_id, f"Your ethchess account{suffix} is connected.", MENU_KEYBOARD)


async def _delete_quietly(message) -> None:
    try:
        await message.delete()
    except TelegramError:
        pass


async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    # Telegram error messages do not contain the bot token, so including the message is safe.
    logger.error("Unhandled error: %s: %s", type(context.error).__name__, context.error)


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


def make_request(read_timeout: float = 30.0) -> HTTPXRequest:
    return HTTPXRequest(
        connection_pool_size=32,
        connect_timeout=30.0,
        read_timeout=read_timeout,
        write_timeout=30.0,
        pool_timeout=30.0,
        httpx_kwargs={
            # retry failed TCP connects, and force IPv4 (broken IPv6 routes are common)
            "transport": httpx.AsyncHTTPTransport(
                retries=3,
                local_address="0.0.0.0",
                limits=httpx.Limits(max_connections=32, max_keepalive_connections=32),
                # proxy="http://127.0.0.1:PORT",   # uncomment if you use a proxy/VPN
            ),
        },
    )


def main() -> None:
    application = (
        Application.builder()
        .token(TOKEN)
        .request(make_request())
        .get_updates_request(make_request(read_timeout=40.0))
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

    logger.info("Ethchess bot starting (backend: %s)", API_URL)
    application.run_polling(
        allowed_updates=["message", "callback_query"],
        bootstrap_retries=5,
    )


if __name__ == "__main__":
    main()