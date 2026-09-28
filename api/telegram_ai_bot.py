# -*- coding: utf-8 -*-
import json
import logging
import os
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s %(levelname)s %(message)s")
LOGGER = logging.getLogger("netguard.telegram_ai_bot")

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()
ENABLED = os.getenv("TELEGRAM_AI_BOT_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"}
POLL_INTERVAL_SEC = max(2, int(float(os.getenv("TELEGRAM_AI_POLL_INTERVAL_SEC", "5"))))
RESPONSE_TIMEOUT_SEC = max(10, int(float(os.getenv("TELEGRAM_AI_RESPONSE_TIMEOUT_SEC", "180"))))
API_BASE_URL = os.getenv("NETGUARD_API_BASE_URL", "http://api:8000").strip().rstrip("/")
SERVICE_TOKEN = os.getenv("NETGUARD_SERVICE_TOKEN", "").strip()
COMMANDS = ("/netguard", "/ng")


def telegram_request(method: str, payload: dict | None = None, timeout: int = 30) -> dict:
    if not BOT_TOKEN:
        return {}
    data = None
    headers = {}
    if payload is not None:
        data = urlencode(payload).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    request = Request(
        f"https://api.telegram.org/bot{BOT_TOKEN}/{method}",
        data=data,
        headers=headers,
        method="POST" if payload is not None else "GET",
    )
    with urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def send_message(chat_id: str, text: str) -> None:
    cleaned = str(text or "").strip() or "Sem resposta do assistente operacional."
    # Telegram accepts up to 4096 chars; keep a margin for predictable delivery.
    if len(cleaned) > 3900:
        cleaned = cleaned[:3890].rstrip() + "\n\n[resposta truncada]"
    telegram_request(
        "sendMessage",
        {
            "chat_id": chat_id,
            "text": cleaned,
            "disable_web_page_preview": "true",
        },
        timeout=30,
    )


def ask_netguard_ai(message: str) -> str:
    payload = {
        "message": message,
        "hours": 24,
        "history": [],
        "response_mode": "auto",
    }
    headers = {"Content-Type": "application/json"}
    if SERVICE_TOKEN:
        headers["X-NetGuard-Service-Token"] = SERVICE_TOKEN
    request = Request(
        f"{API_BASE_URL}/ai/chat",
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    with urlopen(request, timeout=RESPONSE_TIMEOUT_SEC) as response:
        data = json.loads(response.read().decode("utf-8"))
    return str(data.get("reply_md") or "").strip()


def extract_command_text(text: str) -> str | None:
    raw = str(text or "").strip()
    lowered = raw.lower()
    for command in COMMANDS:
        if lowered == command:
            return "Resuma o estado atual do ambiente."
        if lowered.startswith(command + " "):
            return raw[len(command) :].strip() or "Resuma o estado atual do ambiente."
    return None


def iter_updates(offset: int | None) -> tuple[int | None, list[dict]]:
    params = {"timeout": "20", "allowed_updates": json.dumps(["message"])}
    if offset is not None:
        params["offset"] = str(offset)
    data = telegram_request("getUpdates", params, timeout=30)
    updates = data.get("result") or []
    next_offset = offset
    for item in updates:
        update_id = item.get("update_id")
        if isinstance(update_id, int):
            next_offset = max(next_offset or 0, update_id + 1)
    return next_offset, updates


def handle_update(update: dict) -> None:
    message = update.get("message") or {}
    text = message.get("text") or ""
    chat = message.get("chat") or {}
    chat_id = str(chat.get("id") or "").strip()
    if not chat_id:
        return
    if CHAT_ID and chat_id != CHAT_ID:
        return
    question = extract_command_text(text)
    if question is None:
        return
    try:
        reply = ask_netguard_ai(question)
    except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
        LOGGER.warning("Falha ao consultar IA para Telegram: %s", exc)
        reply = (
            "NetGuard IA\n\n"
            "Não consegui consultar o assistente operacional agora. "
            "Verifique a API, o Ollama e tente novamente em instantes."
        )
    send_message(chat_id, f"NetGuard IA\n\n{reply}")


def main() -> None:
    if not ENABLED:
        LOGGER.info("Telegram AI bot desativado por TELEGRAM_AI_BOT_ENABLED=false.")
        while True:
            time.sleep(60)
    if not BOT_TOKEN:
        LOGGER.warning("TELEGRAM_BOT_TOKEN não configurado; bot ficará em espera.")
        while True:
            time.sleep(60)

    LOGGER.info("Telegram AI bot iniciado.")
    offset = None
    while True:
        try:
            offset, updates = iter_updates(offset)
            for update in updates:
                handle_update(update)
        except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
            LOGGER.warning("Falha no polling do Telegram: %s", exc)
            time.sleep(POLL_INTERVAL_SEC)
        time.sleep(POLL_INTERVAL_SEC)


if __name__ == "__main__":
    main()

