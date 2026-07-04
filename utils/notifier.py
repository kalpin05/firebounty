"""
FireBounty v2 - Notification Utility
"""

import requests
from core.config_loader import load_config
from utils.logger import log

def send_telegram(message: str) -> bool:
    """
    Sends an alert message to a configured Telegram bot chat.
    """
    try:
        config = load_config()
        notif_cfg = config.get("notifications", {})
        token = notif_cfg.get("telegram_token")
        chat_id = notif_cfg.get("telegram_chat_id")

        if not token or not chat_id:
            return False

        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": message
        }
        r = requests.post(url, json=payload, timeout=10)
        if r.status_code == 200:
            log(f"[Notifier] Telegram alert sent successfully.")
            return True
        else:
            log(f"[Notifier] Telegram alert failed with code {r.status_code}: {r.text}")
    except Exception as e:
        log(f"[Notifier] Error sending Telegram alert: {e}")
    return False


def send_discord(message: str) -> bool:
    """
    Sends an alert message to a configured Discord channel via Webhook.
    """
    try:
        config = load_config()
        notif_cfg = config.get("notifications", {})
        webhook_url = notif_cfg.get("discord_webhook_url")

        if not webhook_url:
            return False

        payload = {
            "content": message
        }
        r = requests.post(webhook_url, json=payload, timeout=10)
        if r.status_code in [200, 204]:
            log(f"[Notifier] Discord alert sent successfully.")
            return True
        else:
            log(f"[Notifier] Discord alert failed with code {r.status_code}: {r.text}")
    except Exception as e:
        log(f"[Notifier] Error sending Discord alert: {e}")
    return False


def send_alert(message: str) -> None:
    """
    Sends alert to all configured notification channels.
    """
    telegram_sent = send_telegram(message)
    discord_sent = send_discord(message)
    
    if not telegram_sent and not discord_sent:
        log(f"[Notifier] No notifications sent (channels not configured or failed). Alert: {message}")
