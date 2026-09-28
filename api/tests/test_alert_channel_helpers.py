import os
import sys
import unittest


sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from main import (
    alert_display_severity,
    alert_display_status,
    mask_channel_config,
    normalize_alert_min_severity,
    normalize_channel_config,
)


class AlertChannelHelperTest(unittest.TestCase):
    def test_masks_sensitive_channel_fields(self):
        discord = mask_channel_config(
            "discord",
            {"webhook_url": "https://discord.com/api/webhooks/abc/secret"},
        )
        telegram = mask_channel_config("telegram", {"bot_token": "123456:abcdef"})
        email = mask_channel_config("email", {"smtp_password": "super-secret"})
        slack = mask_channel_config("slack", {"webhook_url": "https://hooks.slack.com/services/T000/B000/secret"})
        pushover = mask_channel_config("pushover", {"app_token": "app-secret", "user_key": "user-secret"})

        self.assertEqual(discord["webhook_url"], "https://discord.com/api/webhooks/***")
        self.assertEqual(telegram["bot_token"], "123456:***")
        self.assertEqual(email["smtp_password"], "********")
        self.assertEqual(slack["webhook_url"], "https://hooks.slack.com/***")
        self.assertEqual(pushover["app_token"], "app-se***")
        self.assertEqual(pushover["user_key"], "user-s***")

    def test_preserves_existing_sensitive_values_when_payload_is_masked(self):
        discord = normalize_channel_config(
            "discord",
            {"webhook_url": "https://discord.com/api/webhooks/***"},
            {"webhook_url": "https://discord.com/api/webhooks/real/token"},
        )
        email = normalize_channel_config(
            "email",
            {"smtp_password": "********"},
            {"smtp_password": "smtp-secret"},
        )
        pushover = normalize_channel_config(
            "pushover",
            {"app_token": "app-to***", "user_key": "user-k***"},
            {"app_token": "app-token-real", "user_key": "user-key-real"},
        )

        self.assertEqual(discord["webhook_url"], "https://discord.com/api/webhooks/real/token")
        self.assertEqual(email["smtp_password"], "smtp-secret")
        self.assertEqual(pushover["app_token"], "app-token-real")
        self.assertEqual(pushover["user_key"], "user-key-real")

    def test_normalizes_min_severity(self):
        self.assertEqual(normalize_alert_min_severity("critical"), "CRITICAL")

    def test_maps_legacy_incident_values_for_alert_display(self):
        self.assertEqual(alert_display_severity("warning"), "MEDIUM")
        self.assertEqual(alert_display_severity("critical"), "CRITICAL")
        self.assertEqual(alert_display_status("closed"), "RESOLVED")
        self.assertEqual(alert_display_status("open"), "OPEN")


if __name__ == "__main__":
    unittest.main()
