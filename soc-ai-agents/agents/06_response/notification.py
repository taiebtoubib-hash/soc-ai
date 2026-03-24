"""
Notification Service: Sends alerts to Slack, Email, etc.
"""
import requests
from shared.logger import get_logger
from shared.config import settings

logger = get_logger("notification_service")

class NotificationService:
    def __init__(self):
        self.slack_url = settings.SLACK_WEBHOOK_URL

    def send_slack(self, message: str):
        """Send a message to a Slack channel."""
        logger.info(f"Sending Slack notification: {message}")
        if self.slack_url:
            # requests.post(self.slack_url, json={"text": message})
            pass

    def send_email(self, subject: str, body: str):
        """Send an email alert."""
        logger.info(f"Sending email notification: {subject}")
        # TODO: Implement SMTP logic
        pass
