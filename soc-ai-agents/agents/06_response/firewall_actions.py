"""
Firewall Actions: Manage local or network firewall rules.
"""
from shared.logger import get_logger

logger = get_logger("firewall_actions")

class FirewallActions:
    def add_block_rule(self, ip: str):
        """Add a firewall rule to block an IP."""
        logger.info(f"Adding firewall block rule for: {ip}")
        # TODO: Implement iptables or cloud FW logic
        pass
