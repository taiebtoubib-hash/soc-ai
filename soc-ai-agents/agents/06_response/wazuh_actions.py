"""
Wazuh Actions: Execute host isolation and IP blocking via Wazuh API.
"""
from shared.logger import get_logger

logger = get_logger("wazuh_actions")

class WazuhActions:
    def block_ip(self, ip: str):
        """Add IP to Wazuh Active Response blocklist."""
        logger.info(f"Blocking IP via Wazuh: {ip}")
        # TODO: Implement API call
        pass

    def isolate_host(self, agent_id: str):
        """Isolate a host from the network via Wazuh agent."""
        logger.info(f"Isolating host via Wazuh: {agent_id}")
        # TODO: Implement API call
        pass
