"""
Playbook Selector: Matches attack types to YAML playbooks.
"""
import yaml
import os
from shared.logger import get_logger

logger = get_logger("playbook_selector")

class PlaybookSelector:
    def __init__(self, playbooks_dir: str = "playbooks"):
        self.playbooks_dir = playbooks_dir

    def match_playbook(self, attack_type: str) -> dict:
        """Load and return the playbook matching the attack type."""
        playbook_path = os.path.join(self.playbooks_dir, f"{attack_type}.yaml")
        if os.path.exists(playbook_path):
            with open(playbook_path, 'r') as f:
                return yaml.safe_load(f)
        logger.warning(f"No playbook found for {attack_type}")
        return None
