"""
Configuration module for NetScan.

This module handles configuration loading from file and provides
default configuration values.
"""
import json
import os


class Config:
    """Configuration class for NetScan application."""

    # Default configuration values
    DEFAULT_CONFIG = {
        "scan": {
            "max_workers": 2,
            "timeout": 2,
            "rate_limit": None,
            "exclude_ips": ["192.168.1.1"],  # IPs to exclude from scanning
        },
        "output": {
            "format": "json",  # json, csv, xml
            "file": "scan_results.json",
            "save_topology": True,
        },
        "network": {
            "interface": "Wi-Fi",  # Network interface to use
            "subnet_mask": "/24",
        },
        "features": {
            "service_detection": True,
            "os_detection": True,
            "banner_grabbing": True,
            "traceroute": True,
        },
    }

    def __init__(self, config_file=None):
        """
        Initialize configuration.

        Args:
            config_file (str, optional): Path to configuration file
        """
        self.config = self.DEFAULT_CONFIG.copy()
        if config_file and os.path.exists(config_file):
            self.load_config(config_file)

    def load_config(self, config_file):
        """
        Load configuration from a JSON file.

        Args:
            config_file (str): Path to configuration file
        """
        try:
            with open(config_file, 'r') as f:
                user_config = json.load(f)
                self._merge_config(user_config)
        except Exception as e:
            print(f"Error loading configuration: {e}")
            print("Using default configuration")

    def _merge_config(self, user_config):
        """
        Merge user configuration with default configuration.

        Args:
            user_config (dict): User-provided configuration
        """
        for section, values in user_config.items():
            if section in self.config:
                if isinstance(values, dict):
                    self.config[section].update(values)
                else:
                    self.config[section] = values

    def get(self, section, key=None):
        """
        Get configuration value.

        Args:
            section (str): Configuration section
            key (str, optional): Configuration key within section

        Returns:
            Configuration value or section
        """
        if key:
            return self.config.get(section, {}).get(key)
        return self.config.get(section)

    def save_config(self, config_file):
        """
        Save current configuration to a file.

        Args:
            config_file (str): Path to save configuration file
        """
        try:
            with open(config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
            print(f"Configuration saved to {config_file}")
        except Exception as e:
            print(f"Error saving configuration: {e}")


def create_default_config(filename="config.json"):
    """
    Create a default configuration file.

    Args:
        filename (str): Name of configuration file to create
    """
    config = Config()
    config.save_config(filename)
