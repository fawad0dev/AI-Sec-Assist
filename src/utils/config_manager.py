"""
Configuration Manager
Handles application settings and persistence
"""
import json
import os
from typing import Dict, List


class ConfigManager:
    """Manage application configuration"""
    
    DEFAULT_CONFIG = {
        "ai": {
            "model": "llama2",
            "ollama_url": "http://localhost:11434",
            "temperature": 0.1
        },
        "scan": {
            "log_paths": [],
            "max_log_lines": 1000,
            "scan_file_strings": True,
            "network_scan_enabled": True,
            "registry_scan_enabled": True
        },
        "ui": {
            "theme": "dark",
            "window_width": 1200,
            "window_height": 800
        }
    }
    
    def __init__(self, config_file: str = "config.json"):
        self.config_file = config_file
        self.config = self.load_config()
    
    def load_config(self) -> Dict:
        """Load configuration from file or create default"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    loaded_config = json.load(f)
                    # Merge with defaults to ensure all keys exist
                    config = self.DEFAULT_CONFIG.copy()
                    config.update(loaded_config)
                    return config
            except Exception as e:
                print(f"Error loading config: {e}")
                return self.DEFAULT_CONFIG.copy()
        else:
            return self.DEFAULT_CONFIG.copy()
    
    def save_config(self):
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            print(f"Error saving config: {e}")
    
    def get(self, section: str, key: str, default=None):
        """Get a configuration value"""
        return self.config.get(section, {}).get(key, default)
    
    def set(self, section: str, key: str, value):
        """Set a configuration value"""
        if section not in self.config:
            self.config[section] = {}
        self.config[section][key] = value
        self.save_config()
    
    def get_log_paths(self) -> List[str]:
        """Get configured log paths"""
        return self.config.get("scan", {}).get("log_paths", [])
    
    def add_log_path(self, path: str):
        """Add a log path to configuration"""
        paths = self.get_log_paths()
        if path not in paths:
            paths.append(path)
            self.set("scan", "log_paths", paths)
    
    def remove_log_path(self, path: str):
        """Remove a log path from configuration"""
        paths = self.get_log_paths()
        if path in paths:
            paths.remove(path)
            self.set("scan", "log_paths", paths)
    
    def get_ai_model(self) -> str:
        """Get configured AI model"""
        return self.config.get("ai", {}).get("model", "llama2")
    
    def set_ai_model(self, model: str):
        """Set AI model"""
        self.set("ai", "model", model)
    
    def get_ollama_url(self) -> str:
        """Get Ollama URL"""
        return self.config.get("ai", {}).get("ollama_url", "http://localhost:11434")
    
    def set_ollama_url(self, url: str):
        """Set Ollama URL"""
        self.set("ai", "ollama_url", url)
