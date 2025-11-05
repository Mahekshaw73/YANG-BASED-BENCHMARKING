#!/usr/bin/env python3
"""
YANG Configuration Management Module
Handles YANG model validation and JSON configuration instantiation.
"""

import json
import logging
import subprocess
import tempfile
import os
from pathlib import Path
from typing import Dict, List, Optional, Any
import sys


class YANGConfigManager:
    """Manages YANG model configuration and validation."""
    
    def __init__(self, yang_file: str = "dnssec-benchmark.yang"):
        self.yang_file = yang_file
        self.logger = logging.getLogger(__name__)
        
        # Check if pyang is available
        self.pyang_available = self._check_pyang()
        if not self.pyang_available:
            self.logger.warning("pyang not available - YANG validation will be skipped")
    
    def _check_pyang(self) -> bool:
        """Check if pyang is available in the system."""
        try:
            result = subprocess.run(['pyang', '--version'], 
                                  capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def validate_yang_model(self) -> bool:
        """Validate the YANG model using pyang."""
        if not self.pyang_available:
            self.logger.warning("pyang not available - skipping YANG validation")
            return True
        
        try:
            result = subprocess.run(
                ['pyang', self.yang_file],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                self.logger.info("YANG model validation successful")
                return True
            else:
                self.logger.error(f"YANG model validation failed: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.error("YANG validation timed out")
            return False
        except Exception as e:
            self.logger.error(f"YANG validation error: {e}")
            return False
    
    def validate_config_json(self, config_json: Dict) -> bool:
        """Validate configuration JSON against YANG model."""
        try:
            # Basic validation of required fields
            required_fields = ['target_ip', 'query_count', 'domains']
            for field in required_fields:
                if field not in config_json:
                    self.logger.error(f"Missing required field: {field}")
                    return False
            
            # Validate data types and ranges
            if not isinstance(config_json['target_ip'], str):
                self.logger.error("target_ip must be a string")
                return False
            
            if not isinstance(config_json['query_count'], int) or config_json['query_count'] <= 0:
                self.logger.error("query_count must be a positive integer")
                return False
            
            if not isinstance(config_json['domains'], list) or len(config_json['domains']) == 0:
                self.logger.error("domains must be a non-empty list")
                return False
            
            # Validate optional fields
            if 'port' in config_json:
                port = config_json['port']
                if not isinstance(port, int) or port < 1 or port > 65535:
                    self.logger.error("port must be an integer between 1 and 65535")
                    return False
            
            if 'rate_limit' in config_json:
                rate = config_json['rate_limit']
                if not isinstance(rate, (int, float)) or rate <= 0:
                    self.logger.error("rate_limit must be a positive number")
                    return False
            
            if 'dnssec_enabled' in config_json:
                if not isinstance(config_json['dnssec_enabled'], bool):
                    self.logger.error("dnssec_enabled must be a boolean")
                    return False
            
            self.logger.info("Configuration JSON validation successful")
            return True
            
        except Exception as e:
            self.logger.error(f"Configuration validation error: {e}")
            return False
    
    def load_config(self, config_path: str) -> Dict:
        """Load configuration from JSON file."""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            # Validate the configuration
            if not self.validate_config_json(config):
                raise ValueError("Configuration validation failed")
            
            return config
            
        except FileNotFoundError:
            self.logger.error(f"Configuration file not found: {config_path}")
            raise
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in configuration file: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Error loading configuration: {e}")
            raise
    
    def save_config(self, config: Dict, config_path: str):
        """Save configuration to JSON file."""
        try:
            # Validate before saving
            if not self.validate_config_json(config):
                raise ValueError("Configuration validation failed")
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=2)
            
            self.logger.info(f"Configuration saved to {config_path}")
            
        except Exception as e:
            self.logger.error(f"Error saving configuration: {e}")
            raise
    
    def create_default_config(self, target_ip: str, domains: List[str], 
                            query_count: int, **kwargs) -> Dict:
        """Create a default configuration with specified parameters."""
        config = {
            'target_ip': target_ip,
            'port': kwargs.get('port', 53),
            'dnssec_enabled': kwargs.get('dnssec_enabled', True),
            'query_count': query_count,
            'rate_limit': kwargs.get('rate_limit', 100.0),
            'timeout': kwargs.get('timeout', 5000),
            'capture_interface': kwargs.get('capture_interface', 'any'),
            'domains': domains
        }
        
        # Validate the created configuration
        if self.validate_config_json(config):
            return config
        else:
            raise ValueError("Failed to create valid configuration")
    
    def generate_sample_config(self, output_path: str = "sample_config.json"):
        """Generate a sample configuration file."""
        sample_config = {
            "target_ip": "8.8.8.8",
            "port": 53,
            "dnssec_enabled": True,
            "query_count": 1000,
            "rate_limit": 100.0,
            "timeout": 5000,
            "capture_interface": "any",
            "domains": [
                "example.com",
                "google.com",
                "cloudflare.com",
                "github.com",
                "stackoverflow.com"
            ]
        }
        
        self.save_config(sample_config, output_path)
        print(f"Sample configuration generated: {output_path}")
    
    def convert_to_yang_json(self, config: Dict) -> Dict:
        """Convert flat configuration to YANG-modeled JSON structure."""
        yang_json = {
            "dnssec-benchmark:benchmark-session": {
                "target-ip": config['target_ip'],
                "port": config['port'],
                "dnssec-enabled": config['dnssec_enabled'],
                "query-count": config['query_count'],
                "rate-limit": config['rate_limit'],
                "timeout": config['timeout'],
                "capture-interface": config['capture_interface'],
                "domains": [
                    {"name": domain} for domain in config['domains']
                ]
            }
        }
        
        return yang_json
    
    def convert_from_yang_json(self, yang_json: Dict) -> Dict:
        """Convert YANG-modeled JSON to flat configuration structure."""
        session = yang_json.get("dnssec-benchmark:benchmark-session", {})
        
        config = {
            'target_ip': session.get('target-ip'),
            'port': session.get('port', 53),
            'dnssec_enabled': session.get('dnssec-enabled', True),
            'query_count': session.get('query-count'),
            'rate_limit': session.get('rate-limit', 100.0),
            'timeout': session.get('timeout', 5000),
            'capture_interface': session.get('capture-interface', 'any'),
            'domains': [domain['name'] for domain in session.get('domains', [])]
        }
        
        return config
    
    def install_config(self, config: Dict, system_config_dir: str = "/etc/dnssec-benchmark/config/"):
        """Install configuration to system directory."""
        try:
            # Create system config directory
            os.makedirs(system_config_dir, exist_ok=True)
            
            # Save main configuration
            config_path = os.path.join(system_config_dir, "benchmark.json")
            self.save_config(config, config_path)
            
            # Save YANG-modeled configuration
            yang_config = self.convert_to_yang_json(config)
            yang_config_path = os.path.join(system_config_dir, "benchmark_yang.json")
            
            with open(yang_config_path, 'w') as f:
                json.dump(yang_config, f, indent=2)
            
            self.logger.info(f"Configuration installed to {system_config_dir}")
            
        except PermissionError:
            self.logger.error(f"Permission denied - cannot install to {system_config_dir}")
            raise
        except Exception as e:
            self.logger.error(f"Error installing configuration: {e}")
            raise
    
    def load_system_config(self, system_config_dir: str = "/etc/dnssec-benchmark/config/") -> Dict:
        """Load configuration from system directory."""
        config_path = os.path.join(system_config_dir, "benchmark.json")
        return self.load_config(config_path)
    
    def export_yang_tree(self, output_path: str = "yang_tree.txt"):
        """Export YANG model tree structure."""
        if not self.pyang_available:
            self.logger.error("pyang not available - cannot export tree")
            return False
        
        try:
            result = subprocess.run(
                ['pyang', '-f', 'tree', self.yang_file],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                with open(output_path, 'w') as f:
                    f.write(result.stdout)
                self.logger.info(f"YANG tree exported to {output_path}")
                return True
            else:
                self.logger.error(f"Failed to export YANG tree: {result.stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error exporting YANG tree: {e}")
            return False


# Example usage and testing
if __name__ == "__main__":
    # Initialize configuration manager
    config_manager = YANGConfigManager()
    
    # Validate YANG model
    if config_manager.validate_yang_model():
        print("✅ YANG model is valid")
    else:
        print("❌ YANG model validation failed")
    
    # Generate sample configuration
    config_manager.generate_sample_config()
    
    # Test configuration loading
    try:
        config = config_manager.load_config("sample_config.json")
        print("✅ Sample configuration loaded successfully")
        print(f"Target IP: {config['target_ip']}")
        print(f"Domains: {config['domains']}")
    except Exception as e:
        print(f"❌ Configuration loading failed: {e}")
    
    # Export YANG tree
    config_manager.export_yang_tree()
