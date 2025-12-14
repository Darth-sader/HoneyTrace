"""
HONEYTRACE - Configuration Management
"""

import os
import logging

logger = logging.getLogger('HONEYTRACE')

def load_decoy_paths(config_file='config/honeypots.list'):
    """Reads the config file and returns a list of decoy file paths."""
    decoys = []
    try:
        with open(config_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    decoys.append(line)
        return decoys
    except FileNotFoundError:
        logger.error(f"Configuration file '{config_file}' not found.")
        raise
    except Exception as e:
        logger.error(f"Error reading config file: {e}")
        raise

def setup_report_directory():
    """Creates the report directory if it doesn't exist."""
    report_dir = '/var/log/honeytrace/reports'  # System-wide
    os.makedirs(report_dir, exist_ok=True)
    os.chmod('/var/log/honeytrace', 0o755)
    os.chmod(report_dir, 0o755)
    return report_dir

