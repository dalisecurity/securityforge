"""
SecurityForge — AI-Powered WAF Security Testing Platform

Open-source offensive security toolkit with 4,025+ attack payloads,
25 WAF vendor fingerprints, and AI-native workflows.

Usage:
    pip install securityforge
    securityforge detect https://example.com
    securityforge test https://example.com --category xss
"""

__version__ = "3.0.0"
__author__ = "DALI Security"
__license__ = "MIT"

from pathlib import Path

PACKAGE_DIR = Path(__file__).parent
PAYLOADS_DIR = PACKAGE_DIR / "payloads"
