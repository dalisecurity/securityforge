"""
Fray — AI-Powered WAF Security Testing Platform

Open-source offensive security toolkit with 5,500+ attack payloads,
25 WAF vendor fingerprints, and AI-native workflows.

Usage:
    pip install fray
    fray detect https://example.com
    fray test https://example.com --category xss
"""

__version__ = "3.0.1"
__author__ = "DALI Security"
__license__ = "MIT"

from pathlib import Path

PACKAGE_DIR = Path(__file__).parent
PAYLOADS_DIR = PACKAGE_DIR / "payloads"
