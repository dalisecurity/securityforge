#!/usr/bin/env python3
"""
Easy Payload Creator — backward-compatible wrapper.
Implementation: securityforge/payload_creator.py

Preferred usage:
    pip install securityforge
    securityforge payloads
"""
import runpy, sys, os
sys.argv[0] = os.path.join(os.path.dirname(os.path.abspath(__file__)), "securityforge", "payload_creator.py")
runpy.run_path(sys.argv[0], run_name="__main__")
