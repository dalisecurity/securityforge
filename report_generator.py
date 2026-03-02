#!/usr/bin/env python3
"""
Report Generator — backward-compatible wrapper.
Implementation: securityforge/reporter.py

Preferred usage:
    pip install securityforge
    securityforge report
"""
import runpy, sys, os
sys.argv[0] = os.path.join(os.path.dirname(os.path.abspath(__file__)), "securityforge", "reporter.py")
runpy.run_path(sys.argv[0], run_name="__main__")
