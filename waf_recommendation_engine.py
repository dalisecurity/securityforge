#!/usr/bin/env python3
"""
WAF Recommendation Engine — backward-compatible wrapper.
Implementation: securityforge/recommender.py

Preferred usage:
    pip install securityforge
"""
import runpy, sys, os
sys.argv[0] = os.path.join(os.path.dirname(os.path.abspath(__file__)), "securityforge", "recommender.py")
runpy.run_path(sys.argv[0], run_name="__main__")
