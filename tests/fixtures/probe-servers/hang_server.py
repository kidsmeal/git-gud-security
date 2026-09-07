#!/usr/bin/env python3
"""Test fixture: reads stdin and never answers. The probe must time out and kill it."""
import sys

for _ in sys.stdin:
    pass
