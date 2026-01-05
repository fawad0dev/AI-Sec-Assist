#!/usr/bin/env python3
"""
AI Security Assistant
Main entry point for the application
"""
import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from gui.main_gui import main

if __name__ == "__main__":
    main()
