"""
Vulnerable Applications for IDOR Testing

This module contains intentionally vulnerable web applications 
for educational and security testing purposes only.
"""

from .basic_app import create_basic_app
from .advanced_app import create_advanced_app

__all__ = ['create_basic_app', 'create_advanced_app']