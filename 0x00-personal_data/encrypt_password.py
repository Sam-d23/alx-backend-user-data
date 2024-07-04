#!/usr/bin/env python3
"""
This module for encrypting passwords.
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hashing a password using a random salt.
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Checking if a hashed password was formed from the given password.
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
