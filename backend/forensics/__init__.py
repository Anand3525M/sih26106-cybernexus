"""
TraceMail Protocol Forensics Engine
Zero Custom Crypto: pyspf (RFC 7208), dkimpy (RFC 6376, RFC 8617), checkdmarc (RFC 7489)
"""
from backend.forensics.protocols import evaluate_email_protocols

__all__ = ["evaluate_email_protocols"]
